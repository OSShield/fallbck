// Package k8sbackup holds the Kubernetes backup job specification (backup_jobs.k8s_config),
// the discovery plan exchanged between server and agent, and the run manifest. It is
// shared by the server (validation), the workflow and the agent, so it stays
// free of client-go machinery beyond label-selector parsing.
package k8sbackup

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/labels"
)

// Volume selection modes
const (
	VolumesAll     = "all"     // every PVC passing the filters
	VolumesLabeled = "labeled" // only PVCs matching volumes.label_selector
	VolumesNone    = "none"    // resources only
)

// Per-volume backup modes decided at discovery
const (
	ModeSnapshot = "snapshot" // CSI VolumeSnapshot → clone → upload
	ModeLive     = "live"     // read-only mount of the live volume
	ModeSkipped  = "skipped"
)

// DefaultExcludedNamespaces prefills the UI form (control-plane churn)
var DefaultExcludedNamespaces = []string{"kube-system", "kube-node-lease", "kube-public"}

// Limits
const (
	MaxParallelism    = 8
	MaxVolumes        = 500
	MaxSnapshotWait   = 30 * time.Minute
	MaxVolumeTimeout  = 5 * time.Hour
	DefaultParallel   = 2
	DefaultSnapWait   = 10 * time.Minute
	DefaultVolTimeout = 2 * time.Hour
)

// NamespaceFilter selects namespaces with glob patterns (path.Match syntax);
// an empty include list means all namespaces.
type NamespaceFilter struct {
	Include []string `json:"include,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}

// Matches reports whether a namespace passes the filter
func (f NamespaceFilter) Matches(ns string) bool {
	match := func(patterns []string) bool {
		for _, p := range patterns {
			if ok, _ := path.Match(p, ns); ok || p == ns {
				return true
			}
		}
		return false
	}
	if len(f.Include) > 0 && !match(f.Include) {
		return false
	}
	return !match(f.Exclude)
}

// ResourceOptions configure the API resource dump
type ResourceOptions struct {
	// ExcludeExtra adds group/resource patterns to the built-in exclusion list
	// ("apps/deployments", "*/secrets", "cert-manager.io/*")
	ExcludeExtra []string `json:"exclude_extra,omitempty"`
	// IncludeSecrets defaults to true: a disaster-recovery backup without Secrets is
	// crippled; the UI carries the warning instead
	IncludeSecrets *bool `json:"include_secrets,omitempty"`
}

// VolumeOptions configure PVC backups
type VolumeOptions struct {
	Mode          string `json:"mode,omitempty"` // all | labeled | none
	LabelSelector string `json:"label_selector,omitempty"`
	// Namespaces overrides the top-level namespace filter for volumes (nil = inherit)
	Namespaces            *NamespaceFilter `json:"namespaces,omitempty"`
	StorageClasses        []string         `json:"storage_classes,omitempty"`
	ExcludeStorageClasses []string         `json:"exclude_storage_classes,omitempty"`
	// SnapshotClassOverrides maps a StorageClass to the VolumeSnapshotClass to use
	SnapshotClassOverrides map[string]string `json:"snapshot_class_overrides,omitempty"`
	// AllowLiveFallback (default true) backs up volumes without snapshot support by
	// mounting them read-only (rsync-grade consistency)
	AllowLiveFallback *bool `json:"allow_live_fallback,omitempty"`
	// ContinueOnError (default true) records failed volumes and completes the run
	ContinueOnError *bool `json:"continue_on_error,omitempty"`
	// Parallelism bounds concurrent volume uploads (worker pods), 1..8, default 2
	Parallelism int `json:"parallelism,omitempty"`
	// SnapshotTimeout waits for a VolumeSnapshot to become ready (default 10m, max 30m)
	SnapshotTimeout string `json:"snapshot_timeout,omitempty"`
	// VolumeTimeout bounds one volume's snapshot+upload (default 2h, max 5h)
	VolumeTimeout string `json:"volume_timeout,omitempty"`
}

// Spec is the Kubernetes job configuration (backup_jobs.k8s_config)
type Spec struct {
	Namespaces    NamespaceFilter `json:"namespaces"`
	LabelSelector string          `json:"label_selector,omitempty"`
	Resources     ResourceOptions `json:"resources"`
	Volumes       VolumeOptions   `json:"volumes"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid kubernetes job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

var nsPatternRe = regexp.MustCompile(`^[a-z0-9*?.\-\[\]]+$`)
var grPatternRe = regexp.MustCompile(`^[a-z0-9*?.\-]*/[a-z0-9*?.\-]+$`)

func validateNamespacePatterns(patterns []string, field string) error {
	for _, p := range patterns {
		if p == "" || !nsPatternRe.MatchString(p) {
			return specErr("%s pattern %q is not a valid namespace glob", field, p)
		}
		if _, err := path.Match(p, "x"); err != nil {
			return specErr("%s pattern %q does not parse: %v", field, p, err)
		}
	}
	return nil
}

// Validate normalises the spec and rejects inconsistent settings; called at job
// create/update and defensively before a run.
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	if err := validateNamespacePatterns(s.Namespaces.Include, "namespaces.include"); err != nil {
		return err
	}
	if err := validateNamespacePatterns(s.Namespaces.Exclude, "namespaces.exclude"); err != nil {
		return err
	}
	if s.LabelSelector != "" {
		if _, err := labels.Parse(s.LabelSelector); err != nil {
			return specErr("label_selector: %v", err)
		}
	}
	for _, p := range s.Resources.ExcludeExtra {
		if !grPatternRe.MatchString(p) {
			return specErr("resources.exclude_extra %q must be group/resource (e.g. \"apps/deployments\", \"*/secrets\")", p)
		}
	}

	v := &s.Volumes
	switch v.Mode {
	case "":
		v.Mode = VolumesAll
	case VolumesAll, VolumesLabeled, VolumesNone:
	default:
		return specErr("volumes.mode %q is not one of all, labeled, none", v.Mode)
	}
	if v.Mode == VolumesLabeled && strings.TrimSpace(v.LabelSelector) == "" {
		return specErr("volumes.mode \"labeled\" requires volumes.label_selector")
	}
	if v.LabelSelector != "" {
		if _, err := labels.Parse(v.LabelSelector); err != nil {
			return specErr("volumes.label_selector: %v", err)
		}
	}
	if v.Namespaces != nil {
		if err := validateNamespacePatterns(v.Namespaces.Include, "volumes.namespaces.include"); err != nil {
			return err
		}
		if err := validateNamespacePatterns(v.Namespaces.Exclude, "volumes.namespaces.exclude"); err != nil {
			return err
		}
	}
	for sc, vsc := range v.SnapshotClassOverrides {
		if strings.TrimSpace(sc) == "" || strings.TrimSpace(vsc) == "" {
			return specErr("volumes.snapshot_class_overrides entries must map a storage class to a snapshot class")
		}
	}
	if v.Parallelism == 0 {
		v.Parallelism = DefaultParallel
	}
	if v.Parallelism < 1 || v.Parallelism > MaxParallelism {
		return specErr("volumes.parallelism must be between 1 and %d", MaxParallelism)
	}
	if _, err := parseBoundedDuration(v.SnapshotTimeout, DefaultSnapWait, MaxSnapshotWait); err != nil {
		return specErr("volumes.snapshot_timeout: %v", err)
	}
	if _, err := parseBoundedDuration(v.VolumeTimeout, DefaultVolTimeout, MaxVolumeTimeout); err != nil {
		return specErr("volumes.volume_timeout: %v", err)
	}
	return nil
}

func parseBoundedDuration(s string, def, max time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 || d > max {
		return 0, fmt.Errorf("%s is out of range (0 .. %s]", s, max)
	}
	return d, nil
}

// Effective option accessors (defaults applied)

func (s *Spec) IncludeSecrets() bool { return boolDefault(s.Resources.IncludeSecrets, true) }

func (v *VolumeOptions) EffAllowLiveFallback() bool { return boolDefault(v.AllowLiveFallback, true) }
func (v *VolumeOptions) EffContinueOnError() bool   { return boolDefault(v.ContinueOnError, true) }
func (v *VolumeOptions) EffParallelism() int {
	if v.Parallelism < 1 {
		return DefaultParallel
	}
	if v.Parallelism > MaxParallelism {
		return MaxParallelism
	}
	return v.Parallelism
}
func (v *VolumeOptions) EffSnapshotTimeout() time.Duration {
	d, _ := parseBoundedDuration(v.SnapshotTimeout, DefaultSnapWait, MaxSnapshotWait)
	return d
}
func (v *VolumeOptions) EffVolumeTimeout() time.Duration {
	d, _ := parseBoundedDuration(v.VolumeTimeout, DefaultVolTimeout, MaxVolumeTimeout)
	return d
}

// VolumeNamespaces is the namespace filter that applies to volumes
func (s *Spec) VolumeNamespaces() NamespaceFilter {
	if s.Volumes.Namespaces != nil {
		return *s.Volumes.Namespaces
	}
	return s.Namespaces
}

func boolDefault(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

// Clone returns a deep copy
func (s *Spec) Clone() *Spec {
	if s == nil {
		return nil
	}
	c := *s
	c.Namespaces.Include = append([]string(nil), s.Namespaces.Include...)
	c.Namespaces.Exclude = append([]string(nil), s.Namespaces.Exclude...)
	c.Resources.ExcludeExtra = append([]string(nil), s.Resources.ExcludeExtra...)
	c.Volumes.StorageClasses = append([]string(nil), s.Volumes.StorageClasses...)
	c.Volumes.ExcludeStorageClasses = append([]string(nil), s.Volumes.ExcludeStorageClasses...)
	if s.Volumes.Namespaces != nil {
		ns := NamespaceFilter{Include: append([]string(nil), s.Volumes.Namespaces.Include...), Exclude: append([]string(nil), s.Volumes.Namespaces.Exclude...)}
		c.Volumes.Namespaces = &ns
	}
	if s.Volumes.SnapshotClassOverrides != nil {
		m := make(map[string]string, len(s.Volumes.SnapshotClassOverrides))
		for k, val := range s.Volumes.SnapshotClassOverrides {
			m[k] = val
		}
		c.Volumes.SnapshotClassOverrides = m
	}
	return &c
}

// Summary is a short human-readable description for the UI list
func (s *Spec) Summary() string {
	if s == nil {
		return ""
	}
	ns := "all namespaces"
	if len(s.Namespaces.Include) > 0 {
		ns = strings.Join(s.Namespaces.Include, ", ")
	}
	vols := s.Volumes.Mode
	if vols == "" {
		vols = VolumesAll
	}
	return fmt.Sprintf("resources: %s · volumes: %s", ns, vols)
}
