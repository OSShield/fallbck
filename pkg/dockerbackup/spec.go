// Package dockerbackup holds the Docker host backup job specification, the agent-side
// settings and the run manifest. It is shared by the server (validation) and the
// filesystem agent (execution on the Docker host), so it must stay free of
// process-execution dependencies.
package dockerbackup

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/osshield/fallbck/pkg/fsutil"
	"github.com/osshield/gopbs/scan"
)

// Names inside the snapshot
const (
	// ArchiveName is the pxar archive holding the definitions and the volumes
	ArchiveName = "docker"
	// ManifestBlobName / ManifestFileName is the run manifest (blob and inside collect/)
	ManifestBlobName = "fallbck-docker.json"
	ManifestFileName = "fallbck-docker.json"
	// RestoreScriptName is the generated restore runbook inside collect/
	RestoreScriptName = "fallbck-docker-restore.sh"
	// CollectEntry is the archive entry holding definitions, compose files, the
	// daemon configuration, saved images, the manifest and the restore script
	CollectEntry = "collect"
	// VolumeEntryPrefix prefixes the archive entry of every named volume
	VolumeEntryPrefix = "vol-"
	// HostPathEntryPrefix prefixes the archive entry of every additional host path
	// (/srv/app → host-srv-app)
	HostPathEntryPrefix = "host-"
)

// Labels honoured on containers and volumes
const (
	// LabelSkip excludes a container (its definition) or a volume from the backup
	LabelSkip = "fallbck.io/skip"
	// LabelPause pauses a container while the volumes it mounts are read
	LabelPause = "fallbck.io/pause"
)

// Image modes
const (
	// ImagesRefs records image references (name, tag, digest) only
	ImagesRefs = "refs"
	// ImagesLocal additionally saves images without a registry reference (built locally)
	ImagesLocal = "local"
	// ImagesAll saves every image a container uses
	ImagesAll = "all"
)

// Spec is the Docker host job configuration (backup_jobs.docker_config). Container,
// network and volume definitions, compose config files and the daemon configuration
// are always included; every named volume is archived file by file unless excluded.
type Spec struct {
	// ExcludeContainers are name globs of containers whose definitions are skipped
	ExcludeContainers []string `json:"exclude_containers,omitempty"`
	// ExcludeVolumes are name globs of volumes that are not archived
	ExcludeVolumes []string `json:"exclude_volumes,omitempty"`
	// IncludeUnusedVolumes archives volumes no container mounts (default true)
	IncludeUnusedVolumes *bool `json:"include_unused_volumes,omitempty"`
	// IncludeStopped records the definitions of stopped containers (default true)
	IncludeStopped *bool `json:"include_stopped,omitempty"`
	// Images is refs (default), local or all
	Images string `json:"images,omitempty"`
	// PauseContainers are name globs of containers paused while their volumes are
	// read, in addition to those labeled fallbck.io/pause=true
	PauseContainers []string `json:"pause_containers,omitempty"`
	// HostPaths are additional host directories archived file by file next to the
	// volumes (compose project directories, bind-mounted data, /etc/docker extras),
	// each as its own entry host-<path>
	HostPaths []string `json:"host_paths,omitempty"`
	// ExcludePaths are proxmox-backup-client style patterns against archive paths
	// (/vol-<name>/..., /host-<path>/...)
	ExcludePaths []string `json:"exclude_paths,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid Docker host job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// Validate normalises the globs and patterns and checks the image mode
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	var err error
	if s.ExcludeContainers, err = cleanGlobs("exclude_containers", s.ExcludeContainers); err != nil {
		return err
	}
	if s.ExcludeVolumes, err = cleanGlobs("exclude_volumes", s.ExcludeVolumes); err != nil {
		return err
	}
	if s.PauseContainers, err = cleanGlobs("pause_containers", s.PauseContainers); err != nil {
		return err
	}
	mode, ok := NormalizeImages(s.Images)
	if !ok {
		return specErr("images must be %s, %s or %s", ImagesRefs, ImagesLocal, ImagesAll)
	}
	s.Images = mode
	if s.HostPaths, err = cleanHostPaths(s.HostPaths); err != nil {
		return err
	}
	var patterns []string
	for _, p := range s.ExcludePaths {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	if _, err := scan.ParsePatterns(patterns); err != nil {
		return specErr("invalid exclude pattern: %v", err)
	}
	s.ExcludePaths = patterns
	return nil
}

// cleanGlobs trims, drops empty entries and checks the glob syntax
func cleanGlobs(field string, globs []string) ([]string, error) {
	var out []string
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, err := path.Match(g, ""); err != nil {
			return nil, specErr("%s: invalid pattern %q", field, g)
		}
		out = append(out, g)
	}
	return out, nil
}

// cleanHostPaths normalises the host paths: absolute, cleaned, not the root, no
// duplicates and none inside another
func cleanHostPaths(paths []string) ([]string, error) {
	seen := map[string]bool{}
	var cleaned []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			return nil, specErr("host path %q must be absolute", p)
		}
		p = filepath.ToSlash(filepath.Clean(p))
		if p == "/" {
			return nil, specErr("host path / is not allowed; this job backs up definitions and volumes, not the whole disk")
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	sort.Strings(cleaned)
	for i := 1; i < len(cleaned); i++ {
		if strings.HasPrefix(cleaned[i], cleaned[i-1]+"/") {
			return nil, specErr("host path %s is inside %s", cleaned[i], cleaned[i-1])
		}
	}
	return cleaned, nil
}

// HostPathEntry is the archive entry name of a host path (/srv/app → host-srv-app)
func HostPathEntry(p string) string {
	return HostPathEntryPrefix + fsutil.FlattenPath(p)
}

// NormalizeImages maps "" to refs and reports unknown modes
func NormalizeImages(mode string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ImagesRefs:
		return ImagesRefs, true
	case ImagesLocal:
		return ImagesLocal, true
	case ImagesAll:
		return ImagesAll, true
	}
	return mode, false
}

// MatchesAny reports whether name matches one of the globs (container names are
// matched with and without their leading slash)
func MatchesAny(name string, globs []string) bool {
	name = strings.TrimPrefix(name, "/")
	for _, g := range globs {
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// EffIncludeUnusedVolumes / EffIncludeStopped / EffImages apply the defaults
func (s *Spec) EffIncludeUnusedVolumes() bool {
	return s == nil || s.IncludeUnusedVolumes == nil || *s.IncludeUnusedVolumes
}
func (s *Spec) EffIncludeStopped() bool {
	return s == nil || s.IncludeStopped == nil || *s.IncludeStopped
}
func (s *Spec) EffImages() string {
	if s == nil {
		return ImagesRefs
	}
	mode, _ := NormalizeImages(s.Images)
	return mode
}

// Clone returns a deep copy
func (s *Spec) Clone() *Spec {
	if s == nil {
		return nil
	}
	c := *s
	c.ExcludeContainers = append([]string(nil), s.ExcludeContainers...)
	c.ExcludeVolumes = append([]string(nil), s.ExcludeVolumes...)
	c.PauseContainers = append([]string(nil), s.PauseContainers...)
	c.HostPaths = append([]string(nil), s.HostPaths...)
	c.ExcludePaths = append([]string(nil), s.ExcludePaths...)
	if s.IncludeUnusedVolumes != nil {
		v := *s.IncludeUnusedVolumes
		c.IncludeUnusedVolumes = &v
	}
	if s.IncludeStopped != nil {
		v := *s.IncludeStopped
		c.IncludeStopped = &v
	}
	return &c
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	parts := []string{"definitions + volumes"}
	if s == nil {
		return parts[0]
	}
	if len(s.ExcludeVolumes) > 0 {
		parts = append(parts, "except "+strings.Join(s.ExcludeVolumes, ", "))
	}
	if len(s.HostPaths) > 0 {
		parts = append(parts, "+ "+strings.Join(s.HostPaths, ", "))
	}
	switch s.EffImages() {
	case ImagesLocal:
		parts = append(parts, "local images")
	case ImagesAll:
		parts = append(parts, "all images")
	}
	return strings.Join(parts, "; ")
}
