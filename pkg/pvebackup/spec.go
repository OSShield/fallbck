// Package pvebackup holds the Proxmox VE host backup job specification and run
// manifest. It is shared by the server (validation) and the filesystem agent
// (execution on the PVE node), so it must stay free of process-execution dependencies.
package pvebackup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/osshield/gopbs/scan"
)

// Names inside the snapshot
const (
	// ArchiveName is the pxar archive holding the host configuration and data paths
	ArchiveName = "pve"
	// ManifestBlobName / ManifestFileName is the run manifest (blob and inside collect/)
	ManifestBlobName = "fallbck-pve.json"
	ManifestFileName = "fallbck-pve.json"
	// RestoreScriptName is the generated restore runbook inside collect/
	RestoreScriptName = "fallbck-pve-restore.sh"
	// CollectEntry is the archive entry holding everything the agent collected
	CollectEntry = "collect"
)

// PVE host markers (pmxcfs mount and the pve-manager CLI)
var pveMarkers = []string{"/etc/pve/.version", "/usr/bin/pveversion"}

// IsPVEHost reports whether this machine is a Proxmox VE node
func IsPVEHost() bool {
	for _, m := range pveMarkers {
		if _, err := os.Stat(m); err == nil {
			return true
		}
	}
	return false
}

// Spec is the Proxmox VE job configuration (backup_jobs.pve_config). The host
// configuration (/etc, /etc/pve, package lists, storage and network definitions,
// partition tables) is always included; DataPaths adds mounted data filesystems.
type Spec struct {
	// DataPaths are additional directories archived file by file (mounted data
	// storages such as /var/lib/vz or /mnt/pve/<storage>)
	DataPaths []string `json:"data_paths,omitempty"`
	// ExcludePaths are proxmox-backup-client style patterns against archive paths
	ExcludePaths []string `json:"exclude_paths,omitempty"`
	// IncludeRootHome archives /root (default true)
	IncludeRootHome *bool `json:"include_root_home,omitempty"`
	// IncludeGuestImages keeps VM/CT disk images found under the data paths
	// (images/, private/, subvol-*). Default false: vzdump/PBS already cover guests.
	IncludeGuestImages *bool `json:"include_guest_images,omitempty"`
}

// ErrInvalidSpec wraps every validation failure
var ErrInvalidSpec = errors.New("invalid Proxmox VE job configuration")

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}

// reservedRoots are archived by the job itself; data paths must not overlap them
var reservedRoots = []string{"/etc", "/root"}

// Validate normalises the data paths and checks the exclude patterns
func (s *Spec) Validate() error {
	if s == nil {
		return specErr("configuration is missing")
	}
	seen := map[string]bool{}
	var cleaned []string
	for _, p := range s.DataPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) {
			return specErr("data path %q must be absolute", p)
		}
		p = filepath.Clean(p)
		if p == "/" {
			return specErr("data path / is not allowed; this job backs up the host configuration, not the whole disk")
		}
		for _, r := range reservedRoots {
			if p == r || strings.HasPrefix(p, r+"/") {
				return specErr("data path %s is inside %s, which the job archives already", p, r)
			}
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		cleaned = append(cleaned, p)
	}
	sort.Strings(cleaned)
	for i := 1; i < len(cleaned); i++ {
		parent := cleaned[i-1]
		if strings.HasPrefix(cleaned[i], parent+"/") {
			return specErr("data path %s is inside %s", cleaned[i], parent)
		}
	}
	s.DataPaths = cleaned
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

// EffIncludeRootHome / EffIncludeGuestImages apply the defaults
func (s *Spec) EffIncludeRootHome() bool {
	return s == nil || s.IncludeRootHome == nil || *s.IncludeRootHome
}
func (s *Spec) EffIncludeGuestImages() bool {
	return s != nil && s.IncludeGuestImages != nil && *s.IncludeGuestImages
}

// Clone returns a deep copy
func (s *Spec) Clone() *Spec {
	if s == nil {
		return nil
	}
	c := *s
	c.DataPaths = append([]string(nil), s.DataPaths...)
	c.ExcludePaths = append([]string(nil), s.ExcludePaths...)
	if s.IncludeRootHome != nil {
		v := *s.IncludeRootHome
		c.IncludeRootHome = &v
	}
	if s.IncludeGuestImages != nil {
		v := *s.IncludeGuestImages
		c.IncludeGuestImages = &v
	}
	return &c
}

// Summary is a short human-readable description (UI tables, logs)
func (s *Spec) Summary() string {
	if s == nil || len(s.DataPaths) == 0 {
		return "host configuration"
	}
	return "host configuration + " + strings.Join(s.DataPaths, ", ")
}
