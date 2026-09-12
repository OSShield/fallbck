package pvebackup

import (
	"encoding/json"
	"time"
)

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// Manifest describes one Proxmox VE host backup: what was collected, how the
// archive is laid out and how to restore it. It is stored as fallbck-pve.json inside
// the collect/ entry and as a blob next to the archive.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     ManifestGenerator `json:"generator"`
	Job           ManifestJob       `json:"job"`
	Snapshot      ManifestSnapshot  `json:"snapshot"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Host          HostInfo          `json:"host"`
	Packages      PackageInfo       `json:"packages"`
	Storages      []Storage         `json:"storages"`
	Guests        []Guest           `json:"guests"`
	Disks         []Disk            `json:"disks"`
	// Entries maps archive top-level names to their source on the host
	Entries  []ArchiveEntry `json:"entries"`
	Excludes []string       `json:"excludes,omitempty"`
	// Collected records every collector that ran (and how it went)
	Collected []Collected `json:"collected"`
	Spec      *Spec       `json:"spec,omitempty"`
	Warnings  []string    `json:"warnings,omitempty"`
	Restore   Restore     `json:"restore"`
}

// ManifestGenerator identifies the agent that produced the backup
type ManifestGenerator struct {
	Agent    string `json:"agent"`
	Version  string `json:"version"`
	Hostname string `json:"hostname"`
}

// ManifestJob identifies the job and run
type ManifestJob struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	RunID       string `json:"run_id"`
	BackupRunID string `json:"backup_run_id"`
}

// ManifestSnapshot is the PBS snapshot identity
type ManifestSnapshot struct {
	Type    string    `json:"type"`
	ID      string    `json:"id"`
	Time    time.Time `json:"time"`
	Archive string    `json:"archive"`
}

// HostInfo describes the PVE node
type HostInfo struct {
	Hostname   string `json:"hostname"`
	Node       string `json:"node"`
	PVEVersion string `json:"pve_version,omitempty"` // pve-manager version, e.g. 8.2.4
	PVEMajor   int    `json:"pve_major,omitempty"`
	Kernel     string `json:"kernel,omitempty"`
	OS         string `json:"os,omitempty"` // /etc/os-release PRETTY_NAME
}

// PackageInfo summarises the dpkg state recorded in collect/
type PackageInfo struct {
	Installed  int    `json:"installed"`
	Manual     int    `json:"manual"`
	ListFile   string `json:"list_file,omitempty"`
	ManualFile string `json:"manual_file,omitempty"`
}

// Storage is one entry of /etc/pve/storage.cfg
type Storage struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Path     string   `json:"path,omitempty"`
	Pool     string   `json:"pool,omitempty"`
	Server   string   `json:"server,omitempty"`
	Export   string   `json:"export,omitempty"`
	Content  []string `json:"content,omitempty"`
	Shared   bool     `json:"shared,omitempty"`
	Disabled bool     `json:"disabled,omitempty"`
}

// Guest is a VM or container whose configuration was captured
type Guest struct {
	VMID       int    `json:"vmid"`
	Type       string `json:"type"` // qemu | lxc
	Name       string `json:"name,omitempty"`
	ConfigFile string `json:"config_file"`
}

// Disk is a block device of the host with its saved partition table
type Disk struct {
	Path           string `json:"path"`
	Model          string `json:"model,omitempty"`
	Serial         string `json:"serial,omitempty"`
	SizeBytes      int64  `json:"size_bytes"`
	PartitionTable string `json:"partition_table,omitempty"` // sgdisk backup file inside collect/
}

// ArchiveEntry maps a top-level archive name to its origin
type ArchiveEntry struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// Kind: etc | root | collect | data
	Kind string `json:"kind"`
}

// Collected is the outcome of one collector
type Collected struct {
	Name    string `json:"name"`
	Command string `json:"command,omitempty"`
	File    string `json:"file,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Restore carries the runbook: a summary, the commands to run, and the script's
// location inside the archive
type Restore struct {
	Summary  string   `json:"summary"`
	Commands []string `json:"commands"`
	Script   string   `json:"script,omitempty"`
}

// Marshal renders the manifest as indented JSON
func (m *Manifest) Marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// ParseManifest decodes a manifest
func ParseManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
