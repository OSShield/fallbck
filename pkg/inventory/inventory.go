// Package inventory is what an agent knows about its host and reports to the
// server: a compact Summary every few minutes with the heartbeat, and the full
// Detail on demand (the status page's Refresh). It is shared by the agents (which
// build it) and the server (which stores and renders it), so it stays plain data.
package inventory

import (
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// SummaryInterval is how often an agent attaches the summary to a heartbeat
const SummaryInterval = 5 * time.Minute

// Summary is the periodic, cheap part
type Summary struct {
	At time.Time `json:"at"`
	// Uptime of the agent process
	UptimeSeconds int64 `json:"uptime_seconds,omitempty"`
	// Profiles are the credential profiles the agent holds (names only)
	Profiles []dbspec.ProfileSummary `json:"profiles,omitempty"`
	// Tools are the database client tools by engine ("" when not found)
	Tools map[string][]Tool `json:"tools,omitempty"`
	// Spool is the spool directory and its free space
	Spool *Disk `json:"spool,omitempty"`
	// Data is the data directory (state, caches) and its free space
	Data *Disk `json:"data,omitempty"`
	// Counts are type-specific resource counts (containers, volumes, namespaces, pvcs)
	Counts map[string]int `json:"counts,omitempty"`
	// Warnings the agent noticed itself (tools missing for a profile's engine, ...)
	Warnings []string `json:"warnings,omitempty"`
}

// Tool is one client binary
type Tool struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
}

// Disk is a directory and the free space of the filesystem holding it
type Disk struct {
	Path      string `json:"path"`
	FreeBytes uint64 `json:"free_bytes"`
	// MinFreeBytes is the configured minimum for runs (spool only)
	MinFreeBytes int64 `json:"min_free_bytes,omitempty"`
}

// Detail is the on-demand full inventory
type Detail struct {
	Summary
	// Host facts
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
	// ConfigPath and DataDir locate the agent's files
	ConfigPath string `json:"config_path,omitempty"`
	DataDir    string `json:"data_dir,omitempty"`
	// Settings are the effective, non-secret settings (spool dir, volume access, ...)
	Settings map[string]string `json:"settings,omitempty"`
	// Docker lists containers and volumes on a Docker host
	Docker *DockerDetail `json:"docker,omitempty"`
	// Kubernetes lists namespaces and volumes for a cluster agent
	Kubernetes *KubernetesDetail `json:"kubernetes,omitempty"`
	// PVE describes a Proxmox VE node
	PVE *PVEDetail `json:"pve,omitempty"`
}

// DockerDetail is the Docker host inventory
type DockerDetail struct {
	Version    string            `json:"version,omitempty"`
	Containers []DockerContainer `json:"containers"`
	Volumes    []DockerVolume    `json:"volumes"`
}

// DockerContainer is one container
type DockerContainer struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Project string `json:"project,omitempty"`
}

// DockerVolume is one named volume
type DockerVolume struct {
	Name   string `json:"name"`
	Driver string `json:"driver,omitempty"`
}

// KubernetesDetail is the cluster inventory
type KubernetesDetail struct {
	ServerVersion string                `json:"server_version,omitempty"`
	Namespaces    []KubernetesNamespace `json:"namespaces"`
}

// KubernetesNamespace is one namespace with its volume count
type KubernetesNamespace struct {
	Name string `json:"name"`
	PVCs int    `json:"pvcs"`
}

// PVEDetail describes the node
type PVEDetail struct {
	Version string `json:"version,omitempty"`
	Node    string `json:"node,omitempty"`
}

// LogsResult is what the GetLogs action returns
type LogsResult struct {
	At    time.Time `json:"at"`
	Level string    `json:"level,omitempty"`
	Lines string    `json:"lines"`
}
