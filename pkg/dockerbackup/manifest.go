package dockerbackup

import (
	"encoding/json"
	"time"
)

// ManifestSchemaVersion is bumped on incompatible manifest changes
const ManifestSchemaVersion = 1

// Manifest describes one Docker host backup: what was collected, how the archive is
// laid out and how to restore it. It is stored as fallbck-docker.json inside the
// collect/ entry and as a blob next to the archive.
type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	Generator     ManifestGenerator `json:"generator"`
	Job           ManifestJob       `json:"job"`
	Snapshot      ManifestSnapshot  `json:"snapshot"`
	StartedAt     time.Time         `json:"started_at"`
	FinishedAt    time.Time         `json:"finished_at"`
	Host          HostInfo          `json:"host"`
	Containers    []Container       `json:"containers"`
	Volumes       []Volume          `json:"volumes"`
	Networks      []Network         `json:"networks"`
	Images        []Image           `json:"images"`
	Compose       []ComposeProject  `json:"compose_projects"`
	Daemon        DaemonInfo        `json:"daemon"`
	// BindMounts lists host directories mounted into containers; they are recorded
	// for the operator but not archived (a filesystem job covers them)
	BindMounts []BindMount `json:"bind_mounts,omitempty"`
	// Entries maps archive top-level names to their source
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

// HostInfo describes the Docker host and daemon
type HostInfo struct {
	Hostname          string `json:"hostname"`
	DockerVersion     string `json:"docker_version,omitempty"`
	APIVersion        string `json:"api_version,omitempty"`
	OS                string `json:"os,omitempty"` // OperatingSystem from /info
	OSType            string `json:"os_type,omitempty"`
	Arch              string `json:"arch,omitempty"`
	Kernel            string `json:"kernel,omitempty"`
	RootDir           string `json:"root_dir,omitempty"`
	StorageDriver     string `json:"storage_driver,omitempty"`
	Swarm             string `json:"swarm,omitempty"` // inactive | active | pending | ...
	SwarmManager      bool   `json:"swarm_manager,omitempty"`
	Rootless          bool   `json:"rootless,omitempty"`
	Containers        int    `json:"containers"`
	ContainersRunning int    `json:"containers_running"`
	ImageCount        int    `json:"image_count"`
	// VolumeAccess is the mode the run used: direct | helper | mixed
	VolumeAccess string `json:"volume_access,omitempty"`
}

// Container is one container whose definition was captured
type Container struct {
	Name        string            `json:"name"`
	ID          string            `json:"id"`
	Image       string            `json:"image"`
	ImageID     string            `json:"image_id,omitempty"`
	ImageDigest string            `json:"image_digest,omitempty"`
	State       string            `json:"state"` // running | exited | paused | created | ...
	Status      string            `json:"status,omitempty"`
	Created     string            `json:"created,omitempty"`
	Project     string            `json:"compose_project,omitempty"`
	Service     string            `json:"compose_service,omitempty"`
	WorkingDir  string            `json:"compose_working_dir,omitempty"`
	Networks    []string          `json:"networks,omitempty"`
	Mounts      []Mount           `json:"mounts,omitempty"`
	Ports       []Port            `json:"ports,omitempty"`
	Restart     string            `json:"restart_policy,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Paused      bool              `json:"paused_for_backup,omitempty"`
	Skipped     string            `json:"skipped,omitempty"`    // reason, when the definition was not captured
	Definition  string            `json:"definition,omitempty"` // inspect JSON inside collect/
}

// Mount is one mount of a container
type Mount struct {
	Type        string `json:"type"` // volume | bind | tmpfs | npipe
	Source      string `json:"source,omitempty"`
	Destination string `json:"destination"`
	Volume      string `json:"volume,omitempty"`
	RW          bool   `json:"rw"`
}

// Port is one published port
type Port struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      string `json:"host_port"`
	ContainerPort string `json:"container_port"`
	Protocol      string `json:"protocol"`
}

// Volume is one named volume
type Volume struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint,omitempty"`
	Scope      string            `json:"scope,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	UsedBy     []string          `json:"used_by,omitempty"`
	Entry      string            `json:"entry,omitempty"`  // archive entry (vol-<name>)
	Access     string            `json:"access,omitempty"` // direct | helper
	Skipped    string            `json:"skipped,omitempty"`
	Paused     []string          `json:"paused_containers,omitempty"`
	Definition string            `json:"definition,omitempty"`
}

// Network is one user-defined (or built-in) network
type Network struct {
	Name       string            `json:"name"`
	ID         string            `json:"id"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope,omitempty"`
	Internal   bool              `json:"internal,omitempty"`
	Attachable bool              `json:"attachable,omitempty"`
	IPv6       bool              `json:"ipv6,omitempty"`
	Subnets    []Subnet          `json:"subnets,omitempty"`
	Options    map[string]string `json:"options,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
	Builtin    bool              `json:"builtin,omitempty"` // bridge, host, none: never recreated
	Containers []string          `json:"containers,omitempty"`
	Definition string            `json:"definition,omitempty"`
}

// Subnet is one IPAM configuration of a network
type Subnet struct {
	Subnet  string `json:"subnet,omitempty"`
	Gateway string `json:"gateway,omitempty"`
	IPRange string `json:"ip_range,omitempty"`
}

// Image is one image in use by a container
type Image struct {
	ID          string   `json:"id"`
	RepoTags    []string `json:"repo_tags,omitempty"`
	RepoDigests []string `json:"repo_digests,omitempty"`
	SizeBytes   int64    `json:"size_bytes,omitempty"`
	Local       bool     `json:"local,omitempty"` // no registry reference
	Saved       string   `json:"saved,omitempty"` // tarball inside collect/images/
	UsedBy      []string `json:"used_by,omitempty"`
}

// ComposeProject groups the containers of one compose project
type ComposeProject struct {
	Name        string        `json:"name"`
	WorkingDir  string        `json:"working_dir,omitempty"`
	ConfigFiles []string      `json:"config_files,omitempty"`
	Archived    []ComposeFile `json:"archived,omitempty"`
	Services    []string      `json:"services,omitempty"`
}

// ComposeFile is one compose config or env file stored inside collect/
type ComposeFile struct {
	// File is the path inside collect/ (compose/<project>/<name>)
	File string `json:"file"`
	// Source is the absolute host path it was read from (where a restore puts it back)
	Source string `json:"source"`
}

// DaemonInfo records the daemon configuration file
type DaemonInfo struct {
	ConfigPath string `json:"config_path,omitempty"`
	Archived   bool   `json:"archived"`
}

// BindMount is a host directory mounted into containers
type BindMount struct {
	Source     string   `json:"source"`
	Containers []string `json:"containers"`
}

// ArchiveEntry maps a top-level archive name to its origin
type ArchiveEntry struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	// Kind: collect | volume
	Kind string `json:"kind"`
}

// Collected is the outcome of one collector
type Collected struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint,omitempty"`
	File     string `json:"file,omitempty"`
	Error    string `json:"error,omitempty"`
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
