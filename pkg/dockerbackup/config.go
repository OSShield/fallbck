package dockerbackup

import (
	"fmt"
	"os"
	"strings"
)

// Volume access modes (agent setting docker_backup.volume_access)
const (
	// VolumeAccessAuto reads volumes directly when their mountpoint is visible to
	// the agent and falls back to helper containers otherwise
	VolumeAccessAuto = "auto"
	// VolumeAccessDirect reads /var/lib/docker/volumes/<name>/_data from the host filesystem
	VolumeAccessDirect = "direct"
	// VolumeAccessHelper streams every volume through a throwaway container
	VolumeAccessHelper = "helper"
)

// DefaultHelperImage mounts volumes and host directories for helper-mode reads
const DefaultHelperImage = "alpine:3.20"

// DefaultSocket is the Docker daemon socket unless DOCKER_HOST names another one
const DefaultSocket = "/var/run/docker.sock"

// Config is the agent-side Docker settings block (agent.yaml docker_backup:, env
// FALLBCK_AGENT_DOCKER_*)
type Config struct {
	// VolumeAccess is auto (default), direct or helper
	VolumeAccess string `yaml:"volume_access,omitempty" json:"volume_access,omitempty"`
	// HelperImage is the image of the throwaway containers used in helper mode
	HelperImage string `yaml:"helper_image,omitempty" json:"helper_image,omitempty"`
	// Socket is the daemon's unix socket (default: DOCKER_HOST if unix://, else /var/run/docker.sock)
	Socket string `yaml:"socket,omitempty" json:"socket,omitempty"`
}

// Validate checks the volume access mode
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(c.VolumeAccess)) {
	case "", VolumeAccessAuto, VolumeAccessDirect, VolumeAccessHelper:
	default:
		return fmt.Errorf("docker_backup.volume_access must be %s, %s or %s", VolumeAccessAuto, VolumeAccessDirect, VolumeAccessHelper)
	}
	c.VolumeAccess = strings.ToLower(strings.TrimSpace(c.VolumeAccess))
	return nil
}

// EffVolumeAccess / EffHelperImage / EffSocket apply the defaults
func (c *Config) EffVolumeAccess() string {
	if c == nil || c.VolumeAccess == "" {
		return VolumeAccessAuto
	}
	return c.VolumeAccess
}
func (c *Config) EffHelperImage() string {
	if c == nil || strings.TrimSpace(c.HelperImage) == "" {
		return DefaultHelperImage
	}
	return strings.TrimSpace(c.HelperImage)
}
func (c *Config) EffSocket() string {
	if c != nil && strings.TrimSpace(c.Socket) != "" {
		return strings.TrimSpace(c.Socket)
	}
	return SocketPath()
}

// SocketPath is the daemon socket: DOCKER_HOST when it names a unix socket, else the
// default. TCP daemons are not supported (the agent runs on the host it backs up).
func SocketPath() string {
	if h := os.Getenv("DOCKER_HOST"); strings.HasPrefix(h, "unix://") {
		return strings.TrimPrefix(h, "unix://")
	}
	return DefaultSocket
}
