package runtime

import (
	"context"
	"fmt"
	"os"
	goruntime "runtime"
	"sort"
	"strings"
	"sync"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/agent/dockerbackup"
	"github.com/osshield/fallbck/pkg/config"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/inventory"
	"github.com/osshield/fallbck/pkg/pvebackup"
)

// Inventory builds what the agent reports about its host: the compact Summary the
// heartbeat carries every few minutes and the full Detail an operator asks for.
// Agents plug in the type-specific parts (Docker containers, cluster namespaces).
type Inventory struct {
	cfg        *config.AgentConfig
	configPath string
	version    string
	started    time.Time
	// Extra fills type-specific detail (nil on agents without any)
	Extra func(ctx context.Context, d *inventory.Detail)
	// ExtraCounts fills the cheap resource counts of the summary
	ExtraCounts func(ctx context.Context, counts map[string]int)

	mu       sync.Mutex
	toolsAt  time.Time
	tools    map[string][]inventory.Tool
	warnings []string
}

// NewInventory prepares the collector for a running agent
func NewInventory(cfg *config.AgentConfig, configPath, version string) *Inventory {
	inv := &Inventory{cfg: cfg, configPath: configPath, version: version, started: time.Now()}
	if cfg != nil && cfg.DockerBackup.EffVolumeAccess() != "" {
		inv.ExtraCounts = inv.dockerCounts
		inv.Extra = inv.dockerDetail
	}
	return inv
}

// Summary is the periodic part (tools are re-detected at most every ten minutes)
func (inv *Inventory) Summary(ctx context.Context) *inventory.Summary {
	s := &inventory.Summary{At: time.Now().UTC(), UptimeSeconds: int64(time.Since(inv.started).Seconds())}
	if inv.cfg == nil {
		return s
	}
	s.Profiles = ProfileSummaries(inv.cfg)
	s.Tools, s.Warnings = inv.detectTools(ctx)
	dbCfg := inv.cfg.DBBackup
	dbCfg.ApplyDefaults(inv.cfg.DataDir)
	if dbCfg.SpoolDir != "" {
		s.Spool = &inventory.Disk{Path: dbCfg.SpoolDir, FreeBytes: dbrun.FreeBytes(dirOrParent(dbCfg.SpoolDir)), MinFreeBytes: dbCfg.MinFreeBytes}
	}
	if inv.cfg.DataDir != "" {
		s.Data = &inventory.Disk{Path: inv.cfg.DataDir, FreeBytes: dbrun.FreeBytes(inv.cfg.DataDir)}
	}
	// Profiles whose engine has no tools cannot run
	for _, p := range s.Profiles {
		if p.Engine != dbspec.EngineMSSQL && len(s.Tools[p.Engine]) == 0 {
			s.Warnings = append(s.Warnings, fmt.Sprintf("profile %s is for %s but its client tools were not found", p.Name, p.Engine))
		}
	}
	if inv.ExtraCounts != nil {
		counts := map[string]int{}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		inv.ExtraCounts(cctx, counts)
		cancel()
		if len(counts) > 0 {
			s.Counts = counts
		}
	}
	return s
}

// Detail is the full inventory
func (inv *Inventory) Detail(ctx context.Context) *inventory.Detail {
	d := &inventory.Detail{Summary: *inv.Summary(ctx), OS: goruntime.GOOS, Arch: goruntime.GOARCH, Version: inv.version, ConfigPath: inv.configPath}
	d.Hostname, _ = os.Hostname()
	if inv.cfg != nil {
		if inv.cfg.Hostname != "" {
			d.Hostname = inv.cfg.Hostname
		}
		d.DataDir = inv.cfg.DataDir
		dbCfg := inv.cfg.DBBackup
		dbCfg.ApplyDefaults(inv.cfg.DataDir)
		d.Settings = map[string]string{
			"server_url":           inv.cfg.ServerURL,
			"log_level":            inv.cfg.LogLevel,
			"spool_dir":            dbCfg.SpoolDir,
			"state_dir":            dbCfg.StateDir,
			"min_free_bytes":       fmt.Sprint(dbCfg.MinFreeBytes),
			"keep_failed_spool":    fmt.Sprint(dbCfg.KeepFailedSpool),
			"docker_volume_access": inv.cfg.DockerBackup.EffVolumeAccess(),
			"docker_helper_image":  inv.cfg.DockerBackup.EffHelperImage(),
			"docker_socket":        inv.cfg.DockerBackup.EffSocket(),
			"vss":                  fmt.Sprint(inv.cfg.UseVSS()),
		}
		for k, v := range d.Settings {
			if v == "" {
				delete(d.Settings, k)
			}
		}
	}
	if pvebackup.IsPVEHost() {
		d.PVE = &inventory.PVEDetail{Node: d.Hostname}
		if out, err := os.ReadFile("/etc/pve/.version"); err == nil {
			d.PVE.Version = strings.TrimSpace(string(out))
		}
	}
	if inv.Extra != nil {
		ectx, cancel := context.WithTimeout(ctx, 60*time.Second)
		inv.Extra(ectx, d)
		cancel()
	}
	return d
}

func (inv *Inventory) detectTools(ctx context.Context) (map[string][]inventory.Tool, []string) {
	inv.mu.Lock()
	defer inv.mu.Unlock()
	if inv.tools != nil && time.Since(inv.toolsAt) < 10*time.Minute {
		return inv.tools, inv.warnings
	}
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tools := map[string][]inventory.Tool{}
	var warnings []string
	for _, r := range dbrun.DetectAll(dctx, dbrun.NewRunner(inv.cfg.DBBackup.KillGrace), inv.cfg.DBBackup.Tools) {
		if r.Err != nil {
			continue
		}
		var list []inventory.Tool
		for name, b := range r.Tools.Binaries {
			list = append(list, inventory.Tool{Name: name, Path: b.Path, Version: b.Version})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		tools[r.Engine] = list
	}
	inv.tools, inv.warnings, inv.toolsAt = tools, warnings, time.Now()
	return tools, warnings
}

// dirOrParent returns the first existing ancestor of path (the spool dir may not
// exist before the first run)
func dirOrParent(path string) string {
	for p := path; p != "" && p != "/" && p != "."; p = parentDir(p) {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return path
}

func parentDir(p string) string {
	i := strings.LastIndexAny(p, `/\`)
	if i <= 0 {
		return ""
	}
	return p[:i]
}

// ---- Docker host

func (inv *Inventory) dockerClient(ctx context.Context) (*dockerbackup.Client, bool) {
	socket := inv.cfg.DockerBackup.EffSocket()
	if !dockerspec.IsDockerHost(socket) {
		return nil, false
	}
	c := dockerbackup.NewClient(socket)
	if _, err := c.Negotiate(ctx); err != nil {
		return nil, false
	}
	return c, true
}

func (inv *Inventory) dockerCounts(ctx context.Context, counts map[string]int) {
	c, ok := inv.dockerClient(ctx)
	if !ok {
		return
	}
	if info, _, err := c.Info(ctx); err == nil {
		counts["containers"] = info.Containers
		counts["containers_running"] = info.ContainersRunning
	}
	if vols, err := c.ListVolumes(ctx); err == nil {
		counts["volumes"] = len(vols)
	}
}

func (inv *Inventory) dockerDetail(ctx context.Context, d *inventory.Detail) {
	c, ok := inv.dockerClient(ctx)
	if !ok {
		return
	}
	dd := &inventory.DockerDetail{Containers: []inventory.DockerContainer{}, Volumes: []inventory.DockerVolume{}}
	if info, _, err := c.Info(ctx); err == nil {
		dd.Version = info.ServerVersion
	}
	if list, err := c.ListContainers(ctx, true); err == nil {
		for _, ct := range list {
			dd.Containers = append(dd.Containers, inventory.DockerContainer{Name: ct.Name(), Image: ct.Image, State: ct.State, Project: ct.Labels["com.docker.compose.project"]})
		}
		sort.Slice(dd.Containers, func(i, j int) bool { return dd.Containers[i].Name < dd.Containers[j].Name })
	}
	if vols, err := c.ListVolumes(ctx); err == nil {
		for _, v := range vols {
			dd.Volumes = append(dd.Volumes, inventory.DockerVolume{Name: v.Name, Driver: v.Driver})
		}
		sort.Slice(dd.Volumes, func(i, j int) bool { return dd.Volumes[i].Name < dd.Volumes[j].Name })
	}
	d.Docker = dd
}
