package dockerbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
)

// Host locations (variables so tests can point them at fixtures)
var (
	daemonConfigPath = "/etc/docker/daemon.json"
	procSelfCgroup   = "/proc/self/cgroup"
	procSelfMounts   = "/proc/self/mountinfo"
)

// Compose labels (identical for compose v1 and v2)
const (
	labelProject     = "com.docker.compose.project"
	labelService     = "com.docker.compose.service"
	labelWorkingDir  = "com.docker.compose.project.working_dir"
	labelConfigFiles = "com.docker.compose.project.config_files"
	labelEnvFiles    = "com.docker.compose.project.environment_file"
)

// builtinNetworks are created by the daemon and never recreated by a restore
var builtinNetworks = map[string]bool{"bridge": true, "host": true, "none": true}

// collected is what the collectors gathered, feeding the manifest and the volume phase
type collected struct {
	Host       dockerspec.HostInfo
	Containers []dockerspec.Container
	Volumes    []dockerspec.Volume
	Networks   []dockerspec.Network
	Images     []dockerspec.Image
	Compose    []dockerspec.ComposeProject
	Daemon     dockerspec.DaemonInfo
	BindMounts []dockerspec.BindMount
	Records    []dockerspec.Collected
	Warnings   []string

	// info is the daemon's /info answer (root dir for direct reads)
	info *Info
	// inspects keeps the parsed container documents by id (pause decisions, restore)
	inspects map[string]*ContainerInspect
	// volumeUsers maps a volume name to the containers mounting it (ids)
	volumeUsers map[string][]string
	// selfVolumes are volumes mounted by the agent's own container (never archived)
	selfVolumes map[string]bool
	// selfID is the agent's own container id when it runs as a container
	selfID string
}

// collector talks to the daemon and records files under dir (the collect/ entry)
type collector struct {
	ctx   context.Context
	c     *Client
	dir   string
	spec  *dockerspec.Spec
	files *hostFiles
	out   *collected
}

func (c *collector) record(name, endpoint, file string, err error) {
	rec := dockerspec.Collected{Name: name, Endpoint: endpoint, File: file}
	if err != nil {
		rec.Error = err.Error()
		rec.File = ""
		c.out.Warnings = append(c.out.Warnings, fmt.Sprintf("%s: %v", name, err))
		slog.Warn("Docker collector failed", "collector", name, "error", err)
	}
	c.out.Records = append(c.out.Records, rec)
}

func (c *collector) write(file string, data []byte) error {
	full := filepath.Join(c.dir, file)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	return os.WriteFile(full, data, 0o600)
}

// collect gathers definitions, compose files, the daemon configuration and image
// references (and tarballs, per the job) into dir
func collect(ctx context.Context, client *Client, files *hostFiles, spec *dockerspec.Spec, dir string) *collected {
	out := &collected{inspects: map[string]*ContainerInspect{}, volumeUsers: map[string][]string{}, selfVolumes: map[string]bool{}}
	c := &collector{ctx: ctx, c: client, dir: dir, spec: spec, files: files, out: out}
	c.host()
	if ctx.Err() != nil {
		return out
	}
	c.containers()
	c.networks()
	c.volumes()
	c.images()
	c.compose()
	c.daemon()
	return out
}

func (c *collector) host() {
	v, err := c.c.Negotiate(c.ctx)
	if err != nil {
		c.record("version", "/version", "", err)
		return
	}
	raw, _ := json.MarshalIndent(v, "", "  ")
	c.record("version", "/version", "version.json", c.write("version.json", raw))
	info, rawInfo, err := c.c.Info(c.ctx)
	if err != nil {
		c.record("info", "/info", "", err)
		return
	}
	c.record("info", "/info", "info.json", c.write("info.json", rawInfo))
	c.out.info = info
	c.out.Host = dockerspec.HostInfo{
		Hostname: info.Name, DockerVersion: info.ServerVersion, APIVersion: v.APIVersion,
		OS: info.OperatingSystem, OSType: info.OSType, Arch: info.Architecture, Kernel: info.KernelVersion,
		RootDir: info.DockerRootDir, StorageDriver: info.Driver, Swarm: info.Swarm.LocalNodeState,
		SwarmManager: info.Swarm.ControlAvailable, Rootless: info.Rootless(),
		Containers: info.Containers, ContainersRunning: info.ContainersRunning, ImageCount: info.Images,
	}
	if info.Swarm.LocalNodeState == "active" {
		c.out.Warnings = append(c.out.Warnings, "host is a Swarm node: services, configs and secrets are not part of this backup")
	}
	c.out.selfID = selfContainerID()
}

func (c *collector) containers() {
	list, err := c.c.ListContainers(c.ctx, true)
	if err != nil {
		c.record("containers", "/containers/json", "", err)
		return
	}
	c.record("containers", "/containers/json", "", nil)
	sort.Slice(list, func(i, j int) bool { return list[i].Name() < list[j].Name() })
	binds := map[string][]string{}
	for _, s := range list {
		name := s.Name()
		entry := dockerspec.Container{Name: name, ID: s.ID, Image: s.Image, ImageID: s.ImageID, State: s.State, Status: s.Status, Labels: s.Labels}
		switch {
		case dockerspec.MatchesAny(name, c.spec.ExcludeContainers):
			entry.Skipped = "excluded by the job"
		case strings.EqualFold(s.Labels[dockerspec.LabelSkip], "true"):
			entry.Skipped = "label " + dockerspec.LabelSkip + "=true"
		case s.State != "running" && s.State != "paused" && !c.spec.EffIncludeStopped():
			entry.Skipped = "not running (include_stopped is off)"
		}
		ci, raw, err := c.c.InspectContainer(c.ctx, s.ID)
		if err != nil {
			c.record("container "+name, "/containers/{id}/json", "", err)
			entry.Skipped = "inspect failed"
			c.out.Containers = append(c.out.Containers, entry)
			continue
		}
		c.out.inspects[s.ID] = ci
		isSelf := c.out.selfID != "" && strings.HasPrefix(s.ID, c.out.selfID)
		// Mounts are recorded even for skipped containers: volume usage decides
		// pausing and which volumes count as unused
		for _, m := range ci.Mounts {
			mount := dockerspec.Mount{Type: m.Type, Source: m.Source, Destination: m.Destination, Volume: m.Name, RW: m.RW}
			entry.Mounts = append(entry.Mounts, mount)
			switch m.Type {
			case "volume":
				c.out.volumeUsers[m.Name] = append(c.out.volumeUsers[m.Name], s.ID)
				if isSelf && strings.HasPrefix(m.Destination, "/var/lib/fallbck") {
					c.out.selfVolumes[m.Name] = true
				}
			case "bind":
				binds[m.Source] = append(binds[m.Source], name)
			}
		}
		if entry.Skipped != "" {
			c.out.Containers = append(c.out.Containers, entry)
			continue
		}
		file := "containers/" + safeName(name) + ".json"
		if err := c.write(file, raw); err != nil {
			c.record("container "+name, "/containers/{id}/json", "", err)
		} else {
			entry.Definition = file
		}
		entry.Created = ci.Created
		entry.Image = ci.Config.Image
		entry.Project = ci.Config.Labels[labelProject]
		entry.Service = ci.Config.Labels[labelService]
		entry.WorkingDir = ci.Config.Labels[labelWorkingDir]
		entry.Restart = ci.HostConfig.RestartPolicy.Name
		if ci.HostConfig.RestartPolicy.MaximumRetryCount > 0 {
			entry.Restart += fmt.Sprintf(":%d", ci.HostConfig.RestartPolicy.MaximumRetryCount)
		}
		for n := range ci.NetworkSettings.Networks {
			entry.Networks = append(entry.Networks, n)
		}
		sort.Strings(entry.Networks)
		for port, hosts := range ci.HostConfig.PortBindings {
			cp, proto, _ := strings.Cut(port, "/")
			for _, h := range hosts {
				entry.Ports = append(entry.Ports, dockerspec.Port{HostIP: h.HostIP, HostPort: h.HostPort, ContainerPort: cp, Protocol: proto})
			}
		}
		sort.Slice(entry.Ports, func(i, j int) bool { return entry.Ports[i].HostPort < entry.Ports[j].HostPort })
		c.out.Containers = append(c.out.Containers, entry)
	}
	for src, names := range binds {
		sort.Strings(names)
		c.out.BindMounts = append(c.out.BindMounts, dockerspec.BindMount{Source: src, Containers: names})
	}
	sort.Slice(c.out.BindMounts, func(i, j int) bool { return c.out.BindMounts[i].Source < c.out.BindMounts[j].Source })
}

func (c *collector) networks() {
	list, err := c.c.ListNetworks(c.ctx)
	if err != nil {
		c.record("networks", "/networks", "", err)
		return
	}
	c.record("networks", "/networks", "", nil)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	for _, n := range list {
		entry := dockerspec.Network{Name: n.Name, ID: n.ID, Driver: n.Driver, Scope: n.Scope, Builtin: builtinNetworks[n.Name]}
		ni, raw, err := c.c.InspectNetwork(c.ctx, n.ID)
		if err != nil {
			c.record("network "+n.Name, "/networks/{id}", "", err)
			c.out.Networks = append(c.out.Networks, entry)
			continue
		}
		entry.Internal, entry.Attachable, entry.IPv6 = ni.Internal, ni.Attachable, ni.EnableIPv6
		entry.Options, entry.Labels = ni.Options, ni.Labels
		for _, cfg := range ni.IPAM.Config {
			entry.Subnets = append(entry.Subnets, dockerspec.Subnet{Subnet: cfg.Subnet, Gateway: cfg.Gateway, IPRange: cfg.IPRange})
		}
		for _, ct := range ni.Containers {
			entry.Containers = append(entry.Containers, strings.TrimPrefix(ct.Name, "/"))
		}
		sort.Strings(entry.Containers)
		if !entry.Builtin {
			file := "networks/" + safeName(n.Name) + ".json"
			if err := c.write(file, raw); err != nil {
				c.record("network "+n.Name, "/networks/{id}", "", err)
			} else {
				entry.Definition = file
			}
		}
		c.out.Networks = append(c.out.Networks, entry)
	}
}

func (c *collector) volumes() {
	list, err := c.c.ListVolumes(c.ctx)
	if err != nil {
		c.record("volumes", "/volumes", "", err)
		return
	}
	c.record("volumes", "/volumes", "", nil)
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	for _, v := range list {
		entry := dockerspec.Volume{Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, Scope: v.Scope, Labels: v.Labels, Options: v.Options}
		for _, id := range c.out.volumeUsers[v.Name] {
			if ci := c.out.inspects[id]; ci != nil {
				entry.UsedBy = append(entry.UsedBy, ci.CleanName())
			}
		}
		sort.Strings(entry.UsedBy)
		_, raw, err := c.c.InspectVolume(c.ctx, v.Name)
		if err != nil {
			c.record("volume "+v.Name, "/volumes/{name}", "", err)
		} else {
			file := "volumes/" + safeName(v.Name) + ".json"
			if err := c.write(file, raw); err != nil {
				c.record("volume "+v.Name, "/volumes/{name}", "", err)
			} else {
				entry.Definition = file
			}
		}
		c.out.Volumes = append(c.out.Volumes, entry)
	}
}

func (c *collector) images() {
	list, raw, err := c.c.ListImages(c.ctx)
	if err != nil {
		c.record("images", "/images/json", "", err)
		return
	}
	c.record("images", "/images/json", "images.json", c.write("images.json", raw))
	used := map[string][]string{} // image id -> container names
	for _, ct := range c.out.Containers {
		if ct.Skipped == "" {
			used[ct.ImageID] = append(used[ct.ImageID], ct.Name)
		}
	}
	mode := c.spec.EffImages()
	for _, im := range list {
		names, ok := used[im.ID]
		if !ok {
			continue
		}
		sort.Strings(names)
		tags := dropNone(im.RepoTags)
		digests := dropNone(im.RepoDigests)
		entry := dockerspec.Image{ID: im.ID, RepoTags: tags, RepoDigests: digests, SizeBytes: im.Size, UsedBy: names, Local: len(digests) == 0}
		if mode == dockerspec.ImagesAll || (mode == dockerspec.ImagesLocal && entry.Local) {
			ref := im.ID
			if len(tags) > 0 {
				ref = tags[0]
			}
			file := "images/" + safeName(strings.TrimPrefix(ref, "sha256:")) + ".tar"
			if err := c.saveImage(ref, file); err != nil {
				c.record("image "+ref, "/images/get", "", err)
			} else {
				c.record("image "+ref, "/images/get", file, nil)
				entry.Saved = file
			}
		}
		c.out.Images = append(c.out.Images, entry)
	}
	sort.Slice(c.out.Images, func(i, j int) bool { return c.out.Images[i].ID < c.out.Images[j].ID })
}

// saveImage streams `docker save` of one image into collect/images/
func (c *collector) saveImage(ref, file string) error {
	rc, err := c.c.SaveImages(c.ctx, []string{ref})
	if err != nil {
		return err
	}
	defer rc.Close()
	full := filepath.Join(c.dir, file)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, rc); err != nil {
		_ = f.Close()
		_ = os.Remove(full)
		return err
	}
	return f.Close()
}

// compose archives the config files (and env files) of every compose project seen
// on the containers, read from the host filesystem
func (c *collector) compose() {
	type src struct {
		workingDir string
		files      []string
		services   map[string]bool
	}
	projects := map[string]*src{}
	for _, ct := range c.out.Containers {
		if ct.Skipped != "" || ct.Project == "" {
			continue
		}
		ci := c.out.inspects[ct.ID]
		if ci == nil {
			continue
		}
		p := projects[ct.Project]
		if p == nil {
			p = &src{workingDir: ct.WorkingDir, services: map[string]bool{}}
			projects[ct.Project] = p
		}
		p.services[ct.Service] = true
		for _, f := range strings.Split(ci.Config.Labels[labelConfigFiles], ",") {
			if f = strings.TrimSpace(f); f != "" {
				if abs := absIn(p.workingDir, f); !slices.Contains(p.files, abs) {
					p.files = append(p.files, abs)
				}
			}
		}
		for _, f := range strings.Split(ci.Config.Labels[labelEnvFiles], ",") {
			if f = strings.TrimSpace(f); f != "" {
				if abs := absIn(p.workingDir, f); !slices.Contains(p.files, abs) {
					p.files = append(p.files, abs)
				}
			}
		}
	}
	names := make([]string, 0, len(projects))
	for n := range projects {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		p := projects[name]
		entry := dockerspec.ComposeProject{Name: name, WorkingDir: p.workingDir, ConfigFiles: p.files}
		for s := range p.services {
			entry.Services = append(entry.Services, s)
		}
		sort.Strings(entry.Services)
		// A .env next to the first config file is read by compose implicitly
		candidates := append([]string(nil), p.files...)
		if len(p.files) > 0 {
			candidates = append(candidates, filepath.Join(filepath.Dir(p.files[0]), ".env"))
		} else if p.workingDir != "" {
			candidates = append(candidates, filepath.Join(p.workingDir, ".env"))
		}
		seen := map[string]bool{}
		for i, f := range candidates {
			data, how, err := c.files.read(c.ctx, f)
			if err != nil {
				implicit := i >= len(p.files)
				if implicit && (os.IsNotExist(err) || IsNotFound(err)) {
					continue
				}
				if implicit {
					c.record("compose "+name+" "+f, how, "", err)
					continue
				}
				c.record("compose "+name+" "+f, how, "", fmt.Errorf("config file %s: %w", f, err))
				continue
			}
			base := filepath.Base(f)
			if seen[base] {
				base = fmt.Sprintf("%d-%s", i, base)
			}
			seen[base] = true
			file := "compose/" + safeName(name) + "/" + base
			if err := c.write(file, data); err != nil {
				c.record("compose "+name+" "+f, how, "", err)
				continue
			}
			c.record("compose "+name+" "+f, how, file, nil)
			entry.Archived = append(entry.Archived, dockerspec.ComposeFile{File: file, Source: f})
		}
		c.out.Compose = append(c.out.Compose, entry)
	}
}

func (c *collector) daemon() {
	c.out.Daemon.ConfigPath = daemonConfigPath
	data, how, err := c.files.read(c.ctx, daemonConfigPath)
	if err != nil {
		if os.IsNotExist(err) || IsNotFound(err) {
			c.record("daemon.json", how, "", nil)
			return
		}
		c.record("daemon.json", how, "", err)
		return
	}
	file := "daemon/daemon.json"
	if err := c.write(file, data); err != nil {
		c.record("daemon.json", how, "", err)
		return
	}
	c.record("daemon.json", how, file, nil)
	c.out.Daemon.Archived = true
}

// selfContainerID returns the id of the container the agent runs in ("" on a host)
func selfContainerID() string {
	for _, p := range []string{procSelfCgroup, procSelfMounts} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if id := containerIDRe.FindString(string(data)); id != "" {
			return id
		}
	}
	return ""
}

var containerIDRe = regexp.MustCompile(`[0-9a-f]{64}`)

// safeName makes a container/volume/project name usable as a file name
func safeName(s string) string {
	s = strings.TrimPrefix(s, "/")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "_"
	}
	return b.String()
}

func dropNone(list []string) []string {
	var out []string
	for _, s := range list {
		if s != "" && !strings.HasPrefix(s, "<none>") {
			out = append(out, s)
		}
	}
	return out
}

// absIn resolves a compose-relative file name against the project's working directory
func absIn(workingDir, f string) string {
	if filepath.IsAbs(f) || workingDir == "" {
		return filepath.Clean(f)
	}
	return filepath.Join(workingDir, f)
}
