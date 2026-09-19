package dockerbackup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	dockerspec "github.com/osshield/fallbck/pkg/dockerbackup"
	"github.com/osshield/fallbck/pkg/fsutil"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

// UploadFunc archives the given roots into PBS: paths name the entries (virtual,
// under logicalRoot), readPaths are where the data is read (same order), plus the
// exclude patterns and blobs; the activity binds it to the pxar engine with the
// run's session
type UploadFunc func(ctx context.Context, paths, readPaths, excludes []string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

// logicalRoot is the virtual directory the archive entries are named under
// (/fallbck-docker/collect → collect, /fallbck-docker/vol-<name> → vol-<name>)
const logicalRoot = "/fallbck-docker"

// RunOptions parameterise Run
type RunOptions struct {
	Session *temporal.BackupSessionInfo
	Spec    *dockerspec.Spec
	// Settings is the agent-side docker_backup block
	Settings dockerspec.Config
	// SpoolDir receives the collected definitions and staged volumes (<SpoolDir>/<run id>)
	SpoolDir string
	Upload   UploadFunc
	Progress func(phase string)
	// Client overrides the daemon client (tests)
	Client       *Client
	Hostname     string
	AgentVersion string
	// KeepSpool leaves the spool directory in place after the run (debugging)
	KeepSpool bool
}

// Run executes one Docker host backup: collect → volumes → manifest → upload
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil {
		return nil, errors.New("dockerbackup: session and upload are required")
	}
	spec := o.Spec.Clone()
	if spec == nil {
		spec = &dockerspec.Spec{}
	}
	if err := spec.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	if err := o.Settings.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid agent configuration", Err: err}
	}
	if o.SpoolDir == "" {
		return nil, &dbrun.PrecheckError{Msg: "no spool directory configured", Hint: "set data_dir in the agent configuration"}
	}
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	client := o.Client
	if client == nil {
		client = NewClient(o.Settings.EffSocket())
	}
	pctx, cancel := context.WithTimeout(ctx, callTimeout)
	err := dockerspec.Ping(pctx, client.Socket())
	cancel()
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "Docker daemon is not reachable on " + client.Socket(), Err: err,
			Hint: "assign the job to the agent running on the Docker host (as root, or with the socket mounted into its container)"}
	}

	runID := o.Session.BackupRunID.String()
	runDir := filepath.Join(o.SpoolDir, runID)
	collectDir := filepath.Join(runDir, dockerspec.CollectEntry)
	stageDir := filepath.Join(runDir, "volumes")
	_ = os.RemoveAll(runDir)
	if err := os.MkdirAll(collectDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating spool directory: %w", err)
	}
	defer func() {
		if !o.KeepSpool {
			_ = os.RemoveAll(runDir)
		}
	}()

	mode := o.Settings.EffVolumeAccess()
	files := &hostFiles{client: client, mode: mode, helperImage: o.Settings.EffHelperImage(), runID: runID}
	if mode != dockerspec.VolumeAccessDirect {
		if n := SweepHelpers(ctx, client); n > 0 {
			slog.Warn("Removed helper containers left behind by an earlier run", "count", n)
		}
	}

	started := time.Now().UTC()
	progress("collecting definitions")
	inv := collect(ctx, client, files, spec, collectDir)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if inv.info == nil {
		return nil, &dbrun.PrecheckError{Msg: "Docker daemon did not answer /version or /info", Hint: "see the warnings in the agent log"}
	}
	selectVolumes(spec, inv)

	// Volumes: read in place (direct), or staged into the spool when the containers
	// using them are paused for the copy or when the mountpoint is not visible
	paths := []string{logicalRoot + "/" + dockerspec.CollectEntry}
	readPaths := []string{collectDir}
	entries := []dockerspec.ArchiveEntry{{Name: dockerspec.CollectEntry, Source: collectDir, Kind: "collect"}}
	p := &pauser{client: client}
	usedModes := map[string]bool{}
	for i := range inv.Volumes {
		v := &inv.Volumes[i]
		if v.Skipped != "" {
			continue
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		access, err := volumeAccess(mode, v)
		if err != nil {
			v.Skipped = err.Error()
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("volume %s skipped: %v", v.Name, err))
			continue
		}
		var toPause []*ContainerInspect
		for _, id := range inv.volumeUsers[v.Name] {
			if ci := inv.inspects[id]; wantsPause(spec, ci) {
				toPause = append(toPause, ci)
			}
		}
		entry := dockerspec.VolumeEntryPrefix + v.Name
		source := v.Mountpoint
		if access == accessDirect && len(toPause) == 0 {
			v.Access = accessDirect
		} else {
			progress("copying volume " + v.Name)
			dst := filepath.Join(stageDir, safeName(v.Name))
			if len(toPause) > 0 {
				paused, thaw := p.pause(ctx, toPause)
				v.Paused = paused
				markPaused(inv, paused)
				err = stageVolume(ctx, access, files, v, dst)
				inv.Warnings = append(inv.Warnings, thaw()...)
			} else {
				err = stageVolume(ctx, access, files, v, dst)
			}
			if err != nil {
				_ = os.RemoveAll(dst)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				v.Skipped = "copy failed: " + err.Error()
				inv.Warnings = append(inv.Warnings, fmt.Sprintf("volume %s skipped: %v", v.Name, err))
				continue
			}
			source = dst
			if access == accessDirect {
				v.Access = accessStaged
			} else {
				v.Access = accessHelper
			}
		}
		usedModes[v.Access] = true
		v.Entry = entry
		paths = append(paths, logicalRoot+"/"+entry)
		readPaths = append(readPaths, source)
		entries = append(entries, dockerspec.ArchiveEntry{Name: entry, Source: source, Kind: "volume"})
	}
	// Additional host paths: read in place when visible, otherwise through a helper
	// container (the agent running as a container without that directory mounted)
	var hostPaths []dockerspec.HostPath
	for _, hp := range spec.HostPaths {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		entry := dockerspec.HostPathEntry(hp)
		h := dockerspec.HostPath{Path: hp, Entry: entry}
		source := hp
		if st, err := os.Stat(hp); err == nil && st.IsDir() {
			h.Access = accessDirect
		} else if mode == dockerspec.VolumeAccessDirect {
			h.Entry, h.Skipped = "", fmt.Sprintf("not readable by the agent: %v", err)
		} else {
			progress("copying host path " + hp)
			dst := filepath.Join(stageDir, safeName(entry))
			if err := extractViaHelper(ctx, files, hp, dst); err != nil {
				_ = os.RemoveAll(dst)
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				h.Entry, h.Skipped = "", "copy failed: "+err.Error()
			} else {
				h.Access, source = accessHelper, dst
			}
		}
		if h.Skipped != "" {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("host path %s skipped: %s", hp, h.Skipped))
			hostPaths = append(hostPaths, h)
			continue
		}
		usedModes[h.Access] = true
		hostPaths = append(hostPaths, h)
		paths = append(paths, logicalRoot+"/"+entry)
		readPaths = append(readPaths, source)
		entries = append(entries, dockerspec.ArchiveEntry{Name: entry, Source: hp, Kind: "host"})
	}
	inv.Host.VolumeAccess = summarizeModes(usedModes)

	// Manifest + restore runbook, both inside collect/ and the manifest as a blob
	progress("writing manifest")
	snapshotTime := time.Unix(o.Session.BackupTime, 0).UTC()
	hostname := o.Hostname
	if hostname == "" {
		hostname = inv.Host.Hostname
	}
	manifest := &dockerspec.Manifest{
		SchemaVersion: dockerspec.ManifestSchemaVersion,
		Generator:     dockerspec.ManifestGenerator{Agent: "fallbck-agent", Version: o.AgentVersion, Hostname: hostname},
		Job:           dockerspec.ManifestJob{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: runID},
		Snapshot:      dockerspec.ManifestSnapshot{Type: o.Session.BackupType, ID: o.Session.BackupID, Time: snapshotTime, Archive: dockerspec.ArchiveName + ".pxar.didx"},
		StartedAt:     started,
		FinishedAt:    time.Now().UTC(),
		Host:          inv.Host,
		Containers:    nonNil(inv.Containers),
		Volumes:       nonNil(inv.Volumes),
		Networks:      nonNil(inv.Networks),
		Images:        nonNil(inv.Images),
		Compose:       nonNil(inv.Compose),
		Daemon:        inv.Daemon,
		HostPaths:     hostPaths,
		BindMounts:    inv.BindMounts,
		Entries:       entries,
		Excludes:      spec.ExcludePaths,
		Collected:     inv.Records,
		Spec:          spec,
		Warnings:      inv.Warnings,
	}
	manifest.Restore = dockerspec.Restore{
		Summary:  restoreSummary(manifest, snapshotTime),
		Commands: restoreCommands(manifest, o.Session.Namespace),
		Script:   dockerspec.CollectEntry + "/" + dockerspec.RestoreScriptName,
	}
	script := restoreScript(manifest, o.Session.Namespace, o.Settings.EffHelperImage())
	if err := os.WriteFile(filepath.Join(collectDir, dockerspec.RestoreScriptName), []byte(script), 0o700); err != nil {
		return nil, fmt.Errorf("writing restore script: %w", err)
	}
	data, err := manifest.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(collectDir, dockerspec.ManifestFileName), data, 0o600); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	progress("uploading")
	result, err := o.Upload(ctx, paths, readPaths, spec.ExcludePaths, []gopbs.Blob{{Name: dockerspec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, err
	}
	result.Details = rundetail.WrapManifest(rundetail.TypeDocker, data)
	slog.Info("Docker host backup completed", "snapshot", result.SnapshotID, "containers", len(manifest.Containers),
		"volumes", len(entries)-1, "warnings", len(manifest.Warnings))
	return result, nil
}

// markPaused flags the manifest entries of containers that were paused for a copy
func markPaused(inv *collected, names []string) {
	for _, n := range names {
		for i := range inv.Containers {
			if inv.Containers[i].Name == n {
				inv.Containers[i].Paused = true
			}
		}
	}
}

// stageVolume copies a volume into dst by the chosen access mode
func stageVolume(ctx context.Context, access string, files *hostFiles, v *dockerspec.Volume, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	if access == accessDirect {
		return fsutil.CopyTree(v.Mountpoint, dst)
	}
	return extractViaHelper(ctx, files, v.Name, dst)
}

func summarizeModes(used map[string]bool) string {
	var modes []string
	for m := range used {
		modes = append(modes, m)
	}
	sort.Strings(modes)
	switch len(modes) {
	case 0:
		return ""
	case 1:
		return modes[0]
	}
	return "mixed"
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
