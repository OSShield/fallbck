package pvebackup

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	pvespec "github.com/osshield/fallbck/pkg/pvebackup"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

// UploadFunc archives the given roots (with the exclude patterns) plus blobs into
// PBS; the activity binds it to the pxar engine with the run's session
type UploadFunc func(ctx context.Context, paths, excludes []string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

// RunOptions parameterise Run
type RunOptions struct {
	Session *temporal.BackupSessionInfo
	Spec    *pvespec.Spec
	// SpoolDir receives the collected inventory (<SpoolDir>/<run id>/collect)
	SpoolDir string
	Upload   UploadFunc
	Progress func(phase string)
	// Runner overrides the process runner (tests)
	Runner       dbrun.Runner
	Hostname     string
	AgentVersion string
	// KeepSpool leaves the collect directory in place after the run (debugging)
	KeepSpool bool
}

// guestImageExcludes are added under every data entry unless the job keeps guest
// images: directory-storage images and CT roots, and ZFS subvolume mounts
var guestImageExcludes = []string{"images", "private", "subvol-*"}

// Run executes one Proxmox VE host backup: collect → archive → manifest → upload

// minFreeBytes is the free space a Proxmox VE run leaves on the spool filesystem
// (ponytail: fixed; make it a setting if someone runs the agent on a tight disk)
const minFreeBytes = 256 << 20

func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil {
		return nil, errors.New("pvebackup: session and upload are required")
	}
	spec := o.Spec.Clone()
	if spec == nil {
		spec = &pvespec.Spec{}
	}
	if err := spec.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	if !pvespec.IsPVEHost() {
		return nil, &dbrun.PrecheckError{Msg: "this host is not a Proxmox VE node", Hint: "assign the job to the agent running on the PVE host"}
	}
	if o.SpoolDir == "" {
		return nil, &dbrun.PrecheckError{Msg: "no spool directory configured", Hint: "set data_dir in the agent configuration"}
	}
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	runner := o.Runner
	if runner == nil {
		runner = dbrun.NewRunner(0)
	}

	runID := o.Session.BackupRunID.String()
	runDir := filepath.Join(o.SpoolDir, runID)
	collectDir := filepath.Join(runDir, pvespec.CollectEntry)
	_ = os.RemoveAll(runDir)
	if err := os.MkdirAll(collectDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating spool directory: %w", err)
	}
	defer func() {
		if !o.KeepSpool {
			_ = os.RemoveAll(runDir)
		}
	}()
	// The inventory is small (configuration and command output), but a nearly full
	// disk on a hypervisor is worse than a skipped backup
	if free, err := dbrun.FreeSpace(runDir); err == nil && free < minFreeBytes {
		return nil, &dbrun.PrecheckError{Msg: "not enough free space for the spool",
			Err:  fmt.Errorf("%s has %d MiB free, below %d MiB", o.SpoolDir, free>>20, minFreeBytes>>20),
			Hint: "free space on the node's agent data filesystem"}
	}

	started := time.Now().UTC()
	progress("collecting host inventory")
	inv := collect(ctx, runner, collectDir)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Archive roots and their entry names
	roots := []string{"/etc", collectDir}
	kinds := map[string]string{"/etc": "etc", collectDir: "collect"}
	if spec.EffIncludeRootHome() {
		if _, err := os.Stat("/root"); err == nil {
			roots = append(roots, "/root")
			kinds["/root"] = "root"
		}
	}
	for _, p := range spec.DataPaths {
		if _, err := os.Stat(p); err != nil {
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("data path %s skipped: %v", p, err))
			continue
		}
		roots = append(roots, p)
		kinds[p] = "data"
	}
	names, err := backup.ArchiveEntryNames(roots)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "archive layout", Err: err}
	}
	var entries []pvespec.ArchiveEntry
	for _, r := range roots {
		entries = append(entries, pvespec.ArchiveEntry{Name: names[r], Source: r, Kind: kinds[r]})
	}
	// /etc/pve is a FUSE mount copied into collect/; never archive it in place
	excludes := []string{"/" + names["/etc"] + "/pve"}
	if !spec.EffIncludeGuestImages() {
		for _, r := range roots {
			if kinds[r] != "data" {
				continue
			}
			for _, g := range guestImageExcludes {
				excludes = append(excludes, "/"+names[r]+"/"+g)
			}
		}
	}
	excludes = append(excludes, spec.ExcludePaths...)

	// Manifest + restore runbook, both inside collect/ and the manifest as a blob
	progress("writing manifest")
	snapshotTime := time.Unix(o.Session.BackupTime, 0).UTC()
	manifest := &pvespec.Manifest{
		SchemaVersion: pvespec.ManifestSchemaVersion,
		Generator:     pvespec.ManifestGenerator{Agent: "fallbck-agent", Version: o.AgentVersion, Hostname: o.Hostname},
		Job:           pvespec.ManifestJob{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: runID},
		Snapshot:      pvespec.ManifestSnapshot{Type: o.Session.BackupType, ID: o.Session.BackupID, Time: snapshotTime, Archive: pvespec.ArchiveName + ".pxar.didx"},
		StartedAt:     started,
		FinishedAt:    time.Now().UTC(),
		Host:          inv.Host,
		Packages:      inv.Packages,
		Storages:      inv.Storages,
		Guests:        inv.Guests,
		Disks:         inv.Disks,
		Entries:       entries,
		Excludes:      excludes,
		Collected:     inv.Records,
		Spec:          spec,
		Warnings:      inv.Warnings,
	}
	if manifest.Storages == nil {
		manifest.Storages = []pvespec.Storage{}
	}
	if manifest.Guests == nil {
		manifest.Guests = []pvespec.Guest{}
	}
	if manifest.Disks == nil {
		manifest.Disks = []pvespec.Disk{}
	}
	manifest.Restore = pvespec.Restore{
		Summary: fmt.Sprintf("Proxmox VE %s host %s (%d guests, %d storages, %d packages) taken %s; restore onto a fresh PVE %s install with the generated script",
			cmp.Or(manifest.Host.PVEVersion, "-"), manifest.Host.Hostname, len(manifest.Guests), len(manifest.Storages), manifest.Packages.Installed, snapshotTime.Format(time.RFC3339), pveMajorString(manifest)),
		Commands: restoreCommands(manifest, o.Session.Namespace),
		Script:   pvespec.CollectEntry + "/" + pvespec.RestoreScriptName,
	}
	script := restoreScript(manifest, o.Session.Namespace)
	if err := os.WriteFile(filepath.Join(collectDir, pvespec.RestoreScriptName), []byte(script), 0o700); err != nil {
		return nil, fmt.Errorf("writing restore script: %w", err)
	}
	data, err := manifest.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(collectDir, pvespec.ManifestFileName), data, 0o600); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	progress("uploading")
	result, err := o.Upload(ctx, roots, excludes, []gopbs.Blob{{Name: pvespec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, err
	}
	result.Details = rundetail.WrapManifest(rundetail.TypePVE, data)
	slog.Info("Proxmox VE host backup completed", "snapshot", result.SnapshotID, "guests", len(manifest.Guests), "storages", len(manifest.Storages), "warnings", len(manifest.Warnings))
	return result, nil
}
