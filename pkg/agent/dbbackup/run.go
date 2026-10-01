package dbbackup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

// UploadFunc uploads the spool directory (as the archive) plus blobs to PBS; the
// activity binds it to the pxar engine with the run's session.
type UploadFunc func(ctx context.Context, spoolDir string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

// RunOptions parameterise Run
type RunOptions struct {
	Session *temporal.BackupSessionInfo
	Spec    *dbspec.Spec
	// Password is the server-stored job password ("" = resolve from an agent profile)
	Password string
	Config   dbspec.Config
	Upload   UploadFunc
	Progress ProgressFunc
	// Runner overrides the process runner (tests)
	Runner       Runner
	Hostname     string
	AgentVersion string
	// PollInterval overrides the spool poll interval (tests)
	PollInterval time.Duration
	// State overrides where the job's chain state is read and written (default: JSON
	// files under Config.StateDir)
	State StateStore
	// Generator names the agent in the manifest (default fallbck-agent)
	Generator string
}

// Run executes one database backup run end to end
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Spec == nil || o.Upload == nil {
		return nil, errors.New("dbbackup: session, spec and upload are required")
	}
	spec := o.Spec.Clone()
	if err := spec.Validate(); err != nil {
		return nil, &PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	engine, ok := Lookup(spec.Engine)
	if !ok {
		return nil, precheckf("", "unsupported engine %q", spec.Engine)
	}
	cfg := o.Config
	cfg.ApplyDefaults("")
	if cfg.SpoolDir == "" {
		return nil, precheckf("set db_backup.spool_dir or data_dir in the agent configuration", "no spool directory configured")
	}
	runner := o.Runner
	if runner == nil {
		runner = NewRunner(cfg.KillGrace)
	}
	report := func(p Progress) {
		if o.Progress != nil {
			o.Progress(p)
		}
	}

	creds, err := dbspec.ResolveCredentials(spec, o.Password, cfg.Profiles)
	if errors.Is(err, dbspec.ErrNoCredentials) {
		// Nothing configured: as root on the database host, use what the engine
		// grants the local superuser without a password
		local, lerr := localCredentials(ctx, spec)
		if lerr != nil {
			return nil, &PrecheckError{Msg: "resolving credentials", Err: err,
				Hint: "passwordless local authentication does not apply: " + lerr.Error()}
		}
		slog.Info("No credentials configured; using passwordless local authentication", "engine", spec.Engine, "method", local.Source, "host", local.Host, "user", local.User, "run_as", local.RunAs)
		creds, err = local, nil
	}
	if err != nil {
		return nil, &PrecheckError{Msg: "resolving credentials", Err: err}
	}
	slog.Info("Database backup starting", "engine", spec.Engine, "host", creds.Host, "port", creds.Port, "user", creds.User, "credentials", creds.Source, "databases", spec.Databases)
	// Whatever the tools print must not carry the password into errors or logs
	if creds.Password != "" {
		runner = redactingRunner{Runner: runner, secrets: secretForms(creds.Password)}
	}

	report(Progress{Phase: "detect"})
	tools, err := engine.Detect(ctx, runner, cfg.Tools)
	if err != nil {
		if IsPrecheck(err) {
			return nil, err
		}
		return nil, &PrecheckError{Msg: "detecting client tools", Err: err}
	}

	runID := o.Session.BackupRunID.String()
	jobID := o.Session.JobID.String()
	spoolDir, err := prepareRunDir(cfg.SpoolDir, runID)
	if err != nil {
		return nil, err
	}
	secretDir := filepath.Join(cfg.SpoolDir, ".secret-"+runID)
	_ = os.RemoveAll(secretDir)
	if err := os.Mkdir(secretDir, 0o700); err != nil {
		return nil, fmt.Errorf("creating credential directory: %w", err)
	}
	failed := true
	defer func() {
		_ = os.RemoveAll(secretDir)
		if !failed || !cfg.KeepFailedSpool {
			_ = os.RemoveAll(spoolDir)
		} else {
			slog.Warn("Keeping failed spool directory for inspection", "dir", spoolDir)
		}
	}()

	state := o.State
	if state == nil {
		state = FileStateStore{Dir: cfg.StateDir}
	}
	prev, err := state.Load(ctx, jobID)
	if err != nil {
		slog.Warn("Ignoring unreadable job state", "error", err)
		prev = nil
	}

	// Phase tracking shared with the spool poller
	var current Progress
	req := &DumpRequest{
		RunID: runID, JobID: jobID, Label: fmt.Sprintf("fallbck-%s-%s", jobID, runID),
		Spec: spec, Creds: creds, Tools: tools, SpoolDir: spoolDir, SecretDir: secretDir,
		PrevState: prev, Runner: runner,
		Snapshot: fmt.Sprintf("%s/%s/%s", o.Session.BackupType, o.Session.BackupID, time.Unix(o.Session.BackupTime, 0).UTC().Format(time.RFC3339)),
		Progress: func(p Progress) {
			current = p
			p.BytesInSpool = dirSize(spoolDir)
			report(p)
		},
	}

	req.progress("precheck", "")
	server, err := engine.Precheck(ctx, req)
	if err != nil {
		return nil, err
	}
	req.Server = server
	for _, n := range server.Notes {
		slog.Info("Precheck note", "note", n)
	}

	// Disk space
	need := uint64(cfg.MinFreeBytes) + uint64(float64(server.EstimatedBytes)*cfg.SizeSafetyFactor)
	if free, err := freeBytes(cfg.SpoolDir); err == nil {
		if free < need {
			return nil, precheckf("free space or lower db_backup.min_free_bytes / move db_backup.spool_dir",
				"insufficient space in spool directory %s: %d MiB free, %d MiB required (estimate %d MiB)", cfg.SpoolDir, free>>20, need>>20, server.EstimatedBytes>>20)
		}
	}

	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	interval := o.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	p := &poller{dir: spoolDir, interval: interval, minFree: uint64(cfg.MinFreeBytes) / 4,
		onTick: func(bytes int64) {
			cp := current
			cp.BytesInSpool = bytes
			report(cp)
		},
		abort: func(err error) { cancel(err) },
	}
	pollDone := make(chan struct{})
	go func() { defer close(pollDone); p.run(runCtx) }()

	started := time.Now().UTC()
	req.progress("dump", "")
	res, dumpErr := engine.Dump(runCtx, req)
	cancel(nil)
	<-pollDone
	if dumpErr != nil {
		if cause := context.Cause(runCtx); cause != nil && !errors.Is(cause, context.Canceled) && ctx.Err() == nil {
			return nil, cause
		}
		if ctx.Err() != nil {
			return nil, dumpErr
		}
		var te *ToolError
		if errors.As(dumpErr, &te) && te.Config {
			return nil, &PrecheckError{Msg: "database backup failed", Err: dumpErr}
		}
		return nil, dumpErr
	}
	if len(res.Warnings) > 0 {
		slog.Warn("Dump finished with warnings", "warnings", res.Warnings)
	}

	// Manifest
	req.progress("manifest", "")
	files, err := collectFiles(spoolDir, cfg.ChecksumsEnabled())
	if err != nil {
		return nil, fmt.Errorf("listing spool files: %w", err)
	}
	bySize := map[string]dbspec.FileEntry{}
	for _, f := range files {
		bySize[f.Path] = f
	}
	for i := range res.Databases {
		if f, ok := bySize[res.Databases[i].File]; ok {
			res.Databases[i].SizeBytes, res.Databases[i].SHA256 = f.SizeBytes, f.SHA256
		}
	}
	redacted := spec.Redacted()
	redacted.HasPassword = o.Password != ""
	snapshotTime := time.Unix(o.Session.BackupTime, 0).UTC()
	consistent := res.ConsistentAsOf
	if consistent.IsZero() {
		consistent = started
	}
	generator := o.Generator
	if generator == "" {
		generator = "fallbck-agent"
	}
	manifest := &dbspec.Manifest{
		SchemaVersion:  dbspec.ManifestSchemaVersion,
		Generator:      dbspec.ManifestGenerator{Agent: generator, Version: o.AgentVersion, Hostname: o.Hostname},
		Job:            dbspec.ManifestJob{ID: jobID, Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: runID},
		Snapshot:       dbspec.ManifestSnapshot{Type: o.Session.BackupType, ID: o.Session.BackupID, Time: snapshotTime, Archive: dbspec.ArchiveName + ".pxar.didx"},
		Engine:         spec.Engine,
		StartedAt:      started,
		FinishedAt:     time.Now().UTC(),
		ConsistentAsOf: consistent,
		Server:         dbspec.ManifestServer{Host: creds.Host, Port: creds.Port, User: creds.User, Version: server.Version, VersionNum: server.VersionNum, Flavor: server.Flavor, IsReplica: server.IsReplica},
		Tools:          req.Tools.Manifest(),
		Spec:           redacted,
		Databases:      res.Databases,
		Files:          files,
		Warnings:       res.Warnings,
		Notes:          append(append([]string{}, server.Notes...), res.Notes...),
		Postgres:       res.Postgres,
		MySQL:          res.MySQL,
		MongoDB:        res.MongoDB,
		MSSQL:          res.MSSQL,
		Restore:        res.Restore,
	}
	if manifest.Databases == nil {
		manifest.Databases = []dbspec.DatabaseEntry{}
	}
	if o.Session.Encrypted {
		// The snapshot is client-side encrypted: fetching the dump from PBS needs the
		// target's key file before any of the engine commands apply
		manifest.Restore.Commands = append([]string{
			fmt.Sprintf("# snapshot is encrypted (key %s): proxmox-backup-client restore --keyfile <exported key file> %s %s.pxar.didx ./", o.Session.KeyFingerprint, manifest.Snapshot.Type+"/"+manifest.Snapshot.ID+"/"+snapshotTime.Format(time.RFC3339), dbspec.ArchiveName),
		}, manifest.Restore.Commands...)
	}
	data, err := manifest.Marshal()
	if err != nil {
		return nil, fmt.Errorf("encoding manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(spoolDir, dbspec.ManifestFileName), data, 0o600); err != nil {
		return nil, fmt.Errorf("writing manifest: %w", err)
	}

	// Upload
	req.progress("upload", "")
	result, err := o.Upload(ctx, spoolDir, []gopbs.Blob{{Name: dbspec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, err
	}
	result.Details = rundetail.WrapManifest(rundetail.TypeDatabase, data)

	// State (only after a successful upload: a failed run must not advance the chain)
	record := res.State
	if record == nil {
		record = &dbspec.JobStateRecord{}
	}
	record.RunID, record.Snapshot, record.CompletedAt = runID, result.SnapshotID, time.Now().UTC()
	if err := state.Save(ctx, jobID, &dbspec.JobState{JobID: jobID, Engine: spec.Engine, LastSuccess: record}); err != nil {
		slog.Warn("Job state could not be saved", "error", err)
	}
	failed = false
	slog.Info("Database backup completed", "engine", spec.Engine, "snapshot", result.SnapshotID, "databases", len(res.Databases), "spool_bytes", dirSize(spoolDir))
	return result, nil
}
