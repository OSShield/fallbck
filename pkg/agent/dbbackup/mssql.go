package dbbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/fsutil"
)

// mssqlEngine backs up Microsoft SQL Server with native BACKUP DATABASE / BACKUP LOG
// ... TO DISK statements over the built-in driver: SQL Server writes the files into a
// directory on its own host, the agent moves them into the run's spool and uploads
// them. No client tools are needed, so every agent offers this engine.
type mssqlEngine struct{}

func (mssqlEngine) Name() string { return dbspec.EngineMSSQL }

// Backup kinds
const (
	mssqlFull = "full"
	mssqlDiff = "differential"
	mssqlLog  = "log"
	// mssqlSpoolDir is the spool subdirectory holding the backup files
	mssqlSpoolDir = "mssql"
	// mssqlPlanAttr carries the plan from Precheck to Dump
	mssqlPlanAttr = "mssql_plan"
)

// Detect reports the built-in driver; there are no binaries to find
func (mssqlEngine) Detect(context.Context, Runner, dbspec.ToolConfig) (ToolInfo, error) {
	version := "built in"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == "github.com/microsoft/go-mssqldb" {
				version = dep.Version
			}
		}
	}
	return ToolInfo{Binaries: map[string]Binary{"go-mssqldb": {Path: "(built-in driver)", Version: version}}}, nil
}

// mssqlDB is one row of sys.databases
type mssqlDB struct {
	Name       string
	Recovery   string // SIMPLE | FULL | BULK_LOGGED
	State      string // ONLINE | ...
	IsSnapshot bool
}

// mssqlTask is one backup statement to run
type mssqlTask struct {
	DB       string `json:"db"`
	Kind     string `json:"kind"`
	Recovery string `json:"recovery"`
	Reason   string `json:"reason,omitempty"`
}

// mssqlPlan is what Precheck decided
type mssqlPlan struct {
	Edition        string                `json:"edition"`
	ProductVersion string                `json:"product_version"`
	BackupDir      string                `json:"backup_dir"`
	AgentDir       string                `json:"agent_dir"`
	Compression    bool                  `json:"compression"`
	Tasks          []mssqlTask           `json:"tasks"`
	Skipped        []dbspec.MSSQLSkipped `json:"skipped,omitempty"`
}

// planMSSQLDatabase decides what to take for one database. lastFullUUID is the
// backup_set_uuid of the newest non-copy-only full backup msdb knows ("" = none);
// comparing it with the chain FallBCK holds is what detects fulls taken by another
// tool (or by a run whose upload failed), after which a differential would restore
// from a base FallBCK does not have.
func planMSSQLDatabase(opts *dbspec.MSSQLOptions, d mssqlDB, st *dbspec.MSSQLDBState, lastFullUUID string, now time.Time) (tasks []mssqlTask, skip string) {
	if d.IsSnapshot {
		return nil, "database snapshot"
	}
	if d.State != "ONLINE" {
		return nil, "state " + d.State
	}
	simple := d.Recovery == "SIMPLE"
	if opts.Mode == dbspec.MSSQLModeLog {
		switch {
		case simple:
			return nil, "recovery model SIMPLE has no log backups"
		case lastFullUUID == "":
			return nil, "no full backup exists yet; log backups need one (run a full or auto job first)"
		}
		reason := ""
		if st == nil || st.LastFull == nil {
			reason = "the base full backup is not held by this job; restoring needs it from wherever it was taken"
		}
		return []mssqlTask{{DB: d.Name, Kind: mssqlLog, Recovery: d.Recovery, Reason: reason}}, ""
	}

	kind, reason := mssqlDiff, ""
	switch {
	case opts.Mode == dbspec.MSSQLModeFull:
		kind = mssqlFull
	case d.Name == "master":
		kind, reason = mssqlFull, "master supports full backups only"
	case st == nil || st.LastFull == nil:
		kind, reason = mssqlFull, "no full backup in this job's chain yet"
	case st.RecoveryModel != "" && st.RecoveryModel != d.Recovery:
		kind, reason = mssqlFull, fmt.Sprintf("chain reset: recovery model changed from %s to %s", st.RecoveryModel, d.Recovery)
	case lastFullUUID != st.LastFull.BackupSetUUID:
		kind, reason = mssqlFull, "chain reset: the server's newest full backup is not the one this job holds (taken by another tool, or a previous run failed after the backup)"
	case opts.Mode == dbspec.MSSQLModeAuto && now.Sub(st.LastFull.At) >= time.Duration(opts.EffFullEveryDays())*24*time.Hour:
		kind, reason = mssqlFull, fmt.Sprintf("last full is %d days old (full_every_days %d)", int(now.Sub(st.LastFull.At).Hours()/24), opts.EffFullEveryDays())
	}
	tasks = []mssqlTask{{DB: d.Name, Kind: kind, Recovery: d.Recovery, Reason: reason}}
	if opts.IncludeLog && !simple {
		tasks = append(tasks, mssqlTask{DB: d.Name, Kind: mssqlLog, Recovery: d.Recovery})
	}
	return tasks, ""
}

// selectMSSQLDatabases applies the job's database and exclude lists (tempdb is never
// backed up)
func selectMSSQLDatabases(spec *dbspec.Spec, all []mssqlDB) ([]mssqlDB, error) {
	byName := map[string]mssqlDB{}
	for _, d := range all {
		byName[strings.ToLower(d.Name)] = d
	}
	excluded := map[string]bool{"tempdb": true}
	for _, e := range spec.ExcludeDatabases {
		excluded[strings.ToLower(e)] = true
	}
	var out []mssqlDB
	if len(spec.Databases) > 0 {
		for _, name := range spec.Databases {
			d, ok := byName[strings.ToLower(name)]
			if !ok {
				return nil, precheckf("check the database list of the job", "database %q does not exist on the server", name)
			}
			if !excluded[strings.ToLower(d.Name)] {
				out = append(out, d)
			}
		}
		return out, nil
	}
	for _, d := range all {
		if !excluded[strings.ToLower(d.Name)] {
			out = append(out, d)
		}
	}
	return out, nil
}

// mssqlIdent quotes an identifier, mssqlNString a Unicode string literal
func mssqlIdent(s string) string   { return "[" + strings.ReplaceAll(s, "]", "]]") + "]" }
func mssqlNString(s string) string { return "N" + quoteLiteral(s) }

// mssqlServerJoin joins a file name onto a directory the way the SQL Server host
// spells paths (Windows or Linux), whatever OS the agent runs on
func mssqlServerJoin(dir, name string) string {
	sep := "/"
	if strings.Contains(dir, `\`) || (len(dir) >= 2 && dir[1] == ':') {
		sep = `\`
	}
	return strings.TrimRight(dir, `/\`) + sep + name
}

var mssqlUnsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// mssqlFileNames names the backup files of one task (several when striped)
func mssqlFileNames(runID string, t mssqlTask, stripes int) []string {
	ext := ".bak"
	if t.Kind == mssqlLog {
		ext = ".trn"
	}
	short := strings.ReplaceAll(runID, "-", "")
	if len(short) > 8 {
		short = short[:8]
	}
	base := fmt.Sprintf("fallbck-%s-%s-%s", short, mssqlUnsafeName.ReplaceAllString(t.DB, "_"), t.Kind)
	if stripes <= 1 {
		return []string{base + ext}
	}
	names := make([]string, stripes)
	for i := range names {
		names[i] = fmt.Sprintf("%s-%dof%d%s", base, i+1, stripes, ext)
	}
	return names
}

// mssqlBackupSQL renders the BACKUP statement for a task
func mssqlBackupSQL(opts *dbspec.MSSQLOptions, t mssqlTask, serverPaths []string, compression bool, label string) string {
	var b strings.Builder
	if t.Kind == mssqlLog {
		b.WriteString("BACKUP LOG ")
	} else {
		b.WriteString("BACKUP DATABASE ")
	}
	b.WriteString(mssqlIdent(t.DB) + " TO ")
	for i, p := range serverPaths {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString("DISK = " + mssqlNString(p))
	}
	with := []string{}
	if t.Kind == mssqlDiff {
		with = append(with, "DIFFERENTIAL")
	}
	if opts.CopyOnly {
		with = append(with, "COPY_ONLY")
	}
	if opts.EffChecksum() {
		with = append(with, "CHECKSUM")
	}
	if compression {
		with = append(with, "COMPRESSION")
	} else {
		with = append(with, "NO_COMPRESSION")
	}
	if opts.MaxTransferSize > 0 {
		with = append(with, fmt.Sprintf("MAXTRANSFERSIZE = %d", opts.MaxTransferSize))
	}
	with = append(with, "FORMAT", "INIT", "NAME = "+mssqlNString(label), "STATS = 10")
	b.WriteString(" WITH " + strings.Join(with, ", "))
	return b.String()
}

var mssqlPercent = regexp.MustCompile(`^(\d+) percent processed`)

func (mssqlEngine) Precheck(ctx context.Context, req *DumpRequest) (ServerInfo, error) {
	opts := req.Spec.MSSQL
	if req.Creds.User == "" && goruntime.GOOS != "windows" {
		return ServerInfo{}, precheckf("set a SQL login on the job or in the credential profile", "no database user configured: Windows integrated authentication is only available to an agent running on Windows")
	}
	conn, err := mssqlConnect(ctx, req.Creds)
	if err != nil {
		return ServerInfo{}, &PrecheckError{Msg: "connecting to SQL Server", Err: err, Hint: "check host (host\\instance for a named instance), port, login and TLS mode; with integrated authentication the agent's service account needs a login on the server"}
	}
	defer conn.close()

	rows, err := conn.queryRows(ctx, `SELECT CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')), CONVERT(nvarchar(128), SERVERPROPERTY('Edition')), CONVERT(nvarchar(16), SERVERPROPERTY('EngineEdition')), CONVERT(nvarchar(512), SERVERPROPERTY('InstanceDefaultBackupPath'))`)
	if err != nil || len(rows) != 1 || len(rows[0]) < 4 {
		return ServerInfo{}, &PrecheckError{Msg: "reading the server properties", Err: err}
	}
	version, edition, engineEdition, defaultDir := rows[0][0], rows[0][1], rows[0][2], rows[0][3]
	major, minor, patch := parseServerVersion(version)
	info := ServerInfo{Version: version, VersionNum: major*10000 + minor*100 + patch%100, Flavor: edition, Attrs: map[string]string{}}

	dbRows, err := conn.queryRows(ctx, `SELECT name, recovery_model_desc, state_desc, CASE WHEN source_database_id IS NULL THEN 0 ELSE 1 END FROM sys.databases ORDER BY name`)
	if err != nil {
		return info, &PrecheckError{Msg: "listing databases", Err: err}
	}
	var all []mssqlDB
	for _, r := range dbRows {
		if len(r) >= 4 {
			all = append(all, mssqlDB{Name: r[0], Recovery: r[1], State: r[2], IsSnapshot: r[3] == "1"})
		}
	}
	selected, err := selectMSSQLDatabases(req.Spec, all)
	if err != nil {
		return info, err
	}
	if len(selected) == 0 {
		return info, precheckf("check the database and exclude lists", "no databases selected")
	}

	// The newest real full backup per database, as msdb sees it
	lastFull := map[string]string{}
	fullRows, err := conn.queryRows(ctx, `SELECT bs.database_name, CONVERT(nvarchar(36), bs.backup_set_uuid) FROM msdb.dbo.backupset bs WHERE bs.backup_set_id IN (SELECT MAX(backup_set_id) FROM msdb.dbo.backupset WHERE type = 'D' AND is_copy_only = 0 GROUP BY database_name)`)
	if err != nil {
		return info, &PrecheckError{Msg: "reading the backup history (msdb.dbo.backupset)", Err: err}
	}
	for _, r := range fullRows {
		if len(r) >= 2 {
			lastFull[strings.ToLower(r[0])] = strings.ToLower(r[1])
		}
	}

	plan := mssqlPlan{Edition: edition, ProductVersion: version, Compression: opts.Compression}
	var prev *dbspec.MSSQLState
	if req.PrevState != nil && req.PrevState.LastSuccess != nil {
		prev = req.PrevState.LastSuccess.MSSQL
	}
	now := time.Now().UTC()
	for _, d := range selected {
		var st *dbspec.MSSQLDBState
		if prev != nil {
			st = prev.Databases[d.Name]
		}
		tasks, skip := planMSSQLDatabase(opts, d, st, lastFull[strings.ToLower(d.Name)], now)
		if skip != "" {
			plan.Skipped = append(plan.Skipped, dbspec.MSSQLSkipped{Database: d.Name, Reason: skip})
			continue
		}
		plan.Tasks = append(plan.Tasks, tasks...)
	}
	if len(plan.Tasks) == 0 {
		reasons := make([]string, 0, len(plan.Skipped))
		for _, s := range plan.Skipped {
			reasons = append(reasons, s.Database+": "+s.Reason)
		}
		return info, precheckf("", "nothing to back up (%s)", strings.Join(reasons, "; "))
	}

	// Permissions for what is planned
	for _, t := range plan.Tasks {
		perm := "BACKUP DATABASE"
		if t.Kind == mssqlLog {
			perm = "BACKUP LOG"
		}
		var has string
		pr, err := conn.queryRows(ctx, fmt.Sprintf(`SELECT CONVERT(nvarchar(4), HAS_PERMS_BY_NAME(%s, 'DATABASE', '%s'))`, mssqlNString(t.DB), perm))
		if err == nil && len(pr) == 1 && len(pr[0]) == 1 {
			has = pr[0][0]
		}
		if has == "0" {
			return info, precheckf("add the login to the db_backupoperator role of the database (or grant "+perm+")", "login lacks %s on %s", perm, t.DB)
		}
	}

	// Express cannot write compressed backups
	if plan.Compression && engineEdition == "4" {
		plan.Compression = false
		info.Notes = append(info.Notes, "backup compression is not available on "+edition+"; backups are written uncompressed")
	}

	// Where SQL Server writes and where the agent reads
	plan.BackupDir = opts.BackupDir
	if plan.BackupDir == "" {
		plan.BackupDir = defaultDir
	}
	if plan.BackupDir == "" {
		return info, precheckf("set mssql.backup_dir on the job", "the server reports no default backup path (SQL Server older than 2012)")
	}
	plan.AgentDir = opts.AgentDir
	if plan.AgentDir == "" {
		plan.AgentDir = plan.BackupDir
	}
	if note, err := mssqlProbeDir(ctx, conn, plan, req.RunID); err != nil {
		return info, err
	} else if note != "" {
		info.Notes = append(info.Notes, note)
	}

	// Spool estimate: full backups are bounded by the data file sizes
	var fulls []string
	for _, t := range plan.Tasks {
		if t.Kind == mssqlFull {
			fulls = append(fulls, mssqlNString(t.DB))
		}
	}
	if len(fulls) > 0 {
		if sr, err := conn.queryRows(ctx, `SELECT CONVERT(nvarchar(32), SUM(CAST(size AS bigint)) * 8192) FROM sys.master_files WHERE type = 0 AND DB_NAME(database_id) IN (`+strings.Join(fulls, ", ")+`)`); err == nil && len(sr) == 1 {
			info.EstimatedBytes, _ = strconv.ParseInt(sr[0][0], 10, 64)
		}
	}
	for _, s := range plan.Skipped {
		info.Notes = append(info.Notes, fmt.Sprintf("database %s skipped: %s", s.Database, s.Reason))
	}
	data, _ := json.Marshal(plan)
	info.Attrs[mssqlPlanAttr] = string(data)
	req.Databases = nil
	return info, nil
}

// mssqlProbeDir verifies that the agent's view and SQL Server's view of the backup
// directory are the same place: the agent writes a probe file, the server is asked
// whether it sees it. A server that may not run xp_fileexist only yields a note.
func mssqlProbeDir(ctx context.Context, conn mssqlConn, plan mssqlPlan, runID string) (string, error) {
	name := "fallbck-probe-" + strings.ReplaceAll(runID, "-", "") + ".tmp"
	agentPath := filepath.Join(plan.AgentDir, name)
	if err := os.WriteFile(agentPath, []byte("fallbck"), 0o644); err != nil {
		hint := "the agent must be able to read and delete files in " + plan.AgentDir
		if plan.AgentDir == plan.BackupDir {
			hint += "; when SQL Server runs on another host or in a container, set mssql.backup_dir to the directory as the server sees it and mssql.agent_dir to the same directory as the agent sees it (share or bind mount)"
		}
		return "", &PrecheckError{Msg: "backup directory " + plan.AgentDir + " is not usable by the agent", Err: err, Hint: hint}
	}
	defer os.Remove(agentPath)
	rows, err := conn.queryRows(ctx, `EXEC master.dbo.xp_fileexist `+mssqlNString(mssqlServerJoin(plan.BackupDir, name)))
	if err != nil || len(rows) != 1 || len(rows[0]) < 1 {
		return "could not verify that SQL Server sees the backup directory (xp_fileexist is not available to this login)", nil
	}
	if rows[0][0] != "1" {
		return "", precheckf("mssql.backup_dir and mssql.agent_dir must name the same directory, once as SQL Server sees it and once as the agent sees it",
			"SQL Server does not see the probe file the agent wrote: %s (server) and %s (agent) are not the same directory", plan.BackupDir, plan.AgentDir)
	}
	return "", nil
}

// mssqlReadBackupSet reads the msdb record of the backup just written to serverPath
func mssqlReadBackupSet(ctx context.Context, conn mssqlConn, db, serverPath string) (dbspec.MSSQLBackupSet, error) {
	rows, err := conn.queryRows(ctx, `SELECT TOP 1 CONVERT(nvarchar(36), bs.backup_set_uuid), CONVERT(nvarchar(40), bs.first_lsn), CONVERT(nvarchar(40), bs.last_lsn), CONVERT(nvarchar(40), bs.checkpoint_lsn), CONVERT(nvarchar(40), bs.database_backup_lsn), CONVERT(nvarchar(36), bs.differential_base_guid), CONVERT(nvarchar(32), bs.backup_size), CONVERT(nvarchar(32), bs.compressed_backup_size), CONVERT(nvarchar(33), bs.backup_start_date, 126), CONVERT(nvarchar(33), bs.backup_finish_date, 126) FROM msdb.dbo.backupset bs JOIN msdb.dbo.backupmediafamily mf ON mf.media_set_id = bs.media_set_id WHERE bs.database_name = `+mssqlNString(db)+` AND mf.physical_device_name = `+mssqlNString(serverPath)+` ORDER BY bs.backup_set_id DESC`)
	if err != nil {
		return dbspec.MSSQLBackupSet{}, err
	}
	if len(rows) != 1 || len(rows[0]) < 10 {
		return dbspec.MSSQLBackupSet{}, fmt.Errorf("msdb has no record of the backup written to %s", serverPath)
	}
	r := rows[0]
	set := dbspec.MSSQLBackupSet{
		BackupSetUUID: strings.ToLower(r[0]), FirstLSN: r[1], LastLSN: r[2], CheckpointLSN: r[3],
		DatabaseBackupLSN: r[4], DifferentialBaseGUID: strings.ToLower(r[5]),
	}
	set.BackupBytes, _ = strconv.ParseInt(strings.SplitN(r[6], ".", 2)[0], 10, 64)
	set.CompressedBytes, _ = strconv.ParseInt(strings.SplitN(r[7], ".", 2)[0], 10, 64)
	// msdb stores server-local times without a zone
	set.StartedAt, _ = time.Parse("2006-01-02T15:04:05", strings.SplitN(r[8], ".", 2)[0])
	set.FinishedAt, _ = time.Parse("2006-01-02T15:04:05", strings.SplitN(r[9], ".", 2)[0])
	return set, nil
}

// mssqlCollect moves a backup file from the backup directory into the spool (rename
// when possible, copy and delete across filesystems)
func mssqlCollect(agentDir, spoolDir, name string) error {
	src := filepath.Join(agentDir, name)
	dst := filepath.Join(spoolDir, mssqlSpoolDir, name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := fsutil.CopyFile(src, dst); err != nil {
		return fmt.Errorf("collecting %s: %w", src, err)
	}
	if err := os.Remove(src); err != nil {
		slog.Warn("Could not delete the collected backup file", "file", src, "error", err)
	}
	return nil
}

func (mssqlEngine) Dump(ctx context.Context, req *DumpRequest) (*EngineResult, error) {
	opts := req.Spec.MSSQL
	var plan mssqlPlan
	if err := json.Unmarshal([]byte(req.Server.Attrs[mssqlPlanAttr]), &plan); err != nil || len(plan.Tasks) == 0 {
		return nil, fmt.Errorf("SQL Server backup plan missing (precheck did not run): %v", err)
	}
	conn, err := mssqlConnect(ctx, req.Creds)
	if err != nil {
		return nil, fmt.Errorf("connecting to SQL Server: %w", err)
	}
	defer conn.close()

	// Files still sitting in the backup directory when the run fails are removed
	var pending []string
	defer func() {
		for _, name := range pending {
			_ = os.Remove(filepath.Join(plan.AgentDir, name))
		}
	}()

	state := cloneMSSQLState(req.PrevState)
	res := &EngineResult{
		MSSQL: &dbspec.MSSQLManifest{
			Edition: plan.Edition, ProductVersion: plan.ProductVersion, Mode: opts.Mode,
			BackupDir: plan.BackupDir, Compression: plan.Compression, Checksum: opts.EffChecksum(), CopyOnly: opts.CopyOnly,
			BackupSets: []dbspec.MSSQLBackupSet{}, Skipped: plan.Skipped,
		},
	}
	if plan.AgentDir != plan.BackupDir {
		res.MSSQL.AgentDir = plan.AgentDir
	}
	label := "fallbck " + req.Label + " " + req.RunID
	if len(label) > 128 {
		label = label[:128]
	}

	for _, t := range plan.Tasks {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		names := mssqlFileNames(req.RunID, t, opts.EffStripeCount())
		serverPaths := make([]string, len(names))
		for i, n := range names {
			serverPaths[i] = mssqlServerJoin(plan.BackupDir, n)
		}
		pending = append(pending, names...)
		started := time.Now()
		req.progress("dump", t.DB+" ("+t.Kind+")")
		err := conn.exec(ctx, mssqlBackupSQL(opts, t, serverPaths, plan.Compression, label), func(msg string) {
			if m := mssqlPercent.FindStringSubmatch(msg); m != nil {
				req.progress("dump", fmt.Sprintf("%s (%s) %s%%", t.DB, t.Kind, m[1]))
			}
		})
		if err != nil {
			return nil, fmt.Errorf("%s backup of %s: %w", t.Kind, t.DB, err)
		}
		set, err := mssqlReadBackupSet(ctx, conn, t.DB, serverPaths[0])
		if err != nil {
			return nil, fmt.Errorf("reading the backup set of %s: %w", t.DB, err)
		}
		set.Database, set.Type, set.RecoveryModel, set.Reason = t.DB, t.Kind, t.Recovery, t.Reason
		for _, n := range names {
			if err := mssqlCollect(plan.AgentDir, req.SpoolDir, n); err != nil {
				return nil, &PrecheckError{Msg: "picking up the backup file", Err: err,
					Hint: "SQL Server wrote the backup but the agent cannot read it in " + plan.AgentDir + "; check mssql.agent_dir and the directory's permissions"}
			}
			set.Files = append(set.Files, mssqlSpoolDir+"/"+n)
		}
		pending = pending[:len(pending)-len(names)]
		res.MSSQL.BackupSets = append(res.MSSQL.BackupSets, set)
		res.Databases = append(res.Databases, dbspec.DatabaseEntry{Name: t.DB, File: set.Files[0], Format: "mssql-" + t.Kind, DurationMS: time.Since(started).Milliseconds()})
		if t.Reason != "" {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %s backup (%s)", t.DB, t.Kind, t.Reason))
		}
		if w := applyMSSQLSet(state, set, req.RunID, req.Snapshot); w != "" {
			res.Warnings = append(res.Warnings, w)
		}
	}
	res.ConsistentAsOf = time.Now().UTC()
	res.State = &dbspec.JobStateRecord{MSSQL: state}
	res.Restore = mssqlRestore(state, res.MSSQL.BackupSets, req.Snapshot)
	return res, nil
}

// cloneMSSQLState deep-copies the previous chain (or starts an empty one)
func cloneMSSQLState(prev *dbspec.JobState) *dbspec.MSSQLState {
	out := &dbspec.MSSQLState{Databases: map[string]*dbspec.MSSQLDBState{}}
	if prev == nil || prev.LastSuccess == nil || prev.LastSuccess.MSSQL == nil {
		return out
	}
	data, _ := json.Marshal(prev.LastSuccess.MSSQL)
	_ = json.Unmarshal(data, out)
	if out.Databases == nil {
		out.Databases = map[string]*dbspec.MSSQLDBState{}
	}
	return out
}

// applyMSSQLSet records a new backup set in the chain and reports a log chain gap: a
// log backup whose first LSN is not where the previous held one ended means log
// backups in between are not in FallBCK's snapshots.
func applyMSSQLSet(state *dbspec.MSSQLState, set dbspec.MSSQLBackupSet, runID, snapshot string) (warning string) {
	st := state.Databases[set.Database]
	if st == nil {
		st = &dbspec.MSSQLDBState{}
		state.Databases[set.Database] = st
	}
	st.RecoveryModel = set.RecoveryModel
	ref := dbspec.MSSQLBackupRef{RunID: runID, Snapshot: snapshot, Files: set.Files, BackupSetUUID: set.BackupSetUUID, FirstLSN: set.FirstLSN, LastLSN: set.LastLSN, At: time.Now().UTC()}
	switch set.Type {
	case mssqlFull:
		st.LastFull, st.LastDiff, st.Logs = &ref, nil, nil
	case mssqlDiff:
		st.LastDiff, st.Logs = &ref, nil
	case mssqlLog:
		if n := len(st.Logs); n > 0 && st.Logs[n-1].LastLSN != "" && set.FirstLSN != "" && st.Logs[n-1].LastLSN != set.FirstLSN {
			warning = fmt.Sprintf("%s: log chain gap between LSN %s and %s: log backups in between are not in FallBCK's snapshots (taken by another tool, or lost with a failed run); a point-in-time restore past the gap needs a new full or differential backup", set.Database, st.Logs[n-1].LastLSN, set.FirstLSN)
			st.Logs = nil
		}
		st.Logs = append(st.Logs, ref)
	}
	return warning
}

// mssqlRestore renders the restore chain of every database backed up in this run:
// full, newest differential, then the log backups in order
func mssqlRestore(state *dbspec.MSSQLState, sets []dbspec.MSSQLBackupSet, snapshot string) dbspec.Restore {
	seen := map[string]bool{}
	var dbs []string
	for _, s := range sets {
		if !seen[s.Database] {
			seen[s.Database] = true
			dbs = append(dbs, s.Database)
		}
	}
	sort.Strings(dbs)
	from := func(dir string, files []string) string {
		parts := make([]string, len(files))
		for i, f := range files {
			parts[i] = "DISK = " + mssqlNString(dir+"/"+f)
		}
		return strings.Join(parts, ", ")
	}
	snapDir := func(snap string) string {
		return "/var/tmp/fallbck-mssql/" + mssqlUnsafeName.ReplaceAllString(snap, "_")
	}
	var cmds []string
	snaps := map[string]bool{}
	var snapOrder []string
	need := func(snap string) {
		if snap != "" && !snaps[snap] {
			snaps[snap] = true
			snapOrder = append(snapOrder, snap)
		}
	}
	var sqlLines []string
	for _, name := range dbs {
		st := state.Databases[name]
		if st == nil {
			continue
		}
		id := mssqlIdent(name)
		if st.LastFull == nil {
			sqlLines = append(sqlLines, fmt.Sprintf("-- %s: this job holds no full backup; restore the base full from where it was taken WITH NORECOVERY first", id))
		} else {
			need(st.LastFull.Snapshot)
			sqlLines = append(sqlLines, fmt.Sprintf("RESTORE DATABASE %s FROM %s WITH REPLACE, NORECOVERY;", id, from(snapDir(st.LastFull.Snapshot), st.LastFull.Files)))
		}
		if st.LastDiff != nil {
			need(st.LastDiff.Snapshot)
			sqlLines = append(sqlLines, fmt.Sprintf("RESTORE DATABASE %s FROM %s WITH NORECOVERY;", id, from(snapDir(st.LastDiff.Snapshot), st.LastDiff.Files)))
		}
		for _, l := range st.Logs {
			need(l.Snapshot)
			sqlLines = append(sqlLines, fmt.Sprintf("RESTORE LOG %s FROM %s WITH NORECOVERY;", id, from(snapDir(l.Snapshot), l.Files)))
		}
		sqlLines = append(sqlLines, fmt.Sprintf("RESTORE DATABASE %s WITH RECOVERY;", id))
	}
	cmds = append(cmds, "# 1. Fetch the snapshots of the chain onto the SQL Server host (a directory the SQL Server service can read):")
	for _, snap := range snapOrder {
		cmds = append(cmds, fmt.Sprintf("proxmox-backup-client restore %s %s.pxar %s", snap, dbspec.ArchiveName, snapDir(snap)))
	}
	cmds = append(cmds, "# 2. Restore in order (sqlcmd or SSMS); every step but the last keeps the database restoring:")
	cmds = append(cmds, sqlLines...)
	cmds = append(cmds, "# Point in time: add STOPAT = '2026-01-31T12:00:00' to the RESTORE LOG statements; to another name or location add MOVE clauses (RESTORE FILELISTONLY shows the logical file names).")
	_ = snapshot
	return dbspec.Restore{
		Summary:  fmt.Sprintf("SQL Server native backups of %d database(s); the chain per database is full, newest differential, then log backups in LSN order", len(dbs)),
		Commands: cmds,
	}
}
