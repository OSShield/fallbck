package dbbackup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

type postgresEngine struct{}

func (postgresEngine) Name() string { return dbspec.EnginePostgres }

// pgToolNames are the tools detected per directory; psql runs the prechecks when the
// tools run as another OS user (peer authentication)
var pgToolNames = []string{"pg_dump", "pg_dumpall", "pg_basebackup", "psql"}

// pgSearchGlobs are the per-major install directories of common distributions
var pgSearchGlobs = []string{
	"/usr/lib/postgresql/*/bin", // Debian/Ubuntu
	"/usr/pgsql-*/bin",          // RHEL PGDG
	"/usr/libexec/postgresql*",  // Alpine
	"/usr/local/pgsql/bin",      // source installs
	"/opt/homebrew/opt/postgresql@*/bin",
	"/usr/local/opt/postgresql@*/bin",
}

const pgInstallHint = "install the PostgreSQL client tools (Debian: postgresql-client-NN, Alpine: postgresqlNN-client, RHEL: postgresqlNN) or set db_backup.tools.postgres_bindir"

func pgBinary(ctx context.Context, r Runner, name, path string) (Binary, error) {
	line, err := version(ctx, r, name, path)
	if err != nil {
		return Binary{}, err
	}
	major, minor, ok := parsePGVersion(line)
	if !ok {
		return Binary{}, fmt.Errorf("%s: unrecognised version output %q", path, line)
	}
	return Binary{Path: path, Version: fmt.Sprintf("%d.%d", major, minor), Major: major, Minor: minor}, nil
}

// pgToolSet detects the PostgreSQL tools in one directory (pg_dump is required)
func pgToolSet(ctx context.Context, r Runner, dir string) (map[string]Binary, error) {
	set := map[string]Binary{}
	for _, name := range pgToolNames {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		b, err := pgBinary(ctx, r, name, path)
		if err != nil {
			return nil, err
		}
		set[name] = b
	}
	if _, ok := set["pg_dump"]; !ok {
		return nil, fmt.Errorf("no pg_dump in %s", dir)
	}
	return set, nil
}

func (postgresEngine) Detect(ctx context.Context, r Runner, tools dbspec.ToolConfig) (ToolInfo, error) {
	info := ToolInfo{Binaries: map[string]Binary{}}
	if tools.PostgresBinDir != "" {
		set, err := pgToolSet(ctx, r, tools.PostgresBinDir)
		if err != nil {
			return info, precheckf("check db_backup.tools.postgres_bindir", "postgres tools: %v", err)
		}
		info.Binaries = set
		return info, nil
	}
	for _, name := range pgToolNames {
		path, err := r.LookPath(name)
		if err != nil {
			continue
		}
		b, err := pgBinary(ctx, r, name, path)
		if err != nil {
			return info, err
		}
		info.Binaries[name] = b
	}
	// Alternatives are deduplicated by the real pg_dump binary (distributions symlink
	// the default major into PATH and unversioned directories)
	seen := map[string]bool{}
	realPath := func(p string) string {
		if real, err := filepath.EvalSymlinks(p); err == nil {
			return real
		}
		return p
	}
	if pd, ok := info.Binaries["pg_dump"]; ok {
		seen[realPath(pd.Path)] = true
	}
	for _, g := range pgSearchGlobs {
		dirs, _ := filepath.Glob(g)
		sort.Strings(dirs)
		for _, dir := range dirs {
			real := realPath(filepath.Join(dir, "pg_dump"))
			if seen[real] {
				continue
			}
			set, err := pgToolSet(ctx, r, dir)
			if err != nil {
				continue
			}
			seen[real] = true
			info.Alternatives = append(info.Alternatives, set)
		}
	}
	if len(info.Binaries) == 0 && len(info.Alternatives) == 0 {
		return info, precheckf(pgInstallHint, "pg_dump not found")
	}
	return info, nil
}

// selectPGTools picks the tool set for a server major: PATH if new enough, else the
// smallest installed major that is
func selectPGTools(info ToolInfo, serverMajor int) (map[string]Binary, error) {
	if pd, ok := info.Binaries["pg_dump"]; ok && pd.Major >= serverMajor {
		return info.Binaries, nil
	}
	var best map[string]Binary
	for _, alt := range info.Alternatives {
		pd := alt["pg_dump"]
		if pd.Major < serverMajor {
			continue
		}
		if best == nil || pd.Major < best["pg_dump"].Major {
			best = alt
		}
	}
	if best != nil {
		return best, nil
	}
	found := "none"
	if pd, ok := info.Binaries["pg_dump"]; ok {
		found = pd.Version
	}
	return nil, precheckf(pgInstallHint, "pg_dump %s cannot back up a PostgreSQL %d server (a pg_dump of major %d or newer is required)", found, serverMajor, serverMajor)
}

func pgMode(spec *dbspec.Spec) (dump, base bool) {
	switch spec.Postgres.Mode {
	case dbspec.PostgresModeBasebackup:
		return false, true
	case dbspec.PostgresModeBoth:
		return true, true
	}
	return true, false
}

// pgOpen connects for the checks: in-process (pgx) normally, through psql running as
// the run's OS user when the tools run as one (peer authentication is decided by the
// OS user on the socket, which the agent itself is not)
func pgOpen(ctx context.Context, req *DumpRequest) (querier, error) {
	if req.Creds.RunAs == "" {
		return pgConnect(ctx, req.Creds)
	}
	psql, ok := req.Tools.Binaries["psql"]
	for _, alt := range req.Tools.Alternatives {
		if ok {
			break
		}
		psql, ok = alt["psql"]
	}
	if !ok {
		return nil, precheckf(pgInstallHint, "psql not found (needed to run the checks as OS user %s)", req.Creds.RunAs)
	}
	env, err := pgEnv(req)
	if err != nil {
		return nil, err
	}
	return psqlQuerier{path: psql.Path, env: env, runAs: req.Creds.RunAs, runner: req.Runner}, nil
}

// runToFile runs a tool with its stdout on a file the agent opens itself, so a tool
// running as another OS user needs no write access to the spool
func runToFile(ctx context.Context, req *DumpRequest, c Command, path string) (Result, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return Result{}, err
	}
	c.Stdout, c.RunAs = f, req.Creds.RunAs
	r, err := req.Runner.Run(ctx, c)
	if cerr := f.Close(); err == nil && cerr != nil {
		err = cerr
	}
	return r, err
}

func (postgresEngine) Precheck(ctx context.Context, req *DumpRequest) (ServerInfo, error) {
	var info ServerInfo
	q, err := pgOpen(ctx, req)
	if err != nil {
		if IsPrecheck(err) {
			return info, err
		}
		return info, &PrecheckError{Msg: fmt.Sprintf("connecting to PostgreSQL at %s:%d as %s", req.Creds.Host, req.Creds.Port, req.Creds.User), Err: err, Hint: "check host, port, credentials, pg_hba.conf and TLS settings"}
	}
	defer q.close()

	var vnum int
	var vstr string
	if err := q.queryRow(ctx, "SELECT current_setting('server_version_num')::int, current_setting('server_version')", &vnum, &vstr); err != nil {
		return info, fmt.Errorf("reading server version: %w", err)
	}
	info.VersionNum = vnum
	info.Version = strings.Fields(vstr + " ")[0]
	serverMajor := vnum / 10000

	set, err := selectPGTools(req.Tools, serverMajor)
	if err != nil {
		return info, err
	}
	req.Tools.Binaries = set

	var super, repl bool
	if err := q.queryRow(ctx, "SELECT rolsuper, rolreplication FROM pg_roles WHERE rolname = current_user", &super, &repl); err != nil {
		return info, fmt.Errorf("reading role attributes: %w", err)
	}
	info.Superuser = super
	if err := q.queryRow(ctx, "SELECT pg_is_in_recovery()", &info.IsReplica); err != nil {
		return info, fmt.Errorf("reading recovery state: %w", err)
	}

	doDump, doBase := pgMode(req.Spec)
	opts := req.Spec.Postgres
	if doDump {
		if _, ok := set["pg_dump"]; !ok {
			return info, precheckf(pgInstallHint, "pg_dump not found")
		}
		if dbspec.Bool(opts.Globals, true) {
			if _, ok := set["pg_dumpall"]; !ok {
				return info, precheckf(pgInstallHint, "pg_dumpall not found (needed for postgres.globals)")
			}
			if opts.RolePasswords == "include" && !super {
				return info, precheckf("use a superuser or set postgres.role_passwords to auto/omit", "role passwords can only be dumped by a superuser")
			}
		}
	}
	if doBase {
		if _, ok := set["pg_basebackup"]; !ok {
			return info, precheckf(pgInstallHint, "pg_basebackup not found (needed for postgres.mode %s)", opts.Mode)
		}
		if !super && !repl {
			return info, precheckf("ALTER ROLE <user> REPLICATION, and allow replication connections in pg_hba.conf", "role %s lacks the REPLICATION attribute required by pg_basebackup", req.Creds.User)
		}
		var walLevel string
		var senders int
		if err := q.queryRow(ctx, "SELECT current_setting('wal_level'), current_setting('max_wal_senders')::int", &walLevel, &senders); err == nil {
			if walLevel != "replica" && walLevel != "logical" {
				return info, precheckf("set wal_level = replica (or logical) on the server", "wal_level is %q; pg_basebackup requires replica or logical", walLevel)
			}
			if senders < 2 {
				return info, precheckf("set max_wal_senders >= 2 on the server", "max_wal_senders is %d; --wal-method=stream needs two", senders)
			}
		}
	}

	rows, err := q.queryRows(ctx, "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname")
	if err != nil {
		return info, fmt.Errorf("listing databases: %w", err)
	}
	existing := map[string]bool{}
	var all []string
	for _, r := range rows {
		if len(r) > 0 {
			existing[r[0]] = true
			all = append(all, r[0])
		}
	}
	if doDump {
		var list []string
		if len(req.Spec.Databases) > 0 {
			for _, name := range req.Spec.Databases {
				if !existing[name] {
					return info, precheckf("check the database list", "database %q does not exist on the server", name)
				}
				list = append(list, name)
			}
		} else {
			excl := map[string]bool{}
			for _, e := range req.Spec.ExcludeDatabases {
				excl[e] = true
			}
			for _, name := range all {
				if !excl[name] {
					list = append(list, name)
				}
			}
		}
		if len(list) == 0 {
			return info, precheckf("", "no databases to dump")
		}
		req.Databases = list
	}

	var size int64
	if err := q.queryRow(ctx, "SELECT COALESCE(SUM(pg_database_size(datname)), 0)::bigint FROM pg_database WHERE datallowconn AND NOT datistemplate", &size); err != nil {
		info.Notes = append(info.Notes, "database sizes not readable (CONNECT privilege missing?); spool space estimate unknown")
		size = 0
	}
	if doDump {
		info.EstimatedBytes += size
	}
	if doBase {
		info.EstimatedBytes += size
	}
	if !super {
		info.Notes = append(info.Notes, fmt.Sprintf("role %s is not a superuser", req.Creds.User))
	}
	if info.IsReplica {
		info.Notes = append(info.Notes, "server is a standby (in recovery)")
	}
	return info, nil
}

// pgEnv builds the libpq environment; the password travels via PGPASSFILE
func pgEnv(req *DumpRequest) ([]string, error) {
	c := req.Creds
	env := append(baseEnv(),
		"PGHOST="+c.Host,
		fmt.Sprintf("PGPORT=%d", c.Port),
		"PGUSER="+c.User,
		"PGCONNECT_TIMEOUT=15",
		"PGAPPNAME=fallbck-agent",
	)
	if c.TLS.Mode != "" {
		env = append(env, "PGSSLMODE="+c.TLS.Mode)
	}
	if c.TLS.CAFile != "" {
		env = append(env, "PGSSLROOTCERT="+c.TLS.CAFile)
	}
	if c.TLS.CertFile != "" {
		env = append(env, "PGSSLCERT="+c.TLS.CertFile)
	}
	if c.TLS.KeyFile != "" {
		env = append(env, "PGSSLKEY="+c.TLS.KeyFile)
	}
	if c.Password != "" {
		esc := strings.NewReplacer(`\`, `\\`, `:`, `\:`)
		path, err := writeSecret(req.SecretDir, "pgpass", "*:*:*:"+esc.Replace(c.User)+":"+esc.Replace(c.Password)+"\n")
		if err != nil {
			return nil, err
		}
		env = append(env, "PGPASSFILE="+path)
	}
	return env, nil
}

var (
	pgWALStartRe = regexp.MustCompile(`write-ahead log start point: ([0-9A-Fa-f]+/[0-9A-Fa-f]+) on timeline (\d+)`)
	pgWALEndRe   = regexp.MustCompile(`write-ahead log end point: ([0-9A-Fa-f]+/[0-9A-Fa-f]+)`)
	pgLSNRe      = regexp.MustCompile(`^[0-9A-Fa-f]+/[0-9A-Fa-f]+$`)
)

func pgWarnings(stderr string) []string {
	var out []string
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(strings.ToLower(line), "warning") {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}

func (postgresEngine) Dump(ctx context.Context, req *DumpRequest) (*EngineResult, error) {
	opts := req.Spec.Postgres
	tools := req.Tools.Binaries
	env, err := pgEnv(req)
	if err != nil {
		return nil, err
	}
	doDump, doBase := pgMode(req.Spec)
	gzip := req.Spec.Compression == dbspec.CompressionGzip
	res := &EngineResult{Postgres: &dbspec.PostgresManifest{Mode: opts.Mode}}
	pgDir := filepath.Join(req.SpoolDir, "postgres")
	restore := []string{}

	if doDump {
		dumpDir := filepath.Join(pgDir, "dumps")
		if err := os.MkdirAll(dumpDir, 0o700); err != nil {
			return nil, err
		}
		if dbspec.Bool(opts.Globals, true) {
			req.progress("dump", "globals")
			file := filepath.Join(pgDir, "globals.sql")
			args := []string{"--globals-only", "--no-password"}
			includePw := opts.RolePasswords == "include" || (opts.RolePasswords == "auto" && req.Server.Superuser)
			if !includePw {
				args = append(args, "--no-role-passwords")
			}
			r, err := runToFile(ctx, req, Command{Name: "pg_dumpall", Path: tools["pg_dumpall"].Path, Args: args, Env: env}, file)
			if err != nil {
				return nil, err
			}
			res.Warnings = append(res.Warnings, pgWarnings(r.Stderr)...)
			res.Postgres.Globals = &dbspec.PostgresGlobals{File: "postgres/globals.sql", RolePasswordsIncluded: includePw}
			restore = append(restore, "psql --dbname=postgres --file=postgres/globals.sql")
		}
		used := map[string]bool{}
		for _, name := range req.Databases {
			req.progress("dump", name)
			ext, format := ".dump", "custom"
			if opts.Format == "plain" {
				ext, format = ".sql", "plain"
			}
			file := filepath.Join(dumpDir, sanitizeName(name, used)+ext)
			args := []string{"--format=" + format, "--no-password"}
			if format == "custom" {
				if gzip {
					args = append(args, "--compress=6")
				} else {
					args = append(args, "--compress=0")
				}
			}
			args = append(args, opts.ExtraDumpArgs...)
			args = append(args, "--dbname="+name)
			start := time.Now()
			r, err := runToFile(ctx, req, Command{Name: "pg_dump", Path: tools["pg_dump"].Path, Args: args, Env: env}, file)
			if err != nil {
				return nil, fmt.Errorf("dumping database %s: %w", name, err)
			}
			res.Warnings = append(res.Warnings, pgWarnings(r.Stderr)...)
			rel, _ := filepath.Rel(req.SpoolDir, file)
			res.Databases = append(res.Databases, dbspec.DatabaseEntry{Name: name, File: filepath.ToSlash(rel), Format: format, DurationMS: time.Since(start).Milliseconds()})
			if format == "custom" {
				restore = append(restore, fmt.Sprintf("pg_restore --create --clean --if-exists --dbname=postgres --jobs=4 %s", filepath.ToSlash(rel)))
			} else {
				restore = append(restore, fmt.Sprintf("psql --dbname=postgres --file=%s", filepath.ToSlash(rel)))
			}
		}
		res.ConsistentAsOf = time.Now().UTC()
		if len(req.Databases) > 1 {
			res.Notes = append(res.Notes, "each database dump is its own consistent snapshot (dumped sequentially)")
		}
		if q, err := pgOpen(ctx, req); err == nil {
			var lsn string
			fn := "pg_current_wal_lsn()"
			if req.Server.IsReplica {
				fn = "pg_last_wal_replay_lsn()"
			}
			if err := q.queryRow(ctx, "SELECT "+fn+"::text", &lsn); err == nil {
				res.Postgres.WALLSN = lsn
			}
			q.close()
		}
	}

	if doBase {
		req.progress("basebackup", "")
		baseDir := filepath.Join(pgDir, "base")
		if req.Creds.RunAs != "" {
			// pg_basebackup creates and writes the directory itself
			if err := prepareDirFor(pgDir, req.Creds.RunAs); err != nil {
				return nil, err
			}
		} else if err := os.MkdirAll(pgDir, 0o700); err != nil {
			return nil, err
		}
		bb := tools["pg_basebackup"]
		args := []string{"--pgdata=" + baseDir, "--format=tar", "--wal-method=stream", "--checkpoint=fast", "--label=" + req.Label, "--no-password", "--verbose"}
		if gzip {
			args = append(args, "--gzip")
		}
		if bb.Major >= 13 {
			args = append(args, "--manifest-checksums=sha256")
		}
		r, err := req.Runner.Run(ctx, Command{Name: "pg_basebackup", Path: bb.Path, Args: args, Env: env, RunAs: req.Creds.RunAs})
		if err != nil {
			return nil, err
		}
		entries, _ := os.ReadDir(baseDir)
		var files []string
		for _, e := range entries {
			files = append(files, e.Name())
		}
		sort.Strings(files)
		compression := dbspec.CompressionNone
		if gzip {
			compression = dbspec.CompressionGzip
		}
		bm := &dbspec.PostgresBasebackup{Dir: "postgres/base", Files: files, Label: req.Label, Compression: compression}
		if m := pgWALStartRe.FindStringSubmatch(r.Stderr); m != nil {
			bm.WALStartLSN = m[1]
			bm.Timeline = int64(atoi(m[2]))
			bm.WALSource = "pg_basebackup"
		}
		if m := pgWALEndRe.FindStringSubmatch(r.Stderr); m != nil {
			bm.WALEndLSN = m[1]
		}
		if q, err := pgOpen(ctx, req); err == nil {
			if bm.Timeline == 0 {
				var tl int64
				if err := q.queryRow(ctx, "SELECT timeline_id FROM pg_control_checkpoint()", &tl); err == nil {
					bm.Timeline = tl
				}
			}
			if bm.WALEndLSN == "" {
				var lsn string
				if err := q.queryRow(ctx, "SELECT pg_current_wal_lsn()::text", &lsn); err == nil {
					bm.WALEndLSN, bm.WALSource = lsn, "pg_current_wal_lsn"
				}
			}
			for lsn, dst := range map[string]*string{bm.WALStartLSN: &bm.WALStartFile, bm.WALEndLSN: &bm.WALEndFile} {
				if pgLSNRe.MatchString(lsn) {
					var f string
					if err := q.queryRow(ctx, "SELECT pg_walfile_name("+quoteLiteral(lsn)+"::pg_lsn)", &f); err == nil {
						*dst = f
					}
				}
			}
			q.close()
		}
		res.Postgres.Basebackup = bm
		res.ConsistentAsOf = time.Now().UTC()
		if res.State == nil {
			res.State = &dbspec.JobStateRecord{}
		}
		res.State.Postgres = &dbspec.PostgresState{WALEndLSN: bm.WALEndLSN, Timeline: bm.Timeline}
		tarFlag := "-xf"
		suffix := ".tar"
		if gzip {
			tarFlag, suffix = "-xzf", ".tar.gz"
		}
		restore = append(restore,
			"# physical restore (same PostgreSQL major, as the postgres user, into an empty data directory)",
			fmt.Sprintf("tar %s postgres/base/base%s -C $PGDATA", tarFlag, suffix),
			fmt.Sprintf("mkdir -p $PGDATA/pg_wal && tar %s postgres/base/pg_wal%s -C $PGDATA/pg_wal", tarFlag, suffix),
			"# extract each postgres/base/<oid>.tar into the tablespace path listed in $PGDATA/tablespace_map",
			"# for point-in-time recovery beyond wal_end_lsn: touch $PGDATA/recovery.signal and set restore_command/recovery_target_time in postgresql.auto.conf",
			"pg_ctl -D $PGDATA start",
		)
	}

	res.Restore = dbspec.Restore{
		Summary:  fmt.Sprintf("PostgreSQL %s backup (mode %s) of %s:%d taken %s", req.Server.Version, opts.Mode, req.Creds.Host, req.Creds.Port, res.ConsistentAsOf.Format(time.RFC3339)),
		Commands: restore,
	}
	return res, nil
}
