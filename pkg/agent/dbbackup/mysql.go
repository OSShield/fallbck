package dbbackup

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

type mysqlEngine struct{}

func (mysqlEngine) Name() string { return dbspec.EngineMySQL }

const mysqlInstallHint = "install the MySQL/MariaDB client tools (Debian: mariadb-client or mysql-client, Alpine: mariadb-client, RHEL: mariadb or mysql) or set db_backup.tools.mysql_bindir"

// mysqlToolNames lists the candidates per logical tool, preferred first
var mysqlToolNames = map[string][]string{
	"dump":   {"mariadb-dump", "mysqldump"},
	"binlog": {"mariadb-binlog", "mysqlbinlog"},
	"client": {"mariadb", "mysql"},
}

var mysqlSystemSchemas = map[string]bool{"information_schema": true, "performance_schema": true, "sys": true, "mysql": true}

func (mysqlEngine) Detect(ctx context.Context, r Runner, tools dbspec.ToolConfig) (ToolInfo, error) {
	info := ToolInfo{Binaries: map[string]Binary{}}
	for logical, names := range mysqlToolNames {
		for _, name := range names {
			var path string
			if tools.MySQLBinDir != "" {
				p := filepath.Join(tools.MySQLBinDir, name)
				if _, err := os.Stat(p); err != nil {
					continue
				}
				path = p
			} else {
				p, err := r.LookPath(name)
				if err != nil {
					continue
				}
				path = p
			}
			line, err := version(ctx, r, name, path)
			if err != nil {
				return info, err
			}
			b, ok := parseMySQLVersion(line)
			if !ok {
				return info, fmt.Errorf("%s: unrecognised version output %q", path, line)
			}
			b.Path = path
			info.Binaries[logical] = b
			break
		}
	}
	if _, ok := info.Binaries["dump"]; !ok {
		return info, precheckf(mysqlInstallHint, "mysqldump/mariadb-dump not found")
	}
	return info, nil
}

func (mysqlEngine) Precheck(ctx context.Context, req *DumpRequest) (ServerInfo, error) {
	info := ServerInfo{Attrs: map[string]string{}}
	opts := req.Spec.MySQL
	q, err := mysqlConnect(ctx, req.Creds)
	if err != nil {
		return info, &PrecheckError{Msg: fmt.Sprintf("connecting to MySQL at %s:%d as %s", req.Creds.Host, req.Creds.Port, req.Creds.User), Err: err, Hint: "check host, port, credentials and TLS settings"}
	}
	defer q.close()

	var ver string
	if err := q.queryRow(ctx, "SELECT VERSION()", &ver); err != nil {
		return info, fmt.Errorf("reading server version: %w", err)
	}
	info.Version = ver
	maj, min, pat := parseServerVersion(ver)
	info.VersionNum = versionNum(maj, min, pat)
	info.Flavor = "mysql"
	if strings.Contains(strings.ToLower(ver), "mariadb") {
		info.Flavor = "mariadb"
	}
	if tool := req.Tools.Binaries["dump"]; tool.Flavor != info.Flavor {
		info.Notes = append(info.Notes, fmt.Sprintf("dump tool is %s %s but the server is %s %s", tool.Flavor, tool.Version, info.Flavor, ver))
	}

	var logBin string
	_ = q.queryRow(ctx, "SELECT @@log_bin", &logBin)
	info.Attrs["log_bin"] = logBin
	if opts.IncludeBinlogs {
		if logBin != "1" && strings.ToUpper(logBin) != "ON" {
			return info, precheckf("enable log_bin on the server or disable mysql.include_binlogs", "binary logging is not enabled on the server")
		}
		if _, ok := req.Tools.Binaries["binlog"]; !ok {
			return info, precheckf(mysqlInstallHint, "mysqlbinlog/mariadb-binlog not found (needed for mysql.include_binlogs)")
		}
	}
	var serverID string
	_ = q.queryRow(ctx, "SELECT @@server_id", &serverID)
	info.Attrs["server_id"] = serverID
	if info.Flavor == "mysql" {
		var uuid, gtidMode string
		_ = q.queryRow(ctx, "SELECT @@server_uuid", &uuid)
		_ = q.queryRow(ctx, "SELECT @@gtid_mode", &gtidMode)
		info.Attrs["server_uuid"] = uuid
		info.Attrs["gtid_mode"] = gtidMode
	} else {
		var pos string
		_ = q.queryRow(ctx, "SELECT @@gtid_current_pos", &pos)
		info.Attrs["gtid_current_pos"] = pos
	}

	rows, err := q.queryRows(ctx, "SHOW DATABASES")
	if err != nil {
		return info, fmt.Errorf("listing databases: %w", err)
	}
	existing := map[string]bool{}
	var user []string
	for _, r := range rows {
		if len(r) == 0 {
			continue
		}
		existing[r[0]] = true
		if !mysqlSystemSchemas[r[0]] {
			user = append(user, r[0])
		}
	}
	if len(req.Spec.Databases) > 0 {
		var list []string
		for _, name := range req.Spec.Databases {
			if !existing[name] {
				return info, precheckf("check the database list", "database %q does not exist on the server", name)
			}
			list = append(list, name)
		}
		if opts.IncludeSystemSchemas && existing["mysql"] {
			list = append(list, "mysql")
		}
		req.Databases = list
	} else if len(req.Spec.ExcludeDatabases) > 0 {
		excl := map[string]bool{}
		for _, e := range req.Spec.ExcludeDatabases {
			excl[e] = true
		}
		var list []string
		for _, name := range user {
			if !excl[name] {
				list = append(list, name)
			}
		}
		if existing["mysql"] && !excl["mysql"] {
			list = append(list, "mysql")
		}
		req.Databases = list
	} else {
		req.Databases = nil // --all-databases
	}

	var size int64
	if err := q.queryRow(ctx, "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.TABLES WHERE table_schema NOT IN ('information_schema','performance_schema','sys')", &size); err == nil {
		info.EstimatedBytes = size
	} else {
		info.Notes = append(info.Notes, "table sizes not readable; spool space estimate unknown")
	}
	var nonTx int
	if err := q.queryRow(ctx, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_TYPE = 'BASE TABLE' AND ENGINE IS NOT NULL AND ENGINE <> 'InnoDB' AND table_schema NOT IN ('information_schema','performance_schema','sys','mysql')", &nonTx); err == nil {
		info.Attrs["non_transactional_tables"] = fmt.Sprint(nonTx)
		if nonTx > 0 && dbspec.Bool(opts.SingleTransaction, true) {
			info.Notes = append(info.Notes, fmt.Sprintf("%d non-InnoDB tables are not covered by --single-transaction consistency", nonTx))
		}
	}
	return info, nil
}

// mysqlSecretFile writes the --defaults-extra-file with the credentials
func mysqlSecretFile(req *DumpRequest) (string, error) {
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	content := "[client]\nuser=" + req.Creds.User + "\n"
	if req.Creds.Password != "" {
		content += "password=\"" + esc.Replace(req.Creds.Password) + "\"\n"
	}
	return writeSecret(req.SecretDir, "my.cnf", content)
}

// mysqlConnArgs are the non-secret connection arguments; defaults file must be first
func mysqlConnArgs(req *DumpRequest, secret string) []string {
	args := []string{"--defaults-extra-file=" + secret}
	c := req.Creds
	if strings.HasPrefix(c.Host, "/") {
		args = append(args, "--socket="+c.Host)
	} else {
		args = append(args, "--host="+c.Host, fmt.Sprintf("--port=%d", c.Port), "--protocol=TCP")
	}
	tool := req.Tools.Binaries["dump"]
	switch c.TLS.Mode {
	case "", dbspec.TLSPrefer:
	case dbspec.TLSDisable:
		if tool.Flavor == "mysql" {
			args = append(args, "--ssl-mode=DISABLED")
		} else {
			args = append(args, "--skip-ssl")
		}
	case dbspec.TLSRequire:
		if tool.Flavor == "mysql" {
			args = append(args, "--ssl-mode=REQUIRED")
		} else {
			args = append(args, "--ssl")
		}
	case dbspec.TLSVerifyCA, dbspec.TLSVerifyFull:
		if tool.Flavor == "mysql" {
			mode := "VERIFY_CA"
			if c.TLS.Mode == dbspec.TLSVerifyFull {
				mode = "VERIFY_IDENTITY"
			}
			args = append(args, "--ssl-mode="+mode)
		} else {
			args = append(args, "--ssl", "--ssl-verify-server-cert")
		}
	}
	if c.TLS.CAFile != "" {
		args = append(args, "--ssl-ca="+c.TLS.CAFile)
	}
	if c.TLS.CertFile != "" {
		args = append(args, "--ssl-cert="+c.TLS.CertFile)
	}
	if c.TLS.KeyFile != "" {
		args = append(args, "--ssl-key="+c.TLS.KeyFile)
	}
	return args
}

// mysqlDumpArgs builds the flavor/version-specific dump options (without target/output)
func mysqlDumpArgs(req *DumpRequest) []string {
	opts := req.Spec.MySQL
	tool := req.Tools.Binaries["dump"]
	args := []string{}
	if dbspec.Bool(opts.SingleTransaction, true) {
		args = append(args, "--single-transaction")
	}
	args = append(args, "--quick", "--hex-blob", "--default-character-set=utf8mb4")
	if dbspec.Bool(opts.Routines, true) {
		args = append(args, "--routines")
	}
	if dbspec.Bool(opts.Triggers, true) {
		args = append(args, "--triggers")
	}
	if dbspec.Bool(opts.Events, true) {
		args = append(args, "--events")
	}
	logBin := req.Server.Attrs["log_bin"]
	if logBin == "1" || strings.ToUpper(logBin) == "ON" {
		switch {
		case tool.Flavor == "mysql" && tool.versionAtLeast(8, 0, 26):
			args = append(args, "--source-data=2")
		default:
			args = append(args, "--master-data=2")
		}
		if tool.Flavor == "mariadb" {
			args = append(args, "--gtid")
		}
		if dbspec.Bool(opts.FlushLogs, opts.IncludeBinlogs) {
			args = append(args, "--flush-logs")
		}
	}
	if tool.Flavor == "mysql" {
		args = append(args, "--set-gtid-purged=AUTO", "--no-tablespaces")
	}
	args = append(args, opts.ExtraDumpArgs...)
	return args
}

var (
	mysqlPosRe  = regexp.MustCompile(`CHANGE (?:MASTER TO MASTER_LOG_FILE|REPLICATION SOURCE TO SOURCE_LOG_FILE)='([^']+)',\s*(?:MASTER_LOG_POS|SOURCE_LOG_POS)=(\d+)`)
	mariaGTIDRe = regexp.MustCompile(`SET GLOBAL gtid_slave_pos='([^']*)'`)
	mysqlGTIDRe = regexp.MustCompile(`GTID_PURGED=(?:/\*[^*]*\*/\s*)?'([^']*)'`)
)

// parseDumpHeader reads the binlog position recorded at the top of a dump file
func parseDumpHeader(path string) (file string, pos int64, gtid string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	head, _ := io.ReadAll(io.LimitReader(f, 64*1024))
	if m := mysqlPosRe.FindSubmatch(head); m != nil {
		file, pos = string(m[1]), int64(atoi(string(m[2])))
	}
	if m := mariaGTIDRe.FindSubmatch(head); m != nil {
		gtid = string(m[1])
	} else if m := mysqlGTIDRe.FindSubmatch(head); m != nil {
		gtid = strings.TrimSpace(string(m[1]))
	}
	return
}

func (mysqlEngine) Dump(ctx context.Context, req *DumpRequest) (*EngineResult, error) {
	opts := req.Spec.MySQL
	tool := req.Tools.Binaries["dump"]
	secret, err := mysqlSecretFile(req)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(req.SpoolDir, "mysql")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	conn := mysqlConnArgs(req, secret)
	common := mysqlDumpArgs(req)
	all := req.Databases == nil
	man := &dbspec.MySQLManifest{Flavor: req.Server.Flavor, AllDatabases: all, SingleTransaction: dbspec.Bool(opts.SingleTransaction, true), FlushLogs: dbspec.Bool(opts.FlushLogs, opts.IncludeBinlogs), NonTransactionalTables: atoi(req.Server.Attrs["non_transactional_tables"])}
	res := &EngineResult{MySQL: man}
	client := "mysql"
	if tool.Flavor == "mariadb" {
		client = "mariadb"
	}
	restore := []string{"# restore with the same flavor's client; the credentials file holds [client] user/password"}

	run := func(label, file string, target ...string) error {
		req.progress("dump", label)
		args := append(append(append([]string{}, conn...), common...), "--result-file="+file)
		args = append(args, target...)
		start := time.Now()
		r, err := req.Runner.Run(ctx, Command{Name: filepath.Base(tool.Path), Path: tool.Path, Args: args, Env: baseEnv()})
		if err != nil {
			return err
		}
		for _, line := range strings.Split(r.Stderr, "\n") {
			l := strings.ToLower(line)
			if strings.Contains(l, "warning") && !strings.Contains(l, "deprecated") {
				res.Warnings = append(res.Warnings, strings.TrimSpace(line))
			}
		}
		rel, _ := filepath.Rel(req.SpoolDir, file)
		man.DumpFiles = append(man.DumpFiles, filepath.ToSlash(rel))
		res.Databases = append(res.Databases, dbspec.DatabaseEntry{Name: label, File: filepath.ToSlash(rel), Format: "sql", DurationMS: time.Since(start).Milliseconds()})
		restore = append(restore, fmt.Sprintf("%s --defaults-extra-file=restore.cnf < %s", client, filepath.ToSlash(rel)))
		return nil
	}
	if all {
		if err := run("all-databases", filepath.Join(dir, "all-databases.sql"), "--all-databases"); err != nil {
			return nil, err
		}
	} else {
		used := map[string]bool{}
		for _, name := range req.Databases {
			if err := run(name, filepath.Join(dir, sanitizeName(name, used)+".sql"), "--databases", name); err != nil {
				return nil, fmt.Errorf("dumping database %s: %w", name, err)
			}
		}
		if len(req.Databases) > 1 {
			res.Notes = append(res.Notes, "databases were dumped one at a time; they are not mutually consistent")
		}
	}
	res.ConsistentAsOf = time.Now().UTC()

	// Binlog position from the first dump's header
	logBin := req.Server.Attrs["log_bin"]
	bl := &dbspec.MySQLBinlog{Enabled: logBin == "1" || strings.ToUpper(logBin) == "ON", GTIDMode: req.Server.Attrs["gtid_mode"], ServerID: int64(atoi(req.Server.Attrs["server_id"])), ServerUUID: req.Server.Attrs["server_uuid"]}
	if bl.Enabled && len(man.DumpFiles) > 0 {
		file, pos, gtid := parseDumpHeader(filepath.Join(req.SpoolDir, filepath.FromSlash(man.DumpFiles[0])))
		if file != "" {
			bl.File, bl.Position, bl.GTID, bl.PositionSource = file, pos, gtid, "dump-header"
		}
	}
	man.Binlog = bl
	if bl.Enabled && bl.File != "" {
		res.State = &dbspec.JobStateRecord{MySQL: &dbspec.MySQLState{BinlogFile: bl.File, BinlogPos: bl.Position, GTID: bl.GTID, ServerID: bl.ServerID, ServerUUID: bl.ServerUUID}}
	}

	if opts.IncludeBinlogs && bl.Enabled && bl.File != "" {
		if err := fetchBinlogs(ctx, req, conn, bl, &restore); err != nil {
			return nil, err
		}
	}
	res.Restore = dbspec.Restore{
		Summary:  fmt.Sprintf("%s %s dump of %s:%d taken %s", req.Server.Flavor, req.Server.Version, req.Creds.Host, req.Creds.Port, res.ConsistentAsOf.Format(time.RFC3339)),
		Commands: restore,
	}
	return res, nil
}
