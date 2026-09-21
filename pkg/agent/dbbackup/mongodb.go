package dbbackup

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

type mongoEngine struct{}

func (mongoEngine) Name() string { return dbspec.EngineMongoDB }

const mongoInstallHint = "install MongoDB Database Tools 100.x (Debian/RHEL: mongodb-database-tools from the MongoDB repository, Alpine: mongodb-tools) or set db_backup.tools.mongo_bindir"

func (mongoEngine) Detect(ctx context.Context, r Runner, tools dbspec.ToolConfig) (ToolInfo, error) {
	info := ToolInfo{Binaries: map[string]Binary{}}
	for _, name := range []string{"mongodump", "mongorestore"} {
		var path string
		if tools.MongoBinDir != "" {
			p := filepath.Join(tools.MongoBinDir, name)
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
		b, ok := parseMongoVersion(line)
		if !ok {
			return info, fmt.Errorf("%s: unrecognised version output %q", path, line)
		}
		b.Path = path
		info.Binaries[name] = b
	}
	md, ok := info.Binaries["mongodump"]
	if !ok {
		return info, precheckf(mongoInstallHint, "mongodump not found")
	}
	if md.Major < 100 {
		return info, precheckf(mongoInstallHint, "mongodump %s is too old; Database Tools 100.x are required (--config support)", md.Version)
	}
	return info, nil
}

func (mongoEngine) Precheck(ctx context.Context, req *DumpRequest) (ServerInfo, error) {
	info := ServerInfo{Attrs: map[string]string{}}
	opts := req.Spec.MongoDB
	oplog := dbspec.Bool(opts.Oplog, len(req.Spec.Databases) == 0)
	if oplog && len(req.Spec.Databases) > 0 {
		return info, precheckf("remove the database list or disable mongodb.oplog", "--oplog requires dumping all databases")
	}
	info.Attrs["oplog"] = fmt.Sprint(oplog)
	req.Databases = req.Spec.Databases
	info.Notes = append(info.Notes, "MongoDB server version and size are not queried (no driver); spool space estimate unknown")
	if len(req.Spec.ExcludeDatabases) > 0 {
		info.Notes = append(info.Notes, "exclude_databases is not supported by mongodump and is ignored")
	}
	return info, nil
}

// mongoURI builds the connection URI (credentials percent-encoded)
func mongoURI(req *DumpRequest) (string, error) {
	c := req.Creds
	opts := req.Spec.MongoDB
	u := &url.URL{Scheme: "mongodb", Path: "/"}
	if strings.HasPrefix(c.Host, "/") {
		u.Host = url.PathEscape(c.Host)
	} else {
		u.Host = fmt.Sprintf("%s:%d", c.Host, c.Port)
	}
	if c.User != "" && c.Password != "" {
		u.User = url.UserPassword(c.User, c.Password)
	} else if c.User != "" {
		// Certificate / Kerberos / AWS mechanisms carry no password
		u.User = url.User(c.User)
	}
	q := url.Values{}
	if c.User != "" || opts.AuthMechanism != "" {
		q.Set("authSource", opts.EffAuthSource())
	}
	if opts.AuthMechanism != "" {
		q.Set("authMechanism", opts.AuthMechanism)
	}
	if opts.AuthMechanism == dbspec.MongoAuthX509 {
		if c.TLS.CertFile == "" {
			return "", precheckf("set tls.cert_file (and tls.key_file) on the job or profile", "MONGODB-X509 authenticates with a client certificate")
		}
		switch c.TLS.Mode {
		case dbspec.TLSRequire, dbspec.TLSVerifyCA, dbspec.TLSVerifyFull:
		default:
			return "", precheckf("set tls.mode to require, verify-ca or verify-full", "MONGODB-X509 needs a TLS connection")
		}
	}
	if opts.ReplicaSet != "" {
		q.Set("replicaSet", opts.ReplicaSet)
	}
	if opts.ReadPreference != "" {
		q.Set("readPreference", opts.ReadPreference)
	}
	q.Set("connectTimeoutMS", "15000")
	switch c.TLS.Mode {
	case "", dbspec.TLSDisable, dbspec.TLSPrefer:
	case dbspec.TLSRequire:
		q.Set("tls", "true")
		q.Set("tlsInsecure", "true")
	case dbspec.TLSVerifyCA:
		q.Set("tls", "true")
		q.Set("tlsAllowInvalidHostnames", "true")
	case dbspec.TLSVerifyFull:
		q.Set("tls", "true")
	}
	if c.TLS.CAFile != "" {
		q.Set("tlsCAFile", c.TLS.CAFile)
	}
	if c.TLS.CertFile != "" {
		pem := c.TLS.CertFile
		if c.TLS.KeyFile != "" && c.TLS.KeyFile != c.TLS.CertFile {
			cert, err := os.ReadFile(c.TLS.CertFile)
			if err != nil {
				return "", fmt.Errorf("reading tls.cert_file: %w", err)
			}
			key, err := os.ReadFile(c.TLS.KeyFile)
			if err != nil {
				return "", fmt.Errorf("reading tls.key_file: %w", err)
			}
			p, err := writeSecret(req.SecretDir, "client.pem", string(cert)+"\n"+string(key))
			if err != nil {
				return "", err
			}
			pem = p
		}
		q.Set("tlsCertificateKeyFile", pem)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func yamlQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (mongoEngine) Dump(ctx context.Context, req *DumpRequest) (*EngineResult, error) {
	opts := req.Spec.MongoDB
	tool := req.Tools.Binaries["mongodump"]
	uri, err := mongoURI(req)
	if err != nil {
		return nil, err
	}
	cfgPath, err := writeSecret(req.SecretDir, "mongodump.yaml", "uri: "+yamlQuote(uri)+"\n")
	if err != nil {
		return nil, err
	}
	out := filepath.Join(req.SpoolDir, "mongodb")
	if err := os.MkdirAll(out, 0o700); err != nil {
		return nil, err
	}
	gzip := req.Spec.Compression == dbspec.CompressionGzip
	oplog := req.Server.Attrs["oplog"] == "true"
	common := []string{"--config=" + cfgPath, "--out=" + out}
	if gzip {
		common = append(common, "--gzip")
	}
	if opts.NumParallelCollections > 0 {
		common = append(common, fmt.Sprintf("--numParallelCollections=%d", opts.NumParallelCollections))
	}
	common = append(common, opts.ExtraArgs...)

	res := &EngineResult{MongoDB: &dbspec.MongoManifest{Dir: "mongodb", Oplog: oplog, Gzip: gzip, ReadPreference: opts.ReadPreference, PerDatabase: len(req.Databases) > 0}}
	restoreURI := "mongodb://" + func() string {
		if req.Creds.User != "" {
			return url.PathEscape(req.Creds.User) + "@"
		}
		return ""
	}() + fmt.Sprintf("%s:%d/?authSource=%s", req.Creds.Host, req.Creds.Port, url.QueryEscape(opts.EffAuthSource())) + func() string {
		if opts.AuthMechanism != "" {
			return "&authMechanism=" + opts.AuthMechanism
		}
		return ""
	}()
	gz := ""
	if gzip {
		gz = " --gzip"
	}
	if len(req.Databases) == 0 {
		req.progress("mongodump", "all databases")
		args := append([]string{}, common...)
		if oplog {
			args = append(args, "--oplog")
		}
		start := time.Now()
		if _, err := req.Runner.Run(ctx, Command{Name: "mongodump", Path: tool.Path, Args: args, Env: baseEnv()}); err != nil {
			return nil, err
		}
		entries, _ := os.ReadDir(out)
		for _, e := range entries {
			if e.IsDir() {
				res.MongoDB.Databases = append(res.MongoDB.Databases, e.Name())
				res.Databases = append(res.Databases, dbspec.DatabaseEntry{Name: e.Name(), File: "mongodb/" + e.Name(), Format: "bson", DurationMS: time.Since(start).Milliseconds()})
			}
		}
		if oplog {
			name := "oplog.bson"
			if gzip {
				name += ".gz"
			}
			if fileSize(filepath.Join(out, name)) > 0 || fileExists(filepath.Join(out, name)) {
				res.MongoDB.OplogFile = "mongodb/" + name
			}
			res.Restore.Commands = append(res.Restore.Commands, fmt.Sprintf("mongorestore --uri=%q --oplogReplay%s --drop --dir=mongodb", restoreURI, gz),
				"# point in time within the dump window: add --oplogLimit=<unix-seconds>:<ordinal>")
		} else {
			res.Restore.Commands = append(res.Restore.Commands, fmt.Sprintf("mongorestore --uri=%q%s --drop --dir=mongodb", restoreURI, gz))
		}
	} else {
		for _, name := range req.Databases {
			req.progress("mongodump", name)
			args := append(append([]string{}, common...), "--db="+name, "--dumpDbUsersAndRoles")
			start := time.Now()
			if _, err := req.Runner.Run(ctx, Command{Name: "mongodump", Path: tool.Path, Args: args, Env: baseEnv()}); err != nil {
				return nil, fmt.Errorf("dumping database %s: %w", name, err)
			}
			res.MongoDB.Databases = append(res.MongoDB.Databases, name)
			res.Databases = append(res.Databases, dbspec.DatabaseEntry{Name: name, File: "mongodb/" + name, Format: "bson", DurationMS: time.Since(start).Milliseconds()})
			res.Restore.Commands = append(res.Restore.Commands, fmt.Sprintf("mongorestore --uri=%q%s --drop --nsInclude='%s.*' --dir=mongodb", restoreURI, gz, name))
		}
		if len(req.Databases) > 1 {
			res.Notes = append(res.Notes, "databases were dumped one at a time without the oplog; they are not mutually consistent")
		}
	}
	sort.Strings(res.MongoDB.Databases)
	res.ConsistentAsOf = time.Now().UTC()
	res.Restore.Summary = fmt.Sprintf("mongodump of %s:%d taken %s (oplog: %v)", req.Creds.Host, req.Creds.Port, res.ConsistentAsOf.Format(time.RFC3339), oplog)
	return res, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
