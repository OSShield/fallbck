// Package dbbackup executes database backups on fallbck-agent (and, through the
// db-worker mode, inside kubernetes dump pods): it detects the
// client tools, checks the server, dumps into a spool directory, writes the manifest
// and hands the spool to the pxar upload engine.
package dbbackup

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// Binary is a detected client tool
type Binary struct {
	Path    string
	Version string
	Major   int
	Minor   int
	Patch   int
	// Flavor distinguishes mysql/mariadb tools
	Flavor string
}

func (b Binary) String() string {
	if b.Path == "" {
		return "(missing)"
	}
	return fmt.Sprintf("%s (%s)", b.Path, b.Version)
}

// ToolInfo is the result of Engine.Detect
type ToolInfo struct {
	// Binaries by logical name (pg_dump, pg_dumpall, pg_basebackup; dump, binlog; mongodump)
	Binaries map[string]Binary
	// Alternatives are complete tool sets found in other well-known directories
	// (several PostgreSQL majors installed side by side); Precheck may switch to one
	Alternatives []map[string]Binary
}

// Manifest converts the detected tools for the manifest
func (t ToolInfo) Manifest() map[string]dbspec.Tool {
	out := map[string]dbspec.Tool{}
	for name, b := range t.Binaries {
		out[name] = dbspec.Tool{Path: b.Path, Version: b.Version}
	}
	return out
}

// ServerInfo is the result of Engine.Precheck
type ServerInfo struct {
	Version    string
	VersionNum int
	Flavor     string
	IsReplica  bool
	// EstimatedBytes of the dump (0 = unknown)
	EstimatedBytes int64
	// Superuser reports whether the backup role is a superuser (PostgreSQL)
	Superuser bool
	// Attrs carries engine-specific server facts needed by Dump (binlog state, gtid mode)
	Attrs map[string]string
	Notes []string
}

// Progress is reported while a run executes
type Progress struct {
	// Phase: detect, precheck, dump, basebackup, binlog, manifest, upload
	Phase string
	// Current names the database/file being processed
	Current      string
	BytesInSpool int64
}

// Describe renders the progress for heartbeats
func (p Progress) Describe() string {
	if p.Current == "" {
		return p.Phase
	}
	return p.Phase + ": " + p.Current
}

// ProgressFunc receives progress updates
type ProgressFunc func(Progress)

// DumpRequest carries everything an engine needs for one run
type DumpRequest struct {
	RunID string
	JobID string
	Label string
	Spec  *dbspec.Spec
	Creds dbspec.Credentials
	Tools ToolInfo
	// Server is filled by Precheck
	Server ServerInfo
	// Databases is the resolved list to dump (filled by Precheck; nil = all-in-one dump)
	Databases []string
	// SpoolDir exists and is empty on entry; SecretDir (0700) holds credential files
	SpoolDir  string
	SecretDir string
	// PrevState is the last successful run's state (nil on the first run)
	PrevState *dbspec.JobState
	Progress  ProgressFunc
	Runner    Runner
}

func (r *DumpRequest) progress(phase, current string) {
	if r.Progress != nil {
		r.Progress(Progress{Phase: phase, Current: current})
	}
}

// EngineResult is the engine-specific outcome of Dump
type EngineResult struct {
	ConsistentAsOf time.Time
	Databases      []dbspec.DatabaseEntry
	Warnings       []string
	Notes          []string
	Postgres       *dbspec.PostgresManifest
	MySQL          *dbspec.MySQLManifest
	MongoDB        *dbspec.MongoManifest
	Restore        dbspec.Restore
	// State is the engine part of the job state saved after a successful upload
	State *dbspec.JobStateRecord
}

// Engine is one database family
type Engine interface {
	Name() string
	// Detect finds the client binaries and their versions; it never contacts a server
	Detect(ctx context.Context, r Runner, tools dbspec.ToolConfig) (ToolInfo, error)
	// Precheck connects to the server and verifies versions, privileges and options
	// the dump would otherwise fail on late; configuration problems are *PrecheckError
	Precheck(ctx context.Context, req *DumpRequest) (ServerInfo, error)
	// Dump writes everything for this run under req.SpoolDir
	Dump(ctx context.Context, req *DumpRequest) (*EngineResult, error)
}

// PrecheckError is a configuration or environment problem that a retry will not fix
type PrecheckError struct {
	Msg  string
	Hint string
	Err  error
}

func (e *PrecheckError) Error() string {
	msg := e.Msg
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

func (e *PrecheckError) Unwrap() error { return e.Err }

func precheckf(hint, format string, args ...any) error {
	return &PrecheckError{Msg: fmt.Sprintf(format, args...), Hint: hint}
}

// IsPrecheck reports whether err is (or wraps) a PrecheckError
func IsPrecheck(err error) bool {
	var pe *PrecheckError
	return errors.As(err, &pe)
}

var engines = map[string]Engine{
	dbspec.EnginePostgres: postgresEngine{},
	dbspec.EngineMySQL:    mysqlEngine{},
	dbspec.EngineMongoDB:  mongoEngine{},
}

// Lookup returns the engine for a canonical engine name
func Lookup(name string) (Engine, bool) {
	e, ok := engines[name]
	return e, ok
}

// DetectResult is one line of `fallbck-agent tools`
type DetectResult struct {
	Engine string
	Tools  ToolInfo
	Err    error
}

// DetectAll runs Detect for every engine (diagnostics)
func DetectAll(ctx context.Context, r Runner, tools dbspec.ToolConfig) []DetectResult {
	names := make([]string, 0, len(engines))
	for n := range engines {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []DetectResult
	for _, n := range names {
		info, err := engines[n].Detect(ctx, r, tools)
		out = append(out, DetectResult{Engine: n, Tools: info, Err: err})
	}
	return out
}

// Format renders a DetectResult for humans
func (d DetectResult) Format() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s:\n", d.Engine)
	if d.Err != nil {
		fmt.Fprintf(&b, "  error: %v\n", d.Err)
	}
	names := make([]string, 0, len(d.Tools.Binaries))
	for n := range d.Tools.Binaries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "  %-14s %s\n", n, d.Tools.Binaries[n])
	}
	for _, alt := range d.Tools.Alternatives {
		if pg, ok := alt["pg_dump"]; ok {
			fmt.Fprintf(&b, "  alternative    %s\n", pg)
		}
	}
	return b.String()
}
