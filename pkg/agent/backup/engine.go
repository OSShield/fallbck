// Package backup runs filesystem backups from the agent into Proxmox Backup Server
// with gopbs, over a session the FallBCK server opened on the agent's behalf.
package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/db"
	fbpbs "github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
	"github.com/osshield/gopbs/scan"
)

// DefaultArchiveName is used for jobs with more than one backup path
const DefaultArchiveName = "root"

// DirectOptions connects the agent straight to PBS (job setting direct_pbs)
type DirectOptions struct {
	Endpoint    string
	Fingerprint string
	TLSVerify   bool
	// Namespace within the datastore (configured on the target by an administrator);
	// empty means the root namespace
	Namespace string
	// APIToken in canonical user@realm!tokenid:secret form
	APIToken string
}

// Options for one backup run
type Options struct {
	// Session carries the snapshot identity, format and paths from the server
	Session *temporal.BackupSessionInfo
	// Dial returns a connection on which the PBS backup session is already open
	// (proxy.Dial through the FallBCK server). Ignored when Direct is set.
	Dial func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error)
	// Direct, when set, makes gopbs connect to PBS itself with these credentials
	Direct *DirectOptions
	// Workers is the number of concurrent chunk uploads (0 = gopbs default)
	Workers int
	// ArchiveName names the pxar archive inside the snapshot (default: gopbs default)
	ArchiveName string
	// Blobs are small extra files stored in the snapshot as <name>.blob (manifests)
	Blobs []gopbs.Blob
	// OnPhase is told what the engine is doing (opening the session, uploading an
	// archive, finalizing); used for activity heartbeats and failure reporting
	OnPhase func(phase string)
}

// Run executes the backup and maps the outcome to a BackupExecutionResult
func Run(ctx context.Context, opts Options) (*temporal.BackupExecutionResult, error) {
	phase := opts.OnPhase
	if phase == nil {
		phase = func(string) {}
	}
	phase("preparing backup")

	s := opts.Session
	if s == nil {
		return nil, errors.New("backup session is required")
	}
	if opts.Dial == nil && opts.Direct == nil {
		return nil, errors.New("backup session dialer or direct PBS options are required")
	}
	paths, err := db.ValidateBackupPaths(s.BackupPaths)
	if err != nil {
		return nil, err
	}
	s.BackupPaths = paths
	for _, p := range s.BackupPaths {
		if _, err := os.Lstat(p); err != nil {
			return nil, fmt.Errorf("backup path %s: %w", p, err)
		}
	}

	format := gopbs.FormatV1
	if s.PxarFormat == db.PxarFormatV2 {
		format = gopbs.FormatV2
	}
	// A single directory is the archive itself and gopbs names it after the directory;
	// several paths live under a virtual root that needs a name ("root.pxar" by convention),
	// each entry named by ArchiveEntryNames.
	archiveName := opts.ArchiveName
	if archiveName == "" && len(s.BackupPaths) > 1 {
		archiveName = DefaultArchiveName
	}
	ref := pbs.SnapshotRef{Type: s.BackupType, ID: s.BackupID}
	if s.BackupTime > 0 {
		ref.Time = time.Unix(s.BackupTime, 0).UTC()
	}

	start := time.Now()

	// The PBS namespace is server-controlled: in tunnel mode the server opens the
	// session in the target's namespace (gopbs ignores Namespace when DialSession is
	// set), and in direct mode it is delivered from the target via the run's
	// credentials. The agent never sources it from the (client-held) session.
	clientCfg := pbs.Config{
		DialSession: opts.Dial,
		Datastore:   s.Datastore,
		Workers:     opts.Workers,
	}
	namespace := "(server-controlled)"
	if d := opts.Direct; d != nil {
		authID, secret, err := fbpbs.SplitAPIToken(d.APIToken)
		if err != nil {
			return nil, err
		}
		clientCfg.DialSession = nil
		clientCfg.BaseURL = d.Endpoint
		clientCfg.Namespace = d.Namespace
		clientCfg.Auth = pbs.TokenAuth{AuthID: authID, Secret: secret}
		clientCfg.Fingerprint = strings.TrimPrefix(strings.TrimPrefix(d.Fingerprint, "SHA256:"), "sha256:")
		clientCfg.InsecureSkipAll = clientCfg.Fingerprint == "" && !d.TLSVerify
		namespace = d.Namespace
		slog.Info("Connecting to PBS directly", "endpoint", d.Endpoint, "token_id", authID, "namespace", d.Namespace, "fingerprint_pinned", clientCfg.Fingerprint != "", "tls_verify", d.TLSVerify)
	} else {
		slog.Debug("Connecting to PBS through the server tunnel")
	}
	slog.Info("Starting PBS backup", "paths", s.BackupPaths, "format", s.PxarFormat, "backup_id", ref.ID, "datastore", s.Datastore, "namespace", namespace)

	// Exclude patterns use proxmox-backup-client syntax and are recorded in the
	// archive exactly like the official client's --exclude; .pxarexclude files inside
	// the tree are honoured as well, matching proxmox-backup-client.
	// No gopbs OnProgress: setting it would cost a full extra metadata scan of the
	// tree just for progress totals; liveness comes from the caller's phase heartbeats.
	result, err := runBackup(ctx, gopbs.BackupOptions{
		Client: clientCfg,
		Archive: archive.Options{
			Name: archiveName,
			Scan: scan.Options{Exclude: s.ExcludePaths, PxarExcludeFiles: true},
		},
		Blobs:  opts.Blobs,
		Ref:    ref,
		Format: format,
		Paths:  s.BackupPaths,
	}, opts.OnPhase)
	if err != nil {
		return nil, err
	}

	stats := []pbs.UploadStats{result.Archive, result.Payload, result.Catalog}
	var size, chunks, newChunks uint64
	for _, st := range stats {
		size += st.Size
		chunks += st.ChunkCount
		newChunks += st.NewChunks
	}
	// gopbs reports chunk counts, not uploaded bytes: estimate transferred bytes from
	// the share of chunks that were new to the server.
	uploaded := size
	if chunks > 0 {
		uploaded = size * newChunks / chunks
	}
	dedup := 1.0
	if uploaded > 0 {
		dedup = float64(size) / float64(uploaded)
	} else if size > 0 {
		dedup = float64(chunks)
	}
	for _, w := range result.Warnings {
		slog.Warn("Backup warning", "path", w.Path, "message", w.Err)
	}

	snapshot := fmt.Sprintf("%s/%s/%s", result.Ref.Type, result.Ref.ID, result.Ref.Time.UTC().Format("2006-01-02T15:04:05Z"))
	duration := time.Since(start)
	slog.Info("PBS backup completed", "snapshot", snapshot, "archive", result.ArchiveName, "size", size, "chunks", chunks, "new_chunks", newChunks, "duration", duration)

	detail := rundetail.Filesystem{
		Type: rundetail.TypeFilesystem, Format: s.PxarFormat, SnapshotID: snapshot,
		Paths: s.BackupPaths, ExcludePaths: s.ExcludePaths,
		Archives: archiveStats(result),
	}
	for _, w := range result.Warnings {
		detail.Warnings = append(detail.Warnings, rundetail.Warning{Path: w.Path, Message: w.Err.Error()})
	}

	return &temporal.BackupExecutionResult{
		Status:        db.RunStatusCompleted,
		BytesScanned:  int64(size),
		BytesUploaded: int64(uploaded),
		DedupRatio:    dedup,
		ChunkCount:    int(chunks),
		SnapshotID:    snapshot,
		Duration:      duration,
		Details:       rundetail.Marshal(detail),
	}, nil
}

// archiveStats renders each uploaded archive's stats for the run detail page
func archiveStats(result *gopbs.BackupResult) []rundetail.ArchiveStat {
	entries := []struct {
		name, kind string
		st         pbs.UploadStats
	}{
		{result.ArchiveName, "pxar", result.Archive},
		{"payload", "payload", result.Payload},
		{"catalog", "catalog", result.Catalog},
	}
	var out []rundetail.ArchiveStat
	for _, e := range entries {
		if e.st.Size == 0 && e.st.ChunkCount == 0 {
			continue
		}
		a := rundetail.ArchiveStat{
			Name: e.name, Kind: e.kind, SizeBytes: e.st.Size,
			Chunks: e.st.ChunkCount, NewChunks: e.st.NewChunks, ReusedChunks: e.st.ReusedChunks,
		}
		if e.st.NewChunks > 0 {
			a.Dedup = float64(e.st.ChunkCount) / float64(e.st.NewChunks)
		}
		out = append(out, a)
	}
	return out
}
