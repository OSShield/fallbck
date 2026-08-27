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
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

// DefaultArchiveName is used for jobs with more than one backup path
const DefaultArchiveName = "root"

// DirectOptions connects the agent straight to PBS (job setting direct_pbs)
type DirectOptions struct {
	Endpoint    string
	Fingerprint string
	TLSVerify   bool
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
	// OnProgress receives upload progress per archive
	OnProgress func(archive string, stats pbs.UploadStats, done bool)
}

// Run executes the backup and maps the outcome to a BackupExecutionResult
func Run(ctx context.Context, opts Options) (*temporal.BackupExecutionResult, error) {
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
	if len(s.ExcludePaths) > 0 {
		slog.Warn("Exclude patterns are not applied yet by the pxar archiver; backing up the full paths", "excludes", s.ExcludePaths)
	}

	format := gopbs.FormatV1
	if s.PxarFormat == db.PxarFormatV2 {
		format = gopbs.FormatV2
	}
	// A single directory is the archive itself and gopbs names it after the directory;
	// several paths live under a virtual root that needs a name ("root.pxar" by convention).
	archiveName := opts.ArchiveName
	if archiveName == "" && len(s.BackupPaths) > 1 {
		archiveName = DefaultArchiveName
	}
	ref := pbs.SnapshotRef{Type: s.BackupType, ID: s.BackupID}
	if s.BackupTime > 0 {
		ref.Time = time.Unix(s.BackupTime, 0).UTC()
	}

	start := time.Now()
	slog.Info("Starting PBS backup", "paths", s.BackupPaths, "format", s.PxarFormat, "backup_id", ref.ID, "datastore", s.Datastore, "namespace", s.Namespace)

	clientCfg := pbs.Config{
		DialSession: opts.Dial,
		Datastore:   s.Datastore,
		Namespace:   s.Namespace,
		Workers:     opts.Workers,
	}
	if d := opts.Direct; d != nil {
		authID, secret, err := fbpbs.SplitAPIToken(d.APIToken)
		if err != nil {
			return nil, err
		}
		clientCfg.DialSession = nil
		clientCfg.BaseURL = d.Endpoint
		clientCfg.Auth = pbs.TokenAuth{AuthID: authID, Secret: secret}
		clientCfg.Fingerprint = strings.TrimPrefix(strings.TrimPrefix(d.Fingerprint, "SHA256:"), "sha256:")
		clientCfg.InsecureSkipAll = clientCfg.Fingerprint == "" && !d.TLSVerify
		slog.Info("Connecting to PBS directly", "endpoint", d.Endpoint, "token_id", authID, "fingerprint_pinned", clientCfg.Fingerprint != "", "tls_verify", d.TLSVerify)
	} else {
		slog.Debug("Connecting to PBS through the server tunnel")
	}

	result, err := gopbs.Backup(ctx, gopbs.BackupOptions{
		Client:     clientCfg,
		Archive:    archive.Options{Name: archiveName},
		Ref:        ref,
		Format:     format,
		Paths:      s.BackupPaths,
		OnProgress: progressAdapter(opts.OnProgress),
	})
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

	return &temporal.BackupExecutionResult{
		Status:        db.RunStatusCompleted,
		BytesScanned:  int64(size),
		BytesUploaded: int64(uploaded),
		DedupRatio:    dedup,
		ChunkCount:    int(chunks),
		SnapshotID:    snapshot,
		Duration:      duration,
	}, nil
}

func progressAdapter(fn func(string, pbs.UploadStats, bool)) func(gopbs.Progress) {
	if fn == nil {
		return nil
	}
	return func(p gopbs.Progress) { fn(p.Archive, p.Stats, p.Done) }
}
