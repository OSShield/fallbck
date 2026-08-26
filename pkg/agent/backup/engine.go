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
	"time"

	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/archive"
	"github.com/osshield/gopbs/pbs"
)

// Options for one backup run
type Options struct {
	// Session carries the snapshot identity, format and paths from the server
	Session *temporal.BackupSessionInfo
	// Dial returns a connection on which the PBS backup session is already open
	// (proxy.Dial through the FallBCK server)
	Dial func(ctx context.Context, ref pbs.SnapshotRef) (net.Conn, error)
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
	if opts.Dial == nil {
		return nil, errors.New("backup session dialer is required")
	}
	if len(s.BackupPaths) == 0 {
		return nil, errors.New("backup job has no paths")
	}
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
	ref := pbs.SnapshotRef{Type: s.BackupType, ID: s.BackupID}
	if s.BackupTime > 0 {
		ref.Time = time.Unix(s.BackupTime, 0).UTC()
	}

	start := time.Now()
	slog.Info("Starting PBS backup", "paths", s.BackupPaths, "format", s.PxarFormat, "backup_id", ref.ID, "datastore", s.Datastore, "namespace", s.Namespace)

	result, err := gopbs.Backup(ctx, gopbs.BackupOptions{
		Client: pbs.Config{
			DialSession: opts.Dial,
			Datastore:   s.Datastore,
			Namespace:   s.Namespace,
			Workers:     opts.Workers,
		},
		Archive:    archive.Options{Name: opts.ArchiveName},
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
