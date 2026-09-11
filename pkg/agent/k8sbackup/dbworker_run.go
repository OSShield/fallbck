package k8sbackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/osshield/fallbck/pkg/agent/backup"
	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

// runDBWorker dumps the session's database inside the worker pod (engine image with
// the client tools, this binary injected) and uploads the spool to PBS
func runDBWorker(ctx context.Context) workerOutcome {
	session, ticket, err := workerSession()
	if err != nil {
		return fail("startup", err)
	}
	if session.DBConfig == nil {
		return fail("startup", errors.New("worker session carries no database configuration"))
	}
	spec := session.DBConfig.Clone()
	if user := os.Getenv(EnvWorkerDBUser); user != "" {
		spec.User = user
	}
	// Engines and the manifest work with a concrete host; resolve the Service name here
	spec.Host = spec.EffectiveHost()
	password := os.Getenv(EnvWorkerDBPassword)

	var prev *dbspec.JobState
	if raw := os.Getenv(EnvWorkerDBState); raw != "" {
		var st dbspec.JobState
		if err := json.Unmarshal([]byte(raw), &st); err != nil {
			slog.Warn("Ignoring unreadable previous job state", "error", err)
		} else {
			prev = &st
		}
	}

	dial, direct, closeFn, err := workerTransport(ticket)
	if err != nil {
		return fail("connect", err)
	}
	defer closeFn()

	upload := func(ctx context.Context, spoolDir string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error) {
		s := *session
		s.BackupPaths = []string{spoolDir}
		s.ExcludePaths = nil
		return backup.Run(ctx, backup.Options{
			Session: &s, Dial: dial, Direct: direct,
			ArchiveName: dbspec.ArchiveName, Blobs: blobs,
			OnPhase: func(p string) { slog.Info("Upload phase", "phase", p) },
		})
	}

	store := &dbrun.MemoryStateStore{Prev: prev}
	runCtx, cancel := context.WithTimeout(ctx, workerUploadTimeout)
	defer cancel()
	result, err := dbrun.Run(runCtx, dbrun.RunOptions{
		Session:      session,
		Spec:         spec,
		Password:     password,
		Config:       dbspec.Config{SpoolDir: envDefault(EnvWorkerSpool, "/spool")},
		Upload:       upload,
		Hostname:     os.Getenv(EnvWorkerHostname),
		AgentVersion: os.Getenv(EnvWorkerAgentVersion),
		State:        store,
		Generator:    "fallbck-k8s-agent",
		Progress: func(p dbrun.Progress) {
			slog.Info("Database backup progress", "phase", p.Describe(), "spool_bytes", p.BytesInSpool)
		},
	})
	if err != nil {
		if dbrun.IsPrecheck(err) {
			return workerOutcome{Error: err.Error(), Phase: "precheck", Precheck: true}
		}
		return fail("dump", fmt.Errorf("database backup failed: %w", err))
	}
	return workerOutcome{Result: result, State: store.Saved}
}
