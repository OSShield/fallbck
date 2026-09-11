package dbbackup

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// StateStore persists the per-job chain state (last binlog position, WAL LSN) between
// runs. The db agent keeps one JSON file per job; the kubernetes worker pod is
// ephemeral and receives/returns the state through the agent instead.
type StateStore interface {
	// Load returns the job state or nil when none exists
	Load(ctx context.Context, jobID string) (*dbspec.JobState, error)
	Save(ctx context.Context, jobID string, st *dbspec.JobState) error
}

// FileStateStore keeps <dir>/<jobID>.json; an empty dir disables persistence
type FileStateStore struct{ Dir string }

func (f FileStateStore) Load(_ context.Context, jobID string) (*dbspec.JobState, error) {
	return loadState(f.Dir, jobID)
}

func (f FileStateStore) Save(_ context.Context, jobID string, st *dbspec.JobState) error {
	return saveState(f.Dir, jobID, st)
}

// MemoryStateStore holds the previous state supplied by the caller and captures the
// state a run wants saved (worker pods hand it back in their termination message)
type MemoryStateStore struct {
	Prev  *dbspec.JobState
	Saved *dbspec.JobState
}

func (m *MemoryStateStore) Load(context.Context, string) (*dbspec.JobState, error) {
	return m.Prev, nil
}

func (m *MemoryStateStore) Save(_ context.Context, _ string, st *dbspec.JobState) error {
	m.Saved = st
	return nil
}

func statePath(stateDir, jobID string) string {
	return filepath.Join(stateDir, jobID+".json")
}

// loadState returns the job state or nil when none exists
func loadState(stateDir, jobID string) (*dbspec.JobState, error) {
	if stateDir == "" {
		return nil, nil
	}
	data, err := os.ReadFile(statePath(stateDir, jobID))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var st dbspec.JobState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parsing job state %s: %w", statePath(stateDir, jobID), err)
	}
	return &st, nil
}

// saveState writes the job state atomically (temp file + rename)
func saveState(stateDir, jobID string, st *dbspec.JobState) error {
	if stateDir == "" {
		return nil
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, jobID+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, statePath(stateDir, jobID))
}
