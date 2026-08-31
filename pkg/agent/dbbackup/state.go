package dbbackup

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

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
