package vcs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// IndexVersion is bumped when the index layout changes incompatibly (an old file is
// then ignored; the mirrors themselves stay valid)
const IndexVersion = 1

// DefaultForgetAfter is how many runs a project may be missing from the selection
// before its mirrors are deleted
const DefaultForgetAfter = 7

// Index is what the agent remembers about a job between runs. The mirrors on disk are
// the real state; the index records when each was last fetched and how long a
// project has been gone. Saved only after the run's snapshot finished.
type Index struct {
	Version  int                      `json:"version"`
	Projects map[string]*ProjectIndex `json:"projects"`
}

type ProjectIndex struct {
	Path string `json:"path"`
	URL  string `json:"url"`
	// the last successful fetch (the age of a stale mirror)
	LastFetched time.Time `json:"last_fetched"`
	// a wiki mirror exists next to the repository
	HasWiki bool `json:"has_wiki,omitempty"`
	// when the last LFS download failed, the next run retries it even when
	// no ref changed
	LFSPending bool `json:"lfs_pending,omitempty"`
	// counts consecutive runs the project was not selected
	Missing int `json:"missing,omitempty"`
}

// State is a job's directory under the agent's VCS state directory
type State struct {
	Dir string
}

func (s State) indexPath() string { return filepath.Join(s.Dir, "index.json") }

// RepoDir / WikiDir are the mirrors of a project
func (s State) RepoDir(key string) string { return filepath.Join(s.Dir, "mirrors", key+".git") }
func (s State) WikiDir(key string) string { return filepath.Join(s.Dir, "mirrors", key+".wiki.git") }

// Load reads the index; a missing or outdated file is an empty index
func (s State) Load() (*Index, error) {
	idx := &Index{Version: IndexVersion, Projects: map[string]*ProjectIndex{}}
	data, err := os.ReadFile(s.indexPath())
	if errors.Is(err, os.ErrNotExist) {
		return idx, nil
	}
	if err != nil {
		return nil, err
	}
	var stored Index
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("%s: %w", s.indexPath(), err)
	}
	if stored.Version != IndexVersion || stored.Projects == nil {
		return idx, nil
	}
	return &stored, nil
}

// Save writes the index atomically
func (s State) Save(idx *Index) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.indexPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.indexPath())
}

// Forget deletes a project's mirrors
func (s State) Forget(key string) error {
	if err := os.RemoveAll(s.RepoDir(key)); err != nil {
		return err
	}
	return os.RemoveAll(s.WikiDir(key))
}
