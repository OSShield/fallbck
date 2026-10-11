// Package vss backs Windows backups with Volume Shadow Copies: every volume a job's
// paths live on is snapshotted, the shadow copy is exposed through a directory
// symlink under the agent's data directory, and the job's paths are remapped onto
// it so open and locked files are read from a consistent point in time. On other
// platforms nothing is snapshotted.
package vss

import "context"

// Snapshots holds the shadow copies of one backup run
type Snapshots struct {
	links   []string //nolint:unused
	shadows []shadow //nolint:unused
}

// shadow is one created shadow copy (platform-specific handle)
type shadow struct { //nolint:unused
	id     string
	volume string
	remove func() error
}

// Supported reports whether this platform can take shadow copies
func Supported() bool { return supported }

// Take snapshots the volumes of paths and returns each path remapped into its
// shadow copy (same order). linkDir receives one directory symlink per shadow copy.
// The caller must Release the snapshots when the backup is done.
func Take(ctx context.Context, linkDir string, paths []string) ([]string, *Snapshots, error) {
	return take(ctx, linkDir, paths)
}

// Release removes the symlinks and deletes the shadow copies (best effort, logged)
func (s *Snapshots) Release() {
	if s == nil {
		return
	}
	release(s)
}

// Sweep removes shadow copies and links left behind by a crashed run
func Sweep(linkDir string) { sweep(linkDir) }
