package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/agent/vtree"
	spec "github.com/osshield/fallbck/pkg/remote"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
)

// UploadFunc writes one snapshot in group (the job's group, or a root's group when
// the job splits per root; the caller mints a sub-ticket for those): the caller
// opens the transport and runs the backup engine with the tree (archive
// spec.ArchiveName) and the blobs
type UploadFunc func(ctx context.Context, group string, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

type RunOptions struct {
	Session *temporal.BackupSessionInfo
	Spec    *spec.Spec
	// Credentials is what the server sent: the remote and, for a job without a
	// profile, its stored credential
	Credentials spec.RunCredentials
	// Profile looks up an agent credential profile by name (the job's Spec.Profile);
	// nil means the agent has no credential store
	Profile func(name string) (*spec.Profile, error)
	// Open connects to the remote (backends.NewSession; tests pass a fake)
	Open   func(r *spec.Remote, c Credentials) (Opener, error)
	Upload UploadFunc
	// StateDir is the job's state directory (<data dir>/remote-state/<job id>): a
	// per-root run records the roots it finished, so a retried attempt skips them
	StateDir string
	Progress func(phase string)
	Hostname string
	Version  string
	Now      func() time.Time
}

// Run executes one remote backup. Every root is listed (a root that fails leaves the
// others running) and gopbs reads only the objects that changed since the previous
// snapshot of the same group.
//   - split single: one snapshot in the job's group, each root at its own path
//   - split per_root: one snapshot per root in <job group>-<root>, then a snapshot
//     in the job's group holding only the run manifest (the run's snapshot ID)
//
// The run is partial when a root failed or an object couldn't be backed up as
// listed, and fails when no root could be backed up.
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil || o.Open == nil || o.Spec == nil || o.Credentials.Remote == nil {
		return nil, errors.New("remote: session, spec, remote, open and upload are required")
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Progress == nil {
		o.Progress = func(string) {}
	}
	started := o.Now()

	s, r := *o.Spec, o.Credentials.Remote
	if err := s.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	if err := s.ValidateFor(r); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "the job does not match its remote", Err: err}
	}
	creds, err := credentials(&s, o.Credentials, o.Profile)
	if err != nil {
		return nil, err
	}
	sess, err := o.Open(r, creds)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "remote " + r.Name, Err: err}
	}
	defer sess.Close()

	run := &runner{o: o, s: &s, sess: sess, warn: &Warnings{}, manifest: &spec.Manifest{
		SchemaVersion: spec.ManifestSchemaVersion,
		Generator:     spec.Generator{Agent: "fallbck-agent", Version: o.Version, Hostname: o.Hostname},
		Job:           spec.JobInfo{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: o.Session.BackupRunID.String(), Group: o.Session.BackupID},
		Remote:        spec.RemoteInfo{Name: r.Name, Backend: r.Backend, Identity: r.Identity(), Profile: s.Profile},
		Spec:          &s,
		StartedAt:     started,
	}}
	run.roots = s.Roots
	if what, ok := spec.DiscoversRoots(r.Backend); ok && len(s.Roots) == 0 {
		o.Progress("listing the " + what + "s")
		if run.roots, err = sess.Discover(ctx); err != nil {
			return nil, fmt.Errorf("listing the %ss: %w", what, err)
		}
		run.manifest.Discovered = true
		if len(run.roots) == 0 {
			run.warn.Add("the credential can't see any %s", what)
		}
	}
	var res *temporal.BackupExecutionResult
	if s.Split == spec.SplitPerRoot {
		res, err = run.perRoot(ctx)
	} else {
		res, err = run.single(ctx)
	}
	if err != nil {
		return res, err
	}

	m := run.manifest
	res.Details = rundetail.WrapManifest(rundetail.TypeRemote, run.marshal())
	res.Duration = o.Now().Sub(started)
	res.Status = "completed"
	var problems []string
	if m.Totals.Failed > 0 {
		problems = append(problems, fmt.Sprintf("%d of %d roots failed: %s", m.Totals.Failed, len(run.roots), strings.Join(run.failures(), "; ")))
	}
	if n := len(m.Warnings); n > 0 {
		problems = append(problems, fmt.Sprintf("%d warnings: %s", n, strings.Join(m.Warnings, "; ")))
	}
	if len(problems) > 0 {
		res.Status = "partial"
		res.ErrorMessage = truncate(strings.Join(problems, "; "), 8<<10)
		slog.Warn("Remote backup completed with problems", "failed_roots", m.Totals.Failed, "warnings", len(m.Warnings))
	}
	return res, nil
}

type runner struct {
	o RunOptions
	s *spec.Spec
	// roots are the job's, or the discovered ones when it names none
	roots    []string
	sess     Opener
	warn     *Warnings
	manifest *spec.Manifest
}

// marshal stamps the manifest with the current warnings and time
func (run *runner) marshal() []byte {
	run.manifest.Warnings = run.warn.List()
	run.manifest.FinishedAt = run.o.Now()
	run.manifest.Tally()
	data, _ := json.MarshalIndent(run.manifest, "", "  ")
	return data
}

func (run *runner) failures() []string {
	var out []string
	for _, r := range run.manifest.Roots {
		if r.Status == spec.RootFailed {
			out = append(out, display(r.Root)+": "+r.Error)
		}
	}
	return out
}

// allFailed ends a run in which no root could be backed up
func (run *runner) allFailed() (*temporal.BackupExecutionResult, error) {
	msg := "no root could be backed up: " + truncate(strings.Join(run.failures(), "; "), 8<<10)
	return &temporal.BackupExecutionResult{Status: "failed", ErrorMessage: msg}, errors.New(msg)
}

// list opens and walks one root; prefix places its entries in the tree
func (run *runner) list(ctx context.Context, i int, root, prefix string, warn *Warnings) ([]vtree.Entry, []vtree.Dir, spec.RootResult) {
	run.o.Progress(fmt.Sprintf("listing %s (%d of %d)", display(root), i+1, len(run.roots)))
	res := spec.RootResult{Root: root, Status: spec.RootCompleted}
	entries, dirs, err := func() ([]vtree.Entry, []vtree.Dir, error) {
		src, err := run.sess.Open(ctx, root)
		if err != nil {
			return nil, nil, err
		}
		return Walk(ctx, src, prefix, run.s.Include, run.s.Exclude, warn)
	}()
	if err != nil {
		res.Status, res.Error = spec.RootFailed, err.Error()
		slog.Error("Remote root failed", "remote", run.manifest.Remote.Name, "root", root, "error", err)
		return nil, nil, res
	}
	res.Objects = len(entries)
	for _, e := range entries {
		res.Bytes += e.Size
	}
	return entries, dirs, res
}

// single writes one snapshot with every root at its own path (roots never overlap)
func (run *runner) single(ctx context.Context) (*temporal.BackupExecutionResult, error) {
	var (
		entries []vtree.Entry
		dirs    []vtree.Dir
	)
	for i, root := range run.roots {
		e, d, res := run.list(ctx, i, root, root, run.warn)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		entries, dirs = append(entries, e...), append(dirs, d...)
		run.manifest.Roots = append(run.manifest.Roots, res)
	}
	run.manifest.Tally()
	if n := len(run.roots); n > 0 && run.manifest.Totals.Failed == n {
		return run.allFailed()
	}
	tree, err := vtree.BuildTree(spec.ArchiveName, entries, dirs, DirMtime)
	if err != nil {
		return nil, err
	}
	data := run.marshal()
	run.o.Progress(fmt.Sprintf("uploading %d objects (%d bytes listed)", run.manifest.Totals.Objects, run.manifest.Totals.Bytes))
	res, err := run.o.Upload(ctx, run.o.Session.BackupID, tree, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}
	return res, nil
}

// perRoot writes one snapshot per root, then the manifest snapshot in the job's
// group. A root finished by an earlier attempt of the same run is not read again.
func (run *runner) perRoot(ctx context.Context) (*temporal.BackupExecutionResult, error) {
	st := loadRunState(run.o.StateDir, run.o.Session.BackupRunID.String())
	total := &temporal.BackupExecutionResult{}
	// ponytail: roots one after another; run several at once if many small roots
	// make runs slow
	groups := map[string]string{}
	for i, root := range run.roots {
		group := spec.UnitGroup(run.o.Session.BackupID, root)
		if prev, ok := groups[group]; ok {
			// Only discovered names can collide: Validate refuses it for listed roots
			res := spec.RootResult{Root: root, Status: spec.RootFailed, Group: group,
				Error: fmt.Sprintf("would share the PBS group %s with %s; back it up in a job of its own", group, display(prev))}
			run.manifest.Roots = append(run.manifest.Roots, res)
			continue
		}
		groups[group] = root
		if done, ok := st.Roots[root]; ok {
			done.Note = "finished by an earlier attempt of this run"
			run.manifest.Roots = append(run.manifest.Roots, done)
			continue
		}
		// The root's contents sit at the top of its snapshot; its warnings name it
		warn := &Warnings{}
		entries, dirs, res := run.list(ctx, i, root, "", warn)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res.Group = group
		if res.Status == spec.RootCompleted {
			up, err := run.uploadRoot(ctx, res, entries, dirs, warn)
			for _, w := range warn.List() {
				run.warn.Add("%s: %s", display(root), w)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if err != nil {
				res.Status, res.Error = spec.RootFailed, err.Error()
				slog.Error("Remote root snapshot failed", "root", root, "group", group, "error", err)
			} else {
				res.SnapshotID = up.SnapshotID
				total.BytesScanned += up.BytesScanned
				total.BytesUploaded += up.BytesUploaded
				st.Roots[root] = res
				st.save(run.o.StateDir)
			}
		}
		run.manifest.Roots = append(run.manifest.Roots, res)
	}
	run.manifest.Tally()
	if n := len(run.roots); n > 0 && run.manifest.Totals.Failed == n {
		return run.allFailed()
	}

	// The job's group gets the run manifest, so the run has one snapshot ID
	run.o.Progress("writing the run manifest")
	data := run.marshal()
	tree, err := vtree.BuildTree(spec.ArchiveName, []vtree.Entry{memEntry(spec.ManifestBlobName, data, run.o.Now())}, nil, DirMtime)
	if err != nil {
		return nil, err
	}
	res, err := run.o.Upload(ctx, run.o.Session.BackupID, tree, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, fmt.Errorf("manifest snapshot: %w", err)
	}
	res.BytesScanned += total.BytesScanned
	res.BytesUploaded += total.BytesUploaded
	if res.BytesUploaded > 0 {
		res.DedupRatio = float64(res.BytesScanned) / float64(res.BytesUploaded)
	}
	return res, nil
}

// uploadRoot writes one root's snapshot with a manifest of that root alone
func (run *runner) uploadRoot(ctx context.Context, res spec.RootResult, entries []vtree.Entry, dirs []vtree.Dir, warn *Warnings) (*temporal.BackupExecutionResult, error) {
	tree, err := vtree.BuildTree(spec.ArchiveName, entries, dirs, DirMtime)
	if err != nil {
		return nil, err
	}
	m := *run.manifest
	m.Roots, m.Warnings, m.FinishedAt = []spec.RootResult{res}, warn.List(), run.o.Now()
	m.Job.Group = res.Group
	m.Tally()
	data, _ := json.MarshalIndent(&m, "", "  ")
	run.o.Progress(fmt.Sprintf("uploading %s: %d objects (%d bytes listed)", display(res.Root), res.Objects, res.Bytes))
	return run.o.Upload(ctx, res.Group, tree, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
}

// runState is what a per-root run has finished (<state dir>/run.json); an attempt
// of another run starts from scratch
type runState struct {
	BackupRunID string                     `json:"backup_run_id"`
	Roots       map[string]spec.RootResult `json:"roots"`
}

func loadRunState(dir, runID string) *runState {
	st := &runState{BackupRunID: runID, Roots: map[string]spec.RootResult{}}
	if dir == "" {
		return st
	}
	var saved runState
	if data, err := os.ReadFile(filepath.Join(dir, "run.json")); err == nil && json.Unmarshal(data, &saved) == nil && saved.BackupRunID == runID && saved.Roots != nil {
		return &saved
	}
	return st
}

// save records progress; failing to only costs a retry the work again
func (st *runState) save(dir string) {
	if dir == "" {
		return
	}
	data, _ := json.Marshal(st)
	tmp := filepath.Join(dir, "run.json.tmp")
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		err = os.WriteFile(tmp, data, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(dir, "run.json"))
	}
	if err != nil {
		slog.Warn("Could not record the run's progress; a retry repeats finished roots", "error", err)
	}
}

// memEntry is an in-memory file
func memEntry(path string, data []byte, mtime time.Time) vtree.Entry {
	return vtree.Entry{Path: path, Size: int64(len(data)), Mtime: mtime, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	}}
}

// credentials picks the run's credential: the job's agent profile when it names
// one (only for the remote it was made for), otherwise the server's
func credentials(s *spec.Spec, rc spec.RunCredentials, lookup func(string) (*spec.Profile, error)) (Credentials, error) {
	if s.Profile == "" {
		return Credentials{Secrets: rc.Secrets}, nil
	}
	name, r := s.Profile, rc.Remote
	if lookup == nil {
		return Credentials{}, &dbrun.PrecheckError{Msg: "the job names the agent credential profile " + name, Hint: "this agent has no credential store"}
	}
	p, err := lookup(name)
	if err != nil {
		return Credentials{}, &dbrun.PrecheckError{Msg: "remote credential profile " + name, Err: err,
			Hint: "create it on the agent: fallbck-agent remote profile create --name " + name + " --backend " + r.Backend + " --endpoint " + r.Identity()}
	}
	if err := p.Matches(r); err != nil {
		return Credentials{}, &dbrun.PrecheckError{Msg: "remote credential profile " + name, Err: err,
			Hint: "the agent only uses a profile for the remote it was made for"}
	}
	secrets, err := p.Credentials()
	if err != nil {
		return Credentials{}, &dbrun.PrecheckError{Msg: "remote credential profile " + name, Err: err}
	}
	return Credentials{Secrets: secrets, EnvAuth: p.EnvAuth}, nil
}

func display(root string) string {
	if root == "" {
		return "/"
	}
	return root
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
