package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

// UploadFunc writes the run's snapshot: the caller opens the transport and runs the
// backup engine with the tree (archive spec.ArchiveName) and the blobs
type UploadFunc func(ctx context.Context, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

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
	Open     func(r *spec.Remote, c Credentials) (Opener, error)
	Upload   UploadFunc
	Progress func(phase string)
	Hostname string
	Version  string
	Now      func() time.Time
}

// Run executes one remote backup with one snapshot: every root is listed (a root
// that fails leaves the others running), the listing becomes one tree with each
// root at its own path, and gopbs reads only the objects that changed since the
// previous snapshot. The run is partial when a root failed or an object couldn't
// be backed up as listed, and fails when no root could be listed.
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil || o.Open == nil || o.Spec == nil || o.Credentials.Remote == nil {
		return nil, errors.New("remote: session, spec, remote, open and upload are required")
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	started := now()

	s, r := *o.Spec, o.Credentials.Remote
	if err := s.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	if err := s.ValidateFor(r); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "the job does not match its remote", Err: err}
	}
	if s.Split != spec.SplitSingle {
		return nil, &dbrun.PrecheckError{Msg: "split " + s.Split + " is not supported by this agent yet", Hint: "update the agent"}
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

	manifest := &spec.Manifest{
		SchemaVersion: spec.ManifestSchemaVersion,
		Generator:     spec.Generator{Agent: "fallbck-agent", Version: o.Version, Hostname: o.Hostname},
		Job:           spec.JobInfo{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: o.Session.BackupRunID.String(), Group: o.Session.BackupID},
		Remote:        spec.RemoteInfo{Name: r.Name, Backend: r.Backend, Identity: r.Identity(), Profile: s.Profile},
		Spec:          &s,
		StartedAt:     started,
	}
	warn := &Warnings{}
	var (
		entries  []vtree.Entry
		dirs     []vtree.Dir
		failures []string
	)
	for i, root := range s.Roots {
		progress(fmt.Sprintf("listing %s (%d of %d)", display(root), i+1, len(s.Roots)))
		res := spec.RootResult{Root: root, Status: spec.RootCompleted}
		e, d, err := listRoot(ctx, sess, root, &s, warn)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			res.Status, res.Error = spec.RootFailed, err.Error()
			failures = append(failures, display(root)+": "+err.Error())
			slog.Error("Remote root failed", "remote", r.Name, "root", root, "error", err)
		} else {
			res.Objects = len(e)
			for _, x := range e {
				res.Bytes += x.Size
			}
			entries, dirs = append(entries, e...), append(dirs, d...)
		}
		manifest.Roots = append(manifest.Roots, res)
	}
	manifest.Tally()
	if len(failures) == len(s.Roots) {
		msg := "no root could be listed: " + truncate(strings.Join(failures, "; "), 8<<10)
		return &temporal.BackupExecutionResult{Status: "failed", ErrorMessage: msg}, errors.New(msg)
	}

	tree, err := vtree.BuildTree(spec.ArchiveName, entries, dirs, DirMtime)
	if err != nil {
		return nil, err
	}
	manifest.Warnings = warn.List()
	manifest.FinishedAt = now()
	data, _ := json.MarshalIndent(manifest, "", "  ")
	progress(fmt.Sprintf("uploading %d objects (%d bytes listed)", manifest.Totals.Objects, manifest.Totals.Bytes))
	res, err := o.Upload(ctx, tree, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	// Objects read during the upload may have added warnings
	manifest.Warnings = warn.List()
	manifest.FinishedAt = now()
	data, _ = json.MarshalIndent(manifest, "", "  ")
	res.Details = rundetail.WrapManifest(rundetail.TypeRemote, data)
	res.Duration = now().Sub(started)
	res.Status = "completed"
	var problems []string
	if len(failures) > 0 {
		problems = append(problems, fmt.Sprintf("%d of %d roots failed: %s", len(failures), len(s.Roots), strings.Join(failures, "; ")))
	}
	if n := len(manifest.Warnings); n > 0 {
		problems = append(problems, fmt.Sprintf("%d warnings: %s", n, strings.Join(manifest.Warnings, "; ")))
	}
	if len(problems) > 0 {
		res.Status = "partial"
		res.ErrorMessage = truncate(strings.Join(problems, "; "), 8<<10)
		slog.Warn("Remote backup completed with problems", "failed_roots", len(failures), "warnings", len(manifest.Warnings))
	}
	return res, nil
}

// listRoot opens and walks one root; its entries sit at the root's own path, so
// the snapshot keeps the remote's layout (roots never overlap)
func listRoot(ctx context.Context, sess Opener, root string, s *spec.Spec, warn *Warnings) ([]vtree.Entry, []vtree.Dir, error) {
	src, err := sess.Open(ctx, root)
	if err != nil {
		return nil, nil, err
	}
	return Walk(ctx, src, root, s.Include, s.Exclude, warn)
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
