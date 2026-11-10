package vcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	spec "github.com/osshield/fallbck/pkg/vcs"
	"github.com/osshield/gopbs"
	"github.com/osshield/gopbs/scan"
)

// UploadFunc writes the run's snapshot: the caller opens the transport and runs the
// backup engine with the tree (archive spec.ArchiveName) and the blobs
type UploadFunc func(ctx context.Context, tree *scan.Node, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

type RunOptions struct {
	Session     *temporal.BackupSessionInfo
	Spec        *spec.Spec
	Credentials spec.Credentials
	// Provider lists the projects; nil derives it from the credentials
	// (GitProvider or GitLabProvider)
	Provider Provider
	// StateDir holds the job's mirrors and index (<vcs_state_dir>/<job id>)
	StateDir string
	// TempDir receives the run's CA bundle file
	TempDir string
	// GitPath is the git binary ("" looks it up in PATH)
	GitPath string
	// looks up an agent credential profile by name (the job's Spec.Profile); nil
	// means the agent has no credential store
	Profile func(name string) (*spec.Profile, error)
	// RefreshCredentials fetches the connection credentials again; used when they
	// carry a short-lived token (Credentials.ExpiresAt, a GitHub App connection)
	RefreshCredentials func(ctx context.Context) (*spec.Credentials, error)
	Upload             UploadFunc
	// Progress names the current step (reported to the server right away); Activity
	// is frequent detail such as git's progress lines (shown with the next report)
	Progress func(phase string)
	Activity func(detail string)
	Items    func(items map[string]rundetail.ProgressItem)
	Hostname string
	Version  string
	// RepackThreshold / ForgetAfter override the defaults (tests)
	RepackThreshold int
	ForgetAfter     int
	Now             func() time.Time
}

// the outcome of a single project
type projectOutcome struct {
	project    Project
	result     spec.RepoResult
	included   bool
	hasWiki    bool
	hasMeta    bool
	lfsPending bool
	// set by a complete metadata pass (metaFull also when it was a full one)
	metaSince, metaFull time.Time
}

// Run executes one VCS backup: precheck → list projects → bring every mirror up to
// date (Concurrency in flight) → one snapshot of all mirrors with the run manifest →
// save the index. A project that fails keeps its last good mirror in the snapshot
// (stale) and the run ends partial; the run fails only when nothing could be backed
// up.
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil {
		return nil, errors.New("vcs: session and upload are required")
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	progress, activity, items := o.Progress, o.Activity, o.Items
	if progress == nil {
		progress = func(string) {}
	}
	if activity == nil {
		activity = func(string) {}
	}
	if items == nil {
		items = func(map[string]rundetail.ProgressItem) {}
	}
	started := now()

	// Precheck: configuration, connection, git
	s := o.Spec.Clone()
	if err := s.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	auth := Auth{BaseURL: o.Credentials.BaseURL, Token: o.Credentials.Token, Username: o.Credentials.Username, CAPEM: o.Credentials.CAPEM}
	authType := o.Credentials.AuthType
	if exp := o.Credentials.ExpiresAt; exp != nil && o.RefreshCredentials != nil && s.Profile == "" {
		// ponytail: renewed with the run's backup ticket, which lasts 2h; the upload
		// needs that ticket too, so no run that can finish outlives it
		rt := &spec.RefreshingToken{Fetch: func(ctx context.Context) (string, time.Time, error) {
			c, err := o.RefreshCredentials(ctx)
			if err != nil {
				return "", time.Time{}, err
			}
			if c.Token == "" || c.ExpiresAt == nil {
				return "", time.Time{}, errors.New("the server sent no short-lived token")
			}
			return c.Token, *c.ExpiresAt, nil
		}}
		rt.Seed(auth.Token, *exp)
		auth.Tokens = rt.Token
	}
	if s.Profile != "" {
		var err error
		if authType, err = applyProfile(ctx, &auth, s, o.Credentials, o.Profile); err != nil {
			return nil, err
		}
	}
	conn := &spec.Connection{Provider: o.Credentials.Provider, BaseURL: o.Credentials.BaseURL, Token: auth.Token, AuthType: authType}
	if err := s.ValidateFor(conn); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "the job does not match its connection", Err: err}
	}
	provider := o.Provider
	if provider == nil {
		switch o.Credentials.Provider {
		case spec.ProviderGit:
			provider = GitProvider{Spec: s}
		case spec.ProviderGitLab, spec.ProviderGitHub:
			creds := spec.Credentials{Provider: o.Credentials.Provider, BaseURL: o.Credentials.BaseURL, AuthType: authType,
				Token: auth.Token, Tokens: auth.Tokens, CAPEM: o.Credentials.CAPEM}
			client, err := creds.HTTPClient(gitlabAPITimeout)
			if err != nil {
				return nil, &dbrun.PrecheckError{Msg: "the connection's CA bundle", Err: err}
			}
			if creds.Provider == spec.ProviderGitHub {
				provider = &GitHubProvider{Spec: s, Credentials: creds, Client: client}
			} else {
				provider = &GitLabProvider{Spec: s, Credentials: creds, Client: client}
			}
		default:
			return nil, &dbrun.PrecheckError{Msg: "this agent version cannot list " + o.Credentials.Provider + " projects yet", Hint: "update the agent"}
		}
	}
	if x, ok := provider.(interface{ ExtraURLs() []string }); ok {
		auth.ExtraURLs = x.ExtraURLs()
	}
	var meta MetadataProvider
	if mp, ok := provider.(MetadataProvider); ok && s.Workloads.Metadata {
		meta = mp
	}
	tempDir := o.TempDir
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	g, err := NewGit(o.GitPath, auth, tempDir)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "git", Err: err, Hint: "install git on the agent host"}
	}
	defer g.Close()
	progress("checking git")
	gitVersion, err := g.Version(ctx)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "running git", Err: err}
	}
	if !spec.GitVersionOK(gitVersion) {
		return nil, &dbrun.PrecheckError{Msg: "git " + gitVersion + " is too old", Hint: fmt.Sprintf("VCS jobs need git %d.%d or newer", spec.MinGitMajor, spec.MinGitMinor)}
	}

	manifest := &spec.Manifest{
		SchemaVersion: spec.ManifestSchemaVersion,
		Generator:     spec.Generator{Agent: "fallbck-agent", Version: o.Version, Hostname: o.Hostname, GitVersion: gitVersion},
		Job:           spec.JobInfo{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: o.Session.BackupRunID.String(), Group: o.Session.BackupID},
		Source:        spec.SourceInfo{Provider: o.Credentials.Provider, BaseURL: o.Credentials.BaseURL},
		StartedAt:     started,
		Spec:          s,
		Restore:       restoreNotes(o.Session.BackupType, o.Session.BackupID),
	}
	lfs := false
	if s.Workloads.EffLFS() {
		if v, err := g.LFSVersion(ctx); err == nil {
			lfs = true
			manifest.Generator.LFSVersion = v
		} else {
			manifest.Warnings = append(manifest.Warnings, "git-lfs is not installed on the agent: LFS objects are not backed up, LFS files are only pointers")
		}
	}

	progress("listing repositories")
	projects, warnings, err := provider.Projects(ctx)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "listing repositories", Err: err}
	}
	manifest.Warnings = append(manifest.Warnings, warnings...)
	if d, ok := provider.(interface{ Describe(*spec.SourceInfo) }); ok {
		d.Describe(&manifest.Source)
	}
	sort.Slice(projects, func(i, j int) bool { return projects[i].Path < projects[j].Path })
	invalid := invalidPaths(projects, meta != nil)

	state := State{Dir: o.StateDir}
	idx, err := state.Load()
	if err != nil {
		return nil, fmt.Errorf("loading the job state: %w", err)
	}
	live := map[string]rundetail.ProgressItem{}
	for _, p := range projects {
		kind := "repository"
		if p.Kind != "" {
			kind = p.Kind
		}
		live[p.Key] = rundetail.ProgressItem{Name: p.Path, Kind: kind, Status: "pending"}
	}
	items(live)

	// Mirrors in parallel, bound by Concurrency
	outcomes := make([]projectOutcome, len(projects))
	sem := make(chan struct{}, s.EffConcurrency())
	var wg sync.WaitGroup
	var mu sync.Mutex
	done, failed := 0, 0
	for i := range projects {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			p := projects[i]
			item := live[p.Key]
			item.Status = "running"
			items(map[string]rundetail.ProgressItem{p.Key: item})
			mu.Lock()
			prev := idx.Projects[p.Key]
			mu.Unlock()
			out := backupProject(ctx, g, state, s, o, p, invalid[i], prev, lfs, meta, activity, now)
			mu.Lock()
			outcomes[i] = out
			done++
			if out.result.Status == spec.RepoFailed || out.result.Status == spec.RepoStale {
				failed++
			}
			n, f := done, failed
			mu.Unlock()
			item.Status, item.Error = itemStatus(out.result.Status), out.result.Error
			switch {
			case out.result.Status == spec.RepoStale && out.result.LastFetched != nil:
				item.Note = "stale: last fetched " + out.result.LastFetched.Format(time.RFC3339)
			case out.result.Status == spec.RepoCompleted && !out.result.Changed:
				item.Note = "unchanged"
			}
			items(map[string]rundetail.ProgressItem{p.Key: item})
			progress(fmt.Sprintf("%d of %d repositories done (%d failed)", n, len(projects), f))
		}(i)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// One snapshot of every mirror that has something to show
	var treeProjects []TreeProject
	included, failures := 0, []string{}
	for _, out := range outcomes {
		manifest.Repositories = append(manifest.Repositories, out.result)
		if out.result.Status == spec.RepoFailed || out.result.Status == spec.RepoStale {
			failures = append(failures, out.project.Path+": "+out.result.Error)
		}
		if !out.included {
			continue
		}
		included++
		tp := TreeProject{Path: out.project.Path, Repository: state.RepoDir(out.project.Key)}
		if out.hasWiki {
			tp.Wiki = state.WikiDir(out.project.Key)
		}
		if out.hasMeta {
			tp.Metadata = state.MetaDir(out.project.Key)
		}
		treeProjects = append(treeProjects, tp)
	}
	manifest.Tally()
	if len(projects) > 0 && included == 0 && len(failures) > 0 {
		msg := fmt.Sprintf("all %d repositories failed: %s", len(projects), truncate(strings.Join(failures, "; "), 8<<10))
		return &temporal.BackupExecutionResult{Status: "failed", ErrorMessage: msg}, errors.New(msg)
	}
	tree, err := BuildTree(spec.ArchiveName, treeProjects, now())
	if err != nil {
		return nil, err
	}
	manifest.FinishedAt = now()
	data, _ := json.MarshalIndent(manifest, "", "  ")
	progress(fmt.Sprintf("uploading %d repositories", included))
	res, err := o.Upload(ctx, tree, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, fmt.Errorf("snapshot: %w", err)
	}

	// The snapshot holds the mirrors: only now does the index move on
	saveIndex(state, idx, outcomes, o.ForgetAfter, now())

	res.Details = rundetail.WrapManifest(rundetail.TypeVCS, data)
	res.Duration = now().Sub(started)
	res.Status = "completed"
	if len(failures) > 0 {
		res.Status = "partial"
		res.ErrorMessage = fmt.Sprintf("%d of %d repositories failed: %s", len(failures), len(projects), truncate(strings.Join(failures, "; "), 8<<10))
		slog.Warn("VCS backup completed with failed repositories", "failed", len(failures), "repositories", len(projects))
	}
	return res, nil
}

// puts the token of the job's agent credential profile into auth and returns the
// auth type. The profile is only used for the URL it was created for: the server
// decides the connection URL, and must not be able to send an agent-held token
// anywhere else. A GitHub App profile mints its first installation token here, so a
// wrong key or id fails the precheck.
func applyProfile(ctx context.Context, auth *Auth, s *spec.Spec, creds spec.Credentials, lookup func(string) (*spec.Profile, error)) (string, error) {
	name := s.Profile
	if lookup == nil {
		return "", &dbrun.PrecheckError{Msg: "the job names the agent credential profile " + name, Hint: "this agent has no credential store"}
	}
	p, err := lookup(name)
	if err != nil {
		return "", &dbrun.PrecheckError{Msg: "agent credential profile " + name, Err: err,
			Hint: "create it on the agent: fallbck-agent vcs profile create --name " + name + " --url " + auth.BaseURL + " --ask-token"}
	}
	if p.URL != auth.BaseURL {
		return "", &dbrun.PrecheckError{Msg: fmt.Sprintf("agent credential profile %s is for %s, but the job's connection is %s", name, p.URL, auth.BaseURL),
			Hint: "the agent only sends a profile's token to the URL it was created for; recreate the profile or fix the connection"}
	}
	auth.Tokens = nil
	if p.AuthType != spec.AuthGitHubApp {
		token, err := p.ResolveToken()
		if err != nil {
			return "", &dbrun.PrecheckError{Msg: "agent credential profile " + name, Err: err}
		}
		auth.Token, auth.Username = token, p.Username
		return spec.AuthToken, nil
	}
	if creds.Provider != spec.ProviderGitHub {
		return "", &dbrun.PrecheckError{Msg: "agent credential profile " + name + " is a GitHub App, but the job's connection is " + creds.Provider}
	}
	client, err := creds.HTTPClient(gitlabAPITimeout)
	if err != nil {
		return "", &dbrun.PrecheckError{Msg: "the connection's CA bundle", Err: err}
	}
	api, perms := spec.GitHubAPIURL(auth.BaseURL), spec.GitHubAppPermissions(s)
	rt := &spec.RefreshingToken{Fetch: func(ctx context.Context) (string, time.Time, error) {
		// the key file is read again for every token, so a rotated key is picked up
		app, err := p.App()
		if err != nil {
			return "", time.Time{}, err
		}
		return app.InstallationToken(ctx, api, client, perms)
	}}
	token, err := rt.Token(ctx)
	if err != nil {
		return "", &dbrun.PrecheckError{Msg: "agent credential profile " + name, Err: err,
			Hint: "check it with: fallbck-agent vcs profile test --name " + name}
	}
	auth.Token, auth.Username, auth.Tokens = token, spec.GitHubAppUsername, rt.Token
	return spec.AuthGitHubApp, nil
}

// metadataFullEvery is how often metadata is listed whole instead of since the last
// pass: the only way to notice issues and comments deleted on GitHub
const metadataFullEvery = 7 * 24 * time.Hour

// brings one project's mirrors up to date; never returns an error,
// the outcome says what went into the snapshot (one failing repository must not fail the run)
func backupProject(ctx context.Context, g *Git, state State, s *spec.Spec, o RunOptions, p Project, invalid string, prev *ProjectIndex, lfs bool, meta MetadataProvider, activity func(string), now func() time.Time) projectOutcome {
	out := projectOutcome{project: p, result: spec.RepoResult{ProjectID: p.ID, Path: p.Path, URL: p.URL, Archived: p.Archived, Fork: p.Fork, Kind: p.Kind}}
	r := &out.result
	if prev != nil && !prev.LastFetched.IsZero() {
		t := prev.LastFetched
		r.LastFetched = &t
	}
	if invalid != "" {
		// Not fetched: BuildTree would refuse the path
		r.Status, r.Error = spec.RepoFailed, invalid
		return out
	}
	if s.MaxRepoSize > 0 && p.Size > s.MaxRepoSize {
		r.Status = spec.RepoSkipped
		r.Error = fmt.Sprintf("larger than max_repo_size (%d bytes)", p.Size)
		return out
	}
	lastLine := time.Time{}
	gitProgress := func(line string) {
		if time.Since(lastLine) >= 2*time.Second {
			lastLine = time.Now()
			activity(p.Path + ": " + line)
		}
	}
	m := g.NewMirror(state.RepoDir(p.Key), p.URL)
	existed := m.Exists()
	fail := func(err error) projectOutcome {
		r.Error = err.Error()
		if existed && m.Exists() {
			// The last good mirror goes into the snapshot
			r.Status, out.included = spec.RepoStale, true
			out.hasWiki = prev != nil && prev.HasWiki
			out.lfsPending = prev != nil && prev.LFSPending
			// and the metadata of the last pass with it
			if meta != nil {
				_, serr := os.Stat(state.MetaDir(p.Key))
				out.hasMeta = serr == nil
			}
		} else {
			r.Status = spec.RepoFailed
		}
		slog.Error("VCS repository failed", "path", p.Path, "status", r.Status, "error", err)
		return out
	}

	activity(p.Path + ": checking for changes")
	changed, err := syncMirror(ctx, g, m, gitProgress)
	if err != nil {
		return fail(err)
	}
	r.Changed = changed
	out.included = true
	_, r.Refs, _ = m.LocalRefs(ctx)
	if changed {
		if _, err := m.Repack(ctx, o.RepackThreshold); err != nil {
			r.Warnings = append(r.Warnings, err.Error())
		}
	}
	if lfs && (changed || (prev != nil && prev.LFSPending)) {
		activity(p.Path + ": fetching LFS objects")
		if err := m.FetchLFS(ctx, gitProgress); err != nil {
			out.lfsPending = true
			r.Status, r.Error = spec.RepoStale, "LFS objects: "+err.Error()
			slog.Error("VCS LFS fetch failed", "path", p.Path, "error", err)
		}
	}
	if p.WikiURL != "" && s.Workloads.EffWiki() {
		wm := g.NewMirror(state.WikiDir(p.Key), p.WikiURL)
		hadWiki := wm.Exists()
		if _, err := syncMirror(ctx, g, wm, gitProgress); err != nil && (hadWiki || !repoNotFound(err)) {
			// An enabled wiki without pages has no repository: only worth a warning
			// once it had one
			r.Warnings = append(r.Warnings, "wiki: "+err.Error())
		} else if _, refs, err := wm.LocalRefs(ctx); err == nil && refs == 0 {
			// GitLab answers for an enabled wiki without pages with an empty
			// repository: nothing to keep
			_ = os.RemoveAll(wm.Dir)
		}
		out.hasWiki = wm.Exists()
	}
	if meta != nil {
		activity(p.Path + ": fetching metadata")
		var since time.Time
		if prev != nil && now().Sub(prev.MetaFull) < metadataFullEvery {
			since = prev.MetaSince
		}
		start := now()
		complete, err := meta.Metadata(ctx, p, state.MetaDir(p.Key), since, r)
		if err != nil {
			r.Warnings = append(r.Warnings, "metadata: "+err.Error())
		} else if complete {
			out.metaSince = start
			if since.IsZero() {
				out.metaFull = start
			}
		}
		_, err = os.Stat(state.MetaDir(p.Key))
		out.hasMeta = err == nil
	} else {
		// The workload was switched off: the snapshot stops carrying it
		_ = os.RemoveAll(state.MetaDir(p.Key))
	}
	if r.Status == "" {
		r.Status = spec.RepoCompleted
		t := now()
		r.LastFetched = &t
	}
	r.Wiki = out.hasWiki
	r.Bytes, r.LFSBytes = m.Size()
	return out
}

// fetches a mirror unless the remote's refs already match it (one
// ls-remote instead of a fetch for an unchanged repository); reports whether refs
// changed
func syncMirror(ctx context.Context, g *Git, m *Mirror, progress func(string)) (bool, error) {
	if m.Exists() {
		local, _, err := m.LocalRefs(ctx)
		if err != nil {
			return false, err
		}
		remote, _, err := g.RemoteRefs(ctx, m.URL)
		if err != nil {
			return false, err
		}
		if remote == local {
			return false, nil
		}
	}
	res, err := m.Fetch(ctx, progress)
	if err != nil {
		return false, err
	}
	return res.Changed, nil
}

// records the run's outcomes and forgets projects that have been missing
// from the selection for forgetAfter runs (their mirrors are deleted)
func saveIndex(state State, idx *Index, outcomes []projectOutcome, forgetAfter int, now time.Time) {
	if forgetAfter <= 0 {
		forgetAfter = DefaultForgetAfter
	}
	seen := map[string]bool{}
	for _, out := range outcomes {
		p := out.project
		seen[p.Key] = true
		e := idx.Projects[p.Key]
		if e == nil {
			e = &ProjectIndex{}
			idx.Projects[p.Key] = e
		}
		e.Path, e.URL, e.Missing = p.Path, p.URL, 0
		if out.result.Status == spec.RepoCompleted {
			e.LastFetched = now
		}
		if out.included {
			e.HasWiki, e.LFSPending = out.hasWiki, out.lfsPending
		}
		if !out.metaSince.IsZero() {
			e.MetaSince = out.metaSince
		}
		if !out.metaFull.IsZero() {
			e.MetaFull = out.metaFull
		}
	}
	for key, e := range idx.Projects {
		if seen[key] {
			continue
		}
		e.Missing++
		if e.Missing >= forgetAfter {
			if err := state.Forget(key); err != nil {
				slog.Warn("Could not delete the mirrors of a project no longer backed up", "path", e.Path, "error", err)
				continue
			}
			slog.Info("Deleted the mirrors of a project no longer backed up", "path", e.Path, "missing_runs", e.Missing)
			delete(idx.Projects, key)
		}
	}
	if err := state.Save(idx); err != nil {
		slog.Warn("Could not save the VCS job index; the next run repeats some work", "error", err)
	}
}

// maps a repository outcome onto the live progress
func itemStatus(status string) string {
	switch status {
	case spec.RepoCompleted:
		return "completed"
	case spec.RepoSkipped:
		return "skipped"
	}
	return "failed"
}

// the manifest's restore hints
func restoreNotes(backupType, group string) map[string]string {
	return map[string]string{
		"archive": spec.ArchiveName + ".pxar",
		"restore": fmt.Sprintf("proxmox-backup-client restore %s/%s/<time> %s.pxar ./restore", backupType, group, spec.ArchiveName),
		"push":    "sh ./restore/" + RestoreScript + " <project path> <empty remote URL> [<wiki remote URL>]",
		"readme":  RestoreReadme + " at the archive root",
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
