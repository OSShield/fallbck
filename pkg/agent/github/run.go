// Package github runs GitHub jobs on the agent: a kept bare mirror per repository (and
// wiki) plus API metadata as JSON, uploaded as one snapshot per repository.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	dbrun "github.com/osshield/fallbck/pkg/agent/dbbackup"
	spec "github.com/osshield/fallbck/pkg/github"
	"github.com/osshield/fallbck/pkg/rundetail"
	"github.com/osshield/fallbck/pkg/temporal"
	"github.com/osshield/gopbs"
)

// Unit is one snapshot of the run: a repository, or the job's own index
type Unit struct {
	// Kind is repository or gist (gists carry their git URL and object in Repo)
	Kind    string
	Name    string
	Group   string
	Archive string
	Repo    *spec.Repo
	Sources []string
}

// UploadFunc writes one snapshot of dir: the caller mints the unit's ticket, opens
// the transport and runs the backup engine on the directory
type UploadFunc func(ctx context.Context, unit *Unit, dir string, blobs []gopbs.Blob) (*temporal.BackupExecutionResult, error)

// RunOptions parameterise Run
type RunOptions struct {
	Session     *temporal.BackupSessionInfo
	Spec        *spec.Spec
	Credentials spec.Credentials
	// StateDir holds the job's mirrors and per-repository state (<data>/github-state/<job id>)
	StateDir string
	Upload   UploadFunc
	Progress func(phase string)
	Items    func(items map[string]rundetail.ProgressItem)
	Hostname string
	Version  string
	// Client / GitPath override the REST client and the git binary; AllowFileRemotes
	// accepts file:// clone URLs (tests)
	Client           *spec.Client
	GitPath          string
	AllowFileRemotes bool
	Now              func() time.Time
}

// Layout of a repository snapshot
const (
	dirMirror   = "repo.git"
	dirWiki     = "wiki.git"
	dirMetadata = "metadata"
	dirIndex    = "_index"
	dirState    = "_state"
)

// Run executes one GitHub backup: precheck → select repositories → one snapshot per
// repository (Concurrency in flight) → the index snapshot with the run manifest
func Run(ctx context.Context, o RunOptions) (*temporal.BackupExecutionResult, error) {
	if o.Session == nil || o.Upload == nil {
		return nil, errors.New("github: session and upload are required")
	}
	s := o.Spec.Clone()
	if s == nil {
		return nil, &dbrun.PrecheckError{Msg: "the job has no GitHub configuration"}
	}
	if err := s.Validate(); err != nil {
		return nil, &dbrun.PrecheckError{Msg: "invalid job configuration", Err: err}
	}
	if o.StateDir == "" {
		return nil, &dbrun.PrecheckError{Msg: "the agent has no GitHub state directory (agent too old?)"}
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	progress := o.Progress
	if progress == nil {
		progress = func(string) {}
	}
	items := o.Items
	if items == nil {
		items = func(map[string]rundetail.ProgressItem) {}
	}
	started := now()

	progress("checking git")
	git, err := FindGit(ctx, o.GitPath)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "git", Err: err, Hint: "install git 2.31 or newer on the agent host (the agent container image ships it)"}
	}
	git.Token = o.Credentials.Token
	c := o.Client
	if c == nil {
		if c, err = spec.NewClient(o.Credentials); err != nil {
			return nil, &dbrun.PrecheckError{Msg: "GitHub credentials", Err: err}
		}
	}
	progress("connecting to the GitHub API")
	viewer, err := c.Viewer(ctx)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "GitHub API", Err: err,
			Hint: "check the account's token and that the agent host reaches " + c.APIURL}
	}

	manifest := &spec.Manifest{
		SchemaVersion: spec.ManifestSchemaVersion,
		Generator:     spec.Generator{Agent: "fallbck-agent", Version: o.Version, Hostname: o.Hostname, Git: git.Version},
		Job:           spec.JobInfo{ID: o.Session.JobID.String(), Name: o.Session.JobName, RunID: o.Session.RunID, BackupRunID: o.Session.BackupRunID.String(), Group: o.Session.BackupID},
		Account:       spec.AccountInfo{Login: viewer.Login, APIURL: c.APIURL},
		StartedAt:     started,
		Spec:          s,
		Restore:       restoreNotes(o.Session.BackupType, o.Session.BackupID),
	}
	var mu sync.Mutex
	warn := func(format string, args ...any) {
		mu.Lock()
		manifest.Warnings = append(manifest.Warnings, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	progress("listing repositories")
	units, complete, err := selectRepos(ctx, c, s, viewer.Login, o.Session.BackupID, warn)
	if err != nil {
		return nil, &dbrun.PrecheckError{Msg: "listing repositories", Err: err}
	}
	if err := os.MkdirAll(filepath.Join(o.StateDir, dirState), 0o700); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	live := map[string]rundetail.ProgressItem{}
	for _, u := range units {
		live[u.Group] = rundetail.ProgressItem{Name: u.Name, Kind: u.Kind, Status: "pending"}
	}
	items(live)

	results := make([]spec.RepoResult, len(units))
	sem := make(chan struct{}, s.EffConcurrency())
	var wg sync.WaitGroup
	var done, failed int
	for i := range units {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			u := &units[i]
			mu.Lock()
			item := live[u.Group]
			mu.Unlock()
			item.Status = "running"
			items(map[string]rundetail.ProgressItem{u.Group: item})
			res := backupRepo(ctx, c, git, s, o, u, now)
			mu.Lock()
			results[i] = res
			done++
			if res.Status == "failed" {
				failed++
			}
			n, f := done, failed
			mu.Unlock()
			item.Status, item.Error, item.BytesUploaded = res.Status, res.Error, res.Uploaded
			if res.SnapshotTime > 0 {
				item.SnapshotID = fmt.Sprintf("%s/%s/%s", o.Session.BackupType, u.Group, time.Unix(res.SnapshotTime, 0).UTC().Format("2006-01-02T15:04:05Z"))
			}
			items(map[string]rundetail.ProgressItem{u.Group: item})
			progress(fmt.Sprintf("%d of %d repositories done (%d failed)", n, len(units), f))
		}(i)
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	manifest.Repos = results
	if complete {
		pruneState(o.StateDir, units, warn)
	}

	total := &temporal.BackupExecutionResult{Status: "completed"}
	for _, r := range results {
		total.BytesScanned += r.Bytes
		total.BytesUploaded += r.Uploaded
	}

	// The job's own group carries the index: the run manifest, the viewer and the
	// selection, so a restore starts from one snapshot listing every repository group
	progress("writing the run index")
	manifest.FinishedAt = now()
	data, _ := json.MarshalIndent(manifest, "", "  ")
	indexDir := filepath.Join(o.StateDir, dirIndex)
	_ = os.RemoveAll(indexDir)
	if err := os.MkdirAll(indexDir, 0o700); err != nil {
		return nil, err
	}
	viewerJSON, _ := json.MarshalIndent(viewer, "", "  ")
	for name, content := range map[string][]byte{
		spec.ManifestBlobName: data,
		"RESTORE.md":          []byte(restoreReadme(manifest)),
		"account.json":        viewerJSON,
	} {
		if err := os.WriteFile(filepath.Join(indexDir, name), content, 0o600); err != nil {
			return nil, err
		}
	}
	idxUnit := &Unit{Name: "index", Group: o.Session.BackupID, Archive: spec.ArchiveIndex}
	idxResult, err := o.Upload(ctx, idxUnit, indexDir, []gopbs.Blob{{Name: spec.ManifestBlobName, Data: data}})
	if err != nil {
		return nil, fmt.Errorf("index snapshot: %w", err)
	}
	total.SnapshotID = idxResult.SnapshotID
	total.KeyFingerprint = idxResult.KeyFingerprint
	total.BytesScanned += idxResult.BytesScanned
	total.BytesUploaded += idxResult.BytesUploaded
	total.ChunkCount = idxResult.ChunkCount
	total.Duration = now().Sub(started)
	if total.BytesUploaded > 0 {
		total.DedupRatio = float64(total.BytesScanned) / float64(total.BytesUploaded)
	}
	total.Details = rundetail.WrapManifest(rundetail.TypeGitHub, data)

	if failed > 0 {
		var msgs []string
		for _, r := range results {
			if r.Status == "failed" {
				msgs = append(msgs, r.FullName+": "+r.Error)
			}
		}
		msg := fmt.Sprintf("%d of %d repositories failed: %s", failed, len(units), truncate(strings.Join(msgs, "; "), 8<<10))
		total.ErrorMessage = msg
		if failed == len(units) {
			total.Status = "failed"
			return total, errors.New(msg)
		}
		total.Status = "partial"
		slog.Warn("GitHub backup completed with failed repositories", "failed", failed, "repositories", len(units))
	}
	return total, nil
}

// selectRepos resolves the sources into units with unique groups. complete is false
// when a source could not be listed (the state of unlisted repositories is kept).
func selectRepos(ctx context.Context, c *spec.Client, s *spec.Spec, viewer, jobGroup string, warn func(string, ...any)) ([]Unit, bool, error) {
	type entry struct {
		repo     spec.Repo
		sources  []string
		explicit bool
	}
	byName := map[string]*entry{}
	var order []string
	add := func(r spec.Repo, source string, explicit bool) {
		k := strings.ToLower(r.FullName)
		e := byName[k]
		if e == nil {
			e = &entry{repo: r}
			byName[k] = e
			order = append(order, k)
		}
		e.sources = append(e.sources, source)
		e.explicit = e.explicit || explicit
	}
	complete := true
	listed := 0
	for _, o := range s.Sources.Orgs {
		repos, err := c.OrgRepos(ctx, o.Name, o.Type)
		if spec.IsNotFound(err) {
			// A user entered as an organization: back up what the user owns
			if repos, err = c.UserRepos(ctx, o.Name, strings.EqualFold(o.Name, viewer)); err == nil {
				warn("%s is a user, not an organization; backed up the repositories it owns", o.Name)
			}
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, ctx.Err()
			}
			warn("organization %s: %v", o.Name, err)
			complete = false
			continue
		}
		listed++
		for _, r := range repos {
			add(r, "org:"+o.Name, false)
		}
	}
	for _, u := range s.Sources.Users {
		repos, err := c.UserRepos(ctx, u, strings.EqualFold(u, viewer))
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, ctx.Err()
			}
			warn("user %s: %v", u, err)
			complete = false
			continue
		}
		listed++
		for _, r := range repos {
			add(r, "user:"+u, false)
		}
	}
	if s.Sources.Starred {
		repos, err := c.Starred(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, ctx.Err()
			}
			warn("starred repositories: %v", err)
			complete = false
		} else {
			listed++
			for _, r := range repos {
				add(r, "starred", false)
			}
		}
	}
	for _, full := range s.Sources.Repos {
		owner, name, _ := spec.SplitFullName(full)
		r, err := c.Repo(ctx, owner, name)
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, ctx.Err()
			}
			warn("repository %s: %v", full, err)
			complete = false
			continue
		}
		listed++
		add(*r, "repo", true)
	}
	gists, gistsComplete, gistsListed, err := selectGists(ctx, c, s.Sources.Gists, warn)
	if err != nil {
		return nil, false, err
	}
	complete = complete && gistsComplete
	listed += gistsListed
	if listed == 0 {
		return nil, false, errors.New("no source could be listed (see the warnings)")
	}

	var units []Unit
	for _, k := range order {
		e := byName[k]
		r := e.repo
		if !e.explicit {
			if !spec.Selected(r.FullName, s.Include, s.Exclude) || (s.SkipForks && r.Fork) || (s.SkipArchived && r.Archived) {
				continue
			}
		}
		if r.Disabled {
			warn("repository %s is disabled by GitHub; skipped", r.FullName)
			continue
		}
		rr := r
		units = append(units, Unit{Kind: kindRepo, Name: r.FullName, Archive: spec.ArchiveRepo, Repo: &rr, Sources: e.sources})
	}
	units = append(units, gists...)
	// Group names: <job group>-<owner>-<name>, a short tag of the full name on collision
	seen := map[string]bool{}
	sort.SliceStable(units, func(i, j int) bool { return strings.ToLower(units[i].Name) < strings.ToLower(units[j].Name) })
	for i := range units {
		g := spec.RepoGroup(jobGroup, units[i].Repo.Owner.Login, units[i].Repo.Name)
		if units[i].Kind == kindGist {
			g = spec.GistGroup(jobGroup, units[i].Repo.Owner.Login, units[i].Repo.Name)
		}
		if seen[g] {
			g += "-" + shortTag(units[i].Name)
		}
		seen[g] = true
		units[i].Group = g
	}
	return units, complete, nil
}

const (
	kindRepo = "repository"
	kindGist = "gist"
)

// selectGists resolves the gist sources into units (groups are assigned by the caller)
func selectGists(ctx context.Context, c *spec.Client, g spec.Gists, warn func(string, ...any)) (units []Unit, complete bool, listed int, err error) {
	complete = true
	byID := map[string]*Unit{}
	var order []string
	add := func(gist spec.Gist, source string) {
		id := strings.ToLower(gist.ID)
		if u := byID[id]; u != nil {
			u.Sources = append(u.Sources, source)
			return
		}
		owner := gist.OwnerLogin()
		r := spec.Repo{FullName: "gist:" + owner + "/" + id, Name: id, Private: !gist.Public, CloneURL: gist.GitPullURL, Raw: gist.Raw}
		r.Owner.Login = owner
		byID[id] = &Unit{Kind: kindGist, Name: r.FullName, Archive: spec.ArchiveRepo, Repo: &r, Sources: []string{source}}
		order = append(order, id)
	}
	list := func(what, user string, starred bool, source string) error {
		gists, err := c.Gists(ctx, user, starred)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			warn("%s: %v", what, err)
			complete = false
			return nil
		}
		listed++
		for _, gist := range gists {
			add(gist, source)
		}
		return nil
	}
	if g.Own {
		if err := list("own gists", "", false, "gists"); err != nil {
			return nil, false, 0, err
		}
	}
	if g.Starred {
		if err := list("starred gists", "", true, "starred gists"); err != nil {
			return nil, false, 0, err
		}
	}
	for _, u := range g.Users {
		if err := list("gists of "+u, u, false, "gists:"+u); err != nil {
			return nil, false, 0, err
		}
	}
	for _, id := range g.IDs {
		gist, err := c.Gist(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return nil, false, 0, ctx.Err()
			}
			warn("gist %s: %v", id, err)
			complete = false
			continue
		}
		listed++
		add(*gist, "gist")
	}
	for _, id := range order {
		units = append(units, *byID[id])
	}
	return units, complete, listed, nil
}

// repoState survives between runs (and between attempts of one run)
type repoState struct {
	FullName     string `json:"full_name"`
	LastRunID    string `json:"last_run_id"`
	LastStatus   string `json:"last_status"`
	LastSnapshot int64  `json:"last_snapshot"`
}

func statePath(stateDir, group string) string {
	return filepath.Join(stateDir, dirState, group+".json")
}

func loadState(stateDir, group string) repoState {
	var st repoState
	if data, err := os.ReadFile(statePath(stateDir, group)); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func saveState(stateDir, group string, st repoState) error {
	data, _ := json.MarshalIndent(st, "", "  ")
	tmp := statePath(stateDir, group) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath(stateDir, group))
}

// backupRepo produces one repository snapshot; it never returns an error, the
// outcome is the RepoResult (one failing repository must not fail the job)
func backupRepo(ctx context.Context, c *spec.Client, git *Git, s *spec.Spec, o RunOptions, u *Unit, now func() time.Time) spec.RepoResult {
	r := u.Repo
	res := spec.RepoResult{Kind: u.Kind, FullName: r.FullName, Sources: u.Sources, Group: u.Group, Private: r.Private, Fork: r.Fork, Archived: r.Archived,
		DefaultBranch: r.DefaultBranch, Status: "completed"}
	fail := func(err error) spec.RepoResult {
		if ctx.Err() != nil {
			res.Status, res.Error = "cancelled", "cancelled"
			return res
		}
		res.Status, res.Error = "failed", err.Error()
		slog.Error("GitHub repository failed", "repository", r.FullName, "error", err)
		return res
	}
	warn := func(msg string) { res.Warnings = append(res.Warnings, msg) }

	st := loadState(o.StateDir, u.Group)
	if st.LastRunID == o.Session.BackupRunID.String() && st.LastStatus == "completed" {
		res.SnapshotTime = st.LastSnapshot
		res.Warnings = append(res.Warnings, "finished by an earlier attempt of this run")
		return res
	}

	work := filepath.Join(o.StateDir, u.Group)
	if !s.EffKeepMirrors() {
		_ = os.RemoveAll(work)
		defer os.RemoveAll(work) //nolint:errcheck
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return fail(err)
	}
	if r.CloneURL == "" {
		return fail(errors.New("the API returned no clone URL"))
	}
	if err := checkRemote(r.CloneURL, c.APIURL, o.AllowFileRemotes); err != nil {
		return fail(err)
	}

	mirror := filepath.Join(work, dirMirror)
	if _, err := git.Mirror(ctx, r.CloneURL, mirror); err != nil {
		return fail(fmt.Errorf("mirroring: %w", err))
	}
	info, err := git.Describe(ctx, mirror)
	if err != nil {
		return fail(err)
	}
	res.Refs, res.HeadCommit = info.Refs, info.Head
	if info.Refs == 0 {
		warn("the repository is empty")
	}
	if s.Content.LFS {
		if git.LFSAvailable(ctx) {
			if err := git.FetchLFS(ctx, r.CloneURL, mirror); err != nil {
				warn("LFS objects: " + err.Error())
			}
		} else {
			warn("LFS requested but git-lfs is not installed on the agent")
		}
	}

	wiki := filepath.Join(work, dirWiki)
	if s.Content.EffWiki() && r.HasWiki {
		if _, err := git.Mirror(ctx, WikiURL(r.CloneURL), wiki); err != nil {
			if !IsRemoteNotFound(err) {
				if ctx.Err() != nil {
					return fail(err)
				}
				warn("wiki: " + err.Error())
			}
			_ = os.RemoveAll(wiki)
		} else {
			res.Wiki = true
		}
	} else {
		_ = os.RemoveAll(wiki)
	}

	meta := filepath.Join(work, dirMetadata)
	if err := os.MkdirAll(meta, 0o700); err != nil {
		return fail(err)
	}
	collect := collectMetadata
	if u.Kind == kindGist {
		collect = collectGistMetadata
	}
	if err := collect(ctx, c, s, r, meta, &res, warn); err != nil {
		return fail(err)
	}

	repoManifest, _ := json.MarshalIndent(res, "", "  ")
	if err := writeIfChanged(filepath.Join(work, spec.RepoManifestName), repoManifest); err != nil {
		return fail(err)
	}
	if err := writeIfChanged(filepath.Join(work, "RESTORE.md"), []byte(repoReadme(r.FullName, res.Wiki, u.Kind == kindGist))); err != nil {
		return fail(err)
	}
	result, err := o.Upload(ctx, u, work, []gopbs.Blob{{Name: spec.RepoManifestName, Data: repoManifest}})
	if err != nil {
		return fail(err)
	}
	if t, ok := snapshotTime(result.SnapshotID); ok {
		res.SnapshotTime = t
	}
	res.Bytes, res.Uploaded = result.BytesScanned, result.BytesUploaded
	st = repoState{FullName: r.FullName, LastRunID: o.Session.BackupRunID.String(), LastStatus: "completed", LastSnapshot: res.SnapshotTime}
	if err := saveState(o.StateDir, u.Group, st); err != nil {
		res.Warnings = append(res.Warnings, "state not saved: "+err.Error())
	}
	return res
}

// checkRemote refuses clone URLs on another host than the API (the token travels
// with every git request). github.com serves the API on api.github.com.
func checkRemote(cloneURL, apiURL string, allowFile bool) error {
	cu, err := url.Parse(cloneURL)
	if err != nil {
		return fmt.Errorf("clone URL %q: %w", cloneURL, err)
	}
	au, err := url.Parse(apiURL)
	if err != nil {
		return err
	}
	if cu.Scheme == "file" && allowFile {
		return nil
	}
	if cu.Scheme != "https" && cu.Scheme != "http" {
		return fmt.Errorf("clone URL %q is not HTTP(S)", cloneURL)
	}
	host := strings.TrimPrefix(au.Hostname(), "api.")
	if !strings.EqualFold(cu.Hostname(), host) && !strings.EqualFold(cu.Hostname(), au.Hostname()) && !strings.EqualFold(cu.Hostname(), "gist."+host) {
		return fmt.Errorf("clone URL host %s does not belong to the API host %s", cu.Hostname(), au.Hostname())
	}
	return nil
}

// collectMetadata stores the repository object and, per the job's content
// settings, issues, pull requests, comments, releases, labels and milestones
func collectMetadata(ctx context.Context, c *spec.Client, s *spec.Spec, r *spec.Repo, dir string, res *spec.RepoResult, warn func(string)) error {
	owner, name := r.Owner.Login, r.Name
	written := map[string]bool{}
	write := func(file string, data []byte) error {
		written[file] = true
		return writeIfChanged(filepath.Join(dir, file), data)
	}
	// Files of content that was switched off since the last run
	defer func() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !written[e.Name()] {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}()
	repoJSON, err := json.MarshalIndent(r.Raw, "", "  ")
	if err != nil {
		repoJSON = r.Raw
	}
	if err := write("repository.json", repoJSON); err != nil {
		return err
	}
	type list struct {
		file, sub string
		query     url.Values
		count     *int
	}
	var lists []list
	if s.Content.EffIssues() {
		var comments, reviewComments int
		lists = append(lists,
			// Issues include pull requests (the pull_request key tells them apart)
			list{"issues.json", "issues", url.Values{"state": {"all"}, "sort": {"created"}, "direction": {"asc"}}, &res.Issues},
			list{"issue-comments.json", "issues/comments", url.Values{"sort": {"created"}, "direction": {"asc"}}, &comments},
			list{"pulls.json", "pulls", url.Values{"state": {"all"}, "sort": {"created"}, "direction": {"asc"}}, &res.Pulls},
			list{"pull-review-comments.json", "pulls/comments", url.Values{"sort": {"created"}, "direction": {"asc"}}, &reviewComments},
			list{"labels.json", "labels", nil, nil},
			list{"milestones.json", "milestones", url.Values{"state": {"all"}}, nil},
		)
		defer func() { res.Comments = comments + reviewComments }()
	}
	if s.Content.EffReleases() {
		lists = append(lists, list{"releases.json", "releases", nil, &res.Releases})
	}
	for _, l := range lists {
		items, err := c.RepoList(ctx, owner, name, l.sub, l.query)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			// Metadata is secondary to the git data: keep the last copy, warn, carry on
			written[l.file] = true
			warn(l.sub + ": " + err.Error())
			continue
		}
		if l.count != nil {
			*l.count = len(items)
		}
		if err := write(l.file, spec.MarshalList(items)); err != nil {
			return err
		}
	}
	if res.Issues >= res.Pulls {
		res.Issues -= res.Pulls // the issues list counts pull requests too
	}
	return nil
}

// writeIfChanged leaves an identical file alone, so its mtime holds and change
// detection reuses it from the previous snapshot instead of reading it again
func writeIfChanged(path string, data []byte) error {
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// collectGistMetadata stores the gist object and its comments
func collectGistMetadata(ctx context.Context, c *spec.Client, s *spec.Spec, r *spec.Repo, dir string, res *spec.RepoResult, warn func(string)) error {
	gistJSON, err := json.MarshalIndent(r.Raw, "", "  ")
	if err != nil {
		gistJSON = r.Raw
	}
	if err := writeIfChanged(filepath.Join(dir, "gist.json"), gistJSON); err != nil {
		return err
	}
	comments, err := c.GistComments(ctx, r.Name)
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		warn("comments: " + err.Error()) // keep the last copy
		return nil
	}
	res.Comments = len(comments)
	return writeIfChanged(filepath.Join(dir, "comments.json"), spec.MarshalList(comments))
}

// pruneState removes the mirrors and state of repositories no longer selected
func pruneState(stateDir string, units []Unit, warn func(string, ...any)) {
	keep := map[string]bool{dirIndex: true, dirState: true}
	for _, u := range units {
		keep[u.Group] = true
	}
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if keep[e.Name()] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(stateDir, e.Name())); err != nil {
			warn("removing the old mirror %s: %v", e.Name(), err)
		}
	}
	states, _ := os.ReadDir(filepath.Join(stateDir, dirState))
	for _, e := range states {
		if !keep[strings.TrimSuffix(e.Name(), ".json")] {
			_ = os.Remove(filepath.Join(stateDir, dirState, e.Name()))
		}
	}
}

// snapshotTime parses the time of "host/<group>/<RFC3339>"
func snapshotTime(snapshot string) (int64, bool) {
	i := strings.LastIndexByte(snapshot, '/')
	if i < 0 {
		return 0, false
	}
	t, err := time.Parse("2006-01-02T15:04:05Z", snapshot[i+1:])
	if err != nil {
		return 0, false
	}
	return t.Unix(), true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func shortTag(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)[:6]
}

func restoreNotes(backupType, group string) map[string]string {
	return map[string]string{
		"git":      "repo.git is a bare mirror (every branch, tag and pull request ref). Restore the archive, then: git clone repo.git ./src  — or push everything to a new remote: git -C repo.git push --mirror <new remote URL>",
		"wiki":     "wiki.git is the mirror of the repository wiki; push it with git -C wiki.git push --mirror <repo URL without .git>.wiki.git (create the first wiki page in the UI first).",
		"metadata": "metadata/ holds the API objects as JSON: repository.json, issues.json (issues and pull requests), issue-comments.json, pulls.json, pull-review-comments.json, labels.json, milestones.json, releases.json. GitHub has no bulk import for these; they are for reference or scripted re-creation.",
		"snapshot": fmt.Sprintf("proxmox-backup-client restore %s/<repository group>/<time> repo.pxar ./out   # repository groups are listed under repos[]; the index is %s/%s", backupType, backupType, group),
	}
}

func restoreReadme(m *spec.Manifest) string {
	var b strings.Builder
	b.WriteString("# Restoring this GitHub backup\n\n")
	keys := make([]string, 0, len(m.Restore))
	for k := range m.Restore {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "## %s\n\n%s\n\n", k, m.Restore[k])
	}
	b.WriteString("## Repositories\n\n")
	for _, r := range m.Repos {
		fmt.Fprintf(&b, "- %s → group %s (%s)\n", r.FullName, r.Group, r.Status)
	}
	return b.String()
}

func repoReadme(fullName string, wiki, gist bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", fullName)
	b.WriteString("repo.git is a bare mirror of the repository.\n\n    git clone repo.git ./" + filepath.Base(fullName) + "\n    git -C repo.git push --mirror <new remote URL>\n\n")
	if gist {
		b.WriteString("To recreate the gist, create a new gist and push: git -C repo.git push --force <new gist URL>.git HEAD:main\n\nmetadata/gist.json is the gist object (files, description, visibility); metadata/comments.json its comments.\n")
		return b.String()
	}
	if wiki {
		b.WriteString("wiki.git is the wiki mirror; push it with git -C wiki.git push --mirror <remote>.wiki.git\n\n")
	}
	b.WriteString("metadata/ holds issues, pull requests, comments, releases, labels and milestones as returned by the GitHub API.\n")
	return b.String()
}
