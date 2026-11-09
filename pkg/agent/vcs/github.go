package vcs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	spec "github.com/osshield/fallbck/pkg/vcs"
)

// GitHubProvider lists owners, repositories, stars and gists through the REST API. Clone
// URLs are built from the connection URL (and gist host), never taken from the API.
type GitHubProvider struct {
	Spec        *spec.Spec
	Credentials spec.Credentials
	Client      *http.Client
	// API overrides the REST client (tests)
	API *spec.GitHubClient

	viewer string
}

// GistsDir is the archive directory of gists: GitHub logins cannot contain '_', so
// no owner directory collides with it
const GistsDir = "_gists"

func (p *GitHubProvider) api() *spec.GitHubClient {
	if p.API == nil {
		p.API = spec.NewGitHubClient(p.Credentials, p.Client)
	}
	return p.API
}

// Projects lists, filters and maps the job's repositories and gists. A source that
// cannot be listed is a warning unless none can be.
func (p *GitHubProvider) Projects(ctx context.Context) ([]Project, []string, error) {
	api := p.api()
	v, err := api.Viewer(ctx)
	if err != nil {
		return nil, nil, err
	}
	p.viewer = v.Login
	s := p.Spec
	base := strings.TrimRight(p.Credentials.BaseURL, "/")

	var warnings []string
	listed, failed := 0, 0
	note := func(what string, err error) bool {
		if err == nil {
			listed++
			return true
		}
		failed++
		warnings = append(warnings, what+": "+err.Error())
		return false
	}

	type entry struct {
		repo     spec.GitHubRepo
		explicit bool
	}
	byID := map[int64]*entry{}
	var order []int64
	add := func(r spec.GitHubRepo, explicit bool) {
		if e := byID[r.ID]; e != nil {
			e.explicit = e.explicit || explicit
			return
		}
		byID[r.ID] = &entry{repo: r, explicit: explicit}
		order = append(order, r.ID)
	}
	for _, owner := range s.Groups {
		repos, user, err := api.OwnerRepos(ctx, owner, v.Login)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if note("owner "+owner, err) {
			if user && !strings.EqualFold(owner, v.Login) {
				warnings = append(warnings, owner+" is a user, not an organization: its public repositories are backed up")
			}
			for _, r := range repos {
				add(r, false)
			}
		}
	}
	if s.Starred {
		repos, err := api.StarredRepos(ctx)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if note("starred repositories", err) {
			for _, r := range repos {
				add(r, false)
			}
		}
	}
	for _, u := range s.Repositories {
		owner, name, _ := spec.GitHubRepoFromURL(u, base)
		r, err := api.Repo(ctx, owner, name)
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if note("repository "+owner+"/"+name, err) {
			add(*r, true)
		}
	}

	var out []Project
	for _, id := range order {
		e := byID[id]
		r := e.repo
		path := r.Owner.Login + "/" + r.Name
		if _, _, ok := spec.GitHubRepoFromURL(base+"/"+path, base); !ok {
			warnings = append(warnings, fmt.Sprintf("repository %d: skipped, GitHub returned the unusable name %q", r.ID, r.FullName))
			continue
		}
		if r.Disabled {
			warnings = append(warnings, "repository "+path+" is disabled by GitHub: skipped")
			continue
		}
		if !e.explicit && (s.Excluded(path) || (r.Archived && !s.EffArchived()) || (r.Fork && !s.EffForks())) {
			continue
		}
		pr := Project{ID: r.ID, Key: fmt.Sprintf("r%d", r.ID), Path: path, URL: base + "/" + path + ".git",
			Size: r.Size * 1024, Archived: r.Archived, Fork: r.Fork, Ref: path}
		if r.HasWiki && s.Workloads.EffWiki() {
			pr.WikiURL = base + "/" + path + ".wiki.git"
		}
		if r.PushedAt != nil {
			pr.LastActivity = *r.PushedAt
		}
		out = append(out, pr)
	}

	gists, gistWarnings, gl, gf := p.gists(ctx)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	warnings = append(warnings, gistWarnings...)
	listed, failed = listed+gl, failed+gf
	out = append(out, gists...)
	if listed == 0 && failed > 0 {
		return nil, nil, errors.New("none of the job's sources could be listed: " + strings.Join(warnings, "; "))
	}
	return out, warnings, nil
}

// gists resolves the gist sources; listed/failed count the listings
func (p *GitHubProvider) gists(ctx context.Context) (out []Project, warnings []string, listed, failed int) {
	g := p.Spec.Gists
	if !g.Any() {
		return nil, nil, 0, 0
	}
	api := p.api()
	gistBase := spec.GistBaseURL(p.Credentials.BaseURL)
	byID := map[string]spec.GitHubGist{}
	var order []string
	add := func(list []spec.GitHubGist) {
		for _, gist := range list {
			id := strings.ToLower(gist.ID)
			if _, ok := byID[id]; !ok {
				byID[id] = gist
				order = append(order, id)
			}
		}
	}
	listing := func(what, user string, starred bool) {
		list, err := api.Gists(ctx, user, starred)
		if err != nil {
			failed++
			warnings = append(warnings, what+": "+err.Error())
			return
		}
		listed++
		add(list)
	}
	if g.Own {
		listing("own gists", "", false)
	}
	if g.Starred {
		listing("starred gists", "", true)
	}
	for _, u := range g.Users {
		listing("gists of "+u, u, false)
	}
	for _, id := range g.IDs {
		gist, err := api.Gist(ctx, id)
		if err != nil {
			failed++
			warnings = append(warnings, "gist "+id+": "+err.Error())
			continue
		}
		listed++
		add([]spec.GitHubGist{*gist})
	}
	for _, id := range order {
		gist := byID[id]
		owner := gist.OwnerLogin()
		if !spec.ValidGistID(id) || !validGistOwner(owner) {
			warnings = append(warnings, fmt.Sprintf("gist %q of %q: skipped, unusable id or owner", id, owner))
			continue
		}
		out = append(out, Project{Key: "g" + id, Path: GistsDir + "/" + owner + "/" + id, URL: gistBase + "/" + id + ".git", Kind: "gist", Ref: id})
	}
	return out, warnings, listed, failed
}

func validGistOwner(owner string) bool {
	return owner == "anonymous" || spec.ValidGitHubLogin(owner)
}

// Describe adds the token's user to the manifest source
func (p *GitHubProvider) Describe(s *spec.SourceInfo) {
	s.Username = p.viewer
}

// ExtraURLs are the hosts outside the connection URL that need the token (gists)
func (p *GitHubProvider) ExtraURLs() []string {
	if p.Spec.Gists.Any() && spec.IsGitHubCom(p.Credentials.BaseURL) {
		return []string{spec.GistBaseURL(p.Credentials.BaseURL)}
	}
	return nil
}

// Metadata stores a repository's issues, pulls, comments, releases, labels and milestones,
// or a gist and its comments; a failed list keeps its last file and becomes a warning.
// With since set, issues, pulls and comments only fetch what changed after it and are
// merged into the last files; complete reports that every list was fetched.
func (p *GitHubProvider) Metadata(ctx context.Context, pr Project, dir string, since time.Time, r *spec.RepoResult) (complete bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	api := p.api()
	written := map[string]bool{}
	write := func(name string, data []byte) error {
		written[name] = true
		return writeIfChanged(filepath.Join(dir, name), data)
	}
	defer func() {
		// Do not remove everything if an error occurred during the run
		// Only a successful run can safely remove stale files, a cancelled
		// or failed run might delete repositories that are still valid
		if err != nil {
			return
		}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !written[e.Name()] {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}()
	complete = true
	keep := func(name, what string, err error) {
		written[name] = true
		complete = false
		r.Warnings = append(r.Warnings, "metadata "+what+": "+err.Error())
	}

	if pr.Kind == "gist" {
		gist, err := api.Gist(ctx, pr.Ref)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			keep("gist.json", "gist", err)
		} else if err := write("gist.json", indentJSON(gist.Raw)); err != nil {
			return false, err
		}
		comments, err := api.GistComments(ctx, pr.Ref)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			keep("comments.json", "comments", err)
			return complete, nil
		}
		r.Comments = len(comments)
		return complete, write("comments.json", marshalList(comments))
	}

	owner, name, _ := strings.Cut(pr.Ref, "/")
	asc := url.Values{"sort": {"created"}, "direction": {"asc"}}
	all := url.Values{"state": {"all"}, "sort": {"created"}, "direction": {"asc"}}
	// incremental: "since" for endpoints that take since=, "paged" for pulls (no
	// since=: listed newest update first, paging stops past since), "" always whole
	lists := []struct {
		file, sub, incremental string
		q                      url.Values
	}{
		{"issues.json", "issues", "since", all},
		{"issue-comments.json", "issues/comments", "since", asc},
		{"pulls.json", "pulls", "paged", all},
		{"pull-review-comments.json", "pulls/comments", "since", asc},
		{"releases.json", "releases", "", nil},
		{"labels.json", "labels", "", nil},
		{"milestones.json", "milestones", "", url.Values{"state": {"all"}}},
	}
	// ponytail: an issue or comment deleted on GitHub stays in the files until the
	// next full pass (metadataFullEvery); only a full listing can tell
	cut := since.Add(-metadataSkew)
	for _, l := range lists {
		var old []json.RawMessage
		incr := !since.IsZero() && l.incremental != ""
		if incr {
			var rerr error
			// no usable last file (first pass, workload switched back on): list it whole
			old, rerr = readList(filepath.Join(dir, l.file))
			incr = rerr == nil
		}
		q, more := l.q, (func([]json.RawMessage) bool)(nil)
		switch {
		case incr && l.incremental == "since":
			q = url.Values{"since": {cut.UTC().Format(time.RFC3339)}}
			for k, v := range l.q {
				q[k] = v
			}
		case incr:
			q = url.Values{"state": {"all"}, "sort": {"updated"}, "direction": {"desc"}}
			more = func(page []json.RawMessage) bool {
				var last metaItem
				return len(page) > 0 && json.Unmarshal(page[len(page)-1], &last) == nil && !last.UpdatedAt.Before(cut)
			}
		}
		items, err := api.RepoList(ctx, owner, name, l.sub, q, more)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			keep(l.file, l.sub, err)
			continue
		}
		if incr {
			items = mergeByID(old, items)
		}
		switch l.sub {
		case "issues":
			// The issues listing returns pull requests too
			r.Issues = 0
			for _, it := range items {
				var m metaItem
				if json.Unmarshal(it, &m) == nil && len(m.PullRequest) == 0 {
					r.Issues++
				}
			}
		case "pulls":
			r.Pulls = len(items)
		case "releases":
			r.Releases = len(items)
		case "issues/comments", "pulls/comments":
			r.Comments += len(items)
		}
		if err := write(l.file, marshalList(items)); err != nil {
			return false, err
		}
	}
	return complete, nil
}

// metadataSkew re-reads this much before since, for clock skew between the agent and
// GitHub; merging makes the overlap harmless
const metadataSkew = 10 * time.Minute

// metaItem is what merging and counting need from a listed issue, pull or comment
type metaItem struct {
	ID          int64           `json:"id"`
	UpdatedAt   time.Time       `json:"updated_at"`
	PullRequest json.RawMessage `json:"pull_request"`
}

// readList loads a list file written by marshalList, items compacted
func readList(path string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, err
	}
	for i, it := range items {
		var b bytes.Buffer
		if json.Compact(&b, it) == nil {
			items[i] = b.Bytes()
		}
	}
	return items, nil
}

// mergeByID lays fresh items over old ones with the same id and sorts by id, which
// is creation order (what a full listing returns)
func mergeByID(old, fresh []json.RawMessage) []json.RawMessage {
	type entry struct {
		id   int64
		item json.RawMessage
	}
	var out []entry
	at := map[int64]int{}
	for _, it := range append(old, fresh...) {
		var m metaItem
		_ = json.Unmarshal(it, &m)
		if i, ok := at[m.ID]; ok && m.ID != 0 {
			out[i].item = it
			continue
		}
		at[m.ID] = len(out)
		out = append(out, entry{m.ID, it})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].id < out[j].id })
	items := make([]json.RawMessage, len(out))
	for i, e := range out {
		items[i] = e.item
	}
	return items
}

// writeIfChanged leaves an identical file alone, so its mtime holds and change
// detection reuses it from the previous snapshot
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

func indentJSON(raw json.RawMessage) []byte {
	var b bytes.Buffer
	if json.Indent(&b, raw, "", "  ") != nil {
		return raw
	}
	b.WriteByte('\n')
	return b.Bytes()
}

// marshalList renders a list as indented JSON, sorted as the API returned it
func marshalList(items []json.RawMessage) []byte {
	if len(items) == 0 {
		return []byte("[]\n")
	}
	var b bytes.Buffer
	b.WriteString("[\n")
	for i, it := range items {
		var ind bytes.Buffer
		if json.Indent(&ind, it, "  ", "  ") != nil {
			ind.Reset()
			ind.Write(it)
		}
		b.WriteString("  ")
		b.Write(ind.Bytes())
		if i < len(items)-1 {
			b.WriteByte(',')
		}
		b.WriteByte('\n')
	}
	b.WriteString("]\n")
	return b.Bytes()
}
