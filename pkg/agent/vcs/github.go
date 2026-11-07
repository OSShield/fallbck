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
	"strings"

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
func (p *GitHubProvider) Metadata(ctx context.Context, pr Project, dir string, r *spec.RepoResult) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	api := p.api()
	written := map[string]bool{}
	write := func(name string, data []byte) error {
		written[name] = true
		return writeIfChanged(filepath.Join(dir, name), data)
	}
	defer func() {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !written[e.Name()] {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}()
	keep := func(name, what string, err error) {
		written[name] = true
		r.Warnings = append(r.Warnings, "metadata "+what+": "+err.Error())
	}

	if pr.Kind == "gist" {
		gist, err := api.Gist(ctx, pr.Ref)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			keep("gist.json", "gist", err)
		} else if err := write("gist.json", indentJSON(gist.Raw)); err != nil {
			return err
		}
		comments, err := api.GistComments(ctx, pr.Ref)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			keep("comments.json", "comments", err)
			return nil
		}
		r.Comments = len(comments)
		return write("comments.json", marshalList(comments))
	}

	owner, name, _ := strings.Cut(pr.Ref, "/")
	asc := url.Values{"sort": {"created"}, "direction": {"asc"}}
	all := url.Values{"state": {"all"}, "sort": {"created"}, "direction": {"asc"}}
	lists := []struct {
		file, sub string
		q         url.Values
		count     *int
	}{
		{"issues.json", "issues", all, &r.Issues},
		{"issue-comments.json", "issues/comments", asc, nil},
		{"pulls.json", "pulls", all, &r.Pulls},
		{"pull-review-comments.json", "pulls/comments", asc, nil},
		{"releases.json", "releases", nil, &r.Releases},
		{"labels.json", "labels", nil, nil},
		{"milestones.json", "milestones", url.Values{"state": {"all"}}, nil},
	}
	comments := 0
	for _, l := range lists {
		q := url.Values{}
		for k, v := range l.q {
			q[k] = v
		}
		items, err := api.RepoList(ctx, owner, name, l.sub, q)
		if err != nil {
			if ctx.Err() != nil {
				return err
			}
			keep(l.file, l.sub, err)
			continue
		}
		if l.count != nil {
			*l.count = len(items)
		}
		if strings.HasSuffix(l.sub, "comments") {
			comments += len(items)
		}
		if err := write(l.file, marshalList(items)); err != nil {
			return err
		}
	}
	r.Comments = comments
	// The issues listing counts pull requests too
	if r.Issues >= r.Pulls {
		r.Issues -= r.Pulls
	}
	return nil
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
