package vcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Gists selects GitHub gists; each is a git repository of its own. Filters do not apply.
type Gists struct {
	// Own is every gist of the token's user, secret ones included
	Own     bool `json:"own,omitempty"`
	Starred bool `json:"starred,omitempty"`
	// Users back up the public gists of these accounts; IDs are explicit gist ids or URLs
	Users []string `json:"users,omitempty"`
	IDs   []string `json:"ids,omitempty"`
}

// Any reports whether a gist source is set
func (g *Gists) Any() bool {
	return g != nil && (g.Own || g.Starred || len(g.Users) > 0 || len(g.IDs) > 0)
}

var (
	// githubLoginRe is a GitHub user or organization login
	githubLoginRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	// hex ids, or the short numeric ids of gists from before 2012 (gist.github.com/1234567)
	gistIDRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{20,40}|[0-9]{1,12})$`)
)

// ValidGitHubLogin / ValidGistID check names the API returns before they become paths
func ValidGitHubLogin(s string) bool { return githubLoginRe.MatchString(s) }
func ValidGistID(s string) bool      { return gistIDRe.MatchString(s) }

func (g *Gists) normalize() error {
	var users []string
	for _, u := range cleanList(g.Users) {
		if !githubLoginRe.MatchString(u) {
			return specErr("gists.users: %q is not a GitHub login", u)
		}
		if !containsFold(users, u) {
			users = append(users, u)
		}
	}
	var ids []string
	for _, raw := range cleanList(g.IDs) {
		id, ok := GistID(raw)
		if !ok {
			return specErr("gists.ids: %q is not a gist id or URL", raw)
		}
		if !containsFold(ids, id) {
			ids = append(ids, id)
		}
	}
	g.Users, g.IDs = users, ids
	return nil
}

// GistID takes a gist id or URL (https://gist.github.com/<user>/<id>, with .git or a
// #fragment) and returns the lower-cased id
func GistID(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if i := strings.IndexAny(s, "#?"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		s = s[i+1:]
	}
	if !gistIDRe.MatchString(s) {
		return "", false
	}
	return strings.ToLower(s), true
}

func cleanList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// validateGitHub: groups are owner logins, repositories are owner/name below the
// connection URL, and the listing needs a token (60 anonymous requests an hour)
func (s *Spec) validateGitHub(c *Connection) error {
	for _, g := range s.Groups {
		if !githubLoginRe.MatchString(g) {
			return specErr("groups: %q is not a GitHub organization or user login", g)
		}
	}
	for _, r := range s.Repositories {
		if _, _, ok := GitHubRepoFromURL(r, c.BaseURL); !ok {
			return specErr("repository %s is not an owner/name repository below %s", r, c.BaseURL)
		}
	}
	if len(s.Groups) == 0 && len(s.Repositories) == 0 && !s.Starred && !s.Gists.Any() {
		return specErr("choose owners, repositories, starred repositories or gists")
	}
	if s.Profile == "" && c.Token == "" {
		return specErr("the connection stores no token; name the agent credential profile that holds it")
	}
	return nil
}

// GitHubRepoFromURL splits a normalised repository URL below baseURL into owner/name
func GitHubRepoFromURL(repoURL, baseURL string) (owner, name string, ok bool) {
	if !UnderBaseURL(repoURL, baseURL) {
		return "", "", false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(repoURL, strings.TrimRight(baseURL, "/")+"/"), ".git")
	owner, name, found := strings.Cut(rest, "/")
	if !found || !githubLoginRe.MatchString(owner) || !githubRepoNameRe.MatchString(name) || name == "." || name == ".." {
		return "", "", false
	}
	return owner, name, true
}

var githubRepoNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

func (s *Spec) githubSummary() string {
	// owners or repositories alone read fine in the generic summary
	if !s.Starred && !s.Gists.Any() && (len(s.Groups) == 0 || len(s.Repositories) == 0) {
		return ""
	}
	var parts []string
	if len(s.Groups) > 0 {
		parts = append(parts, "owners "+strings.Join(s.Groups, ", "))
	}
	switch n := len(s.Repositories); {
	case n == 1:
		parts = append(parts, "1 repository")
	case n > 1:
		parts = append(parts, strconv.Itoa(n)+" repositories")
	}
	if s.Starred {
		parts = append(parts, "starred")
	}
	if g := s.Gists; g.Any() {
		if g.Own {
			parts = append(parts, "own gists")
		}
		if g.Starred {
			parts = append(parts, "starred gists")
		}
		for _, u := range g.Users {
			parts = append(parts, "gists of "+u)
		}
		if n := len(g.IDs); n > 0 {
			parts = append(parts, strconv.Itoa(n)+" gists")
		}
	}
	return strings.Join(parts, ", ")
}

// IsGitHubCom reports whether the URL is github.com (API and gists on other hosts)
func IsGitHubCom(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	h := strings.ToLower(u.Hostname())
	return h == "github.com" || h == "www.github.com"
}

// GitHubAPIURL is the REST endpoint of a connection: api.github.com, or <base>/api/v3
// on GitHub Enterprise Server
func GitHubAPIURL(baseURL string) string {
	if IsGitHubCom(baseURL) {
		return "https://api.github.com"
	}
	return strings.TrimRight(baseURL, "/") + "/api/v3"
}

// GistBaseURL is where gists are cloned from; GitHub Enterprise serves them below the
// connection URL, github.com from gist.github.com (the token goes there too)
func GistBaseURL(baseURL string) string {
	if IsGitHubCom(baseURL) {
		return "https://gist.github.com"
	}
	return strings.TrimRight(baseURL, "/") + "/gist"
}

// GitHubClient is a minimal GitHub REST client: token auth, Link pagination that
// never leaves the API host, and rate limits waited out instead of failing the run
type GitHubClient struct {
	APIURL string
	Token  string
	HTTP   *http.Client
	// MaxRateWait caps one rate-limit pause (default 1h)
	MaxRateWait time.Duration
	// Sleep is replaced in tests
	Sleep func(ctx context.Context, d time.Duration) error
}

// NewGitHubClient builds the client of a github connection
func NewGitHubClient(c Credentials, client *http.Client) *GitHubClient {
	return &GitHubClient{APIURL: GitHubAPIURL(c.BaseURL), Token: c.Token, HTTP: client}
}

// GitHubError is a non-2xx answer
type GitHubError struct {
	Status  int
	Path    string
	Message string
}

func (e *GitHubError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return fmt.Sprintf("GitHub rejected the token on %s (expired, revoked or mistyped)", e.Path)
	}
	return fmt.Sprintf("GitHub answered %d to %s: %s", e.Status, e.Path, e.Message)
}

// IsGitHubNotFound reports a 404 or 410 (missing, or a feature such as issues disabled)
func IsGitHubNotFound(err error) bool {
	var e *GitHubError
	return errors.As(err, &e) && (e.Status == http.StatusNotFound || e.Status == http.StatusGone)
}

func ctxSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// do sends one GET, retrying rate limits and transient errors; the caller closes
// the body of a 2xx response
func (c *GitHubClient) do(ctx context.Context, rawURL string) (*http.Response, error) {
	sleep := c.Sleep
	if sleep == nil {
		sleep = ctxSleep
	}
	maxWait := c.MaxRateWait
	if maxWait <= 0 {
		maxWait = time.Hour
	}
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "fallbck-agent")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil || attempt >= 4 {
				return nil, fmt.Errorf("request to %s failed (the caller needs outbound HTTPS to it): %w", c.APIURL, err)
			}
			if err := sleep(ctx, githubBackoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode/100 == 2 {
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		apiErr := &GitHubError{Status: resp.StatusCode, Path: path, Message: githubErrorText(body)}
		if wait, limited := githubRateLimitWait(resp, time.Now()); limited {
			if wait > maxWait || attempt >= 8 {
				return nil, fmt.Errorf("rate limited on %s (the limit resets in %s): %w", path, wait.Round(time.Second), apiErr)
			}
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode >= 500 && attempt < 4 {
			if err := sleep(ctx, githubBackoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		return nil, apiErr
	}
}

func githubBackoff(attempt int) time.Duration { return time.Duration(1<<attempt) * 2 * time.Second }

// githubRateLimitWait tells a rate limit from a permission error (both may be 403):
// Retry-After for the secondary limit, the reset time once the primary quota is spent
func githubRateLimitWait(resp *http.Response, now time.Time) (time.Duration, bool) {
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return 0, false
	}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if s, err := strconv.Atoi(ra); err == nil {
			return time.Duration(s)*time.Second + time.Second, true
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			return max(time.Unix(reset, 0).Sub(now)+time.Second, time.Second), true
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return time.Minute, true
	}
	return 0, false
}

func githubErrorText(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}

func (c *GitHubClient) url(path string, query url.Values) string {
	u := strings.TrimRight(c.APIURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

func (c *GitHubClient) getJSON(ctx context.Context, path string, out any) (http.Header, error) {
	resp, err := c.do(ctx, c.url(path, nil))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return nil, fmt.Errorf("unexpected answer to %s (is %s a GitHub API?)", path, c.APIURL)
	}
	return resp.Header, nil
}

var githubLinkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// List follows the pagination of a list endpoint and returns every element verbatim.
// Only next links below the API URL are followed, so the token stays with the API.
func (c *GitHubClient) List(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	return c.ListWhile(ctx, path, query, nil)
}

// ListWhile is List that stops paging once more (when set) returns false for a page;
// that page is still returned. The query is not modified.
func (c *GitHubClient) ListWhile(ctx context.Context, path string, query url.Values, more func(page []json.RawMessage) bool) ([]json.RawMessage, error) {
	q := url.Values{"per_page": {"100"}}
	for k, v := range query {
		if k != "per_page" {
			q[k] = v
		}
	}
	next := c.url(path, q)
	var out []json.RawMessage
	for page := 0; next != ""; page++ {
		if page == maxPages {
			return nil, fmt.Errorf("listing %s: more than %d pages", path, maxPages)
		}
		resp, err := c.do(ctx, next)
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("unexpected answer to %s (is %s a GitHub API?)", path, c.APIURL)
		}
		out = append(out, items...)
		next = ""
		if more != nil && !more(items) {
			break
		}
		if m := githubLinkNextRe.FindStringSubmatch(resp.Header.Get("Link")); m != nil && strings.HasPrefix(m[1], strings.TrimRight(c.APIURL, "/")+"/") {
			next = m[1]
		}
	}
	return out, nil
}

// GitHubViewer is the token's user
type GitHubViewer struct {
	Login string `json:"login"`
	// Scopes are the classic token scopes (X-OAuth-Scopes); empty for fine-grained tokens
	Scopes []string `json:"-"`
	// Expires is the token expiry GitHub reports (GitHub-Authentication-Token-Expiration)
	Expires *time.Time `json:"-"`
}

// Viewer reads GET /user
func (c *GitHubClient) Viewer(ctx context.Context) (*GitHubViewer, error) {
	var v GitHubViewer
	h, err := c.getJSON(ctx, "/user", &v)
	if err != nil {
		return nil, err
	}
	for _, s := range strings.Split(h.Get("X-OAuth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			v.Scopes = append(v.Scopes, s)
		}
	}
	if exp := h.Get("GitHub-Authentication-Token-Expiration"); exp != "" {
		for _, layout := range []string{"2006-01-02 15:04:05 MST", "2006-01-02 15:04:05 -0700"} {
			if t, err := time.Parse(layout, exp); err == nil {
				t = t.UTC()
				v.Expires = &t
				break
			}
		}
	}
	return &v, nil
}

// GitHubRepo is the part of a repository object the agent needs; Raw is the whole object
type GitHubRepo struct {
	ID       int64  `json:"id"`
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
	Private  bool `json:"private"`
	Fork     bool `json:"fork"`
	Archived bool `json:"archived"`
	Disabled bool `json:"disabled"`
	HasWiki  bool `json:"has_wiki"`
	// Size is in KiB
	Size     int64           `json:"size"`
	PushedAt *time.Time      `json:"pushed_at"`
	Raw      json.RawMessage `json:"-"`
}

func decodeGitHub[T any](raw []json.RawMessage, set func(*T, json.RawMessage)) ([]T, error) {
	out := make([]T, 0, len(raw))
	for _, r := range raw {
		var v T
		if err := json.Unmarshal(r, &v); err != nil {
			return nil, fmt.Errorf("decoding a GitHub object: %w", err)
		}
		set(&v, r)
		out = append(out, v)
	}
	return out, nil
}

func setRepoRaw(r *GitHubRepo, raw json.RawMessage) { r.Raw = raw }

// OwnerRepos lists an organization's repositories, else a user's (user reports which);
// the token's own login uses /user/repos so its private repositories are included
func (c *GitHubClient) OwnerRepos(ctx context.Context, owner, viewer string) (repos []GitHubRepo, user bool, err error) {
	var raw []json.RawMessage
	if strings.EqualFold(owner, viewer) {
		raw, err = c.List(ctx, "/user/repos", url.Values{"affiliation": {"owner"}, "visibility": {"all"}})
		user = true
	} else {
		raw, err = c.List(ctx, "/orgs/"+url.PathEscape(owner)+"/repos", url.Values{"type": {"all"}})
		if IsGitHubNotFound(err) {
			raw, err = c.List(ctx, "/users/"+url.PathEscape(owner)+"/repos", url.Values{"type": {"owner"}})
			user = true
		}
	}
	if err != nil {
		return nil, user, err
	}
	repos, err = decodeGitHub(raw, setRepoRaw)
	return repos, user, err
}

// StarredRepos lists GET /user/starred
func (c *GitHubClient) StarredRepos(ctx context.Context) ([]GitHubRepo, error) {
	raw, err := c.List(ctx, "/user/starred", nil)
	if err != nil {
		return nil, err
	}
	return decodeGitHub(raw, setRepoRaw)
}

// Repo reads GET /repos/{owner}/{name}
func (c *GitHubClient) Repo(ctx context.Context, owner, name string) (*GitHubRepo, error) {
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), &raw); err != nil {
		return nil, err
	}
	repos, err := decodeGitHub([]json.RawMessage{raw}, setRepoRaw)
	if err != nil {
		return nil, err
	}
	return &repos[0], nil
}

// RepoList lists a per-repository collection (issues, pulls, comments, releases); a
// 404/410 (feature disabled) is an empty list
func (c *GitHubClient) RepoList(ctx context.Context, owner, name, sub string, query url.Values, more func([]json.RawMessage) bool) ([]json.RawMessage, error) {
	items, err := c.ListWhile(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/"+sub, query, more)
	if IsGitHubNotFound(err) {
		return nil, nil
	}
	return items, err
}

// GitHubGist is the part of a gist object the agent needs; Raw is the whole object
type GitHubGist struct {
	ID     string `json:"id"`
	Public bool   `json:"public"`
	Owner  *struct {
		Login string `json:"login"`
	} `json:"owner"`
	Raw json.RawMessage `json:"-"`
}

// OwnerLogin is the owner, "anonymous" for the old ownerless gists
func (g *GitHubGist) OwnerLogin() string {
	if g.Owner == nil || g.Owner.Login == "" {
		return "anonymous"
	}
	return g.Owner.Login
}

func setGistRaw(g *GitHubGist, raw json.RawMessage) { g.Raw = raw }

// Gists lists GET /gists (the token user's own, secret ones included), GET
// /gists/starred (starred) or GET /users/{user}/gists (user set)
func (c *GitHubClient) Gists(ctx context.Context, user string, starred bool) ([]GitHubGist, error) {
	path := "/gists"
	switch {
	case user != "":
		path = "/users/" + url.PathEscape(user) + "/gists"
	case starred:
		path = "/gists/starred"
	}
	raw, err := c.List(ctx, path, nil)
	if err != nil {
		return nil, err
	}
	return decodeGitHub(raw, setGistRaw)
}

// Gist reads GET /gists/{id}
func (c *GitHubClient) Gist(ctx context.Context, id string) (*GitHubGist, error) {
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/gists/"+url.PathEscape(id), &raw); err != nil {
		return nil, err
	}
	gists, err := decodeGitHub([]json.RawMessage{raw}, setGistRaw)
	if err != nil {
		return nil, err
	}
	return &gists[0], nil
}

// GistComments lists GET /gists/{id}/comments
func (c *GitHubClient) GistComments(ctx context.Context, id string) ([]json.RawMessage, error) {
	return c.List(ctx, "/gists/"+url.PathEscape(id)+"/comments", nil)
}

// TestGitHubConnection checks the token (/user) and reports its scopes and expiry.
// Missing scopes are warnings: fine-grained tokens report none.
func TestGitHubConnection(ctx context.Context, c Credentials, client *http.Client) (*Instance, error) {
	gh := NewGitHubClient(c, client)
	v, err := gh.Viewer(ctx)
	if err != nil {
		return nil, err
	}
	inst := &Instance{Username: v.Login, Scopes: v.Scopes, TokenExpires: v.Expires}
	if len(v.Scopes) > 0 {
		var missing []string
		for _, want := range []string{"repo", "read:org", "gist"} {
			if !containsFold(v.Scopes, want) {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			inst.Warnings = append(inst.Warnings, "the token lacks "+strings.Join(missing, ", ")+": private repositories, organization repositories or secret gists may be left out")
		}
	}
	if v.Expires != nil && time.Until(*v.Expires) < ExpiryWarning {
		inst.Warnings = append(inst.Warnings, "the token expires "+v.Expires.Format(time.DateOnly))
	}
	return inst, nil
}
