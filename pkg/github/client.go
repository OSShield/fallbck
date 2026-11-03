package github

import (
	"bytes"
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

// Client is a minimal GitHub REST client: token auth, Link-header pagination, and
// waiting out the primary and secondary rate limits instead of failing the run
type Client struct {
	APIURL string
	Token  string
	HTTP   *http.Client
	// MaxRateWait caps one rate-limit pause (default 1h); a longer reset fails the call
	MaxRateWait time.Duration
	// sleep is replaced in tests
	sleep func(ctx context.Context, d time.Duration) error
}

// NewClient builds a client for the credentials
func NewClient(c Credentials) (*Client, error) {
	api, err := NormalizeAPIURL(c.APIURL)
	if err != nil {
		return nil, err
	}
	if c.Token == "" {
		return nil, errors.New("no GitHub token")
	}
	return &Client{APIURL: api, Token: c.Token, HTTP: &http.Client{Timeout: 5 * time.Minute}}, nil
}

// APIError is a non-2xx answer
type APIError struct {
	Status  int
	Path    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub answered %d to %s: %s", e.Status, e.Path, e.Message)
}

// IsNotFound reports a 404 or 410 (missing, or a feature such as issues disabled)
func IsNotFound(err error) bool {
	var e *APIError
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

// do sends one request, retrying rate limits and transient server errors; the
// caller closes the body of a 2xx response
func (c *Client) do(ctx context.Context, rawURL string) (*http.Response, error) {
	sleep := c.sleep
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
				return nil, fmt.Errorf("GitHub request %s: %w", path, err)
			}
			if err := sleep(ctx, backoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode/100 == 2 {
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		apiErr := &APIError{Status: resp.StatusCode, Path: path, Message: errorText(body)}
		if wait, limited := rateLimitWait(resp, time.Now()); limited {
			if wait > maxWait || attempt >= 8 {
				return nil, fmt.Errorf("rate limited for %s (limit resets in %s): %w", path, wait.Round(time.Second), apiErr)
			}
			if err := sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		if resp.StatusCode >= 500 && attempt < 4 {
			if err := sleep(ctx, backoff(attempt)); err != nil {
				return nil, err
			}
			continue
		}
		return nil, apiErr
	}
}

func backoff(attempt int) time.Duration {
	return time.Duration(1<<attempt) * 2 * time.Second
}

// rateLimitWait tells a rate limit from a permission error (both may be 403): Retry-After
// for the secondary limit, the reset time once the primary quota is used up
func rateLimitWait(resp *http.Response, now time.Time) (time.Duration, bool) {
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
			d := time.Unix(reset, 0).Sub(now) + time.Second
			if d < time.Second {
				d = time.Second
			}
			return d, true
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		return time.Minute, true
	}
	return 0, false
}

func errorText(body []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		return e.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func (c *Client) url(path string, query url.Values) string {
	u := c.APIURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

// getJSON decodes one object
func (c *Client) getJSON(ctx context.Context, path string, out any) (http.Header, error) {
	resp, err := c.do(ctx, c.url(path, nil))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}
	return resp.Header, nil
}

var linkNextRe = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// List follows the pagination of a list endpoint and returns every element verbatim
func (c *Client) List(ctx context.Context, path string, query url.Values) ([]json.RawMessage, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("per_page", "100")
	next := c.url(path, query)
	var out []json.RawMessage
	for page := 0; next != ""; page++ {
		if page > 10000 {
			return nil, fmt.Errorf("%s: too many pages", path)
		}
		resp, err := c.do(ctx, next)
		if err != nil {
			return nil, err
		}
		var items []json.RawMessage
		err = json.NewDecoder(resp.Body).Decode(&items)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("decoding %s: %w", path, err)
		}
		out = append(out, items...)
		next = ""
		if m := linkNextRe.FindStringSubmatch(resp.Header.Get("Link")); m != nil {
			// Only follow links to the same API (a forged header must not leak the token)
			if strings.HasPrefix(m[1], c.APIURL+"/") {
				next = m[1]
			}
		}
	}
	return out, nil
}

// Viewer is the token's user
type Viewer struct {
	Login string `json:"login"`
	Name  string `json:"name,omitempty"`
	// Scopes are the classic token scopes (X-OAuth-Scopes); empty for fine-grained tokens
	Scopes []string `json:"scopes,omitempty"`
}

// Viewer reads GET /user
func (c *Client) Viewer(ctx context.Context) (*Viewer, error) {
	var v Viewer
	h, err := c.getJSON(ctx, "/user", &v)
	if err != nil {
		return nil, err
	}
	for _, s := range strings.Split(h.Get("X-OAuth-Scopes"), ",") {
		if s = strings.TrimSpace(s); s != "" {
			v.Scopes = append(v.Scopes, s)
		}
	}
	return &v, nil
}

// TestConnection checks the token against the API; the error names the step that
// failed so an administrator can tell a bad token from blocked egress
func TestConnection(ctx context.Context, creds Credentials) (*Viewer, error) {
	c, err := NewClient(creds)
	if err != nil {
		return nil, err
	}
	v, err := c.Viewer(ctx)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnauthorized {
			return nil, fmt.Errorf("the token was rejected (expired or revoked?): %w", err)
		}
		return nil, fmt.Errorf("GitHub API request failed (the caller needs outbound HTTPS to %s): %w", c.APIURL, err)
	}
	return v, nil
}

// Repo is the part of a repository object the agent needs; Raw is the whole object
type Repo struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Owner    struct {
		Login string `json:"login"`
	} `json:"owner"`
	Private       bool            `json:"private"`
	Fork          bool            `json:"fork"`
	Archived      bool            `json:"archived"`
	Disabled      bool            `json:"disabled"`
	CloneURL      string          `json:"clone_url"`
	HasWiki       bool            `json:"has_wiki"`
	HasIssues     bool            `json:"has_issues"`
	DefaultBranch string          `json:"default_branch"`
	Size          int64           `json:"size"`
	PushedAt      *time.Time      `json:"pushed_at"`
	Raw           json.RawMessage `json:"-"`
}

func decodeRepos(raw []json.RawMessage) ([]Repo, error) {
	out := make([]Repo, 0, len(raw))
	for _, r := range raw {
		var repo Repo
		if err := json.Unmarshal(r, &repo); err != nil {
			return nil, fmt.Errorf("decoding repository: %w", err)
		}
		repo.Raw = r
		out = append(out, repo)
	}
	return out, nil
}

// OrgRepos lists GET /orgs/{org}/repos?type=
func (c *Client) OrgRepos(ctx context.Context, org, repoType string) ([]Repo, error) {
	q := url.Values{}
	if repoType != "" {
		q.Set("type", repoType)
	}
	raw, err := c.List(ctx, "/orgs/"+url.PathEscape(org)+"/repos", q)
	if err != nil {
		return nil, err
	}
	return decodeRepos(raw)
}

// UserRepos lists the repositories a user owns. For the token's own login this is
// GET /user/repos?affiliation=owner, which includes private repositories.
func (c *Client) UserRepos(ctx context.Context, user string, self bool) ([]Repo, error) {
	var raw []json.RawMessage
	var err error
	if self {
		raw, err = c.List(ctx, "/user/repos", url.Values{"affiliation": {"owner"}, "visibility": {"all"}})
	} else {
		raw, err = c.List(ctx, "/users/"+url.PathEscape(user)+"/repos", url.Values{"type": {"owner"}})
	}
	if err != nil {
		return nil, err
	}
	return decodeRepos(raw)
}

// Starred lists GET /user/starred
func (c *Client) Starred(ctx context.Context) ([]Repo, error) {
	raw, err := c.List(ctx, "/user/starred", nil)
	if err != nil {
		return nil, err
	}
	return decodeRepos(raw)
}

// Repo reads GET /repos/{owner}/{name}
func (c *Client) Repo(ctx context.Context, owner, name string) (*Repo, error) {
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name), &raw); err != nil {
		return nil, err
	}
	repos, err := decodeRepos([]json.RawMessage{raw})
	if err != nil {
		return nil, err
	}
	return &repos[0], nil
}

// RepoList lists a per-repository collection (issues, pulls, comments, releases,
// labels, milestones); a 404/410 (feature disabled) is an empty list
func (c *Client) RepoList(ctx context.Context, owner, name, sub string, query url.Values) ([]json.RawMessage, error) {
	items, err := c.List(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/"+sub, query)
	if IsNotFound(err) {
		return nil, nil
	}
	return items, err
}

// MarshalList renders a list as indented JSON ("[]" when empty)
func MarshalList(items []json.RawMessage) []byte {
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

// Gist is the part of a gist object the agent needs; Raw is the whole object
type Gist struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Public      bool   `json:"public"`
	GitPullURL  string `json:"git_pull_url"`
	HTMLURL     string `json:"html_url"`
	Comments    int    `json:"comments"`
	Owner       *struct {
		Login string `json:"login"`
	} `json:"owner"`
	Raw json.RawMessage `json:"-"`
}

// OwnerLogin is the owner, "anonymous" for the old ownerless gists
func (g *Gist) OwnerLogin() string {
	if g.Owner == nil || g.Owner.Login == "" {
		return "anonymous"
	}
	return g.Owner.Login
}

func decodeGists(raw []json.RawMessage) ([]Gist, error) {
	out := make([]Gist, 0, len(raw))
	for _, r := range raw {
		var g Gist
		if err := json.Unmarshal(r, &g); err != nil {
			return nil, fmt.Errorf("decoding gist: %w", err)
		}
		g.Raw = r
		out = append(out, g)
	}
	return out, nil
}

// Gists lists GET /gists (the token user's own, secret ones included), GET
// /gists/starred (starred=true) or GET /users/{user}/gists (user set)
func (c *Client) Gists(ctx context.Context, user string, starred bool) ([]Gist, error) {
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
	return decodeGists(raw)
}

// Gist reads GET /gists/{id}
func (c *Client) Gist(ctx context.Context, id string) (*Gist, error) {
	var raw json.RawMessage
	if _, err := c.getJSON(ctx, "/gists/"+url.PathEscape(id), &raw); err != nil {
		return nil, err
	}
	gists, err := decodeGists([]json.RawMessage{raw})
	if err != nil {
		return nil, err
	}
	return &gists[0], nil
}

// GistComments lists GET /gists/{id}/comments
func (c *Client) GistComments(ctx context.Context, id string) ([]json.RawMessage, error) {
	return c.List(ctx, "/gists/"+url.PathEscape(id)+"/comments", nil)
}
