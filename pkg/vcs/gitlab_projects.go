package vcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitLabProject is a project as the GitLab projects API lists it
type GitLabProject struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	Archived          bool   `json:"archived"`
	// ForkedFrom is only set when the token can see the source project
	ForkedFrom *struct {
		ID int64 `json:"id"`
	} `json:"forked_from_project"`
	// WikiAccessLevel is disabled, private or enabled; WikiEnabled is its
	// deprecated predecessor (instances before 14.x)
	WikiAccessLevel string     `json:"wiki_access_level"`
	WikiEnabled     *bool      `json:"wiki_enabled"`
	LastActivityAt  *time.Time `json:"last_activity_at"`
	// Statistics are only returned to users with at least the Reporter role
	Statistics *struct {
		RepositorySize int64 `json:"repository_size"`
	} `json:"statistics"`
}

// Fork reports whether the project is a fork the token can see the source of
func (p *GitLabProject) Fork() bool { return p.ForkedFrom != nil }

// HasWiki reports whether the project's wiki is enabled (it may still be empty)
func (p *GitLabProject) HasWiki() bool {
	if p.WikiAccessLevel != "" {
		return p.WikiAccessLevel != "disabled"
	}
	return p.WikiEnabled == nil || *p.WikiEnabled
}

// RepositorySize is the size GitLab reports for the repository (0 = unknown)
func (p *GitLabProject) RepositorySize() int64 {
	if p.Statistics == nil {
		return 0
	}
	return p.Statistics.RepositorySize
}

// ErrGroupNotFound is returned by ListGroupProjects for a group that does not exist
// or that the token cannot see
var ErrGroupNotFound = errors.New("GitLab group not found or not visible to the token")

// maxPages stops a listing whose pagination never ends (100 projects per page)
const maxPages = 10000

// ListGroupProjects lists the projects of a group by full path, with those of its
// subgroups when subgroups is set. Projects shared into the group are left out.
func ListGroupProjects(ctx context.Context, c Credentials, client *http.Client, group string, subgroups bool) ([]GitLabProject, error) {
	q := url.Values{
		"include_subgroups": {fmt.Sprint(subgroups)},
		"with_shared":       {"false"},
		"statistics":        {"true"},
		"order_by":          {"id"},
		"sort":              {"asc"},
		"per_page":          {"100"},
	}
	out, err := listProjects(ctx, c, client, "/groups/"+url.PathEscape(group)+"/projects", q)
	if isStatus(err, http.StatusNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrGroupNotFound, group)
	}
	return out, err
}

// ListProjects lists the projects of the instance: every project when all is set
// (an administrator's token), else those the token's user is a member of
func ListProjects(ctx context.Context, c Credentials, client *http.Client, all bool) ([]GitLabProject, error) {
	q := url.Values{
		"statistics": {"true"},
		"pagination": {"keyset"},
		"order_by":   {"id"},
		"sort":       {"asc"},
		"per_page":   {"100"},
	}
	if !all {
		q.Set("membership", "true")
	}
	return listProjects(ctx, c, client, "/projects", q)
}

// listProjects reads every page of a project listing. It follows the Link header's
// next page (offset or keyset) but always sends the request to the connection
// URL: only the next link's query is used, so the token never leaves for the host
// GitLab thinks it is.
func listProjects(ctx context.Context, c Credentials, client *http.Client, path string, q url.Values) ([]GitLabProject, error) {
	var out []GitLabProject
	for page := 0; ; page++ {
		if page == maxPages {
			return nil, fmt.Errorf("listing %s: more than %d pages", path, maxPages)
		}
		body, header, err := gitlabDo(ctx, client, c, path, q, 64<<20)
		if err != nil {
			return nil, err
		}
		var batch []GitLabProject
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("unexpected answer to %s (is %s a GitLab instance?)", path, c.BaseURL)
		}
		out = append(out, batch...)
		next, ok := nextPage(header)
		if !ok || len(batch) == 0 || next.Encode() == q.Encode() {
			return out, nil
		}
		q = next
	}
}

// nextPage returns the query of the Link header's rel="next" URL
func nextPage(h http.Header) (url.Values, bool) {
	for _, v := range h.Values("Link") {
		for link := range strings.SplitSeq(v, ",") {
			target, params, ok := strings.Cut(strings.TrimSpace(link), ";")
			if !ok || !strings.Contains(strings.ReplaceAll(params, " ", ""), `rel="next"`) {
				continue
			}
			u, err := url.Parse(strings.Trim(strings.TrimSpace(target), "<>"))
			if err != nil {
				return nil, false
			}
			return u.Query(), true
		}
	}
	return nil, false
}

// ValidProjectPath reports whether a project path GitLab returned is safe to use
// as a directory in the archive
func ValidProjectPath(p string) bool {
	return fullPathRe.MatchString(p) && !hasDotSegment(p) && !strings.HasSuffix(strings.ToLower(p), ".git")
}
