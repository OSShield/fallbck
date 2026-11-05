package vcs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	spec "github.com/osshield/fallbck/pkg/vcs"
)

// GitLabProvider lists the projects of a GitLab job through the REST API: the
// projects of the job's groups, or every project the token can see when it has
// none. Clone URLs are built from the connection URL, never taken from the API, so
// git only ever sends the token there.
type GitLabProvider struct {
	Spec *spec.Spec
	// Credentials carry the token the run uses (the connection's, or the agent
	// credential profile's)
	Credentials spec.Credentials
	Client      *http.Client

	// instance is what Projects learned about GitLab, for the manifest
	instance *spec.Instance
}

// Projects lists, filters and maps the job's projects. A group that does not exist
// is a warning unless none of the groups exist.
func (p *GitLabProvider) Projects(ctx context.Context) ([]Project, []string, error) {
	inst, err := spec.Identify(ctx, p.Credentials, p.Client)
	if err != nil {
		return nil, nil, err
	}
	p.instance = inst

	var listed []spec.GitLabProject
	var warnings []string
	if len(p.Spec.Groups) == 0 {
		if !inst.IsAdmin {
			warnings = append(warnings, fmt.Sprintf("the token's user %s is not an administrator: only the projects it is a member of are backed up", inst.Username))
		}
		if listed, err = spec.ListProjects(ctx, p.Credentials, p.Client, inst.IsAdmin); err != nil {
			return nil, nil, err
		}
	} else {
		missing := 0
		for _, g := range p.Spec.Groups {
			batch, err := spec.ListGroupProjects(ctx, p.Credentials, p.Client, g, p.Spec.EffIncludeSubgroups())
			if errors.Is(err, spec.ErrGroupNotFound) {
				missing++
				warnings = append(warnings, err.Error())
				continue
			}
			if err != nil {
				return nil, nil, fmt.Errorf("group %s: %w", g, err)
			}
			listed = append(listed, batch...)
		}
		if missing == len(p.Spec.Groups) {
			return nil, nil, fmt.Errorf("none of the job's groups exist or are visible to the token of %s", inst.Username)
		}
	}

	base := strings.TrimRight(p.Credentials.BaseURL, "/")
	seen := map[int64]bool{}
	var out []Project
	for _, gp := range listed {
		// Overlapping groups (platform and platform/api) list a project twice
		if seen[gp.ID] {
			continue
		}
		seen[gp.ID] = true
		path := gp.PathWithNamespace
		if !spec.ValidProjectPath(path) {
			warnings = append(warnings, fmt.Sprintf("project %d: skipped, GitLab returned the unusable path %q", gp.ID, path))
			continue
		}
		if !p.Spec.InScope(path) || (gp.Archived && !p.Spec.EffArchived()) || (gp.Fork() && !p.Spec.EffForks()) {
			continue
		}
		pr := Project{
			ID:       gp.ID,
			Key:      fmt.Sprintf("p%d", gp.ID),
			Path:     path,
			URL:      base + "/" + path + ".git",
			Size:     gp.RepositorySize(),
			Archived: gp.Archived,
			Fork:     gp.Fork(),
		}
		if gp.HasWiki() && p.Spec.Workloads.EffWiki() {
			pr.WikiURL = base + "/" + path + ".wiki.git"
		}
		if gp.LastActivityAt != nil {
			pr.LastActivity = *gp.LastActivityAt
		}
		out = append(out, pr)
	}
	return out, warnings, nil
}

// Describe adds the GitLab version and the token's user to the manifest source
func (p *GitLabProvider) Describe(s *spec.SourceInfo) {
	if p.instance == nil {
		return
	}
	s.Version, s.Username, s.IsAdmin = p.instance.Version, p.instance.Username, p.instance.IsAdmin
}

// gitlabAPITimeout bounds each GitLab API request of a run
const gitlabAPITimeout = 2 * time.Minute
