package vcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"

	spec "github.com/osshield/fallbck/pkg/vcs"
)

// Project is one repository a run backs up
type Project struct {
	// ID is the provider's project id (GitLab); 0 for the git provider
	ID int64
	// names the project's mirrors in the state directory: stable across
	// renames for providers with ids (p<id>), derived from the URL otherwise
	Key string
	// the directory in the archive
	Path string
	// the HTTPS clone URL; WikiURL the wiki's ("" when none)
	URL     string
	WikiURL string
	// the repository size the provider reports (0 = unknown), for
	// max_repo_size
	Size         int64
	Archived     bool
	Fork         bool
	LastActivity time.Time
	// Kind is "gist" for GitHub gists ("" = repository)
	Kind string
	// Ref names the project to the provider's metadata API (GitHub owner/name or gist id)
	Ref string
}

// MetadataProvider writes a project's API metadata (issues, pull requests, ...) as
// files into dir; the counts and warnings go into the manifest. since is the start of
// the last complete pass (zero = fetch everything); complete reports that every list
// was fetched, so the next pass may start from this one.
type MetadataProvider interface {
	Metadata(ctx context.Context, p Project, dir string, since time.Time, r *spec.RepoResult) (complete bool, err error)
}

// Provider lists the projects of a run
type Provider interface {
	// returns what to back up (already filtered by the job's selection) and
	// warnings worth noting in the manifest
	Projects(ctx context.Context) ([]Project, []string, error)
}

// GitProvider backs up the job's explicit repository URLs
type GitProvider struct {
	Spec *spec.Spec
}

// Projects maps every repository URL to its archive directory (<host>/<path>)
func (p GitProvider) Projects(context.Context) ([]Project, []string, error) {
	var out []Project
	for _, raw := range p.Spec.Repositories {
		url, dir, err := spec.ParseRepoURL(raw)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, Project{Key: urlKey(url), Path: dir, URL: url})
	}
	return out, nil, nil
}

// a stable state name for a repository known only by its URL
func urlKey(url string) string {
	sum := sha256.Sum256([]byte(url))
	return "u" + hex.EncodeToString(sum[:8])
}
