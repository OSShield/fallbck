package vcs

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSpecValidate(t *testing.T) {
	conn := uuid.New()
	s := &Spec{ConnectionID: conn, Groups: []string{" /platform/ ", "Platform", "data/pipelines", ""}, Exclude: []string{" platform/sandbox-* ", ""}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(s.Groups) != 2 || s.Groups[0] != "platform" || s.Groups[1] != "data/pipelines" {
		t.Errorf("groups not normalised and deduplicated: %v", s.Groups)
	}
	if len(s.Exclude) != 1 || s.Exclude[0] != "platform/sandbox-*" {
		t.Errorf("exclude: %v", s.Exclude)
	}

	bad := []*Spec{
		nil,
		{},
		{ConnectionID: conn, Groups: []string{"-bad"}},
		{ConnectionID: conn, Groups: []string{"a/../b"}},
		{ConnectionID: conn, Exclude: []string{"[x"}},
		{ConnectionID: conn, Repositories: []string{"http://git.example.com/a.git"}},
		{ConnectionID: conn, Repositories: []string{"https://user:pw@git.example.com/a.git"}},
		{ConnectionID: conn, Repositories: []string{"https://git.example.com/"}},
		{ConnectionID: conn, Repositories: []string{"https://git.example.com/a.git", "https://git.example.com/a"}},
		{ConnectionID: conn, MaxRepoSize: -1},
		{ConnectionID: conn, Concurrency: MaxConcurrency + 1},
		{ConnectionID: conn, BackupID: "no spaces"},
		{ConnectionID: conn, Profile: "no spaces"},
		{ConnectionID: conn, Profile: "-leading"},
	}
	for i, b := range bad {
		if err := b.Validate(); !errors.Is(err, ErrInvalidSpec) {
			t.Errorf("case %d: expected ErrInvalidSpec, got %v", i, err)
		}
	}

	dup := &Spec{ConnectionID: conn, Repositories: []string{"https://Git.Example.com/a.git", "https://git.example.com/a.git"}}
	if err := dup.Validate(); err != nil || len(dup.Repositories) != 1 {
		t.Errorf("identical URLs should collapse: %v %v", dup.Repositories, err)
	}
}

func TestValidateFor(t *testing.T) {
	conn := uuid.New()
	gl := &Connection{Provider: ProviderGitLab, BaseURL: "https://gitlab.example.com", Token: "glpat-x"}
	glcom := &Connection{Provider: ProviderGitLab, BaseURL: "https://gitlab.com", Token: "glpat-x"}
	tokenless := &Connection{Provider: ProviderGitLab, BaseURL: "https://gitlab.example.com"}
	git := &Connection{Provider: ProviderGit, BaseURL: "https://git.example.com/team"}

	whole := &Spec{ConnectionID: conn}
	if err := whole.ValidateFor(gl); err != nil {
		t.Errorf("self-managed instance-wide should be allowed: %v", err)
	}
	if err := whole.ValidateFor(glcom); err == nil {
		t.Error("gitlab.com instance-wide must be refused")
	}
	if err := (&Spec{ConnectionID: conn, Groups: []string{"g"}}).ValidateFor(glcom); err != nil {
		t.Errorf("gitlab.com with groups: %v", err)
	}
	if err := whole.ValidateFor(git); err == nil {
		t.Error("git provider without repositories must be refused")
	}

	repos := &Spec{ConnectionID: conn, Repositories: []string{"https://git.example.com/team/app.git"}}
	if err := repos.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := repos.ValidateFor(git); err != nil {
		t.Errorf("repository below the base URL: %v", err)
	}
	if err := repos.ValidateFor(gl); err == nil {
		t.Error("repositories on a GitLab connection must be refused")
	}
	outside := &Spec{ConnectionID: conn, Repositories: []string{"https://git.example.com/teamx/app.git"}}
	if err := outside.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := outside.ValidateFor(git); err == nil {
		t.Error("a repository outside the base URL must be refused (prefix must end on a segment)")
	}
	both := &Spec{ConnectionID: conn, Groups: []string{"g"}, Repositories: []string{"https://git.example.com/team/a.git"}}
	if err := both.Validate(); err != nil {
		t.Fatal(err)
	}
	if both.ValidateFor(gl) == nil || both.ValidateFor(git) == nil {
		t.Error("groups and repositories together are for GitHub connections only")
	}
	if err := whole.ValidateFor(nil); err == nil {
		t.Error("nil connection")
	}

	// Without a stored token, a GitLab job must name the agent profile holding it
	if err := whole.ValidateFor(tokenless); err == nil {
		t.Error("GitLab job without token or profile must be refused")
	}
	withProfile := &Spec{ConnectionID: conn, Profile: " gitlab-internal "}
	if err := withProfile.Validate(); err != nil || withProfile.Profile != "gitlab-internal" {
		t.Fatalf("profile: %q %v", withProfile.Profile, err)
	}
	if err := withProfile.ValidateFor(tokenless); err != nil {
		t.Errorf("GitLab job with an agent profile: %v", err)
	}
}

func TestParseRepoURL(t *testing.T) {
	cases := map[string]string{
		"https://Git.Example.com/team/app.git":   "git.example.com/team/app",
		"https://git.example.com:8443/a/b/c":     "git.example.com_8443/a/b/c",
		"https://git.example.com//team//app.git": "git.example.com/team/app",
	}
	for in, want := range cases {
		_, dir, err := ParseRepoURL(in)
		if err != nil || dir != want {
			t.Errorf("ParseRepoURL(%q) = %q, %v; want %q", in, dir, err, want)
		}
	}
	for _, in := range []string{"git@example.com:a/b.git", "ext::sh -c x", "file:///etc", "https://example.com/a/../b", "https://example.com/a?x=1"} {
		if _, _, err := ParseRepoURL(in); err == nil {
			t.Errorf("ParseRepoURL(%q) should fail", in)
		}
	}
}

func TestInScope(t *testing.T) {
	off := false
	s := &Spec{Groups: []string{"Platform"}, Exclude: []string{"platform/legacy", "*/sandbox-*"}}
	cases := map[string]bool{
		"platform/api":            true,
		"platform/infra/tf":       true,
		"platform/legacy/old-api": false, // excluded through its parent group
		"platform/sandbox-x":      false,
		"data/api":                false,
		"platformx/api":           false,
	}
	for p, want := range cases {
		if got := s.InScope(p); got != want {
			t.Errorf("InScope(%q) = %v, want %v", p, got, want)
		}
	}
	s.IncludeSubgroups = &off
	if s.InScope("platform/infra/tf") || !s.InScope("platform/api") {
		t.Error("include_subgroups=false should keep direct projects only")
	}
	if !(&Spec{}).InScope("users/alice/dotfiles") {
		t.Error("no groups selects every project")
	}
}

func TestDefaultsSummaryClone(t *testing.T) {
	s := &Spec{}
	if !s.EffIncludeSubgroups() || !s.EffArchived() || !s.EffForks() || !s.Workloads.EffLFS() || !s.Workloads.EffWiki() || s.EffConcurrency() != DefaultConcurrency {
		t.Error("defaults")
	}
	if s.Summary() != "all projects" {
		t.Error(s.Summary())
	}
	off := false
	g := &Spec{Groups: []string{"a", "b/c"}, IncludeSubgroups: &off, Exclude: []string{"a/x"}}
	if got := g.Summary(); got != "groups a, b/c (without subgroups); excluding a/x" {
		t.Error(got)
	}
	if got := (&Spec{Repositories: []string{"x", "y"}}).Summary(); got != "2 repositories" {
		t.Error(got)
	}
	c := g.Clone()
	c.Groups[0], *c.IncludeSubgroups = "changed", true
	if g.Groups[0] != "a" || *g.IncludeSubgroups {
		t.Error("Clone must not share slices or pointers")
	}
	var nilSpec *Spec
	if nilSpec.Clone() != nil || nilSpec.Summary() == "" || nilSpec.EffConcurrency() != DefaultConcurrency {
		t.Error("nil spec helpers")
	}
	if got := DefaultBackupID("GitLab Internal"); got != "vcs-gitlab-internal" {
		t.Error(got)
	}
}

func TestGitVersionOK(t *testing.T) {
	cases := map[string]bool{
		"2.31.0":                 true,
		"git version 2.43.0":     true,
		"2.39.3 (Apple Git-146)": true,
		"2.45.1.windows.1":       true,
		"3.0":                    true,
		"2.30.9":                 false,
		"1.99":                   false,
		"":                       false,
		"garbage":                false,
	}
	for v, want := range cases {
		if got := GitVersionOK(v); got != want {
			t.Errorf("GitVersionOK(%q) = %v, want %v", v, got, want)
		}
	}
	if !strings.Contains(ErrInvalidSpec.Error(), "VCS") {
		t.Error("error text")
	}
}

func TestGitHubSpec(t *testing.T) {
	conn := uuid.New()
	gh := &Connection{Provider: ProviderGitHub, BaseURL: "https://github.com", Token: "ghp_x"}
	ghes := &Connection{Provider: ProviderGitHub, BaseURL: "https://ghe.example.com", Token: "ghp_x"}
	id := "0123456789abcdef0123456789ABCDEF"
	s := &Spec{ConnectionID: conn, Groups: []string{"acme", "1ARdotNO"}, Repositories: []string{"https://github.com/torvalds/linux.git"},
		Starred: true, Gists: &Gists{Own: true, Users: []string{"octo", "OCTO"}, IDs: []string{id, "https://gist.github.com/octo/" + id + "#file-a"}},
		Workloads: Workloads{Metadata: true}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := s.ValidateFor(gh); err != nil {
		t.Fatalf("github job: %v", err)
	}
	if len(s.Gists.Users) != 1 || len(s.Gists.IDs) != 1 || s.Gists.IDs[0] != strings.ToLower(id) {
		t.Errorf("gists not normalised: %+v", s.Gists)
	}
	if got := s.Summary(); got != "owners acme, 1ARdotNO, 1 repository, starred, own gists, gists of octo, 1 gists" {
		t.Errorf("Summary = %q", got)
	}
	c := s.Clone()
	c.Gists.Users[0] = "changed"
	if s.Gists.Users[0] != "octo" || !c.Workloads.Metadata {
		t.Error("Clone shares the gist lists or drops metadata")
	}
	if err := s.ValidateFor(ghes); err == nil {
		t.Error("a github.com repository on an Enterprise connection must be refused")
	}
	for name, bad := range map[string]*Spec{
		"nested owner":  {ConnectionID: conn, Groups: []string{"a/b"}},
		"nothing":       {ConnectionID: conn},
		"three segment": {ConnectionID: conn, Repositories: []string{"https://github.com/a/b/c"}},
	} {
		if err := bad.Validate(); err == nil {
			if err := bad.ValidateFor(gh); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}
	}
	if err := (&Spec{ConnectionID: conn, Starred: true}).ValidateFor(&Connection{Provider: ProviderGitHub, BaseURL: "https://github.com"}); err == nil {
		t.Error("a GitHub job needs a token or a profile")
	}
	if err := (&Spec{ConnectionID: conn, Starred: true, Repositories: []string{"https://git.example.com/team/a.git"}}).ValidateFor(&Connection{Provider: ProviderGit, BaseURL: "https://git.example.com/team"}); err == nil {
		t.Error("starred on a git connection must be refused")
	}
	if (&Spec{Gists: &Gists{IDs: []string{"nope"}}, ConnectionID: conn}).Validate() == nil {
		t.Error("a bad gist id must be refused")
	}
	if got := (&Spec{Groups: []string{"acme"}, Repositories: []string{"https://github.com/other/lib"}}).Summary(); got != "owners acme, 1 repository" {
		t.Errorf("owners and repositories summary: %q", got)
	}
	if id, ok := GistID("https://gist.github.com/1234567"); !ok || id != "1234567" {
		t.Error("legacy numeric gist ids must be accepted")
	}
	if GitHubAPIURL("https://github.com") != "https://api.github.com" || GitHubAPIURL("https://ghe.example.com") != "https://ghe.example.com/api/v3" {
		t.Error("GitHubAPIURL")
	}
	if GistBaseURL("https://github.com") != "https://gist.github.com" || GistBaseURL("https://ghe.example.com") != "https://ghe.example.com/gist" {
		t.Error("GistBaseURL")
	}
}
