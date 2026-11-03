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
		{ConnectionID: conn, Groups: []string{"g"}, Repositories: []string{"https://git.example.com/a.git"}},
		{ConnectionID: conn, MaxRepoSize: -1},
		{ConnectionID: conn, Concurrency: MaxConcurrency + 1},
		{ConnectionID: conn, BackupID: "no spaces"},
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
	gl := &Connection{Provider: ProviderGitLab, BaseURL: "https://gitlab.example.com"}
	glcom := &Connection{Provider: ProviderGitLab, BaseURL: "https://gitlab.com"}
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
	if err := whole.ValidateFor(nil); err == nil {
		t.Error("nil connection")
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
