package vcs

import (
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/temporal"
	spec "github.com/osshield/fallbck/pkg/vcs"
)

// Live check against a GitLab instance:
//
//	FALLBCK_TEST_GITLAB_URL=https://gitlab.example.com \
//	FALLBCK_TEST_GITLAB_TOKEN=glpat-... \
//	FALLBCK_TEST_GITLAB_GROUPS=platform,data \
//	FALLBCK_TEST_GITLAB_CA_FILE=ca.pem \
//	go test ./pkg/agent/vcs -run LiveGitLab
//
// The token needs read_api and read_repository; the CA file is optional.
func liveGitLab(t *testing.T) (spec.Credentials, []string) {
	t.Helper()
	url, token := os.Getenv("FALLBCK_TEST_GITLAB_URL"), os.Getenv("FALLBCK_TEST_GITLAB_TOKEN")
	if url == "" || token == "" {
		t.Skip("FALLBCK_TEST_GITLAB_URL / FALLBCK_TEST_GITLAB_TOKEN not set")
	}
	base, err := spec.NormalizeBaseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	c := spec.Credentials{Provider: spec.ProviderGitLab, BaseURL: base, Token: token}
	if f := os.Getenv("FALLBCK_TEST_GITLAB_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		c.CAPEM = string(pem)
	}
	var groups []string
	for g := range strings.SplitSeq(os.Getenv("FALLBCK_TEST_GITLAB_GROUPS"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return c, groups
}

func TestLiveGitLabRun(t *testing.T) {
	creds, groups := liveGitLab(t)
	rec, state := &recorder{}, t.TempDir()
	opts := func() RunOptions {
		return RunOptions{
			Session:     &temporal.BackupSessionInfo{JobID: uuid.New(), BackupRunID: uuid.New(), BackupType: "host", BackupID: "vcs-live", JobName: "gitlab"},
			Spec:        &spec.Spec{ConnectionID: uuid.New(), Groups: groups},
			Credentials: creds,
			StateDir:    state, TempDir: t.TempDir(),
			Upload: rec.upload,
		}
	}

	res, err := Run(ctx(t), opts())
	if err != nil {
		t.Fatal(err)
	}
	m := rec.manifest
	t.Logf("GitLab %s, token of %s: %d repositories, warnings %v", m.Source.Version, m.Source.Username, m.Totals.Repositories, m.Warnings)
	if res.Status != "completed" || m.Source.Version == "" || m.Totals.Repositories == 0 {
		t.Fatalf("result %+v, manifest totals %+v", res, m.Totals)
	}
	for _, r := range m.Repositories {
		if r.Status != spec.RepoCompleted || r.ProjectID == 0 || !rec.has(r.Path+"/"+RepositoryDir+"/HEAD") {
			t.Errorf("%s: %+v", r.Path, r)
		}
		if r.Wiki && !rec.has(r.Path+"/"+WikiDir+"/HEAD") {
			t.Errorf("%s: wiki reported but not in the snapshot", r.Path)
		}
	}

	// Nothing changed upstream: the second run fetches nothing
	if res, err = Run(ctx(t), opts()); err != nil || res.Status != "completed" {
		t.Fatalf("second run: %+v %v", res, err)
	}
	for _, r := range rec.manifest.Repositories {
		if r.Changed {
			t.Errorf("%s changed between two runs", r.Path)
		}
	}
}
