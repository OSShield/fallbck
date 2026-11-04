package credstore

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
	"github.com/osshield/fallbck/pkg/vcs"
)

func TestVCSProfiles(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir)
	if err := s.Put("prod", dbspec.CredentialProfile{Engine: "postgres", Password: "db-secret"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutVCS(" GitLab-Internal ", vcs.Profile{URL: "https://GitLab.example.com/", Token: "glpat-agent-only"}); err != nil {
		t.Fatal(err)
	}

	// Encrypted at rest: neither secret appears in the file
	raw, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"glpat-agent-only", "db-secret", "gitlab.example.com"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("%q in clear in %s", secret, s.Path())
		}
	}

	p, err := Open(dir).VCSProfile("gitlab-internal")
	if err != nil {
		t.Fatal(err)
	}
	if p.Token != "glpat-agent-only" || p.URL != "https://gitlab.example.com" {
		t.Errorf("profile %+v", p)
	}
	// The database profiles are untouched by the VCS map
	if dbp, _ := Open(dir).Load(); dbp["prod"].Password != "db-secret" {
		t.Error("database profile lost")
	}

	// Summaries should never carry the token, not even through JSON
	all, _ := s.LoadVCS()
	exp := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	p.TokenExpires = &exp
	if err := s.PutVCS("gitlab-internal", *p); err != nil {
		t.Fatal(err)
	}
	all, _ = s.LoadVCS()
	sums := VCSSummaries(all)
	data, _ := json.Marshal(sums)
	if len(sums) != 1 || sums[0].Name != "gitlab-internal" || sums[0].TokenExpires == nil || strings.Contains(string(data), "glpat") {
		t.Errorf("summaries %s", data)
	}
	if data, _ := json.Marshal(all["gitlab-internal"]); strings.Contains(string(data), "glpat") {
		t.Errorf("a profile marshalled for the API carries its token: %s", data)
	}

	for name, bad := range map[string]vcs.Profile{
		"bad name!": {URL: "https://x", Token: "t"},
		"no-token":  {URL: "https://x"},
		"both":      {URL: "https://x", Token: "t", TokenFile: "/run/secrets/t"},
		"http":      {URL: "http://x", Token: "t"},
		"header":    {URL: "https://x", Token: "t\r\nX-Evil: 1"},
	} {
		if err := s.PutVCS(name, bad); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if err := s.DeleteVCS("GITLAB-INTERNAL"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.VCSProfile("gitlab-internal"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted profile: %v", err)
	}
	if err := s.DeleteVCS("gitlab-internal"); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
}
