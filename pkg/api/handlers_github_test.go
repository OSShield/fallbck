package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/github"
)

func TestCreateGitHubJobValidation(t *testing.T) {
	r := newTestRouter()
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rr, req)
		return rr
	}
	agent, target, account := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"
	head := `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"github"`
	cases := map[string]string{
		"no config":        head + `}`,
		"no account":       head + `,"github_config":{"sources":{"starred":true}}}`,
		"no source":        head + `,"github_config":{"account_id":"` + account + `"}}`,
		"with paths":       head + `,"backup_paths":["/etc"],"github_config":{"account_id":"` + account + `","sources":{"starred":true}}}`,
		"foreign config":   head + `,"m365_config":{},"github_config":{"account_id":"` + account + `","sources":{"starred":true}}}`,
		"bad repo":         head + `,"github_config":{"account_id":"` + account + `","sources":{"repos":["nope"]}}}`,
		"fs job gh config": `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["/etc"],"github_config":{"account_id":"` + account + `"}}`,
	}
	for name, body := range cases {
		if rr := post(body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestSubGroupAllowedGitHub(t *testing.T) {
	p := github.GroupPrefix("github-acme")
	for group, ok := range map[string]bool{
		"github-acme-acme-web":         true,
		"github-acme-1ardotno-my.repo": true,
		"github-acme":                  false,
		"github-other-acme-web":        false,
		"github-acme-a/b":              false,
	} {
		if got := subGroupAllowed(p, group); got != ok {
			t.Errorf("subGroupAllowed(%q) = %v, want %v", group, got, ok)
		}
	}
}
