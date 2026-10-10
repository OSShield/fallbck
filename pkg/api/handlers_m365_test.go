package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/k8sbackup"
	"github.com/osshield/fallbck/pkg/m365"
)

func TestCreateM365JobValidation(t *testing.T) {
	r := newTestRouter()
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rr, req)
		return rr
	}
	agent, target, tenant := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333"
	head := `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"m365"`
	cases := map[string]string{
		"no config":         head + `}`,
		"no tenant":         head + `,"m365_config":{}}`,
		"with paths":        head + `,"backup_paths":["/etc"],"m365_config":{"tenant_id":"` + tenant + `"}}`,
		"foreign config":    head + `,"docker_config":{},"m365_config":{"tenant_id":"` + tenant + `"}}`,
		"bad glob":          head + `,"m365_config":{"tenant_id":"` + tenant + `","users":{"include":["[x"]}}}`,
		"all workloads off": head + `,"m365_config":{"tenant_id":"` + tenant + `","workloads":{"mailboxes":false,"onedrive":false,"sites":false,"teams":false,"entra":false}}}`,
		"fs job m365 cfg":   `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["/etc"],"m365_config":{"tenant_id":"` + tenant + `"}}`,
	}
	for name, body := range cases {
		if rr := post(body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, rr.Code, rr.Body.String())
		}
	}
}

func TestSubGroupAllowed(t *testing.T) {
	m := m365.GroupPrefix("m365-contoso")
	k := k8sbackup.VolumeGroupPrefix("k8s-c1")
	cases := []struct {
		prefix, group string
		ok            bool
	}{
		{m, "m365-contoso-user-alice_contoso.com", true},
		{m, "m365-contoso-site-contoso.sharepoint.com-sites-hr", true},
		{m, "m365-contoso", false},
		{m, "m365-contoso-", false},
		{m, "m365-fabrikam-user-x", false},
		{m, "m365-contoso-user-with space", false},
		{m, "m365-contoso-user-../x", false},
		{k, "k8s-c1-pvc-default-data", true},
		{k, "k8s-c1-default-data", false},
	}
	for _, c := range cases {
		if got := subGroupAllowed(c.prefix, c.group); got != c.ok {
			t.Errorf("subGroupAllowed(%q, %q) = %v, want %v", c.prefix, c.group, got, c.ok)
		}
	}
}
