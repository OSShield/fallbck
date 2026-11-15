package credstore

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/vcs"
)

// Microsoft 365 profiles round-trip through the encrypted store next to the other
// kinds, and nothing about the secret leaves it in a summary
func TestM365Profiles(t *testing.T) {
	const tenant, client = "72f988bf-86f1-41af-91ab-2d7cd011db47", "11111111-2222-3333-4444-555555555555"
	dir := t.TempDir()
	s := Open(dir)
	if err := s.PutVCS("gl", vcs.Profile{URL: "https://gitlab.example.com", Token: "glpat-x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutM365(" Contoso ", m365.Profile{TenantID: tenant, ClientID: client, Secret: "m365-agent-only"}); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(s.Path()); err != nil || strings.Contains(string(raw), "m365-agent-only") {
		t.Fatalf("secret in clear at rest (%v)", err)
	}

	p, err := Open(dir).M365Profile("contoso")
	if err != nil || p.Secret != "m365-agent-only" || p.TenantID != tenant || p.AuthMethod != m365.AuthSecret {
		t.Fatalf("profile %+v %v", p, err)
	}
	if v, err := Open(dir).VCSProfile("gl"); err != nil || v.Token != "glpat-x" {
		t.Errorf("VCS profile lost next to M365: %+v %v", v, err)
	}
	all, _ := s.LoadM365()
	sum, _ := json.Marshal(M365Summaries(all))
	if strings.Contains(string(sum), "m365-agent-only") || !strings.Contains(string(sum), `"name":"contoso"`) {
		t.Errorf("summaries %s", sum)
	}

	if err := s.PutM365("bad name!", m365.Profile{TenantID: tenant, ClientID: client, Secret: "x"}); err == nil {
		t.Error("bad name accepted")
	}
	if err := s.DeleteM365("contoso"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.M365Profile("contoso"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}
