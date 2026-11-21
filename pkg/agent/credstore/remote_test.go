package credstore

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/remote"
)

// Remote profiles round-trip through the encrypted store next to the other kinds,
// and nothing about the credential leaves it in a summary
func TestRemoteProfiles(t *testing.T) {
	const tenant, client = "72f988bf-86f1-41af-91ab-2d7cd011db47", "11111111-2222-3333-4444-555555555555"
	dir := t.TempDir()
	s := Open(dir)
	if err := s.PutM365("contoso", m365.Profile{TenantID: tenant, ClientID: client, Secret: "m365-x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRemote(" MinIO ", remote.Profile{Backend: "S3", Endpoint: "HTTP://minio:9000/",
		Secrets: remote.Secrets{AccessKeyID: "AKIAAGENT", SecretAccessKey: "remote-agent-only"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRemote("aws", remote.Profile{Backend: remote.BackendS3, Endpoint: "aws", EnvAuth: true}); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(s.Path()); err != nil || strings.Contains(string(raw), "remote-agent-only") || strings.Contains(string(raw), "AKIAAGENT") {
		t.Fatalf("credential in clear at rest (%v)", err)
	}

	p, err := Open(dir).RemoteProfile("minio")
	if err != nil || p.Secrets.SecretAccessKey != "remote-agent-only" || p.Endpoint != "http://minio:9000" || p.Backend != remote.BackendS3 {
		t.Fatalf("profile %+v %v", p, err)
	}
	r := &remote.Remote{Name: "m", Backend: remote.BackendS3, Endpoint: "http://minio:9000", AuthMethod: remote.AuthAgent}
	if err := r.Validate(); err != nil || p.Matches(r) != nil {
		t.Errorf("profile doesn't match its remote: %v %v", err, p.Matches(r))
	}
	if m, err := Open(dir).M365Profile("contoso"); err != nil || m.Secret != "m365-x" {
		t.Errorf("M365 profile lost next to remote: %+v %v", m, err)
	}
	all, _ := s.LoadRemote()
	sum, _ := json.Marshal(RemoteSummaries(all))
	if strings.Contains(string(sum), "remote-agent-only") || strings.Contains(string(sum), "AKIAAGENT") ||
		!strings.Contains(string(sum), `"name":"minio"`) || !strings.Contains(string(sum), `"env_auth":true`) {
		t.Errorf("summaries %s", sum)
	}

	if err := s.PutRemote("bad name!", remote.Profile{Backend: remote.BackendS3, EnvAuth: true}); err == nil {
		t.Error("bad name accepted")
	}
	if err := s.PutRemote("nocred", remote.Profile{Backend: remote.BackendSMB, Endpoint: "nas"}); err == nil {
		t.Error("profile without a credential accepted")
	}
	if err := s.DeleteRemote("minio"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoteProfile("minio"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: %v", err)
	}
}
