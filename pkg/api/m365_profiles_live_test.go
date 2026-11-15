package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/m365"
	"github.com/osshield/fallbck/pkg/secrets"
)

// Microsoft 365 jobs with an agent credential profile: the server hands out ids only,
// a tenant with credentials on the agents keeps none and requires profiles, and a
// tenant can't move to the agents while a job still uses its secret
func TestLiveM365AgentProfiles(t *testing.T) {
	d := liveDB(t)
	sealer, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	d.Sealer = sealer
	f := seed(t, d)
	ctx := context.Background()
	h := liveRouter(d, &auth.Principal{Kind: auth.PrincipalSession, Email: "root@example.com", Bindings: auth.AdminBindings()})
	const tenantGUID, clientGUID = "72f988bf-86f1-41af-91ab-2d7cd011db47", "11111111-2222-3333-4444-555555555555"

	tenant := func(body map[string]any) m365.Tenant {
		t.Helper()
		body["tenant_id"], body["client_id"] = tenantGUID, clientGUID
		code, raw := call(t, h, http.MethodPost, "/api/v1/m365/tenants", body)
		if code != http.StatusCreated {
			t.Fatalf("create tenant: %d %s", code, raw)
		}
		var tn m365.Tenant
		_ = json.Unmarshal(raw, &tn)
		return tn
	}
	onAgent := tenant(map[string]any{"name": "contoso-agent", "auth_method": "agent", "secret": "ignored"})
	if onAgent.AuthMethod != m365.AuthAgent || onAgent.HasSecret {
		t.Errorf("agent tenant %+v", onAgent)
	}
	var sealed string
	if err := d.Pool.QueryRow(ctx, `SELECT secret_sealed FROM m365_tenants WHERE id = $1`, onAgent.ID).Scan(&sealed); err != nil || sealed != "" {
		t.Errorf("agent tenant stored a secret: %q %v", sealed, err)
	}
	code, raw := call(t, h, http.MethodPost, "/api/v1/m365/tenants/"+onAgent.ID.String()+"/test", nil)
	if code != http.StatusOK || !strings.Contains(string(raw), "profile test") {
		t.Errorf("test of an agent tenant: %d %s", code, raw)
	}

	// A job on it has to name a profile
	newJob := func(name string, tenantID any, profile string) (int, []byte) {
		return call(t, h, http.MethodPost, "/api/v1/jobs", map[string]any{"name": name, "agent_id": f.agentA.ID, "target_id": f.targetA.ID, "job_type": "m365",
			"m365_config": map[string]any{"tenant_id": tenantID, "profile": profile}})
	}
	if code, raw := newJob("no-profile", onAgent.ID, ""); code != http.StatusBadRequest || !strings.Contains(string(raw), "profile") {
		t.Errorf("job without profile on an agent tenant: %d %s", code, raw)
	}
	if code, raw := newJob("with-profile", onAgent.ID, "Contoso"); code != http.StatusCreated {
		t.Fatalf("job with profile: %d %s", code, raw)
	}

	// On a tenant with a server secret, a profile job gets the ids and nothing else
	withSecret := tenant(map[string]any{"name": "contoso-server", "secret": "server-secret"})
	code, raw = newJob("server-tenant-profile", withSecret.ID, "contoso")
	if code != http.StatusCreated {
		t.Fatalf("profile job on a server tenant: %d %s", code, raw)
	}
	var job db.BackupJob
	_ = json.Unmarshal(raw, &job)
	tm := auth.NewTokenManager("test-secret-key-must-be-very-long-123456")
	ticket, _ := tm.CreateBackupTicket(auth.BackupTicketClaims{JobID: job.ID, AgentID: f.agentA.ID, TargetID: f.targetA.ID, BackupType: "host", BackupID: "m365-contoso", BackupTime: time.Now().Unix()}, time.Hour)
	api := NewServerAPI(d, nil, config.DefaultServerConfig(), tm, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/m365-credentials", nil)
	req.Header.Set(BackupTicketHeader, ticket)
	req = req.WithContext(auth.WithAgent(req.Context(), &auth.AgentClaims{AgentID: f.agentA.ID}))
	rr := httptest.NewRecorder()
	api.HandleM365Credentials(rr, req)
	var creds m365.Credentials
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &creds) != nil {
		t.Fatalf("credentials: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "server-secret") || creds.TenantID != tenantGUID || creds.ClientID != clientGUID {
		t.Errorf("a profile job got %s", rr.Body.String())
	}

	// That tenant can't move to the agents while a job uses its secret
	if code, raw := newJob("server-secret-job", withSecret.ID, ""); code != http.StatusCreated {
		t.Fatalf("job without profile: %d %s", code, raw)
	}
	move := map[string]any{"name": "contoso-server", "tenant_id": tenantGUID, "client_id": clientGUID, "auth_method": "agent"}
	if code, raw := call(t, h, http.MethodPut, "/api/v1/m365/tenants/"+withSecret.ID.String(), move); code != http.StatusConflict || !strings.Contains(string(raw), "server-secret-job") {
		t.Errorf("move to agents with a server-secret job: %d %s", code, raw)
	}
}
