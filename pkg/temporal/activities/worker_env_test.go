package activities

import (
	"context"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/agent/backup"
	k8sagent "github.com/osshield/fallbck/pkg/agent/k8sbackup"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/temporal"
)

// The worker pod spec is readable by anyone with get pods in the namespace: it may
// carry the encrypted flag (so the worker fetches the key itself) but never the key
func TestWorkerEnvCarriesNoKeyMaterial(t *testing.T) {
	a := &K8sAgentActivities{Config: &config.AgentConfig{ServerURL: "https://fallbck.example"}}
	a.Credentials = func(context.Context, string) (*backup.DirectOptions, error) {
		return &backup.DirectOptions{Endpoint: "https://pbs.example:8007", APIToken: "u@pbs!t:s"}, nil
	}
	a.EncryptionKey = func(context.Context, string) (*backup.Encryption, error) {
		t.Fatal("the agent must not fetch the key on behalf of the worker")
		return nil, nil
	}
	session := &temporal.BackupSessionInfo{DirectPBS: true, Encrypted: true, KeyFingerprint: "ab:cd", Ticket: "parent"}
	env, err := a.workerEnv(context.Background(), session, "g1", "volume-ticket", 0)
	if err != nil {
		t.Fatal(err)
	}
	var sessionJSON string
	for _, e := range env {
		if e.Name == k8sagent.EnvWorkerSession {
			sessionJSON = e.Value
		}
		if strings.Contains(strings.ToUpper(e.Name), "KEY") {
			t.Errorf("unexpected key-like variable %s", e.Name)
		}
	}
	if !strings.Contains(sessionJSON, `"encrypted":true`) || !strings.Contains(sessionJSON, `"key_fingerprint":"ab:cd"`) {
		t.Errorf("worker session must carry the encrypted flag: %s", sessionJSON)
	}
	if strings.Contains(sessionJSON, `"ticket":"parent"`) {
		t.Error("parent ticket must not reach the worker")
	}
}
