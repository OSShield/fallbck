package k8sbackup

import (
	"context"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/config"
	k8sfake "k8s.io/client-go/kubernetes/fake"
)

func TestIdentitySecretRoundTrip(t *testing.T) {
	core := k8sfake.NewSimpleClientset()
	ctx := context.Background()

	if cfg, err := LoadIdentity(ctx, core, "fallbck", "identity"); err != nil || cfg != nil {
		t.Fatalf("missing secret must be (nil, nil): %v %v", cfg, err)
	}
	cfg := &config.AgentConfig{AgentID: "a-1", TaskQueue: "q", ServerURL: "http://server:8080", AuthToken: "tok", TokenExpiresAt: time.Now().UTC().Truncate(time.Second)}
	if err := SaveIdentity(ctx, core, "fallbck", "identity", cfg); err != nil {
		t.Fatal(err)
	}
	back, err := LoadIdentity(ctx, core, "fallbck", "identity")
	if err != nil || back == nil || back.AgentID != "a-1" || back.AuthToken != "tok" {
		t.Fatalf("round trip: %+v %v", back, err)
	}
	// rotation persists via the TokenStore hook
	persist := IdentityPersist(core, "fallbck", "identity")
	cfg.AuthToken = "rotated"
	if err := persist(cfg); err != nil {
		t.Fatal(err)
	}
	back, _ = LoadIdentity(ctx, core, "fallbck", "identity")
	if back.AuthToken != "rotated" {
		t.Errorf("rotation not persisted: %q", back.AuthToken)
	}
}
