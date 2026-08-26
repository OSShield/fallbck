package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/db"
)

type fakeAgentStore struct {
	states map[uuid.UUID]*db.AgentAuthState
	calls  int
}

func (f *fakeAgentStore) GetAgentAuthState(_ context.Context, id uuid.UUID) (*db.AgentAuthState, error) {
	f.calls++
	st, ok := f.states[id]
	if !ok {
		return nil, db.ErrNotFound
	}
	copied := *st
	return &copied, nil
}

func TestAgentTokenRoundTrip(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	agentID := uuid.New()

	token, expires, err := tm.CreateAgentToken(agentID, "fallbck-agent-x", 3, time.Hour)
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}
	if time.Until(expires) < 59*time.Minute {
		t.Errorf("unexpected expiry %v", expires)
	}

	claims, err := tm.ValidateAgentToken(token)
	if err != nil {
		t.Fatalf("ValidateAgentToken: %v", err)
	}
	got, _ := claims.AgentID()
	if got != agentID || claims.TaskQueue != "fallbck-agent-x" || claims.Version != 3 {
		t.Errorf("claims mismatch: %+v", claims)
	}
}

func TestAudienceSeparation(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	agentID := uuid.New()

	ticket, err := tm.CreateBackupTicket(BackupTicketClaims{AgentID: agentID, Datastore: "ds"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tm.ValidateAgentToken(ticket); err == nil {
		t.Error("backup ticket must not validate as an agent token")
	}
	if _, err := tm.ValidateSession(ticket); err == nil {
		t.Error("backup ticket must not validate as a session")
	}

	agentToken, _, err := tm.CreateAgentToken(agentID, "q", 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tm.ValidateBackupTicket(agentToken); err == nil {
		t.Error("agent token must not validate as a backup ticket")
	}
	if _, err := tm.ValidateBackupTicket(ticket); err != nil {
		t.Errorf("backup ticket should still validate as a ticket: %v", err)
	}

	other := NewTokenManager("a-different-secret-key-that-is-also-long")
	if _, err := other.ValidateAgentToken(agentToken); err == nil {
		t.Error("token signed with another secret must not validate")
	}
}

func TestAgentVerifier(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	agentID := uuid.New()
	store := &fakeAgentStore{states: map[uuid.UUID]*db.AgentAuthState{
		agentID: {ID: agentID, TaskQueue: "fallbck-agent-q", TokenVersion: 1},
	}}
	v := NewAgentVerifier(tm, store, 50*time.Millisecond)
	ctx := context.Background()

	token, _, _ := tm.CreateAgentToken(agentID, "fallbck-agent-q", 1, time.Hour)

	claims, err := v.Verify(ctx, "Bearer "+token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.AgentID != agentID || claims.TaskQueue != "fallbck-agent-q" {
		t.Errorf("unexpected claims %+v", claims)
	}

	// cached: second call does not hit the store
	if _, err := v.Verify(ctx, token); err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 {
		t.Errorf("expected 1 store call (cache hit), got %d", store.calls)
	}

	// superseded version
	store.states[agentID].TokenVersion = 2
	v.Invalidate(agentID)
	if _, err := v.Verify(ctx, token); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for superseded version, got %v", err)
	}

	// task queue in token must match the persisted queue
	forged, _, _ := tm.CreateAgentToken(agentID, "fallbck-agent-other", 2, time.Hour)
	v.Invalidate(agentID)
	if _, err := v.Verify(ctx, forged); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected task queue mismatch error, got %v", err)
	}

	// revoked
	store.states[agentID].Revoked = true
	v.Invalidate(agentID)
	token2, _, _ := tm.CreateAgentToken(agentID, "fallbck-agent-q", 2, time.Hour)
	if _, err := v.Verify(ctx, token2); !errors.Is(err, ErrAgentRevoked) {
		t.Errorf("expected ErrAgentRevoked, got %v", err)
	}

	// deleted
	delete(store.states, agentID)
	v.Invalidate(agentID)
	if _, err := v.Verify(ctx, token2); !errors.Is(err, ErrAgentRevoked) {
		t.Errorf("expected ErrAgentRevoked for deleted agent, got %v", err)
	}

	// cache expiry propagates revocation without Invalidate
	store.states[agentID] = &db.AgentAuthState{ID: agentID, TaskQueue: "fallbck-agent-q", TokenVersion: 2}
	v.Invalidate(agentID)
	if _, err := v.Verify(ctx, token2); err != nil {
		t.Fatal(err)
	}
	store.states[agentID].Revoked = true
	time.Sleep(60 * time.Millisecond)
	if _, err := v.Verify(ctx, token2); !errors.Is(err, ErrAgentRevoked) {
		t.Errorf("expected revocation after cache expiry, got %v", err)
	}

	if _, err := v.Verify(ctx, ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for empty bearer, got %v", err)
	}
}
