package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTokenGenerationAndHashing(t *testing.T) {
	rawToken, tokenHash, err := GenerateSecureToken(32)
	if err != nil {
		t.Fatalf("GenerateSecureToken failed: %v", err)
	}

	if len(rawToken) != 64 { // 32 bytes hex encoded = 64 chars
		t.Errorf("Expected raw token length 64, got %d", len(rawToken))
	}

	if len(tokenHash) != 64 { // sha256 hex = 64 chars
		t.Errorf("Expected token hash length 64, got %d", len(tokenHash))
	}

	// Verify hash is deterministic
	if HashToken(rawToken) != tokenHash {
		t.Errorf("HashToken did not match generated hash")
	}
}

func TestBackupTicketLifecycle(t *testing.T) {
	secret := "test-secret-key-must-be-very-long-123456"
	tm := NewTokenManager(secret)

	jobID := uuid.New()
	agentID := uuid.New()
	targetID := uuid.New()

	claims := BackupTicketClaims{
		JobID:      jobID,
		AgentID:    agentID,
		TargetID:   targetID,
		Datastore:  "datastore1",
		Namespace:  "prod",
		BackupType: "host",
		BackupID:   "web-server",
		BackupTime: time.Now().Unix(),
	}

	// Create ticket
	ticket, err := tm.CreateBackupTicket(claims, 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateBackupTicket failed: %v", err)
	}

	if ticket == "" {
		t.Fatal("Expected non-empty ticket string")
	}

	// Validate ticket
	parsedClaims, err := tm.ValidateBackupTicket(ticket)
	if err != nil {
		t.Fatalf("ValidateBackupTicket failed: %v", err)
	}

	if parsedClaims.JobID != jobID {
		t.Errorf("Expected JobID %s, got %s", jobID, parsedClaims.JobID)
	}
	if parsedClaims.AgentID != agentID {
		t.Errorf("Expected AgentID %s, got %s", agentID, parsedClaims.AgentID)
	}
	if parsedClaims.Datastore != "datastore1" {
		t.Errorf("Expected Datastore 'datastore1', got '%s'", parsedClaims.Datastore)
	}
	if parsedClaims.Namespace != "prod" {
		t.Errorf("Expected Namespace 'prod', got '%s'", parsedClaims.Namespace)
	}
}

func TestExpiredBackupTicket(t *testing.T) {
	secret := "test-secret-key-must-be-very-long-123456"
	tm := NewTokenManager(secret)

	claims := BackupTicketClaims{
		JobID:      uuid.New(),
		AgentID:    uuid.New(),
		TargetID:   uuid.New(),
		Datastore:  "store",
		BackupType: "host",
		BackupID:   "node",
		BackupTime: time.Now().Unix(),
	}

	// Negative TTL -> expired
	ticket, err := tm.CreateBackupTicket(claims, -10*time.Minute)
	if err != nil {
		t.Fatalf("Failed to create expired ticket: %v", err)
	}

	_, err = tm.ValidateBackupTicket(ticket)
	if err == nil {
		t.Fatal("Expected validation error on expired ticket, got nil")
	}
}
