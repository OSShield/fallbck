package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
)

func TestPBSProxyAuthenticationAndForwarding(t *testing.T) {
	secret := "my-secret-key-32-bytes-long-for-testing"
	tm := auth.NewTokenManager(secret)

	var mu sync.Mutex
	var receivedAuthHeader string
	var receivedPath string
	var receivedBody string

	mockPBS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedAuthHeader = r.Header.Get("Authorization")
		receivedPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"digest":"abcdef123456"}}`))
	}))
	defer mockPBS.Close()

	proxy := NewPBSProxy(nil, tm)
	targetID := uuid.New()

	// Pre-populate target cache pointing to mockPBS URL
	proxy.targetCache.Store(targetID, &db.BackupTarget{
		ID:                 targetID,
		Name:               "Mock PBS",
		TargetType:         "pbs",
		Endpoint:           mockPBS.URL,
		Datastore:          "backup-store",
		AuthTokenEncrypted: "PBSAPIToken=root@pam!token=secret",
		TLSVerify:          false,
	})

	r := chi.NewRouter()
	proxy.RegisterRoutes(r)

	// 1. Missing Ticket -> 401
	req1, _ := http.NewRequest(http.MethodPost, "/pbs-proxy/api2/json/admin/datastore/backup-store/upload-chunk", nil)
	rr1 := httptest.NewRecorder()
	r.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for missing ticket, got %d", rr1.Code)
	}

	// 2. Valid Ticket with Target Scope
	claims := auth.BackupTicketClaims{
		JobID:      uuid.New(),
		AgentID:    uuid.New(),
		TargetID:   targetID,
		Datastore:  "backup-store",
		Namespace:  "production",
		BackupType: "host",
		BackupID:   "web-01",
		BackupTime: time.Now().Unix(),
	}

	ticket, err := tm.CreateBackupTicket(claims, 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateBackupTicket failed: %v", err)
	}

	// 3. Datastore Scope Mismatch -> 403 Forbidden
	reqMismatch, _ := http.NewRequest(http.MethodPost, "/pbs-proxy/api2/json/admin/datastore/other-datastore/upload-chunk", nil)
	reqMismatch.Header.Set("Authorization", "Bearer "+ticket)
	rrMismatch := httptest.NewRecorder()
	r.ServeHTTP(rrMismatch, reqMismatch)
	if rrMismatch.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for mismatched datastore scope, got %d", rrMismatch.Code)
	}

	// 4. Valid Request -> Forwarded to mockPBS with injected master token
	chunkPayload := "raw-chunk-bytes-data-12345"
	reqValid, _ := http.NewRequest(http.MethodPost, "/pbs-proxy/api2/json/admin/datastore/backup-store/upload-chunk", strings.NewReader(chunkPayload))
	reqValid.Header.Set("Authorization", "Bearer "+ticket)
	rrValid := httptest.NewRecorder()
	r.ServeHTTP(rrValid, reqValid)

	if rrValid.Code != http.StatusOK {
		t.Errorf("Expected status 200 from proxy forward, got %d: %s", rrValid.Code, rrValid.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()

	if receivedAuthHeader != "PBSAPIToken=root@pam!token=secret" {
		t.Errorf("Expected injected PBS auth header 'PBSAPIToken=root@pam!token=secret', got '%s'", receivedAuthHeader)
	}
	if receivedPath != "/api2/json/admin/datastore/backup-store/upload-chunk" {
		t.Errorf("Expected path '/api2/json/admin/datastore/backup-store/upload-chunk', got '%s'", receivedPath)
	}
	if receivedBody != chunkPayload {
		t.Errorf("Expected chunk payload '%s', got '%s'", chunkPayload, receivedBody)
	}
}
