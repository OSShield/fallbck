package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/certs"
	"github.com/osshield/fallbck/pkg/config"
)

func TestHealthEndpoint(t *testing.T) {
	api := NewServerAPI(nil, nil, config.DefaultServerConfig(), nil, auth.NewTokenManager("test-secret"))

	r := chi.NewRouter()
	api.RegisterRoutes(r)

	req, err := http.NewRequest(http.MethodGet, "/api/v1/health", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if resp["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%v'", resp["status"])
	}
}

func TestEnrollmentRequiresToken(t *testing.T) {
	tempDir := t.TempDir()
	ca, _ := certs.LoadOrCreateCA(tempDir+"/ca.crt", tempDir+"/ca.key")
	api := NewServerAPI(nil, nil, config.DefaultServerConfig(), ca, auth.NewTokenManager("test-secret"))

	r := chi.NewRouter()
	api.RegisterRoutes(r)

	req, err := http.NewRequest(http.MethodPost, "/api/v1/agents/enroll", httptest.NewRecorder().Body)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty body, got %d", rr.Code)
	}
}
