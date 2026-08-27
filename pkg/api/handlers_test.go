package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
)

func passthrough(next http.Handler) http.Handler { return next }

func newTestRouter() *chi.Mux {
	api := NewServerAPI(nil, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
	r := chi.NewRouter()
	api.RegisterRoutes(r, passthrough, passthrough)
	return r
}

func TestHealthEndpoint(t *testing.T) {
	r := newTestRouter()

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
	r := newTestRouter()

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

func TestAdminMiddlewareIsApplied(t *testing.T) {
	api := NewServerAPI(nil, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
	r := chi.NewRouter()
	deny := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) })
	}
	api.RegisterRoutes(r, deny, deny)

	for _, path := range []string{"/api/v1/agents", "/api/v1/tokens", "/api/v1/apikeys", "/api/v1/jobs", "/api/v1/auth/me"} {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected admin middleware to apply, got %d", path, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, "/api/v1/jobs/00000000-0000-0000-0000-000000000000", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("PUT job: expected admin middleware to apply, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("heartbeat: expected agent middleware to apply, got %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("health must stay public, got %d", rr.Code)
	}
}
