package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	for _, path := range []string{"/api/v1/agents/pbs-credentials", "/api/v1/agents/db-credentials"} {
		rr = httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/agents/volume-ticket", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("volume-ticket: expected agent middleware to apply, got %d", rr.Code)
		}
		rr = httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/agents/token/worker", nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("token/worker: expected agent middleware to apply, got %d", rr.Code)
		}
		rr = httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("%s: expected agent middleware to apply, got %d", path, rr.Code)
		}
	}
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rr.Code != http.StatusOK {
		t.Errorf("health must stay public, got %d", rr.Code)
	}
}

func TestCreateJobValidation(t *testing.T) {
	r := newTestRouter()
	post := func(body string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/jobs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(rr, req)
		return rr
	}
	agent, target := "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
	cases := map[string]string{
		"db job with paths":     `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"database","backup_paths":["/etc"],"db_config":{"engine":"postgres","host":"h"}}`,
		"db job without config": `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"database"}`,
		"db job bad engine":     `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"database","db_config":{"engine":"oracle","host":"h"}}`,
		"fs job with db config": `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["/etc"],"db_config":{"engine":"postgres","host":"h"}}`,
		"unknown job type":      `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","job_type":"tape"}`,
		"fs job relative path":  `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["etc"]}`,
		"fs job bad exclude":    `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["/etc"],"exclude_paths":["[unclosed"]}`,
		"bad cron":              `{"name":"j","agent_id":"` + agent + `","target_id":"` + target + `","backup_paths":["/etc"],"schedule_cron":"every day at noon"}`,
	}
	for name, body := range cases {
		if rr := post(body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d: %s", name, rr.Code, rr.Body.String())
		}
	}
}
