package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentOpsRejectInvalidID(t *testing.T) {
	r := newTestRouter()
	for _, path := range []string{"/api/v1/agents/not-a-uuid/logs", "/api/v1/agents/not-a-uuid/inventory"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: expected 400, got %d", path, rr.Code)
		}
	}
}

func TestAgentOpsRequirePost(t *testing.T) {
	r := newTestRouter()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/00000000-0000-0000-0000-000000000000/logs", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestAgentOpErrorMapping(t *testing.T) {
	cases := []struct {
		err  error
		code int
	}{
		{context.DeadlineExceeded, http.StatusGatewayTimeout},
		{errors.New("activity ScheduleToStart timeout"), http.StatusGatewayTimeout},
		{errors.New("unable to find activity type GetAgentLogs"), http.StatusNotImplemented},
		{errors.New("boom"), http.StatusBadGateway},
	}
	for _, c := range cases {
		code, msg := agentOpError(c.err)
		if code != c.code || msg == "" {
			t.Errorf("%v: got %d %q, want %d", c.err, code, msg, c.code)
		}
	}
}
