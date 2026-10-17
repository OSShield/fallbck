package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/config"
	"github.com/osshield/fallbck/pkg/db"
)

// TestEveryAdminRouteIsGated walks every registered route. A principal without
// bindings is refused everywhere except /auth/me; a viewer scoped to team=a is
// refused on every mutating route, by the route gate or the handler's object check.
// The DB is nil here, so a route that reached the database unchecked would panic
// rather than pass.
func TestEveryAdminRouteIsGated(t *testing.T) {
	const agentMarker = http.StatusTeapot
	agentOnly := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(agentMarker) })
	}
	nobody := &auth.Principal{Kind: auth.PrincipalSession, Subject: "nobody"}
	viewer := &auth.Principal{Kind: auth.PrincipalSession, Subject: "viewer", Bindings: []auth.Binding{
		{Role: auth.RoleViewer, Permissions: auth.BuiltinRoles()[auth.RoleViewer], Selector: db.Labels{"team": "a"}},
	}}
	public := map[string]bool{"/api/v1/health": true, "/api/v1/agents/enroll": true}

	type route struct{ method, path string }
	var routes []route
	probe := chi.NewRouter()
	newAPI := func() *ServerAPI {
		return NewServerAPI(nil, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
	}
	newAPI().RegisterRoutes(probe, passthrough, agentOnly)
	_ = chi.Walk(probe, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !public[path] {
			routes = append(routes, route{method, path})
		}
		return nil
	})
	if len(routes) < 50 {
		t.Fatalf("walked only %d routes", len(routes))
	}

	serve := func(p *auth.Principal, rt route) int {
		r := chi.NewRouter()
		newAPI().RegisterRoutes(r, asPrincipal(p), agentOnly)
		path := strings.NewReplacer("{id}", "00000000-0000-0000-0000-000000000001", "{name}", "custom", "{os}", "linux", "{arch}", "amd64").Replace(rt.path)
		rr := httptest.NewRecorder()
		func() {
			defer func() {
				if recover() != nil {
					rr.Code = -1 // reached a handler (nil DB)
				}
			}()
			r.ServeHTTP(rr, httptest.NewRequest(rt.method, path, strings.NewReader("{}")))
		}()
		return rr.Code
	}

	admin := 0
	for _, rt := range routes {
		code := serve(nobody, rt)
		if code == agentMarker {
			continue // agent-authenticated route
		}
		admin++
		want := http.StatusForbidden
		if rt.path == "/api/v1/auth/me" {
			want = http.StatusOK
		}
		if code != want {
			t.Errorf("%s %s without bindings: %d, want %d", rt.method, rt.path, code, want)
		}
		if rt.method != http.MethodGet && rt.method != http.MethodHead {
			if code := serve(viewer, rt); code != http.StatusForbidden {
				t.Errorf("%s %s as a scoped viewer: %d, want 403", rt.method, rt.path, code)
			}
		}
	}
	if admin < 50 {
		t.Errorf("only %d admin routes found", admin)
	}
}

// TestLabelMoveNeedsBothScopes covers newLabels, the rule every relabel goes through
func TestLabelMoveNeedsBothScopes(t *testing.T) {
	op := &auth.Principal{Bindings: []auth.Binding{{Role: auth.RoleOperator, Permissions: auth.BuiltinRoles()[auth.RoleOperator], Selector: db.Labels{"team": "a"}}}}
	s := newTestAPI()
	cases := []struct {
		name     string
		old, req db.Labels
		want     int
	}{
		{"keep (nil)", db.Labels{"team": "a"}, nil, http.StatusOK},
		{"narrow within scope", db.Labels{"team": "a"}, db.Labels{"team": "a", "env": "prod"}, http.StatusOK},
		{"move out of scope", db.Labels{"team": "a"}, db.Labels{"team": "b"}, http.StatusForbidden},
		{"drop the scoping label", db.Labels{"team": "a"}, db.Labels{}, http.StatusForbidden},
		{"move into scope", db.Labels{"team": "b"}, db.Labels{"team": "a"}, http.StatusForbidden},
		{"bad syntax", db.Labels{"team": "a"}, db.Labels{"team": "a b"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPut, "/", nil).WithContext(auth.WithPrincipal(t.Context(), op))
			got, ok := s.newLabels(rr, r, auth.PermJobsWrite, tc.old, tc.req)
			code := http.StatusOK
			if !ok {
				code = rr.Code
			}
			if code != tc.want {
				t.Fatalf("status %d, want %d", code, tc.want)
			}
			if ok && tc.req == nil && !got.Equal(tc.old) {
				t.Errorf("nil should keep the stored labels, got %v", got)
			}
		})
	}
}

func newTestAPI() *ServerAPI {
	return NewServerAPI(nil, nil, config.DefaultServerConfig(), auth.NewTokenManager("test-secret-key-must-be-very-long-123456"), nil)
}
