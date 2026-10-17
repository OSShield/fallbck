package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/osshield/fallbck/pkg/db"
)

func principal(bindings ...Binding) *Principal {
	return &Principal{Kind: PrincipalSession, Bindings: bindings}
}

func bind(role string, sel db.Labels) Binding {
	perms := BuiltinRoles()[role]
	return Binding{Role: role, Permissions: perms, Selector: sel}
}

func TestScopeAndAllowed(t *testing.T) {
	teamA := db.Labels{"team": "a"}
	teamB := db.Labels{"team": "b"}
	prodA := db.Labels{"team": "a", "env": "prod"}

	cases := []struct {
		name   string
		p      *Principal
		perm   string
		labels db.Labels
		want   bool
	}{
		{"nil principal", nil, PermJobsRead, teamA, false},
		{"no bindings", principal(), PermJobsRead, teamA, false},
		{"global viewer reads", principal(bind(RoleViewer, nil)), PermJobsRead, teamB, true},
		{"global viewer cannot write", principal(bind(RoleViewer, nil)), PermJobsWrite, teamA, false},
		{"scoped operator writes in scope", principal(bind(RoleOperator, teamA)), PermJobsWrite, teamA, true},
		{"scoped operator writes subset", principal(bind(RoleOperator, teamA)), PermJobsWrite, prodA, true},
		{"scoped operator outside scope", principal(bind(RoleOperator, teamA)), PermJobsWrite, teamB, false},
		{"scoped operator unlabelled object", principal(bind(RoleOperator, teamA)), PermJobsRead, db.Labels{}, false},
		{"selector AND", principal(bind(RoleOperator, prodA)), PermJobsRead, teamA, false},
		{"union of bindings", principal(bind(RoleViewer, teamA), bind(RoleOperator, teamB)), PermJobsWrite, teamB, true},
		{"union keeps role apart", principal(bind(RoleViewer, teamA), bind(RoleOperator, teamB)), PermJobsWrite, teamA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.Allowed(tc.perm, tc.labels); got != tc.want {
				t.Errorf("Allowed = %v, want %v", got, tc.want)
			}
			// Allowed is Scope(perm).Matches: the SQL side renders the same Scope
			if got := tc.p.Scope(tc.perm).Matches(tc.labels); got != tc.want {
				t.Errorf("Scope.Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestScopeShape(t *testing.T) {
	p := principal(bind(RoleViewer, db.Labels{"team": "a"}), bind(RoleViewer, db.Labels{"team": "a"}), bind(RoleOperator, db.Labels{"team": "b"}))
	s := p.Scope(PermJobsRead)
	if s.All || len(s.Selectors) != 2 {
		t.Fatalf("duplicate selectors should collapse: %+v", s)
	}
	sql, args := s.SQL("j.labels", []any{"x"})
	if sql != "(j.labels @> $2::jsonb OR j.labels @> $3::jsonb)" || len(args) != 3 {
		t.Errorf("SQL = %s %v", sql, args)
	}
	if sql, _ := (db.Scope{}).SQL("labels", nil); sql != "FALSE" {
		t.Errorf("empty scope renders %s", sql)
	}
	global := principal(bind(RoleViewer, db.Labels{"team": "a"}), bind(RoleViewer, nil))
	if sql, _ := global.Scope(PermJobsRead).SQL("labels", nil); sql != "TRUE" {
		t.Errorf("a global binding should win: %s", sql)
	}
	if p.Can(PermRBACManage) || !p.Can(PermJobsWrite) {
		t.Error("Can should follow the bindings' roles")
	}
}

func TestNarrower(t *testing.T) {
	teamA := db.Labels{"team": "a"}
	scopedOp := principal(bind(RoleOperator, teamA))
	admin := principal(bind(RoleAdmin, nil))
	viewer := BuiltinRoles()[RoleViewer]
	operator := BuiltinRoles()[RoleOperator]

	cases := []struct {
		name  string
		p     *Principal
		perms []string
		sel   db.Labels
		ok    bool
	}{
		{"admin grants anything globally", admin, AllPermissions(), nil, true},
		{"admin grants scoped viewer", admin, viewer, teamA, true},
		{"scoped operator grants its own scope", scopedOp, operator, teamA, true},
		{"scoped operator grants a narrower scope", scopedOp, viewer, db.Labels{"team": "a", "env": "prod"}, true},
		{"scoped operator cannot widen to everything", scopedOp, viewer, nil, false},
		{"scoped operator cannot cross scopes", scopedOp, viewer, db.Labels{"team": "b"}, false},
		{"scoped operator cannot add permissions", scopedOp, []string{PermTargetsCredentials}, teamA, false},
		{"global-only needs an empty selector", admin, []string{PermAPIKeysManage}, teamA, false},
		{"rbac:manage on a selector is refused", admin, []string{PermRBACManage, PermJobsRead}, teamA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Narrower(tc.p, tc.perms, tc.sel)
			if (err == nil) != tc.ok {
				t.Errorf("Narrower = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

func TestBuiltinRoles(t *testing.T) {
	roles := BuiltinRoles()
	if !slices.Equal(roles[RoleAdmin], AllPermissions()) {
		t.Error("admin must hold every permission")
	}
	for _, p := range roles[RoleViewer] {
		if !slices.Contains(roles[RoleOperator], p) {
			t.Errorf("operator should include viewer's %s", p)
		}
	}
	for _, role := range []string{RoleOperator, RoleViewer} {
		if HasGlobalOnly(roles[role]) {
			t.Errorf("%s holds a global-only permission; it could not be bound on a selector", role)
		}
		for _, p := range []string{PermTargetsCredentials, PermKeyringsExport, PermAgentsDelete, PermTargetsDelete} {
			if slices.Contains(roles[role], p) {
				t.Errorf("%s should not hold %s", role, p)
			}
		}
	}
	for _, p := range AllPermissions() {
		if !KnownPermission(p) {
			t.Errorf("%s missing from the catalog", p)
		}
	}
}

// roleStore serves built-in roles and one group binding (ops → viewer on team=a)
type roleStore struct{}

func (roleStore) BindingsFor(_ context.Context, email string, groups []string) ([]*db.RoleBinding, error) {
	if slices.Contains(groups, "ops") {
		return []*db.RoleBinding{{Kind: db.BindingGroup, Subject: "ops", Role: RoleViewer, Permissions: BuiltinRoles()[RoleViewer], Selector: db.Labels{"team": "a"}}}, nil
	}
	return nil, nil
}

func (roleStore) GetRole(_ context.Context, name string) (*db.Role, error) {
	perms, ok := BuiltinRoles()[name]
	if !ok {
		return nil, db.ErrNotFound
	}
	return &db.Role{Name: name, Builtin: true, Permissions: perms}, nil
}

// TestAuthenticateResolvesBindings: API keys carry their role on their selector,
// sessions get their group bindings, and without a resolver nothing is granted
func TestAuthenticateResolvesBindings(t *testing.T) {
	tm := NewTokenManager("test-secret-key-must-be-very-long-123456")
	store := &fakeKeyStore{keys: map[string]*db.APIKey{}}
	a := NewAdminAuth(tm, store, false)
	a.RBAC = NewResolver(roleStore{}, time.Minute)

	raw, key, _ := NewAPIKey("ci", "alice", nil)
	key.Role, key.Selector = RoleOperator, db.Labels{"team": "a"}
	_ = store.CreateAPIKey(context.Background(), key)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/jobs", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(PermJobsWrite, db.Labels{"team": "a"}) || p.Allowed(PermJobsWrite, db.Labels{"team": "b"}) || p.Can(PermRBACManage) {
		t.Errorf("API key bindings: %+v", p.Bindings)
	}

	session, _, _ := tm.CreateSession(&Identity{Subject: "s", Email: "bob@example.com", Groups: []string{"ops"}}, 0)
	r = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: session})
	if p, err = a.Authenticate(r); err != nil {
		t.Fatal(err)
	}
	if !p.Allowed(PermJobsRead, db.Labels{"team": "a"}) || p.Can(PermJobsWrite) {
		t.Errorf("session bindings: %+v", p.Bindings)
	}

	a.RBAC = nil
	if p, _ = a.Authenticate(r); len(p.Bindings) != 0 {
		t.Error("no resolver must grant nothing")
	}
}
