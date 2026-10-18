package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/osshield/fallbck/pkg/db"
)

// Binding is one grant held by a principal: the permissions of a role on the objects
// Selector matches (empty: everything)
type Binding struct {
	Role        string      `json:"role"`
	Permissions []string    `json:"permissions"`
	Selector    db.Selector `json:"selector"`
}

// Scope is the set of objects perm reaches for the principal: the union of the
// selectors of every binding whose role holds perm. This is the single access
// decision; Allowed and the repository's SQL filter are both derived from it.
func (p *Principal) Scope(perm string) db.Scope {
	var s db.Scope
	if p == nil {
		return s
	}
	for _, b := range p.Bindings {
		if !b.grants(perm) {
			continue
		}
		if len(b.Selector) == 0 {
			return db.Unscoped
		}
		if !slices.ContainsFunc(s.Selectors, b.Selector.Equal) {
			s.Selectors = append(s.Selectors, b.Selector)
		}
	}
	return s
}

// Allowed reports whether perm reaches an object with these labels
func (p *Principal) Allowed(perm string, labels db.Labels) bool {
	return p.Scope(perm).Matches(labels)
}

// Can reports whether any binding grants perm at all (the route gate)
func (p *Principal) Can(perm string) bool { return !p.Scope(perm).Empty() }

// Permissions is the union of the permissions of all bindings, sorted
func (p *Principal) Permissions() []string {
	out := []string{}
	if p == nil {
		return out
	}
	for _, b := range p.Bindings {
		for _, perm := range b.Permissions {
			if b.grants(perm) && !slices.Contains(out, perm) {
				out = append(out, perm)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Covers reports whether one binding grants perm on a selector that sel narrows, so
// everything sel reaches is already reachable
func (p *Principal) Covers(perm string, sel db.Selector) bool {
	if p == nil {
		return false
	}
	for _, b := range p.Bindings {
		if b.grants(perm) && sel.Narrows(b.Selector) {
			return true
		}
	}
	return false
}

// Narrower checks that a grant of perms on sel stays within what p holds: every
// permission must be covered on a selector sel narrows, and global-only permissions
// need an empty selector. Used for API keys (a key never reaches further than its
// creator) and for bindings created by a principal.
func Narrower(p *Principal, perms []string, sel db.Selector) error {
	if err := CheckGlobalOnly(perms, sel); err != nil {
		return err
	}
	for _, perm := range perms {
		if !p.Covers(perm, sel) {
			return fmt.Errorf("you do not hold %s on a selector that %s narrows", perm, describeSelector(sel))
		}
	}
	return nil
}

// CheckGlobalOnly refuses a selector on a role holding a global-only permission
func CheckGlobalOnly(perms []string, sel db.Selector) error {
	if len(sel) > 0 && HasGlobalOnly(perms) {
		return fmt.Errorf("roles with %s can only be granted on everything (empty selector)", strings.Join(GlobalOnly, " or "))
	}
	return nil
}

func describeSelector(sel db.Selector) string {
	if len(sel) == 0 {
		return "everything"
	}
	return "{" + sel.String() + "}"
}

// grants reports whether the binding gives perm. A global-only permission on a scoped
// binding gives nothing: creating such a binding is refused, and this covers rows from
// before a permission became global-only.
func (b Binding) grants(perm string) bool {
	if !slices.Contains(b.Permissions, perm) {
		return false
	}
	return len(b.Selector) == 0 || !slices.Contains(GlobalOnly, perm)
}

// AdminBindings is the global admin grant (insecure dev mode)
func AdminBindings() []Binding {
	return []Binding{{Role: RoleAdmin, Permissions: AllPermissions()}}
}

// ---- resolver ---------------------------------------------------------------------

// BindingStore loads bindings and roles (implemented by *db.DB)
type BindingStore interface {
	BindingsFor(ctx context.Context, email string, groups, claims []string) ([]*db.RoleBinding, error)
	GetRole(ctx context.Context, name string) (*db.Role, error)
}

// Resolver turns an identity into its bindings. Results are cached for a short TTL
// so a removed binding takes effect within that window, not at session expiry;
// Flush drops the cache at once (called after every access change on this server).
type Resolver struct {
	store BindingStore
	ttl   time.Duration

	mu    sync.Mutex
	cache map[string]resolved
}

type resolved struct {
	bindings []Binding
	at       time.Time
}

// DefaultResolverTTL bounds how long a removed binding keeps working
const DefaultResolverTTL = 30 * time.Second

func NewResolver(store BindingStore, ttl time.Duration) *Resolver {
	return &Resolver{store: store, ttl: ttl, cache: map[string]resolved{}}
}

func (r *Resolver) cached(key string, load func() ([]Binding, error)) ([]Binding, error) {
	r.mu.Lock()
	c, ok := r.cache[key]
	r.mu.Unlock()
	if ok && time.Since(c.at) < r.ttl {
		return c.bindings, nil
	}
	b, err := load()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.cache[key] = resolved{bindings: b, at: time.Now()}
	r.mu.Unlock()
	return b, nil
}

// Flush forgets every cached resolution
func (r *Resolver) Flush() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.cache = map[string]resolved{}
	r.mu.Unlock()
}

// Session resolves an OIDC identity: user bindings on its email (only when the IdP
// did not mark it unverified), group bindings on its groups claim and claim bindings
// on its binding claims ("<claim>=<value>")
func (r *Resolver) Session(ctx context.Context, email string, emailUnverified bool, groups, claims []string) ([]Binding, error) {
	if emailUnverified {
		email = ""
	}
	sorted := func(s []string) string {
		c := slices.Clone(s)
		sort.Strings(c)
		return strings.Join(c, "\x00")
	}
	key := "s\x00" + strings.ToLower(email) + "\x01" + sorted(groups) + "\x01" + sorted(claims)
	return r.cached(key, func() ([]Binding, error) {
		rows, err := r.store.BindingsFor(ctx, email, groups, claims)
		if err != nil {
			return nil, err
		}
		out := make([]Binding, 0, len(rows))
		for _, b := range rows {
			out = append(out, Binding{Role: b.Role, Permissions: b.Permissions, Selector: b.Selector})
		}
		return out, nil
	})
}

// APIKey resolves a key's single binding (its role on its selector)
func (r *Resolver) APIKey(ctx context.Context, key *db.APIKey) ([]Binding, error) {
	perms, err := r.cached("r\x00"+key.Role, func() ([]Binding, error) {
		role, err := r.store.GetRole(ctx, key.Role)
		if err != nil {
			return nil, err
		}
		return []Binding{{Role: role.Name, Permissions: role.Permissions}}, nil
	})
	if err != nil {
		return nil, err
	}
	return []Binding{{Role: key.Role, Permissions: perms[0].Permissions, Selector: key.Selector}}, nil
}

// ---- middleware -----------------------------------------------------------------

// RequirePerm is the route gate: refused unless some binding grants perm on some
// selector. Object-level checks (labels) happen in the handler.
func RequirePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !PrincipalFrom(r.Context()).Can(perm) {
				forbid(w, r, "missing permission "+perm)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyPerm is RequirePerm for a route that serves holders of any of perms
func RequireAnyPerm(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := PrincipalFrom(r.Context())
			if !slices.ContainsFunc(perms, p.Can) {
				forbid(w, r, "missing permission "+strings.Join(perms, " or "))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAny refuses principals without any binding
func RequireAny(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := PrincipalFrom(r.Context()); p == nil || len(p.Bindings) == 0 {
			forbid(w, r, "your account has no role on this server")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func forbid(w http.ResponseWriter, r *http.Request, msg string) {
	if wantsHTML(r) {
		http.Error(w, "Forbidden: "+msg+". Ask an administrator for access.", http.StatusForbidden)
		return
	}
	writeJSONError(w, http.StatusForbidden, msg)
}

// ---- audit ------------------------------------------------------------------------

// NewAuditEntry describes an action of the request's principal for the audit log
func NewAuditEntry(r *http.Request, action, kind, id, name string, labels db.Labels, details any) *db.AuditEntry {
	e := &db.AuditEntry{Action: action, ResourceKind: kind, ResourceID: id, ResourceName: name, Labels: labels.OrEmpty(), SourceIP: ClientIP(r)}
	if p := PrincipalFrom(r.Context()); p != nil {
		e.ActorKind, e.Actor = string(p.Kind), p.Display()
	} else {
		e.ActorKind, e.Actor = "anonymous", ""
	}
	if details != nil {
		if b, err := json.Marshal(details); err == nil {
			e.Details = b
		}
	}
	return e
}

// ClientIP is the address set by the trusted-proxies middleware, else the peer
func ClientIP(r *http.Request) string {
	if ip := middleware.GetClientIP(r.Context()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
