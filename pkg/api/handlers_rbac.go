package api

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
)

// Access management: roles (named permission sets), bindings (a role for a user or
// group on a label selector) and the audit log. Everything here needs rbac:manage,
// which only exists on empty selectors, except the audit log (audit:read, filtered by
// the labels each entry recorded).

var roleNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// RoleRequest creates or updates a custom role
type RoleRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

// BindingRequest grants a role (POST /rbac/bindings)
type BindingRequest struct {
	Kind     string    `json:"kind"`
	Subject  string    `json:"subject"`
	Role     string    `json:"role"`
	Selector db.Labels `json:"selector"`
}

// HandleListPermissions returns the permission catalog grouped by resource
func (s *ServerAPI) HandleListPermissions(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]any{"groups": auth.Catalog, "global_only": auth.GlobalOnly})
}

func (s *ServerAPI) HandleListRoles(w http.ResponseWriter, r *http.Request) {
	roles, err := s.DB.ListRoles(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list roles")
		return
	}
	s.writeJSON(w, http.StatusOK, roles)
}

// cleanPermissions validates and de-duplicates a permission list (catalog order)
func cleanPermissions(perms []string) ([]string, error) {
	for _, p := range perms {
		if !auth.KnownPermission(p) {
			return nil, errors.New("unknown permission " + p)
		}
	}
	out := []string{}
	for _, p := range auth.AllPermissions() {
		if slices.Contains(perms, p) {
			out = append(out, p)
		}
	}
	return out, nil
}

func (s *ServerAPI) HandleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !roleNameRe.MatchString(req.Name) {
		s.writeError(w, http.StatusBadRequest, "Role names are lowercase letters, digits, '.', '_' or '-' (up to 63)")
		return
	}
	perms, err := cleanPermissions(req.Permissions)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	role := &db.Role{Name: req.Name, Description: strings.TrimSpace(req.Description), Permissions: perms}
	if err := s.DB.CreateRole(r.Context(), role); err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "A role with that name exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to create role")
		return
	}
	s.audit(r, "role.create", "role", role.Name, role.Name, nil, map[string]any{"permissions": perms})
	s.writeJSON(w, http.StatusCreated, role)
}

func (s *ServerAPI) HandleUpdateRole(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	existing, err := s.DB.GetRole(r.Context(), name)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Role not found")
		return
	}
	if existing.Builtin {
		s.writeError(w, http.StatusConflict, "Built-in roles cannot be edited; clone it instead")
		return
	}
	var req RoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	perms, err := cleanPermissions(req.Permissions)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A role bound on a selector must not gain a global-only permission: that would
	// grant access management to a scoped subject
	if auth.HasGlobalOnly(perms) && !auth.HasGlobalOnly(existing.Permissions) {
		n, err := s.DB.ScopedBindingsOfRole(r.Context(), name)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to check the role's bindings")
			return
		}
		if n > 0 {
			s.writeError(w, http.StatusConflict, "The role is granted on label selectors; "+strings.Join(auth.GlobalOnly, " and ")+" can only be held on everything")
			return
		}
	}
	role := &db.Role{Name: name, Description: strings.TrimSpace(req.Description), Permissions: perms}
	if err := s.DB.UpdateRole(r.Context(), role); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to update role")
		return
	}
	s.RBAC.Flush()
	s.audit(r, "role.update", "role", name, name, nil, map[string]any{"old_permissions": existing.Permissions, "permissions": perms})
	s.writeJSON(w, http.StatusOK, role)
}

func (s *ServerAPI) HandleDeleteRole(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	switch err := s.DB.DeleteRole(r.Context(), name); {
	case err == nil:
		s.audit(r, "role.delete", "role", name, name, nil, nil)
		s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	case errors.Is(err, db.ErrInUse):
		s.writeError(w, http.StatusConflict, "The role is still bound to users, groups or API keys")
	case errors.Is(err, db.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "Role not found (built-in roles cannot be deleted)")
	default:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete role")
	}
}

func (s *ServerAPI) HandleListBindings(w http.ResponseWriter, r *http.Request) {
	bindings, err := s.DB.ListBindings(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list bindings")
		return
	}
	s.writeJSON(w, http.StatusOK, bindings)
}

func (s *ServerAPI) HandleCreateBinding(w http.ResponseWriter, r *http.Request) {
	var req BindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Kind != db.BindingUser && req.Kind != db.BindingGroup {
		s.writeError(w, http.StatusBadRequest, "kind must be user or group")
		return
	}
	if req.Subject == "" {
		s.writeError(w, http.StatusBadRequest, "subject is required (an email for users, a groups claim value for groups)")
		return
	}
	req.Selector = req.Selector.OrEmpty()
	if !s.validLabels(w, req.Selector) {
		return
	}
	role, err := s.DB.GetRole(r.Context(), req.Role)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Unknown role "+req.Role)
		return
	}
	if err := auth.CheckGlobalOnly(role.Permissions, req.Selector); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	b := &db.RoleBinding{Kind: req.Kind, Subject: req.Subject, Role: role.Name, Selector: req.Selector, CreatedBy: principalName(r)}
	if err := s.DB.CreateBinding(r.Context(), b); err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "That binding exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to create binding")
		return
	}
	s.RBAC.Flush()
	s.audit(r, "binding.create", "binding", b.ID.String(), b.Kind+":"+b.Subject, nil, map[string]any{"role": b.Role, "selector": b.Selector})
	s.writeJSON(w, http.StatusCreated, b)
}

func (s *ServerAPI) HandleDeleteBinding(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid binding ID")
		return
	}
	b, err := s.DB.GetBinding(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Binding not found")
		return
	}
	switch err := s.DB.DeleteBinding(r.Context(), id); {
	case err == nil:
	case errors.Is(err, db.ErrLastAdmin):
		s.writeError(w, http.StatusConflict, "This is the last binding that can manage access on everything; add another before removing it")
		return
	case errors.Is(err, db.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "Binding not found")
		return
	default:
		s.writeError(w, http.StatusInternalServerError, "Failed to delete binding")
		return
	}
	s.RBAC.Flush()
	s.audit(r, "binding.delete", "binding", b.ID.String(), b.Kind+":"+b.Subject, nil, map[string]any{"role": b.Role, "selector": b.Selector})
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// parseAuditTime accepts RFC 3339 or a plain date (YYYY-MM-DD, UTC midnight)
func parseAuditTime(v string) (*time.Time, error) {
	if v == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return &t, nil
		}
	}
	return nil, errors.New("times are RFC 3339 or YYYY-MM-DD")
}

// HandleListAudit returns audit entries within the principal's audit:read scope.
// Query: actor (substring), action (prefix), resource (kind), from, to, limit,
// format=csv for a download.
func (s *ServerAPI) HandleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	from, err := parseAuditTime(q.Get("from"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "from: "+err.Error())
		return
	}
	to, err := parseAuditTime(q.Get("to"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "to: "+err.Error())
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	entries, err := s.DB.ListAudit(r.Context(), db.AuditFilter{
		Actor: q.Get("actor"), Action: q.Get("action"), ResourceKind: q.Get("resource"), From: from, To: to, Limit: limit,
	}, scope(r, auth.PermAuditRead))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to read the audit log")
		return
	}
	if q.Get("format") != "csv" {
		s.writeJSON(w, http.StatusOK, entries)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="fallbck-audit-`+time.Now().UTC().Format("20060102-150405")+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"at", "actor_kind", "actor", "action", "resource_kind", "resource_id", "resource_name", "labels", "source_ip", "details"})
	for _, e := range entries {
		_ = cw.Write([]string{e.At.UTC().Format(time.RFC3339), e.ActorKind, csvSafe(e.Actor), e.Action, e.ResourceKind, e.ResourceID,
			csvSafe(e.ResourceName), e.Labels.String(), e.SourceIP, csvSafe(string(e.Details))})
	}
	cw.Flush()
}

// csvSafe defuses spreadsheet formula injection in free-text cells
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}
