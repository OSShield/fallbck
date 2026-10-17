package api

import (
	"log/slog"
	"net/http"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
)

// scope is the request principal's reach for perm; every admin read passes it to the
// repository so rows outside it never leave the database (a 404, like a missing row)
func scope(r *http.Request, perm string) db.Scope {
	return auth.PrincipalFrom(r.Context()).Scope(perm)
}

// allow answers 403 unless perm reaches every label set given: the object's current
// labels, and its new labels when they change (so nobody moves an object into or out
// of their own scope)
func (s *ServerAPI) allow(w http.ResponseWriter, r *http.Request, perm string, labels ...db.Labels) bool {
	p := auth.PrincipalFrom(r.Context())
	for _, l := range labels {
		if !p.Allowed(perm, l) {
			s.writeError(w, http.StatusForbidden, "missing permission "+perm+" on this object")
			return false
		}
	}
	return true
}

// validLabels answers 400 for labels that break the label syntax
func (s *ServerAPI) validLabels(w http.ResponseWriter, l db.Labels) bool {
	if err := db.ValidateLabels(l); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

// newLabels resolves the labels of an update: nil (field absent) keeps the stored
// ones, anything else replaces them and needs perm on both old and new
func (s *ServerAPI) newLabels(w http.ResponseWriter, r *http.Request, perm string, old, requested db.Labels) (db.Labels, bool) {
	if requested == nil {
		return old.OrEmpty(), true
	}
	if !s.validLabels(w, requested) || !s.allow(w, r, perm, old, requested) {
		return nil, false
	}
	return requested, true
}

// audit records an action of the request's principal. Best effort: the action has
// happened, so a failed write is logged, not returned.
func (s *ServerAPI) audit(r *http.Request, action, kind, id, name string, labels db.Labels, details any) {
	if s.DB == nil {
		return
	}
	e := auth.NewAuditEntry(r, action, kind, id, name, labels, details)
	if err := s.DB.WriteAudit(r.Context(), e); err != nil {
		slog.Error("Writing audit log entry failed", "action", action, "resource", kind, "id", id, "actor", e.Actor, "error", err)
	}
}
