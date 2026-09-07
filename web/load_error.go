package web

import (
	"github.com/osshield/fallbck/pkg/db"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

func (u *UIHandler) renderLoadError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("Unable to load UI data", "path", r.URL.Path, "error", err)
	if r.Header.Get("HX-Request") == "true" {
		uiError(w, "Records could not be loaded. Your current view has been kept; try again shortly.", 503, "#notifications")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	u.renderPage(w, r, "load_error.html", map[string]any{"Title": "Records unavailable", "ActiveNav": strings.TrimPrefix(r.URL.Path, "/")})
}
func keyStatus(key *db.APIKey) string {
	if key.RevokedAt != nil {
		return "revoked"
	}
	if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
		return "expired"
	}
	return "active"
}
