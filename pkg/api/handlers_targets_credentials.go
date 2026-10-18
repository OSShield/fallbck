package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
	"github.com/osshield/fallbck/pkg/tokencheck"
)

// TargetCredentials hands an administrator the PBS connection details of a target in
// the form proxmox-backup-client expects (restores are done with PBS's own tools)
type TargetCredentials struct {
	Endpoint    string `json:"endpoint"`
	Datastore   string `json:"datastore"`
	Namespace   string `json:"namespace,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	TLSVerify   bool   `json:"tls_verify"`
	TokenID     string `json:"token_id"`
	Secret      string `json:"secret"`
	// Repository is the PBS_REPOSITORY value: <token id>@<host[:port]>:<datastore>
	Repository string `json:"repository"`
}

// HandleTargetCredentials returns a target's PBS API token to an administrator, for
// restores with proxmox-backup-client (e.g. the Proxmox VE host restore runbook). The
// request is logged with the acting principal.
func (s *ServerAPI) HandleTargetCredentials(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r, auth.PermTargetsCredentials)
	if !ok {
		return
	}
	token, err := pbs.NormalizeAPIToken(target.AuthToken)
	if err != nil {
		s.writeError(w, http.StatusFailedDependency, "backup target has no usable PBS API token")
		return
	}
	tokenID := pbs.TokenID(token)
	secret := ""
	if i := strings.LastIndexByte(token, ':'); i >= 0 {
		secret = token[i+1:]
	}
	host := target.Endpoint
	if u, err := url.Parse(target.Endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	slog.Warn("PBS target credentials revealed to an administrator", "target", target.Name, "target_id", target.ID, "token_id", tokenID, "principal", principalName(r))
	s.audit(r, "target.credentials", "target", target.ID.String(), target.Name, target.Labels, map[string]any{"token_id": tokenID})
	s.writeJSON(w, http.StatusOK, TargetCredentials{
		Endpoint: target.Endpoint, Datastore: target.Datastore, Namespace: target.Namespace,
		Fingerprint: target.Fingerprint, TLSVerify: target.TLSVerify,
		TokenID: tokenID, Secret: secret,
		Repository: tokenID + "@" + host + ":" + target.Datastore,
	})
}

// HandleCheckTargetToken asks PBS what the target's API token may do and stores the
// verdict on the target (POST /targets/{id}/token-check). See pkg/tokencheck.
func (s *ServerAPI) HandleCheckTargetToken(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r, auth.PermTargetsWrite)
	if !ok {
		return
	}
	res, prev, err := tokencheck.Check(r.Context(), s.DB, target)
	if err != nil {
		slog.Error("Storing the PBS token check failed", "target", target.Name, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to store the token check")
		return
	}
	if prev != res.Status {
		s.audit(r, "target.token_check", "target", target.ID.String(), target.Name, target.Labels,
			map[string]any{"from": prev, "to": res.Status, "token_id": res.TokenID, "findings": res.Findings, "error": res.Error})
	}
	s.writeJSON(w, http.StatusOK, res)
}

// checkTokenLater checks a target's token in the background after it was saved, so
// the form does not wait on PBS; the result shows on the target when it lands
func (s *ServerAPI) checkTokenLater(target *db.BackupTarget) {
	if s.DB == nil || target == nil {
		return
	}
	t := *target
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		tokencheck.CheckAndAudit(ctx, s.DB, &t)
	}()
}
