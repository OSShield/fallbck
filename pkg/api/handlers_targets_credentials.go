package api

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/pbs"
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
