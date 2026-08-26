package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
)

// PBSProxy handles authenticated, scoped reverse proxying of backup chunk streams to Proxmox Backup Server
type PBSProxy struct {
	DB           *db.DB
	TokenManager *auth.TokenManager
	targetCache  sync.Map // targetID (uuid.UUID) -> *db.BackupTarget
	clientPool   sync.Map // targetID -> *http.Client
}

// NewPBSProxy creates a new PBSProxy instance
func NewPBSProxy(database *db.DB, tm *auth.TokenManager) *PBSProxy {
	return &PBSProxy{
		DB:           database,
		TokenManager: tm,
	}
}

// RegisterRoutes mounts the PBS proxy routes onto Chi router
func (p *PBSProxy) RegisterRoutes(r chi.Router) {
	if r != nil {
		r.HandleFunc("/pbs-proxy/*", p.HandleProxyRequest)
	}
}

// SetTarget caches a backup target in memory
func (p *PBSProxy) SetTarget(target *db.BackupTarget) {
	if target != nil {
		p.targetCache.Store(target.ID, target)
	}
}

// HandleProxyRequest validates the short-lived backup ticket and forwards the request to PBS
func (p *PBSProxy) HandleProxyRequest(w http.ResponseWriter, r *http.Request) {
	// 1. Extract Bearer Token
	ticket := extractBearerToken(r)
	if ticket == "" {
		slog.Warn("PBS Proxy request rejected: missing Authorization header", "path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"missing authorization ticket"}`, http.StatusUnauthorized)
		return
	}

	// 2. Validate Ticket Claims
	claims, err := p.TokenManager.ValidateBackupTicket(ticket)
	if err != nil {
		slog.Warn("PBS Proxy request rejected: invalid ticket", "error", err, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"invalid or expired backup ticket"}`, http.StatusUnauthorized)
		return
	}

	// 3. Resolve Target PBS Endpoint & Credentials
	target, err := p.getTarget(r.Context(), claims.TargetID)
	if err != nil {
		slog.Error("PBS Proxy failed to resolve backup target", "target_id", claims.TargetID, "error", err)
		http.Error(w, `{"error":"backup target unavailable"}`, http.StatusBadGateway)
		return
	}

	// 4. Validate Scope (Datastore & Namespace)
	pathRemainder := strings.TrimPrefix(r.URL.Path, "/pbs-proxy")
	if !strings.HasPrefix(pathRemainder, "/") {
		pathRemainder = "/" + pathRemainder
	}

	// Check datastore isolation: path must target the authorized datastore
	if strings.Contains(pathRemainder, "/datastore/") {
		expectedPrefix := fmt.Sprintf("/api2/json/admin/datastore/%s", claims.Datastore)
		if !strings.HasPrefix(pathRemainder, expectedPrefix) && !strings.Contains(pathRemainder, claims.Datastore) {
			slog.Warn("PBS Proxy authorization mismatch: datastore violation", "expected", claims.Datastore, "path", pathRemainder)
			http.Error(w, `{"error":"unauthorized datastore scope"}`, http.StatusForbidden)
			return
		}
	}

	// 5. Construct Upstream Target URL
	targetURL, err := url.Parse(target.Endpoint)
	if err != nil {
		http.Error(w, `{"error":"invalid target endpoint configuration"}`, http.StatusInternalServerError)
		return
	}

	// 6. Reverse Proxy with Header Injection
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.URL.Path = pathRemainder
			req.Host = targetURL.Host

			// Injected PBS Master API Token
			if target.AuthTokenEncrypted != "" {
				token := target.AuthTokenEncrypted
				if !strings.HasPrefix(token, "PBSAPIToken=") {
					token = "PBSAPIToken=" + token
				}
				req.Header.Set("Authorization", token)
			}
		},
		Transport: p.getTransport(target),
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			slog.Error("PBS Proxy forwarding error", "error", err, "path", req.URL.Path)
			rw.WriteHeader(http.StatusBadGateway)
			_, _ = rw.Write([]byte(fmt.Sprintf(`{"error":"upstream PBS error: %v"}`, err)))
		},
	}

	proxy.ServeHTTP(w, r)
}

func (p *PBSProxy) getTarget(ctx context.Context, targetID uuid.UUID) (*db.BackupTarget, error) {
	if cached, ok := p.targetCache.Load(targetID); ok {
		return cached.(*db.BackupTarget), nil
	}

	if p.DB == nil {
		// Mock target for dev / testing mode
		mockTarget := &db.BackupTarget{
			ID:                 targetID,
			Name:               "Dev Target",
			TargetType:         "pbs",
			Endpoint:           "http://localhost:8007",
			Datastore:          "backup-store",
			AuthTokenEncrypted: "PBSAPIToken=root@pam!dev=secret",
			TLSVerify:          false,
		}
		return mockTarget, nil
	}

	target, err := p.DB.GetTargetByID(ctx, targetID)
	if err != nil {
		return nil, err
	}

	p.targetCache.Store(targetID, target)
	return target, nil
}

func (p *PBSProxy) getTransport(target *db.BackupTarget) *http.Transport {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: !target.TLSVerify,
	}

	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
	}
}

func extractBearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return strings.TrimSpace(parts[1])
		}
	}
	// Fallback to query parameter
	return r.URL.Query().Get("ticket")
}
