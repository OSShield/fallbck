package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/osshield/fallbck/pkg/auth"
	"github.com/osshield/fallbck/pkg/db"
	"github.com/osshield/fallbck/pkg/pbs"
)

// Per-target client-side encryption. The key is generated and kept on the server
// (sealed with the master key), handed to agents per run with their backup ticket, and
// exported to administrators only as a passphrase-protected proxmox-backup-client key
// file. Raw key material never appears in an API response.

// TargetEncryptionRequest sets a target's encryption (PUT /targets/{id}/encryption)
type TargetEncryptionRequest struct {
	// Mode: none | encrypt
	Mode string `json:"mode"`
	// MasterPublicKey (PEM, optional): every snapshot then carries the encryption key
	// wrapped with it for recovery with the private key; "" removes it
	MasterPublicKey string `json:"master_public_key"`
}

// TargetEncryption describes a target's encryption (GET /targets/{id}/encryption and
// embedded in the target form response)
type TargetEncryption struct {
	Mode            string          `json:"mode"`
	Fingerprint     string          `json:"fingerprint,omitempty"`
	KeyCreatedAt    *time.Time      `json:"key_created_at,omitempty"`
	HasMasterKey    bool            `json:"has_master_key"`
	MasterPublicKey string          `json:"master_public_key,omitempty"`
	Keys            []*db.TargetKey `json:"keys"`
}

// ExportKeyRequest (POST /targets/{id}/encryption/export)
type ExportKeyRequest struct {
	Passphrase string `json:"passphrase"`
	Hint       string `json:"hint"`
	// KeyID selects a retired key; default: the active one
	KeyID string `json:"key_id"`
}

// ImportKeyRequest adopts an existing proxmox-backup-client key file as the active key
// (POST /targets/{id}/encryption/import)
type ImportKeyRequest struct {
	KeyFile    string `json:"keyfile"`
	Passphrase string `json:"passphrase"`
}

// AgentEncryptionKey is what an agent receives for an encrypted run
// (GET /agents/encryption-key, agent token + backup ticket)
type AgentEncryptionKey struct {
	Mode            string    `json:"mode"`
	Key             string    `json:"key,omitempty"` // base64, 32 bytes
	Fingerprint     string    `json:"fingerprint,omitempty"`
	KeyCreatedAt    time.Time `json:"key_created_at,omitempty"`
	MasterPublicKey string    `json:"master_public_key,omitempty"`
}

func principalName(r *http.Request) string {
	if p := auth.PrincipalFrom(r.Context()); p != nil && p.Name != "" {
		return p.Name
	}
	return "api-key"
}

func (s *ServerAPI) targetFromPath(w http.ResponseWriter, r *http.Request) (*db.BackupTarget, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid target ID")
		return nil, false
	}
	target, err := s.DB.GetTargetByID(r.Context(), id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return nil, false
	}
	return target, true
}

// newTargetKey generates a key, stores it and makes it the target's active key
func (s *ServerAPI) newTargetKey(r *http.Request, target *db.BackupTarget) (*db.TargetKey, error) {
	key, fp, err := pbs.GenerateKey()
	if err != nil {
		return nil, err
	}
	return s.activateKey(r, target, key, fp, time.Now().UTC())
}

func (s *ServerAPI) activateKey(r *http.Request, target *db.BackupTarget, key [32]byte, fingerprint string, created time.Time) (*db.TargetKey, error) {
	ctx := r.Context()
	if target.EncryptionKeyID != nil {
		if err := s.DB.RetireTargetKey(ctx, *target.EncryptionKeyID); err != nil {
			return nil, err
		}
	}
	k := &db.TargetKey{TargetID: target.ID, Key: key, Fingerprint: fingerprint, CreatedAt: created, CreatedBy: principalName(r)}
	if err := s.DB.CreateTargetKey(ctx, k); err != nil {
		return nil, err
	}
	if err := s.DB.SetTargetEncryption(ctx, target.ID, db.EncryptionEncrypt, &k.ID); err != nil {
		return nil, err
	}
	target.EncryptionMode, target.EncryptionKeyID, target.KeyFingerprint = db.EncryptionEncrypt, &k.ID, fingerprint
	slog.Warn("Backup encryption key activated", "target", target.Name, "target_id", target.ID, "fingerprint", fingerprint, "principal", principalName(r))
	return k, nil
}

// applyEncryptionMode switches a target between none and encrypt (idempotent)
func (s *ServerAPI) applyEncryptionMode(r *http.Request, target *db.BackupTarget, mode string) error {
	switch mode {
	case db.EncryptionEncrypt:
		if target.Encrypted() {
			return nil
		}
		// Re-enabling after a disable reuses the newest key so dedup continues
		keys, err := s.DB.ListTargetKeys(r.Context(), target.ID)
		if err != nil {
			return err
		}
		if len(keys) > 0 {
			k := keys[0]
			if err := s.DB.SetTargetEncryption(r.Context(), target.ID, db.EncryptionEncrypt, &k.ID); err != nil {
				return err
			}
			target.EncryptionMode, target.EncryptionKeyID, target.KeyFingerprint = db.EncryptionEncrypt, &k.ID, k.Fingerprint
			return nil
		}
		_, err = s.newTargetKey(r, target)
		return err
	case db.EncryptionNone:
		if target.EncryptionMode == db.EncryptionNone && target.EncryptionKeyID == nil {
			return nil
		}
		if err := s.DB.SetTargetEncryption(r.Context(), target.ID, db.EncryptionNone, nil); err != nil {
			return err
		}
		slog.Warn("Backup encryption disabled; existing keys kept for the snapshots written with them", "target", target.Name, "target_id", target.ID, "principal", principalName(r))
		target.EncryptionMode, target.EncryptionKeyID, target.KeyFingerprint = db.EncryptionNone, nil, ""
		return nil
	}
	return fmt.Errorf("encryption mode %q is not one of none, encrypt", mode)
}

func (s *ServerAPI) encryptionInfo(r *http.Request, target *db.BackupTarget) (*TargetEncryption, error) {
	keys, err := s.DB.ListTargetKeys(r.Context(), target.ID)
	if err != nil {
		return nil, err
	}
	if keys == nil {
		keys = []*db.TargetKey{}
	}
	return &TargetEncryption{
		Mode: target.EncryptionMode, Fingerprint: target.KeyFingerprint, KeyCreatedAt: target.KeyCreatedAt,
		HasMasterKey: target.MasterPublicKey != "", MasterPublicKey: target.MasterPublicKey, Keys: keys,
	}, nil
}

// HandleGetTargetEncryption returns the mode, active key fingerprint and key history
func (s *ServerAPI) HandleGetTargetEncryption(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	info, err := s.encryptionInfo(r, target)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load encryption keys")
		return
	}
	s.writeJSON(w, http.StatusOK, info)
}

// HandleSetTargetEncryption switches the mode and sets or clears the master public key
func (s *ServerAPI) HandleSetTargetEncryption(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	var req TargetEncryptionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Mode == "" {
		req.Mode = target.EncryptionMode
	}
	master := strings.TrimSpace(req.MasterPublicKey)
	if master != "" {
		normalised, err := pbs.ValidateMasterPublicKey(master)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Master public key: "+err.Error())
			return
		}
		master = normalised
	}
	if master != target.MasterPublicKey {
		target.MasterPublicKey = master
		if err := s.DB.UpdateTarget(r.Context(), target); err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to store the master public key")
			return
		}
	}
	if err := s.applyEncryptionMode(r, target, req.Mode); err != nil {
		if strings.Contains(err.Error(), "not one of") {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		slog.Error("Changing target encryption failed", "target", target.ID, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to change encryption")
		return
	}
	info, err := s.encryptionInfo(r, target)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load encryption keys")
		return
	}
	s.writeJSON(w, http.StatusOK, info)
}

// HandleRotateTargetKey generates a new active key; the old one is retired, not deleted
func (s *ServerAPI) HandleRotateTargetKey(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	if !target.Encrypted() {
		s.writeError(w, http.StatusConflict, "Encryption is not enabled on this target")
		return
	}
	if _, err := s.newTargetKey(r, target); err != nil {
		slog.Error("Rotating target key failed", "target", target.ID, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to rotate the key")
		return
	}
	info, err := s.encryptionInfo(r, target)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load encryption keys")
		return
	}
	s.writeJSON(w, http.StatusOK, info)
}

// HandleExportTargetKey returns a key as a passphrase-protected key file download
func (s *ServerAPI) HandleExportTargetKey(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	var req ExportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	keyID := target.EncryptionKeyID
	if req.KeyID != "" {
		id, err := uuid.Parse(req.KeyID)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid key ID")
			return
		}
		keyID = &id
	}
	if keyID == nil {
		s.writeError(w, http.StatusConflict, "This target has no encryption key")
		return
	}
	key, err := s.DB.GetTargetKey(r.Context(), *keyID)
	if err != nil || key.TargetID != target.ID {
		s.writeError(w, http.StatusNotFound, "Key not found on this target")
		return
	}
	data, err := pbs.ExportKeyFile(key.Key, req.Passphrase, strings.TrimSpace(req.Hint))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Warn("Backup encryption key exported", "target", target.Name, "target_id", target.ID, "fingerprint", key.Fingerprint, "principal", principalName(r))
	short := strings.ReplaceAll(key.Fingerprint, ":", "")
	if len(short) > 16 {
		short = short[:16]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fallbck-%s-%s.key.json"`, safeFileName(target.Name), short))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// HandleImportTargetKey adopts a key file as the target's active key
func (s *ServerAPI) HandleImportTargetKey(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r)
	if !ok {
		return
	}
	var req ImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	imp, err := pbs.ImportKeyFile([]byte(req.KeyFile), req.Passphrase)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Key file: "+err.Error())
		return
	}
	if imp.Fingerprint == target.KeyFingerprint {
		s.writeError(w, http.StatusConflict, "This key is already the target's active key")
		return
	}
	created := imp.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}
	if _, err := s.activateKey(r, target, imp.Key, imp.Fingerprint, created); err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			s.writeError(w, http.StatusConflict, "This key was used on the target before; re-enable it with PUT /encryption instead")
			return
		}
		slog.Error("Importing target key failed", "target", target.ID, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to import the key")
		return
	}
	info, err := s.encryptionInfo(r, target)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load encryption keys")
		return
	}
	s.writeJSON(w, http.StatusOK, info)
}

// HandleAgentEncryptionKey hands an agent the key for the run named by its backup
// ticket. The ticket binds agent, job and target; the key is returned only while the
// ticket is valid and only for an encrypted target.
func (s *ServerAPI) HandleAgentEncryptionKey(w http.ResponseWriter, r *http.Request) {
	agent := auth.AgentFrom(r.Context())
	if agent == nil {
		s.writeError(w, http.StatusUnauthorized, "agent token required")
		return
	}
	ticket := r.Header.Get(BackupTicketHeader)
	if ticket == "" {
		s.writeError(w, http.StatusBadRequest, "backup ticket header required")
		return
	}
	claims, err := s.TokenManager.ValidateBackupTicket(ticket)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid or expired backup ticket")
		return
	}
	if claims.AgentID != agent.AgentID {
		slog.Warn("Encryption key request with another agent's ticket", "agent_id", agent.AgentID, "ticket_agent_id", claims.AgentID)
		s.writeError(w, http.StatusForbidden, "backup ticket was not issued to this agent")
		return
	}
	target, err := s.DB.GetTargetByID(r.Context(), claims.TargetID)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "backup target not found")
		return
	}
	if !target.Encrypted() {
		s.writeJSON(w, http.StatusOK, AgentEncryptionKey{Mode: db.EncryptionNone})
		return
	}
	key, err := s.DB.GetTargetKey(r.Context(), *target.EncryptionKeyID)
	if err != nil {
		slog.Error("Encryption key of target unreadable", "target", target.ID, "error", err)
		s.writeError(w, http.StatusFailedDependency, "the target's encryption key cannot be read (master key?)")
		return
	}
	slog.Info("Handing encryption key to agent", "agent_id", agent.AgentID, "job_id", claims.JobID, "target", target.Name, "fingerprint", key.Fingerprint)
	s.writeJSON(w, http.StatusOK, AgentEncryptionKey{
		Mode: db.EncryptionEncrypt, Key: base64.StdEncoding.EncodeToString(key.Key[:]),
		Fingerprint: key.Fingerprint, KeyCreatedAt: key.CreatedAt, MasterPublicKey: target.MasterPublicKey,
	})
}

func safeFileName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "target"
	}
	return out
}
