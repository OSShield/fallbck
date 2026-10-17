package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
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

// Client-side encryption. Keys live on key rings; a target encrypts with the active
// key of the ring it is attached to, and targets that share a ring deduplicate
// against each other on PBS. Keys are generated and kept on the server (sealed with
// the master key), handed to agents per run with their backup ticket, and exported to
// administrators only as a passphrase-protected proxmox-backup-client key file. Raw
// key material never appears in an API response.
//
// The /targets/{id}/encryption endpoints act on the target's ring, so clients from
// before key rings keep working; /keyrings is the ring-level API.

// TargetEncryptionRequest sets a target's encryption (PUT /targets/{id}/encryption)
type TargetEncryptionRequest struct {
	// Mode: none | encrypt
	Mode string `json:"mode"`
	// KeyRingID attaches an existing ring (encrypt mode). Empty: keep the target's ring,
	// or create one named after the target when it has none.
	KeyRingID string `json:"key_ring_id"`
	// MasterPublicKey (PEM, optional) is set on the target's ring: every snapshot then
	// carries the encryption key wrapped with it for recovery; "" removes it. nil
	// keeps the stored one.
	MasterPublicKey *string `json:"master_public_key"`
}

// TargetEncryption describes a target's encryption (GET /targets/{id}/encryption and
// embedded in the target form response)
type TargetEncryption struct {
	Mode            string          `json:"mode"`
	KeyRingID       string          `json:"key_ring_id,omitempty"`
	KeyRingName     string          `json:"key_ring_name,omitempty"`
	Fingerprint     string          `json:"fingerprint,omitempty"`
	KeyCreatedAt    *time.Time      `json:"key_created_at,omitempty"`
	HasMasterKey    bool            `json:"has_master_key"`
	MasterPublicKey string          `json:"master_public_key,omitempty"`
	Keys            []*db.TargetKey `json:"keys"`
}

// KeyRingRequest creates or updates a ring (POST /keyrings, PUT /keyrings/{id})
type KeyRingRequest struct {
	Name            string  `json:"name"`
	MasterPublicKey *string `json:"master_public_key"`
	// Labels: nil on update keeps the stored labels
	Labels db.Labels `json:"labels"`
}

// KeyRingResponse is a ring with its key history
type KeyRingResponse struct {
	*db.KeyRing
	Keys []*db.TargetKey `json:"keys"`
}

// ExportKeyRequest (POST /keyrings/{id}/export, POST /targets/{id}/encryption/export)
type ExportKeyRequest struct {
	Passphrase string `json:"passphrase"`
	Hint       string `json:"hint"`
	// KeyID selects a retired key; default: the active one
	KeyID string `json:"key_id"`
}

// ImportKeyRequest adopts an existing proxmox-backup-client key file as the active key
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
	if d := auth.PrincipalFrom(r.Context()).Display(); d != "" {
		return d
	}
	return "unknown"
}

// targetFromPath loads the target named in the path within targets:read and checks
// perm on its labels (404 when unreadable, 403 when readable but perm is missing)
func (s *ServerAPI) targetFromPath(w http.ResponseWriter, r *http.Request, perm string) (*db.BackupTarget, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid target ID")
		return nil, false
	}
	target, err := s.DB.GetTargetByID(r.Context(), id, scope(r, auth.PermTargetsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Target not found")
		return nil, false
	}
	if !s.allow(w, r, perm, target.Labels) {
		return nil, false
	}
	return target, true
}

// ringFromPath loads the ring named in the path within keyrings:read and checks perm
// on its labels
func (s *ServerAPI) ringFromPath(w http.ResponseWriter, r *http.Request, perm string) (*db.KeyRing, bool) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid key ring ID")
		return nil, false
	}
	ring, err := s.DB.GetKeyRing(r.Context(), id, scope(r, auth.PermKeyringsRead))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "Key ring not found")
		return nil, false
	}
	if !s.allow(w, r, perm, ring.Labels) {
		return nil, false
	}
	return ring, true
}

// targetRing resolves the ring behind a target endpoint: the target must be readable,
// and perm (a key ring permission: the action affects every target on the ring) is
// checked on the ring's labels
func (s *ServerAPI) targetRing(w http.ResponseWriter, r *http.Request, perm string) (*db.BackupTarget, *db.KeyRing, bool) {
	target, ok := s.targetFromPath(w, r, auth.PermTargetsRead)
	if !ok {
		return nil, nil, false
	}
	if target.KeyRingID == nil {
		s.writeError(w, http.StatusConflict, "This target has no encryption key ring; enable encryption first")
		return nil, nil, false
	}
	ring, err := s.DB.GetKeyRing(r.Context(), *target.KeyRingID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load the target's key ring")
		return nil, nil, false
	}
	if !s.allow(w, r, perm, ring.Labels) {
		return nil, nil, false
	}
	return target, ring, true
}

// checkEncryptionAccess runs before a target create/update/encryption change writes
// anything. Attaching a named ring needs keyrings:read on it; encrypting without a
// ring creates one with the target's labels and needs keyrings:write on those;
// changing the master public key of an existing ring needs keyrings:write on it.
func (s *ServerAPI) checkEncryptionAccess(w http.ResponseWriter, r *http.Request, mode string, ringID, currentRing *uuid.UUID, labels db.Labels, masterKey *string) bool {
	effective := currentRing
	if ringID != nil && (currentRing == nil || *ringID != *currentRing) {
		ring, err := s.DB.GetKeyRing(r.Context(), *ringID, scope(r, auth.PermKeyringsRead))
		if err != nil {
			s.writeError(w, http.StatusNotFound, "Key ring not found")
			return false
		}
		effective = &ring.ID
	}
	if mode == db.EncryptionEncrypt && effective == nil && !s.allow(w, r, auth.PermKeyringsWrite, labels) {
		return false
	}
	if masterKey != nil && effective != nil {
		ring, err := s.DB.GetKeyRing(r.Context(), *effective, db.Unscoped)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to load the key ring")
			return false
		}
		if strings.TrimSpace(*masterKey) != ring.MasterPublicKey && !s.allow(w, r, auth.PermKeyringsWrite, ring.Labels) {
			return false
		}
	}
	return true
}

// ---- ring key management -------------------------------------------------------

// newRingKey generates a key and makes it the ring's active key
func (s *ServerAPI) newRingKey(r *http.Request, ring *db.KeyRing) (*db.TargetKey, error) {
	key, fp, err := pbs.GenerateKey()
	if err != nil {
		return nil, err
	}
	return s.activateRingKey(r, ring, key, fp, time.Now().UTC())
}

func (s *ServerAPI) activateRingKey(r *http.Request, ring *db.KeyRing, key [32]byte, fingerprint string, created time.Time) (*db.TargetKey, error) {
	ctx := r.Context()
	if ring.ActiveKeyID != nil {
		if err := s.DB.RetireTargetKey(ctx, *ring.ActiveKeyID); err != nil {
			return nil, err
		}
	}
	k := &db.TargetKey{RingID: ring.ID, Key: key, Fingerprint: fingerprint, CreatedAt: created, CreatedBy: principalName(r)}
	if err := s.DB.CreateTargetKey(ctx, k); err != nil {
		return nil, err
	}
	if err := s.DB.SetRingActiveKey(ctx, ring.ID, &k.ID); err != nil {
		return nil, err
	}
	ring.ActiveKeyID, ring.KeyFingerprint, ring.KeyCreatedAt = &k.ID, fingerprint, &created
	slog.Warn("Backup encryption key activated", "key_ring", ring.Name, "ring_id", ring.ID, "targets", ring.Targets, "fingerprint", fingerprint, "principal", principalName(r))
	return k, nil
}

// ensureRingKey gives a ring an active key: the newest existing one (re-enabling
// keeps dedup going) or a fresh one
func (s *ServerAPI) ensureRingKey(r *http.Request, ring *db.KeyRing) error {
	if ring.ActiveKeyID != nil {
		return nil
	}
	keys, err := s.DB.ListRingKeys(r.Context(), ring.ID)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		k := keys[0]
		if err := s.DB.SetRingActiveKey(r.Context(), ring.ID, &k.ID); err != nil {
			return err
		}
		ring.ActiveKeyID, ring.KeyFingerprint, ring.KeyCreatedAt = &k.ID, k.Fingerprint, &k.CreatedAt
		return nil
	}
	_, err = s.newRingKey(r, ring)
	return err
}

// createRingFor makes a ring named after a target, with its labels (suffixing the
// name when taken)
func (s *ServerAPI) createRingFor(r *http.Request, target *db.BackupTarget, masterPublicKey string) (*db.KeyRing, error) {
	ring := &db.KeyRing{Name: target.Name, MasterPublicKey: masterPublicKey, CreatedBy: principalName(r), Targets: []string{target.Name}, Labels: target.Labels.OrEmpty()}
	err := s.DB.CreateKeyRing(r.Context(), ring)
	if err != nil && isUniqueViolation(err) {
		ring.Name = target.Name + " (" + target.ID.String()[:8] + ")"
		err = s.DB.CreateKeyRing(r.Context(), ring)
	}
	if err != nil {
		return nil, err
	}
	s.audit(r, "keyring.create", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"for_target": target.ID})
	return ring, nil
}

func isUniqueViolation(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate"))
}

// applyEncryptionMode switches a target between none and encrypt and, for encrypt,
// attaches ringID (or keeps the target's ring, or creates one). Idempotent. Access is
// checked by the caller (checkEncryptionAccess) before anything is written.
func (s *ServerAPI) applyEncryptionMode(r *http.Request, target *db.BackupTarget, mode string, ringID *uuid.UUID) error {
	ctx := r.Context()
	switch mode {
	case db.EncryptionEncrypt:
		var ring *db.KeyRing
		var err error
		switch {
		case ringID != nil:
			if ring, err = s.DB.GetKeyRing(ctx, *ringID, db.Unscoped); err != nil {
				return fmt.Errorf("key ring %s: %w", ringID, err)
			}
		case target.KeyRingID != nil:
			if ring, err = s.DB.GetKeyRing(ctx, *target.KeyRingID, db.Unscoped); err != nil {
				return err
			}
		default:
			if ring, err = s.createRingFor(r, target, ""); err != nil {
				return err
			}
		}
		if target.Encrypted() && target.KeyRingID != nil && *target.KeyRingID == ring.ID {
			return nil
		}
		if err := s.ensureRingKey(r, ring); err != nil {
			return err
		}
		if err := s.DB.SetTargetEncryption(ctx, target.ID, db.EncryptionEncrypt, &ring.ID); err != nil {
			return err
		}
		target.EncryptionMode, target.KeyRingID, target.KeyRingName = db.EncryptionEncrypt, &ring.ID, ring.Name
		target.EncryptionKeyID, target.KeyFingerprint, target.KeyCreatedAt, target.MasterPublicKey = ring.ActiveKeyID, ring.KeyFingerprint, ring.KeyCreatedAt, ring.MasterPublicKey
		slog.Warn("Backup encryption enabled", "target", target.Name, "target_id", target.ID, "key_ring", ring.Name, "fingerprint", ring.KeyFingerprint, "principal", principalName(r))
		return nil
	case db.EncryptionNone:
		if target.EncryptionMode == db.EncryptionNone {
			return nil
		}
		if err := s.DB.SetTargetEncryption(ctx, target.ID, db.EncryptionNone, target.KeyRingID); err != nil {
			return err
		}
		slog.Warn("Backup encryption disabled; the key ring stays attached for the snapshots written with it", "target", target.Name, "target_id", target.ID, "principal", principalName(r))
		target.EncryptionMode = db.EncryptionNone
		return nil
	}
	return fmt.Errorf("encryption mode %q is not one of none, encrypt", mode)
}

// setRingMasterKey validates and stores a master public key on a ring ("" clears it)
func (s *ServerAPI) setRingMasterKey(r *http.Request, ring *db.KeyRing, pemText string) error {
	master := strings.TrimSpace(pemText)
	if master != "" {
		normalised, err := pbs.ValidateMasterPublicKey(master)
		if err != nil {
			return fmt.Errorf("master public key: %w", err)
		}
		master = normalised
	}
	if master == ring.MasterPublicKey {
		return nil
	}
	old := ring.MasterPublicKey
	ring.MasterPublicKey = master
	if err := s.DB.UpdateKeyRing(r.Context(), ring); err != nil {
		ring.MasterPublicKey = old
		return err
	}
	s.audit(r, "keyring.master_key", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"set": master != ""})
	return nil
}

func (s *ServerAPI) encryptionInfo(r *http.Request, target *db.BackupTarget) (*TargetEncryption, error) {
	info := &TargetEncryption{Mode: target.EncryptionMode, Keys: []*db.TargetKey{}}
	if target.KeyRingID == nil {
		return info, nil
	}
	ring, err := s.DB.GetKeyRing(r.Context(), *target.KeyRingID, db.Unscoped)
	if err != nil {
		return nil, err
	}
	keys, err := s.DB.ListRingKeys(r.Context(), ring.ID)
	if err != nil {
		return nil, err
	}
	info.KeyRingID, info.KeyRingName, info.Keys = ring.ID.String(), ring.Name, keys
	info.Fingerprint, info.KeyCreatedAt = ring.KeyFingerprint, ring.KeyCreatedAt
	info.HasMasterKey, info.MasterPublicKey = ring.MasterPublicKey != "", ring.MasterPublicKey
	return info, nil
}

func (s *ServerAPI) writeEncryptionInfo(w http.ResponseWriter, r *http.Request, target *db.BackupTarget) {
	info, err := s.encryptionInfo(r, target)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load encryption keys")
		return
	}
	s.writeJSON(w, http.StatusOK, info)
}

func (s *ServerAPI) writeRing(w http.ResponseWriter, r *http.Request, ring *db.KeyRing, status int) {
	fresh, err := s.DB.GetKeyRing(r.Context(), ring.ID, db.Unscoped)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load key ring")
		return
	}
	keys, err := s.DB.ListRingKeys(r.Context(), ring.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to load encryption keys")
		return
	}
	s.writeJSON(w, status, KeyRingResponse{KeyRing: fresh, Keys: keys})
}

// ---- shared actions (ring and target endpoints) ---------------------------------

func (s *ServerAPI) rotateRing(w http.ResponseWriter, r *http.Request, ring *db.KeyRing) bool {
	if _, err := s.newRingKey(r, ring); err != nil {
		slog.Error("Rotating key failed", "ring", ring.ID, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to rotate the key")
		return false
	}
	s.audit(r, "keyring.rotate", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"fingerprint": ring.KeyFingerprint, "targets": ring.Targets})
	return true
}

func (s *ServerAPI) exportRingKey(w http.ResponseWriter, r *http.Request, ring *db.KeyRing, label string) {
	var req ExportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	keyID := ring.ActiveKeyID
	if req.KeyID != "" {
		id, err := uuid.Parse(req.KeyID)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid key ID")
			return
		}
		keyID = &id
	}
	if keyID == nil {
		s.writeError(w, http.StatusConflict, "This key ring has no active key")
		return
	}
	key, err := s.DB.GetTargetKey(r.Context(), *keyID)
	if err != nil || key.RingID != ring.ID {
		s.writeError(w, http.StatusNotFound, "Key not found on this key ring")
		return
	}
	data, err := pbs.ExportKeyFile(key.Key, req.Passphrase, strings.TrimSpace(req.Hint))
	if err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	slog.Warn("Backup encryption key exported", "key_ring", ring.Name, "ring_id", ring.ID, "fingerprint", key.Fingerprint, "principal", principalName(r))
	s.audit(r, "keyring.export", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"fingerprint": key.Fingerprint})
	short := strings.ReplaceAll(key.Fingerprint, ":", "")
	if len(short) > 16 {
		short = short[:16]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="fallbck-%s-%s.key.json"`, safeFileName(label), short))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *ServerAPI) importRingKey(w http.ResponseWriter, r *http.Request, ring *db.KeyRing) bool {
	var req ImportKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return false
	}
	imp, err := pbs.ImportKeyFile([]byte(req.KeyFile), req.Passphrase)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Key file: "+err.Error())
		return false
	}
	if imp.Fingerprint == ring.KeyFingerprint {
		s.writeError(w, http.StatusConflict, "This key is already the ring's active key")
		return false
	}
	created := imp.Created
	if created.IsZero() {
		created = time.Now().UTC()
	}
	if _, err := s.activateRingKey(r, ring, imp.Key, imp.Fingerprint, created); err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "This key was used on the ring before; it is in the key history")
			return false
		}
		slog.Error("Importing key failed", "ring", ring.ID, "error", err)
		s.writeError(w, http.StatusInternalServerError, "Failed to import the key")
		return false
	}
	s.audit(r, "keyring.import", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"fingerprint": imp.Fingerprint})
	return true
}

// ---- target endpoints ----------------------------------------------------------

// HandleGetTargetEncryption returns the mode, ring, active key fingerprint and key history
func (s *ServerAPI) HandleGetTargetEncryption(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r, auth.PermTargetsRead)
	if !ok {
		return
	}
	s.writeEncryptionInfo(w, r, target)
}

// HandleSetTargetEncryption switches the mode, attaches a ring and sets or clears the
// ring's master public key
func (s *ServerAPI) HandleSetTargetEncryption(w http.ResponseWriter, r *http.Request) {
	target, ok := s.targetFromPath(w, r, auth.PermTargetsWrite)
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
	var ringID *uuid.UUID
	if req.KeyRingID != "" {
		id, err := uuid.Parse(req.KeyRingID)
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Invalid key ring ID")
			return
		}
		ringID = &id
	}
	if !s.checkEncryptionAccess(w, r, req.Mode, ringID, target.KeyRingID, target.Labels, req.MasterPublicKey) {
		return
	}
	oldMode := target.EncryptionMode
	if err := s.applyEncryptionMode(r, target, req.Mode, ringID); err != nil {
		switch {
		case strings.Contains(err.Error(), "not one of"):
			s.writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, db.ErrNotFound):
			s.writeError(w, http.StatusNotFound, "Key ring not found")
		default:
			slog.Error("Changing target encryption failed", "target", target.ID, "error", err)
			s.writeError(w, http.StatusInternalServerError, "Failed to change encryption")
		}
		return
	}
	s.audit(r, "target.encryption", "target", target.ID.String(), target.Name, target.Labels, map[string]any{"old_mode": oldMode, "mode": target.EncryptionMode, "key_ring": target.KeyRingName})
	if req.MasterPublicKey != nil && target.KeyRingID != nil {
		ring, err := s.DB.GetKeyRing(r.Context(), *target.KeyRingID, db.Unscoped)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "Failed to load the target's key ring")
			return
		}
		if err := s.setRingMasterKey(r, ring, *req.MasterPublicKey); err != nil {
			s.writeError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	s.writeEncryptionInfo(w, r, target)
}

// HandleRotateTargetKey rotates the target's ring (every target on it switches key)
func (s *ServerAPI) HandleRotateTargetKey(w http.ResponseWriter, r *http.Request) {
	target, ring, ok := s.targetRing(w, r, auth.PermKeyringsWrite)
	if !ok {
		return
	}
	if !target.Encrypted() {
		s.writeError(w, http.StatusConflict, "Encryption is not enabled on this target")
		return
	}
	if s.rotateRing(w, r, ring) {
		s.writeEncryptionInfo(w, r, target)
	}
}

// HandleExportTargetKey returns a key of the target's ring as a key file download
func (s *ServerAPI) HandleExportTargetKey(w http.ResponseWriter, r *http.Request) {
	target, ring, ok := s.targetRing(w, r, auth.PermKeyringsExport)
	if !ok {
		return
	}
	s.exportRingKey(w, r, ring, target.Name)
}

// HandleImportTargetKey adopts a key file as the active key of the target's ring
func (s *ServerAPI) HandleImportTargetKey(w http.ResponseWriter, r *http.Request) {
	target, ring, ok := s.targetRing(w, r, auth.PermKeyringsWrite)
	if !ok {
		return
	}
	if s.importRingKey(w, r, ring) {
		s.writeEncryptionInfo(w, r, target)
	}
}

// ---- ring endpoints ------------------------------------------------------------

func (s *ServerAPI) HandleListKeyRings(w http.ResponseWriter, r *http.Request) {
	rings, err := s.DB.ListKeyRings(r.Context(), scope(r, auth.PermKeyringsRead))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Failed to list key rings")
		return
	}
	s.writeJSON(w, http.StatusOK, rings)
}

// HandleCreateKeyRing creates a ring with a fresh active key
func (s *ServerAPI) HandleCreateKeyRing(w http.ResponseWriter, r *http.Request) {
	var req KeyRingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.writeError(w, http.StatusBadRequest, "Name is required")
		return
	}
	req.Labels = req.Labels.OrEmpty()
	if !s.validLabels(w, req.Labels) || !s.allow(w, r, auth.PermKeyringsWrite, req.Labels) {
		return
	}
	ring := &db.KeyRing{Name: req.Name, CreatedBy: principalName(r), Targets: []string{}, Labels: req.Labels}
	if req.MasterPublicKey != nil && strings.TrimSpace(*req.MasterPublicKey) != "" {
		normalised, err := pbs.ValidateMasterPublicKey(strings.TrimSpace(*req.MasterPublicKey))
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "Master public key: "+err.Error())
			return
		}
		ring.MasterPublicKey = normalised
	}
	if err := s.DB.CreateKeyRing(r.Context(), ring); err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "A key ring with that name exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to create key ring")
		return
	}
	if _, err := s.newRingKey(r, ring); err != nil {
		s.writeError(w, http.StatusInternalServerError, "Key ring created, but generating its key failed")
		return
	}
	s.audit(r, "keyring.create", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"fingerprint": ring.KeyFingerprint})
	s.writeRing(w, r, ring, http.StatusCreated)
}

func (s *ServerAPI) HandleGetKeyRing(w http.ResponseWriter, r *http.Request) {
	ring, ok := s.ringFromPath(w, r, auth.PermKeyringsRead)
	if !ok {
		return
	}
	s.writeRing(w, r, ring, http.StatusOK)
}

// HandleUpdateKeyRing renames a ring and sets or clears its master public key
func (s *ServerAPI) HandleUpdateKeyRing(w http.ResponseWriter, r *http.Request) {
	ring, ok := s.ringFromPath(w, r, auth.PermKeyringsWrite)
	if !ok {
		return
	}
	var req KeyRingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	oldLabels := ring.Labels
	labels, ok := s.newLabels(w, r, auth.PermKeyringsWrite, ring.Labels, req.Labels)
	if !ok {
		return
	}
	ring.Labels = labels
	if name := strings.TrimSpace(req.Name); name != "" {
		ring.Name = name
	}
	master := ring.MasterPublicKey
	if req.MasterPublicKey != nil {
		master = *req.MasterPublicKey
	}
	if err := s.setRingMasterKey(r, ring, master); err != nil {
		s.writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.DB.UpdateKeyRing(r.Context(), ring); err != nil {
		if isUniqueViolation(err) {
			s.writeError(w, http.StatusConflict, "A key ring with that name exists")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to update key ring")
		return
	}
	s.audit(r, "keyring.update", "keyring", ring.ID.String(), ring.Name, ring.Labels, map[string]any{"old_labels": oldLabels})
	s.writeRing(w, r, ring, http.StatusOK)
}

// HandleDeleteKeyRing deletes an unused ring and its keys
func (s *ServerAPI) HandleDeleteKeyRing(w http.ResponseWriter, r *http.Request) {
	ring, ok := s.ringFromPath(w, r, auth.PermKeyringsDelete)
	if !ok {
		return
	}
	if err := s.DB.DeleteKeyRing(r.Context(), ring.ID); err != nil {
		if errors.Is(err, db.ErrInUse) {
			s.writeError(w, http.StatusConflict, "Key ring is attached to targets: "+strings.Join(ring.Targets, ", "))
			return
		}
		s.writeError(w, http.StatusInternalServerError, "Failed to delete key ring")
		return
	}
	slog.Warn("Backup encryption key ring deleted with its keys", "key_ring", ring.Name, "ring_id", ring.ID, "principal", principalName(r))
	s.audit(r, "keyring.delete", "keyring", ring.ID.String(), ring.Name, ring.Labels, nil)
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *ServerAPI) HandleRotateKeyRing(w http.ResponseWriter, r *http.Request) {
	ring, ok := s.ringFromPath(w, r, auth.PermKeyringsWrite)
	if !ok {
		return
	}
	if s.rotateRing(w, r, ring) {
		s.writeRing(w, r, ring, http.StatusOK)
	}
}

func (s *ServerAPI) HandleExportKeyRingKey(w http.ResponseWriter, r *http.Request) {
	ring, ok := s.ringFromPath(w, r, auth.PermKeyringsExport)
	if !ok {
		return
	}
	s.exportRingKey(w, r, ring, ring.Name)
}

func (s *ServerAPI) HandleImportKeyRingKey(w http.ResponseWriter, r *http.Request) {
	ring, ok := s.ringFromPath(w, r, auth.PermKeyringsWrite)
	if !ok {
		return
	}
	if s.importRingKey(w, r, ring) {
		s.writeRing(w, r, ring, http.StatusOK)
	}
}

// ---- agent endpoint ------------------------------------------------------------

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
	target, err := s.DB.GetTargetByID(r.Context(), claims.TargetID, db.Unscoped)
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
	slog.Info("Handing encryption key to agent", "agent_id", agent.AgentID, "job_id", claims.JobID, "target", target.Name, "key_ring", target.KeyRingName, "fingerprint", key.Fingerprint)
	s.writeJSON(w, http.StatusOK, AgentEncryptionKey{
		Mode: db.EncryptionEncrypt, Key: base64.StdEncoding.EncodeToString(key.Key[:]),
		Fingerprint: key.Fingerprint, KeyCreatedAt: key.CreatedAt, MasterPublicKey: target.MasterPublicKey,
	})
}

// applyTargetMasterKey stores a master public key sent with a target create/update
// on the target's ring (nil: keep). A target without a ring ignores it: the key is a
// ring property and there is nothing to wrap yet.
func (s *ServerAPI) applyTargetMasterKey(r *http.Request, target *db.BackupTarget, pemText *string) (string, bool) {
	if pemText == nil || target.KeyRingID == nil {
		return "", true
	}
	ring, err := s.DB.GetKeyRing(r.Context(), *target.KeyRingID, db.Unscoped)
	if err != nil {
		return "Failed to load the target's key ring", false
	}
	if err := s.setRingMasterKey(r, ring, *pemText); err != nil {
		return err.Error(), false
	}
	target.MasterPublicKey = ring.MasterPublicKey
	return "", true
}

func parseOptionalUUID(s string) (*uuid.UUID, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	id, err := uuid.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, err
	}
	return &id, nil
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
