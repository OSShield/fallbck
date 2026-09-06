// Package credstore is the agent's encrypted store for database credential profiles.
// Profiles live in <data dir>/credentials.json, encrypted with AES-256-GCM under a
// random key kept in <data dir>/credentials.key (0600, so only the agent's user can
// read it; on Windows the key is additionally wrapped with DPAPI for the service
// account). Passwords therefore never sit in agent.yaml in clear text, and only the
// profile names and engines are ever reported to the server.
package credstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	dbspec "github.com/osshield/fallbck/pkg/dbbackup"
)

// File names inside the data directory
const (
	StoreFile = "credentials.json"
	KeyFile   = "credentials.key"
)

// ErrNotFound is returned for an unknown profile name
var ErrNotFound = errors.New("profile not found")

// Store is a handle on the encrypted file; every operation reads and writes it whole
type Store struct {
	dir string
}

// Open returns a store for the data directory (nothing is read until needed)
func Open(dataDir string) *Store { return &Store{dir: dataDir} }

// Path returns the store file's path
func (s *Store) Path() string { return filepath.Join(s.dir, StoreFile) }

// Exists reports whether a store file has been written
func (s *Store) Exists() bool {
	_, err := os.Stat(s.Path())
	return err == nil
}

// contents is the decrypted document. Profiles are stored through storedProfile: the
// shared CredentialProfile hides its password from JSON (json:"-") so API answers can
// never carry it, and this file is the one place it must be written.
type contents struct {
	Version  int                      `json:"version"`
	Updated  time.Time                `json:"updated"`
	Profiles map[string]storedProfile `json:"profiles"`
}

type storedProfile struct {
	dbspec.CredentialProfile
	Password string `json:"password,omitempty"`
}

func toStored(p dbspec.CredentialProfile) storedProfile {
	sp := storedProfile{CredentialProfile: p, Password: p.Password}
	sp.CredentialProfile.Password = ""
	return sp
}

func (sp storedProfile) profile() dbspec.CredentialProfile {
	p := sp.CredentialProfile
	p.Password = sp.Password
	return p
}

func (c *contents) profiles() map[string]dbspec.CredentialProfile {
	out := make(map[string]dbspec.CredentialProfile, len(c.Profiles))
	for name, sp := range c.Profiles {
		out[name] = sp.profile()
	}
	return out
}

// envelope is what is written to disk
type envelope struct {
	Version int    `json:"version"`
	Nonce   []byte `json:"nonce"`
	Data    []byte `json:"data"` // AES-GCM ciphertext of contents
}

// Load returns the profiles (an empty map when no store exists)
func (s *Store) Load() (map[string]dbspec.CredentialProfile, error) {
	c, err := s.read()
	if err != nil {
		return nil, err
	}
	return c.profiles(), nil
}

// Names lists the profile names and engines without touching the passwords, for the
// server and the UI. Only this ever leaves the agent.
func (s *Store) Names() ([]dbspec.ProfileSummary, error) {
	profiles, err := s.Load()
	if err != nil {
		return nil, err
	}
	return Summaries(profiles), nil
}

// Summaries lists names, engines and users of a profile set (never passwords)
func Summaries(profiles map[string]dbspec.CredentialProfile) []dbspec.ProfileSummary {
	out := make([]dbspec.ProfileSummary, 0, len(profiles))
	for name, p := range profiles {
		out = append(out, dbspec.ProfileSummary{Name: name, Engine: p.Engine, User: p.User, Host: p.Host})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Put creates or replaces a profile
func (s *Store) Put(name string, p dbspec.CredentialProfile) error {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return errors.New("profile name must not be empty")
	}
	engine, ok := dbspec.NormalizeEngine(p.Engine)
	if !ok {
		return fmt.Errorf("unsupported engine %q", p.Engine)
	}
	p.Engine = engine
	if p.Password != "" && p.PasswordFile != "" {
		return errors.New("set either a password or a password file, not both")
	}
	c, err := s.read()
	if err != nil {
		return err
	}
	c.Profiles[name] = toStored(p)
	return s.write(c)
}

// Delete removes a profile
func (s *Store) Delete(name string) error {
	c, err := s.read()
	if err != nil {
		return err
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if _, ok := c.Profiles[name]; !ok {
		return ErrNotFound
	}
	delete(c.Profiles, name)
	return s.write(c)
}

func (s *Store) read() (*contents, error) {
	data, err := os.ReadFile(s.Path())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &contents{Version: 1, Profiles: map[string]storedProfile{}}, nil
		}
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", s.Path(), err)
	}
	key, err := s.loadKey(false)
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, env.Nonce, env.Data, []byte(StoreFile))
	if err != nil {
		return nil, fmt.Errorf("decrypting %s: %w (the key file %s does not match; restore both files together)", s.Path(), err, filepath.Join(s.dir, KeyFile))
	}
	var c contents
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, fmt.Errorf("parsing the decrypted store: %w", err)
	}
	if c.Profiles == nil {
		c.Profiles = map[string]storedProfile{}
	}
	return &c, nil
}

func (s *Store) write(c *contents) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	key, err := s.loadKey(true)
	if err != nil {
		return err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	c.Version, c.Updated = 1, time.Now().UTC()
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	env := envelope{Version: 1, Nonce: nonce, Data: aead.Seal(nil, nonce, plain, []byte(StoreFile))}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.Path(), data, 0o600)
}

// loadKey reads the key file, creating it when allowed and missing
func (s *Store) loadKey(create bool) ([]byte, error) {
	path := filepath.Join(s.dir, KeyFile)
	wrapped, err := os.ReadFile(path)
	if err == nil {
		key, err := unwrapKey(wrapped)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("%s: not a 32-byte key", path)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !create {
		return nil, fmt.Errorf("%s exists but its key file %s is missing; without the key the store cannot be read", s.Path(), path)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	wrapped, err = wrapKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(path, wrapped, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
