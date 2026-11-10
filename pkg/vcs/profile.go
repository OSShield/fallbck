package vcs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Profile is an agent credential profile for VCS jobs: a token (or a GitHub App) that
// lives only in the agent's encrypted store and is used for exactly one URL. A job names it
// (Spec.Profile); the agent uses it only when URL equals the job's connection URL,
// so a changed connection cannot send the token anywhere else.
type Profile struct {
	// URL is the connection base URL the token belongs to (normalised like
	// Connection.BaseURL)
	URL string `json:"url"`
	// Username for HTTP basic authentication ("" = oauth2)
	Username string `json:"username,omitempty"`
	// Token is in clear in memory only; the credential store encrypts it and it is
	// never reported
	Token string `json:"-"`
	// TokenFile is read at run time instead of Token (a file a secret manager
	// keeps current)
	TokenFile string `json:"token_file,omitempty"`
	// TokenExpires is when the token stops working, as GitLab reported it at the
	// last profile test (reported, so the server can warn)
	TokenExpires *time.Time `json:"token_expires,omitempty"`
	// AuthType is AuthToken ("" in old stores) or AuthGitHubApp: the agent mints
	// installation tokens itself with AppKey (encrypted in the store) or AppKeyFile
	AuthType       string `json:"auth_type,omitempty"`
	AppID          int64  `json:"app_id,omitempty"`
	InstallationID int64  `json:"installation_id,omitempty"`
	AppKey         string `json:"-"`
	AppKeyFile     string `json:"app_key_file,omitempty"`
}

// ProfileSummary is what the agent reports about a profile: never the token
type ProfileSummary struct {
	Name         string     `json:"name"`
	URL          string     `json:"url"`
	AuthType     string     `json:"auth_type,omitempty"`
	TokenFile    bool       `json:"token_file,omitempty"`
	TokenExpires *time.Time `json:"token_expires,omitempty"`
}

// ValidProfileName reports whether name is usable for a profile (letters, digits,
// '.', '_' and '-', at most 64, starting with a letter or digit)
func ValidProfileName(name string) bool { return profileNameRe.MatchString(name) }

// NormalizeProfileName returns the stored form of a profile name (lower case)
func NormalizeProfileName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// Validate normalizes the URL and checks that exactly one token (or App key) source
// is set
func (p *Profile) Validate() error {
	url, err := NormalizeBaseURL(p.URL)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	p.URL = url
	p.Username = strings.TrimSpace(p.Username)
	p.Token = strings.TrimSpace(p.Token)
	p.TokenFile = strings.TrimSpace(p.TokenFile)
	p.AppKey = strings.TrimSpace(p.AppKey)
	p.AppKeyFile = strings.TrimSpace(p.AppKeyFile)
	if p.AuthType, err = normalizeAuthType(p.AuthType); err != nil {
		return err
	}
	if p.AuthType == AuthGitHubApp {
		switch {
		case p.Token != "" || p.TokenFile != "" || p.Username != "":
			return errors.New("a GitHub App profile takes no token, token file or username")
		case p.AppID <= 0 || p.InstallationID <= 0:
			return errors.New("a GitHub App profile needs --app-id and --installation-id")
		case (p.AppKey == "") == (p.AppKeyFile == ""):
			return errors.New("set either the App's private key or its key file")
		case p.AppKey != "":
			_, err := ParseGitHubAppKey(p.AppKey)
			return err
		}
		return nil
	}
	if p.AppID != 0 || p.InstallationID != 0 || p.AppKey != "" || p.AppKeyFile != "" {
		return errors.New("App ids and keys need a GitHub App profile (--auth github_app)")
	}
	switch {
	case p.Token == "" && p.TokenFile == "":
		return errors.New("set a token or a token file")
	case p.Token != "" && p.TokenFile != "":
		return errors.New("set either a token or a token file, not both")
	}
	return checkToken(p.Token)
}

// App returns the profile's GitHub App, reading AppKeyFile when set
func (p *Profile) App() (GitHubApp, error) {
	app := GitHubApp{AppID: p.AppID, InstallationID: p.InstallationID, PrivateKey: p.AppKey}
	if p.AppKeyFile != "" {
		data, err := os.ReadFile(p.AppKeyFile)
		if err != nil {
			return app, fmt.Errorf("reading the App key file: %w", err)
		}
		app.PrivateKey = string(data)
	}
	if _, err := ParseGitHubAppKey(app.PrivateKey); err != nil {
		return app, fmt.Errorf("the App key: %w", err)
	}
	return app, nil
}

// ResolveToken returns the token, reading TokenFile when set
func (p *Profile) ResolveToken() (string, error) {
	if p.TokenFile == "" {
		return p.Token, nil
	}
	data, err := os.ReadFile(p.TokenFile)
	if err != nil {
		return "", fmt.Errorf("reading the token file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("the token file %s is empty", p.TokenFile)
	}
	if err := checkToken(token); err != nil {
		return "", fmt.Errorf("the token file %s: %w", p.TokenFile, err)
	}
	return token, nil
}

// refuses things that could smuggle another header into the request
func checkToken(token string) error {
	for _, r := range token {
		if r <= ' ' || r > '~' {
			return errors.New("the token contains spaces or non-printable characters")
		}
	}
	return nil
}
