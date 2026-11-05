package vcs

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Profile is an agent credential profile for VCS jobs: a token that lives only in
// the agent's encrypted store and is used for exactly one URL. A job names it
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
}

// ProfileSummary is what the agent reports about a profile: never the token
type ProfileSummary struct {
	Name         string     `json:"name"`
	URL          string     `json:"url"`
	TokenFile    bool       `json:"token_file,omitempty"`
	TokenExpires *time.Time `json:"token_expires,omitempty"`
}

// ValidProfileName reports whether name is usable for a profile (letters, digits,
// '.', '_' and '-', at most 64, starting with a letter or digit)
func ValidProfileName(name string) bool { return profileNameRe.MatchString(name) }

// NormalizeProfileName returns the stored form of a profile name (lower case)
func NormalizeProfileName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// Validate normalizes the URL and checks that exactly one token source is set
func (p *Profile) Validate() error {
	url, err := NormalizeBaseURL(p.URL)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	p.URL = url
	p.Username = strings.TrimSpace(p.Username)
	p.Token = strings.TrimSpace(p.Token)
	p.TokenFile = strings.TrimSpace(p.TokenFile)
	switch {
	case p.Token == "" && p.TokenFile == "":
		return errors.New("set a token or a token file")
	case p.Token != "" && p.TokenFile != "":
		return errors.New("set either a token or a token file, not both")
	}
	return checkToken(p.Token)
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
