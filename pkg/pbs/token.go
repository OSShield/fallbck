package pbs

import (
	"errors"
	"fmt"
	"strings"
)

// API token handling. PBS expects
//
//	Authorization: PBSAPIToken=<user>@<realm>!<tokenid>:<secret>
//
// with a colon between the token name and its secret. Operators frequently paste
// the "user@realm!tokenid=secret" form shown in the PBS UI's token dialog (or the
// whole header), so all of these are accepted and normalised.

// ErrInvalidAPIToken is returned for tokens that cannot be parsed
var ErrInvalidAPIToken = errors.New("invalid PBS API token: expected user@realm!tokenid:secret")

// NormalizeAPIToken returns the canonical "user@realm!tokenid:secret" form
func NormalizeAPIToken(raw string) (string, error) {
	authID, secret, err := SplitAPIToken(raw)
	if err != nil {
		return "", err
	}
	return authID + ":" + secret, nil
}

// SplitAPIToken parses a token in any accepted spelling into its auth id
// ("user@realm!tokenid") and secret
func SplitAPIToken(raw string) (authID, secret string, err error) {
	s := strings.TrimSpace(raw)
	for _, prefix := range []string{"PBSAPIToken=", "PBSAPIToken ", "PBSAPIToken:"} {
		s = strings.TrimPrefix(s, prefix)
	}
	s = strings.TrimSpace(s)
	bang := strings.Index(s, "!")
	at := strings.Index(s, "@")
	if at <= 0 || bang <= at+1 {
		return "", "", ErrInvalidAPIToken
	}
	rest := s[bang+1:]
	// Canonical separator is ':'; tolerate '=' (token dialog spelling) when no ':' present
	sep := strings.Index(rest, ":")
	if sep < 0 {
		sep = strings.Index(rest, "=")
	}
	if sep <= 0 || sep == len(rest)-1 {
		return "", "", ErrInvalidAPIToken
	}
	tokenID, secret := rest[:sep], rest[sep+1:]
	if strings.ContainsAny(tokenID, ":=") || strings.ContainsAny(secret, " \t") {
		return "", "", ErrInvalidAPIToken
	}
	return s[:bang+1] + tokenID, secret, nil
}

// AuthorizationHeader returns the PBS Authorization header value for a token in any
// accepted spelling; malformed tokens are passed through so PBS reports the failure
func AuthorizationHeader(raw string) string {
	if normalized, err := NormalizeAPIToken(raw); err == nil {
		return "PBSAPIToken=" + normalized
	}
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "PBSAPIToken") {
		return raw
	}
	return "PBSAPIToken=" + raw
}

// TokenID returns the loggable part of a token (no secret)
func TokenID(raw string) string {
	if authID, _, err := SplitAPIToken(raw); err == nil {
		return authID
	}
	return fmt.Sprintf("<unparseable token, %d chars>", len(strings.TrimSpace(raw)))
}
