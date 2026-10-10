package m365

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// TokenURL is the tenant's v2.0 token endpoint
func TokenURL(authority, tenantID string) string {
	return strings.TrimRight(authority, "/") + "/" + tenantID + "/oauth2/v2.0/token"
}

// TokenSource returns an oauth2 token source for the Graph application permissions of
// the credentials: the client-credentials flow with the secret, or with a freshly
// signed certificate client assertion on every token request (the assertion is
// short-lived, the access token lasts about an hour). authority is AuthorityURL
// unless a test substitutes an endpoint.
func TokenSource(ctx context.Context, c Credentials, authority string) (oauth2.TokenSource, error) {
	if authority == "" {
		authority = AuthorityURL
	}
	tokenURL := TokenURL(authority, c.TenantID)
	switch c.AuthMethod {
	case "", AuthSecret:
		if c.Secret == "" {
			return nil, fmt.Errorf("tenant %s: no client secret", c.TenantID)
		}
		cfg := &clientcredentials.Config{ClientID: c.ClientID, ClientSecret: c.Secret, TokenURL: tokenURL,
			Scopes: []string{GraphScope}, AuthStyle: oauth2.AuthStyleInParams}
		return cfg.TokenSource(ctx), nil
	case AuthCertificate:
		cert, key, err := ParseCertificate(c.CertificatePEM, c.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("tenant %s: %w", c.TenantID, err)
		}
		thumb := sha1.Sum(cert.Raw)
		src := &assertionSource{ctx: ctx, clientID: c.ClientID, tokenURL: tokenURL,
			x5t: base64.RawURLEncoding.EncodeToString(thumb[:]), sign: func(tok *jwt.Token) (string, error) { return tok.SignedString(key) }}
		return oauth2.ReuseTokenSource(nil, src), nil
	}
	return nil, fmt.Errorf("tenant %s: unknown auth method %q", c.TenantID, c.AuthMethod)
}

// assertionSource fetches a token with a new client assertion each time
type assertionSource struct {
	ctx      context.Context
	clientID string
	tokenURL string
	x5t      string
	sign     func(*jwt.Token) (string, error)
}

// ClientAssertion builds the JWT Entra expects from a certificate credential: RS256,
// x5t header = SHA-1 thumbprint of the certificate, audience = token endpoint,
// issuer = subject = client id, valid for ten minutes
func ClientAssertion(clientID, tokenURL, x5t string, now time.Time, sign func(*jwt.Token) (string, error)) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{tokenURL},
		ID:        uuid.NewString(),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	})
	tok.Header["x5t"] = x5t
	return sign(tok)
}

func (s *assertionSource) Token() (*oauth2.Token, error) {
	assertion, err := ClientAssertion(s.clientID, s.tokenURL, s.x5t, time.Now(), s.sign)
	if err != nil {
		return nil, fmt.Errorf("signing client assertion: %w", err)
	}
	cfg := &clientcredentials.Config{ClientID: s.clientID, TokenURL: s.tokenURL, Scopes: []string{GraphScope},
		AuthStyle: oauth2.AuthStyleInParams,
		EndpointParams: url.Values{
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion":      {assertion},
		}}
	return cfg.Token(s.ctx)
}

// Organization is what TestConnection learns about the tenant
type Organization struct {
	ID          string   `json:"id"`
	DisplayName string   `json:"display_name"`
	Domains     []string `json:"domains"`
}

// TestConnection acquires a token and reads /v1.0/organization. graphURL is GraphURL
// unless a test substitutes a server. The error text names the step that failed so an
// administrator can tell a wrong secret from a blocked egress or a missing permission.
func TestConnection(ctx context.Context, c Credentials, authority, graphURL string) (*Organization, error) {
	if graphURL == "" {
		graphURL = GraphURL
	}
	src, err := TokenSource(ctx, c, authority)
	if err != nil {
		return nil, err
	}
	tok, err := src.Token()
	if err != nil {
		return nil, fmt.Errorf("token request failed (check tenant id, client id and the secret or certificate; the caller needs outbound HTTPS to %s): %w", authority, err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(graphURL, "/")+"/v1.0/organization?$select=id,displayName,verifiedDomains", nil)
	tok.SetAuthHeader(req)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Graph request failed (the caller needs outbound HTTPS to %s): %w", graphURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Graph answered %s to /organization (missing Organization.Read.All / Directory.Read.All permission or admin consent?): %s", resp.Status, graphErrorText(body))
	}
	var out struct {
		Value []struct {
			ID              string `json:"id"`
			DisplayName     string `json:"displayName"`
			VerifiedDomains []struct {
				Name string `json:"name"`
			} `json:"verifiedDomains"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Value) == 0 {
		return nil, fmt.Errorf("unexpected /organization response")
	}
	org := &Organization{ID: out.Value[0].ID, DisplayName: out.Value[0].DisplayName}
	for _, d := range out.Value[0].VerifiedDomains {
		org.Domains = append(org.Domains, d.Name)
	}
	return org, nil
}

// graphErrorText extracts error.code: error.message from a Graph error body
func graphErrorText(body []byte) string {
	var e struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Code != "" {
		return e.Error.Code + ": " + e.Error.Message
	}
	s := strings.TrimSpace(string(body))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
