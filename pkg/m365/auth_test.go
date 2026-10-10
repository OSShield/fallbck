package m365

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeEntra answers the token endpoint of one tenant and a Graph /organization call
func fakeEntra(t *testing.T, check func(form map[string]string)) (authority, graph string, tokens *int) {
	t.Helper()
	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/"+testTenantGUID+"/oauth2/v2.0/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		form := map[string]string{}
		for k := range r.PostForm {
			form[k] = r.PostForm.Get(k)
		}
		check(form)
		count++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token_type":"Bearer","expires_in":3599,"access_token":"tok-` + form["client_id"] + `"}`))
	})
	mux.HandleFunc("/v1.0/organization", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-"+testClientGUID {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"bad token"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"value":[{"id":"` + testTenantGUID + `","displayName":"Contoso","verifiedDomains":[{"name":"contoso.onmicrosoft.com"},{"name":"contoso.com"}]}]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL, srv.URL, &count
}

func TestTokenSourceSecret(t *testing.T) {
	authority, graph, tokens := fakeEntra(t, func(form map[string]string) {
		if form["client_id"] != testClientGUID {
			return // the deliberately wrong client below
		}
		if form["grant_type"] != "client_credentials" || form["client_secret"] != "s3cret" || form["scope"] != GraphScope {
			t.Errorf("token form: %v", form)
		}
	})
	creds := Credentials{TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthSecret, Secret: "s3cret"}
	org, err := TestConnection(context.Background(), creds, authority, graph)
	if err != nil {
		t.Fatal(err)
	}
	if org.DisplayName != "Contoso" || len(org.Domains) != 2 || *tokens != 1 {
		t.Errorf("org %+v, tokens %d", org, *tokens)
	}
	if _, err := TestConnection(context.Background(), Credentials{TenantID: testTenantGUID, ClientID: "other", Secret: "x"}, authority, graph); err == nil || !strings.Contains(err.Error(), "InvalidAuthenticationToken") {
		t.Errorf("Graph error not surfaced: %v", err)
	}
	if _, err := TestConnection(context.Background(), Credentials{TenantID: testTenantGUID, ClientID: testClientGUID}, authority, graph); err == nil {
		t.Error("missing secret accepted")
	}
}

func TestTokenSourceCertificate(t *testing.T) {
	certPEM, keyPEM, key := testCertificate(t, time.Now().Add(24*time.Hour))
	block, _ := pem.Decode([]byte(certPEM))
	thumb := sha1.Sum(block.Bytes)
	wantX5t := base64.RawURLEncoding.EncodeToString(thumb[:])
	var tokenURL string
	authority, graph, tokens := fakeEntra(t, func(form map[string]string) {
		if form["client_assertion_type"] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" || form["client_secret"] != "" {
			t.Errorf("token form: %v", form)
		}
		claims := &jwt.RegisteredClaims{}
		tok, err := jwt.ParseWithClaims(form["client_assertion"], claims, func(tok *jwt.Token) (any, error) { return &key.PublicKey, nil },
			jwt.WithAudience(tokenURL), jwt.WithIssuer(testClientGUID), jwt.WithValidMethods([]string{"RS256"}))
		if err != nil || !tok.Valid {
			t.Errorf("assertion does not verify: %v", err)
			return
		}
		if tok.Header["x5t"] != wantX5t || claims.Subject != testClientGUID || claims.ID == "" {
			t.Errorf("assertion header/claims: %v %+v", tok.Header, claims)
		}
	})
	tokenURL = TokenURL(authority, testTenantGUID)
	creds := Credentials{TenantID: testTenantGUID, ClientID: testClientGUID, AuthMethod: AuthCertificate, CertificatePEM: certPEM, KeyPEM: keyPEM}
	src, err := TokenSource(context.Background(), creds, authority)
	if err != nil {
		t.Fatal(err)
	}
	// The source caches the access token: two Token calls, one request
	for i := 0; i < 2; i++ {
		tok, err := src.Token()
		if err != nil {
			t.Fatal(err)
		}
		if tok.AccessToken != "tok-"+testClientGUID {
			t.Error(tok.AccessToken)
		}
	}
	if *tokens != 1 {
		t.Errorf("%d token requests, want 1", *tokens)
	}
	if _, err := TestConnection(context.Background(), creds, authority, graph); err != nil {
		t.Fatal(err)
	}
}
