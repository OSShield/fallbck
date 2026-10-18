package proxy

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osshield/fallbck/pkg/db"
)

func TestTokenPermissions(t *testing.T) {
	var gotAuth, gotPath string
	requests := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Query().Get("path")
		if r.URL.Path != "/api2/json/access/permissions" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"/datastore/s1":{"Datastore.Backup":true},"/":{"Sys.Audit":0}}}`))
	}))
	defer srv.Close()
	pin := sha256.Sum256(srv.Certificate().Raw)

	target := &db.BackupTarget{Endpoint: srv.URL, AuthToken: "fallbck@pbs!backup:secret", Fingerprint: formatFingerprint(pin)}
	perms, err := TokenPermissions(context.Background(), target, "/datastore/s1/ns")
	if err != nil {
		t.Fatal(err)
	}
	if !perms["/datastore/s1"]["Datastore.Backup"] || perms["/"]["Sys.Audit"] {
		t.Errorf("permissions %v", perms)
	}
	if _, ok := perms["/"]["Sys.Audit"]; !ok {
		t.Error("a 0 propagate flag must still list the privilege")
	}
	if !strings.HasPrefix(gotAuth, "PBSAPIToken=fallbck@pbs!backup") || gotPath != "/datastore/s1/ns" {
		t.Errorf("auth %q path %q", gotAuth, gotPath)
	}

	// A wrong pin must fail before the token is sent
	before := requests
	target.Fingerprint = strings.Repeat("00:", 31) + "00"
	if _, err := TokenPermissions(context.Background(), target, ""); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Errorf("fingerprint mismatch: %v", err)
	}
	if requests != before {
		t.Error("the token reached a server with the wrong certificate")
	}
	// No pin and verification on: the test certificate is self-signed, so this fails
	target.Fingerprint, target.TLSVerify = "", true
	if _, err := TokenPermissions(context.Background(), target, ""); err == nil {
		t.Error("an unverifiable certificate was accepted")
	}
}
