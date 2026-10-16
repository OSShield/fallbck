package releasesig

import (
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const releaseIdentity = "https://github.com/osshield/fallbck/.github/workflows/release.yml@refs/tags/v1.2.3"

func TestVerifyEntity(t *testing.T) {
	// The virtual CA issues no SCTs
	saved := verifierOptions
	verifierOptions = []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	defer func() { verifierOptions = saved }()

	virtual, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	checksums := []byte("abc  fallbck_agent_Linux_x86_64.tar.gz\n")
	entity, err := virtual.Sign(releaseIdentity, Issuer, checksums)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEntity(virtual, entity, Issuer, SANRegex, checksums); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := verifyEntity(virtual, entity, Issuer, SANRegex, []byte("abd  fallbck_agent_Linux_x86_64.tar.gz\n")); err == nil {
		t.Error("tampered checksums accepted")
	}
	forged, _ := virtual.Sign("https://github.com/someone-else/fallbck/.github/workflows/release.yml@refs/tags/v1.2.3", Issuer, checksums)
	if err := verifyEntity(virtual, forged, Issuer, SANRegex, checksums); err == nil {
		t.Error("another repository's workflow accepted")
	}
	branch, _ := virtual.Sign("https://github.com/osshield/fallbck/.github/workflows/release.yml@refs/heads/main", Issuer, checksums)
	if err := verifyEntity(virtual, branch, Issuer, SANRegex, checksums); err == nil {
		t.Error("a branch build accepted as a release")
	}
	other, _ := virtual.Sign(releaseIdentity, "https://accounts.google.com", checksums)
	if err := verifyEntity(virtual, other, Issuer, SANRegex, checksums); err == nil {
		t.Error("another issuer accepted")
	}
}

func TestEmbeddedTrustedRootParses(t *testing.T) {
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.FulcioCertificateAuthorities()) == 0 || len(tr.RekorLogs()) == 0 || len(tr.CTLogs()) == 0 {
		t.Error("trusted root lacks Fulcio, Rekor or CT log material")
	}
	if err := Verify([]byte("{}"), []byte("x")); err == nil || !strings.Contains(err.Error(), "bundle") {
		t.Errorf("empty bundle: %v", err)
	}
}

func TestChecksumFor(t *testing.T) {
	sums := []byte("aaa  one.tar.gz\nbbb  two.tar.gz\n")
	if s, err := ChecksumFor(sums, "two.tar.gz"); err != nil || s != "bbb" {
		t.Errorf("got %q %v", s, err)
	}
	if _, err := ChecksumFor(sums, "three.tar.gz"); err == nil {
		t.Error("missing entry accepted")
	}
}
