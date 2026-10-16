// Package releasesig verifies that a release's checksums file carries a valid
// Sigstore (cosign keyless) signature from this project's GitHub release workflow,
// and looks artifacts up in that signed file. The server checks it before mirroring
// an agent release; agents check it before replacing their own binary, so a
// compromised server cannot push them a binary GitHub never built.
package releasesig

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Sigstore public-good trusted root (Fulcio CAs, Rekor and CT log keys), embedded
// so verification works offline and does not depend on reaching Sigstore's TUF
// CDN from every backup host. Refresh it from `root.FetchTrustedRoot()` when
// Sigstore rotates keys; verification fails closed until then.
// ponytail: static snapshot, add a TUF refresh with this as the fallback if a
// rotation ever bites
//
//go:embed sigstore_trusted_root.json
var trustedRootJSON []byte

const (
	// Issuer is GitHub Actions' OIDC issuer
	Issuer = "https://token.actions.githubusercontent.com"
	// SANRegex pins the signing identity to this repository's release workflow on a
	// version tag
	SANRegex = `^https://github\.com/osshield/fallbck/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+.*$`
)

// verifierOptions is what a cosign keyless bundle must satisfy: a Rekor entry
// (inclusion proof) and an SCT on the Fulcio certificate
var verifierOptions = []verify.VerifierOption{
	verify.WithTransparencyLog(1),
	verify.WithObserverTimestamps(1),
	verify.WithSignedCertificateTimestamps(1),
}

// Verify checks that bundleJSON (cosign --new-bundle-format) signs checksums and was
// issued to the release workflow identity.
func Verify(bundleJSON, checksums []byte) error {
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return fmt.Errorf("embedded sigstore trusted root: %w", err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("sigstore bundle: %w", err)
	}
	return verifyEntity(tr, &b, Issuer, SANRegex, checksums)
}

func verifyEntity(tm root.TrustedMaterial, entity verify.SignedEntity, issuer, sanRegex string, artifact []byte) error {
	v, err := verify.NewVerifier(tm, verifierOptions...)
	if err != nil {
		return err
	}
	id, err := verify.NewShortCertificateIdentity(issuer, "", "", sanRegex)
	if err != nil {
		return err
	}
	if _, err := v.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(artifact)), verify.WithCertificateIdentity(id))); err != nil {
		return fmt.Errorf("release signature: %w", err)
	}
	return nil
}

// ChecksumFor finds name in a goreleaser checksums file ("<sha256>  <name>" lines)
func ChecksumFor(checksums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(checksums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name {
			return f[0], nil
		}
	}
	return "", fmt.Errorf("%s is not in the checksums file", name)
}

// ReadAll reads at most limit bytes (checksums and bundles are small)
func ReadAll(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("response larger than %d bytes", limit)
	}
	return b, nil
}
