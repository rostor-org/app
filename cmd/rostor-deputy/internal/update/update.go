// Package update is the deputy half of self-update (contract §1.6): on the
// heartbeat it asks core whether this device should run another deputy
// version, downloads the signed release bundle, checks its size, digest and
// signature against the pinned CA bundle, unpacks it and starts the
// bundle's own install.ps1 detached — that installer stops this service,
// swaps the binary and the credential provider, and starts the new one. On
// the next start the deputy reports how it went.
//
// Nothing here installs a bundle whose signature did not verify: like a
// script, an update is code the core asks the workstation to run as SYSTEM,
// so verification is a separate pure function with its own tests.
package update

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"rostor.org/app/cmd/rostor-deputy/internal/core"
	"rostor.org/app/cmd/rostor-deputy/internal/trust"
)

// Info is the wire type; aliased so callers need not import core for the
// plain data.
type Info = core.UpdateInfo

// Run is an update report (§1.6).
type Run = core.UpdateRun

// Verification failures. ErrSignature is the one that matters
// operationally: the bundle on disk is not the one core signed for this
// version.
var (
	ErrSignature = errors.New("update signature does not verify against the trust bundle")
	ErrNoCA      = errors.New("trust bundle holds no certificates")
)

// SignedMessage returns the bytes the core signs for a bundle: the literal
// "bundle", the version and the zip's sha256 (lowercase hex) joined by
// newlines. Exported so a test can sign exactly what the deputy verifies.
func SignedMessage(version, sha256hex string) []byte {
	return []byte("bundle\n" + version + "\n" + sha256hex)
}

// Verify checks that some CA certificate in the PEM bundle vouches for
// (info.Version, sha256hex), where sha256hex is the digest the deputy
// computed over the bytes it downloaded — not the digest core announced.
// That binds the signature to the file on disk. Every CA in ca.crt is tried
// (all active CAs are pinned, so a bundle signed by the previous CA during
// a rotation still verifies); the signer id is informational.
func Verify(info Info, sha256hex string, caPEMs []byte) error {
	certs, err := trust.ParseBundle(caPEMs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoCA, err)
	}
	if info.Signature == "" {
		return fmt.Errorf("%w: empty signature", ErrSignature)
	}
	sig, err := base64.StdEncoding.DecodeString(info.Signature)
	if err != nil {
		return fmt.Errorf("%w: signature is not base64: %v", ErrSignature, err)
	}
	digest := sha256.Sum256(SignedMessage(info.Version, sha256hex))
	for _, c := range certs {
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		if ecdsa.VerifyASN1(pub, digest[:], sig) {
			return nil
		}
	}
	return ErrSignature
}
