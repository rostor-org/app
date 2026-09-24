// Package trust keeps the device's pinned CA bundle and its client
// certificate current (console-api.md, "Certificates and trust"): it applies
// new bundles from GET /v1/devices/self/trust, renews the certificate through
// POST /v1/devices/self/renew, and swaps the files on disk without ever
// leaving the agent with a pair it has not proven to work.
package trust

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"time"
)

// RenewWithin mirrors core's threshold: renew when less than this remains.
const RenewWithin = 30 * 24 * time.Hour

// Concat joins CA PEMs into the ca.crt content. Every PEM ends with exactly
// one newline so the file parses back into the same set.
func Concat(pems []string) []byte {
	var b strings.Builder
	for _, p := range pems {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		b.WriteString(p)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// ParseBundle returns every CERTIFICATE block in data, in file order.
func ParseBundle(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificates in bundle")
	}
	return certs, nil
}

// ParseCert parses the first certificate in a PEM file.
func ParseCert(data []byte) (*x509.Certificate, error) {
	certs, err := ParseBundle(data)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

// Fingerprint is the SHA-256 of the DER certificate as lowercase hex; the
// console shows its first 16 characters as the CA id.
func Fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// SameBundle reports whether two bundles hold the same certificates,
// regardless of order.
func SameBundle(a, b []*x509.Certificate) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, c := range a {
		set[Fingerprint(c)] = true
	}
	for _, c := range b {
		if !set[Fingerprint(c)] {
			return false
		}
	}
	return true
}

// Issuer returns the bundle certificate that signed leaf, or nil.
func Issuer(leaf *x509.Certificate, bundle []*x509.Certificate) *x509.Certificate {
	for _, ca := range bundle {
		if leaf.CheckSignatureFrom(ca) == nil {
			return ca
		}
	}
	return nil
}

// NeedsRenewal is the local half of the renewal decision (core's "renew"
// flag is the other half and wins when true): the certificate expires within
// RenewWithin, or it was not issued by the newest CA in the bundle, which is
// bundle[0] because core lists active CAs newest first. The returned string
// names the reason for the log.
func NeedsRenewal(leaf *x509.Certificate, bundle []*x509.Certificate, now time.Time) (bool, string) {
	if leaf == nil {
		return false, ""
	}
	if remaining := leaf.NotAfter.Sub(now); remaining < RenewWithin {
		return true, "certificate expires " + leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	if len(bundle) == 0 {
		return false, ""
	}
	issuer := Issuer(leaf, bundle)
	switch {
	case issuer == nil:
		return true, "issuing CA is not in the trust bundle"
	case Fingerprint(issuer) != Fingerprint(bundle[0]):
		return true, "issuing CA is no longer the newest"
	}
	return false, ""
}
