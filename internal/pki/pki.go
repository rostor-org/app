// Package pki implements the core certificate authority (spec D3): device
// identity certificates and the core's own TLS server certificate are issued
// here. Keys are ECDSA P-256 so non-Go clients can use them without surprises.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA creates a self-signed root for a tenant. Lifetime is deliberately long
// (10y): rotation is a key-lifecycle feature that lands with snapshot signing.
func NewCA(tenantName string) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Rostor CA (" + tenantName + ")", Organization: []string{tenantName}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

func (c *CA) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw})
}

func (c *CA) KeyPKCS8() ([]byte, error) { return x509.MarshalPKCS8PrivateKey(c.Key) }

func LoadCA(certPEM, keyPKCS8 []byte) (*CA, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("pki: bad CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		return nil, err
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("pki: CA key is not ECDSA")
	}
	return &CA{Cert: cert, Key: key}, nil
}

// IssueDevice signs a CSR for a device principal. The CN is forced to the
// device principal ID so the certificate itself names the principal; nothing
// from the CSR's subject is trusted.
func (c *CA) IssueDevice(csrPEM []byte, principalID string, lifetime time.Duration) (*x509.Certificate, []byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("pki: bad CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("pki: CSR signature: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: principalID, OrganizationalUnit: []string{"device"}},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, csr.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// IssueServer issues the core's own TLS certificate for the given SANs.
func (c *CA) IssueServer(hosts []string, lifetime time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Rostor core"},
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return nil, nil, err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), nil
}

func Fingerprint(cert *x509.Certificate) []byte {
	s := sha256.Sum256(cert.Raw)
	return s[:]
}
