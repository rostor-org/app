package api

// Device trust and renewal endpoints (SPEC-cert-renewal), plus the admin CA
// actions. All device endpoints are mutual-TLS; a device presenting its
// superseded certificate inside the grace window is told to renew again.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/pki"
)

// handleTrust returns the active CA bundle; the agent replaces its pinned
// file when the version changes.
func (s *Server) handleTrust(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	b, err := s.Devices.TrustBundle(r.Context(), s.DB, s.TenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = devices.RecordTrust(r.Context(), s.DB, s.TenantID, d.Principal.ID, b.Version)
	newest := ""
	if cas, err := s.Devices.ActiveCAs(r.Context(), s.DB, s.TenantID); err == nil {
		for _, c := range cas {
			if c.Newest {
				newest = c.ID
			}
		}
	}
	s.writeJSON(w, 200, map[string]any{
		"version": b.Version, "ca_pems": b.CAs,
		"renew":          d.UsingPrevious || devices.ShouldRenew(d.CertNotAfter, d.CAKeyID, newest),
		"cert_not_after": d.CertNotAfter,
	})
}

// handleRenew issues a new certificate from the newest CA for a CSR signed
// by the device's new key. The old certificate keeps working for the grace
// window in case the reply is lost.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var certPEM []byte
	var notAfter time.Time
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		certPEM, notAfter, err = s.Devices.Renew(r.Context(), tx, s.TenantID, d.Principal.ID, []byte(req.CSRPEM))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	b, _ := s.Devices.TrustBundle(r.Context(), s.DB, s.TenantID)
	s.writeJSON(w, 200, map[string]any{"certificate_pem": string(certPEM), "not_after": notAfter, "ca_pems": b.CAs, "trust_version": b.Version})
}

// ---- admin: CA lifecycle -----------------------------------------------------

func (s *Server) handleListCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := s.Devices.ActiveCAs(r.Context(), s.DB, s.TenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	b, _ := s.Devices.TrustBundle(r.Context(), s.DB, s.TenantID)
	var stale, total int
	_ = s.DB.QueryRow(r.Context(), `SELECT count(*) FILTER (WHERE trust_version IS DISTINCT FROM $2), count(*) FROM devices WHERE tenant_id=$1 AND lifecycle IN ('enrolled','trusted')`, s.TenantID, b.Version).Scan(&stale, &total)
	if cas == nil {
		cas = []devices.CAInfo{}
	}
	s.writeJSON(w, 200, map[string]any{"items": cas, "trust_version": b.Version, "devices": map[string]int{"total": total, "on_older_bundle": stale}})
}

func (s *Server) handleRotateCA(w http.ResponseWriter, r *http.Request) {
	var name string
	_ = s.DB.QueryRow(r.Context(), `SELECT name FROM tenants WHERE id=$1`, s.TenantID).Scan(&name)
	var info *devices.CAInfo
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		info, err = s.Devices.Rotate(r.Context(), tx, s.TenantID, name, actorOf(r))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadTrust()
	s.writeJSON(w, 201, info)
}

func (s *Server) handleRetireCA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Force bool `json:"force"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	err := s.tx(r, func(tx pgx.Tx) error {
		return s.Devices.Retire(r.Context(), tx, s.TenantID, r.PathValue("id"), req.Force, actorOf(r))
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.reloadTrust()
	w.WriteHeader(204)
}

// ---- live TLS trust --------------------------------------------------------------

// trustState is what the TLS listener consults per handshake: the pool of
// active CAs for client certificates and the server certificate. Rebuilt
// on rotation/retirement and on a timer, never requiring a restart.
type trustState struct {
	mu     sync.RWMutex
	pool   *x509.CertPool
	cert   *tls.Certificate
	loaded time.Time
}

func (s *Server) reloadTrust() {
	if s.trust == nil {
		s.trust = &trustState{}
	}
	cas, err := s.Devices.ActiveCAs(s.baseCtx(), s.DB, s.TenantID)
	if err != nil {
		s.Log.Warn("trust reload", "err", err)
		return
	}
	pool := x509.NewCertPool()
	for _, c := range cas {
		if c.RetiredAt == nil {
			pool.AppendCertsFromPEM([]byte(c.CertPEM))
		}
	}
	s.trust.mu.Lock()
	s.trust.pool = pool
	s.trust.loaded = time.Now()
	s.trust.mu.Unlock()
	if s.OnTrustChange != nil {
		s.OnTrustChange()
	}
}

// TLSConfig serves the core certificate and requests (never requires) client
// certificates against the live pool of active CAs.
func (s *Server) TLSConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	s.reloadTrust()
	s.trust.mu.Lock()
	s.trust.cert = &cert
	s.trust.mu.Unlock()
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.VerifyClientCertIfGiven,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			s.trust.mu.RLock()
			pool, c := s.trust.pool, s.trust.cert
			s.trust.mu.RUnlock()
			return &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: pool, Certificates: []tls.Certificate{*c}}, nil
		},
	}, nil
}

// SetServerCert swaps the server certificate (after a CA cutover).
func (s *Server) SetServerCert(certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	s.trust.mu.Lock()
	s.trust.cert = &cert
	s.trust.mu.Unlock()
	return nil
}

var _ = directory.Err
var _ = pki.Fingerprint
