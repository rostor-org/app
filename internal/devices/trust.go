package devices

// Trust bundle, CA rotation and certificate renewal (SPEC-cert-renewal;
// spec §14 "enforcement points pin the tenant key set with overlap windows",
// D3 core CA). A rotation has three steps, each explicit and audited:
//   1. rotate: a new CA becomes active alongside the old one; the bundle
//      version changes and devices pick it up on their next heartbeat;
//   2. devices renew their certificates (automatically) from the newest CA;
//   3. retire: the old CA is retired once no device depends on it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
	"rostor.org/app/internal/pki"
)

// Lifetimes are tenant defaults for now (the device-config policy domain
// will carry them); renewal happens when less than RenewWithin remains or
// when the issuing CA is no longer the newest active one.
const (
	CertLifetime = 90 * 24 * time.Hour
	RenewWithin  = 30 * 24 * time.Hour
	// A superseded fingerprint stays accepted this long after renewal.
	PrevGrace = 24 * time.Hour
)

type CAInfo struct {
	ID          string     `json:"id"`
	Subject     string     `json:"subject"`
	NotAfter    time.Time  `json:"not_after"`
	CreatedAt   time.Time  `json:"created_at"`
	RetiredAt   *time.Time `json:"retired_at,omitempty"`
	Newest      bool       `json:"newest"`
	Devices     int        `json:"devices"` // devices whose current cert this CA issued
	CertPEM     string     `json:"-"`
	Fingerprint string     `json:"fingerprint"`
}

// ActiveCAs returns the non-retired CAs, newest first.
func (s *Service) ActiveCAs(ctx context.Context, q directory.Querier, tenantID string) ([]CAInfo, error) {
	rows, err := q.Query(ctx, `SELECT k.id, k.cert_pem, k.created_at, k.retired_at,
		(SELECT count(*) FROM devices d WHERE d.tenant_id=k.tenant_id AND d.ca_key_id=k.id AND d.lifecycle IN ('enrolled','trusted'))
		FROM ca_keys k WHERE k.tenant_id=$1 AND k.purpose='ca' ORDER BY k.created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CAInfo
	for rows.Next() {
		var c CAInfo
		if err := rows.Scan(&c.ID, &c.CertPEM, &c.CreatedAt, &c.RetiredAt, &c.Devices); err != nil {
			return nil, err
		}
		if ca, err := pki.LoadCACert([]byte(c.CertPEM)); err == nil {
			c.Subject, c.NotAfter = ca.Subject.CommonName, ca.NotAfter
			c.Fingerprint = hex.EncodeToString(pki.Fingerprint(ca)[:8])
		}
		out = append(out, c)
	}
	for i := range out {
		if out[i].RetiredAt == nil {
			out[i].Newest = true
			break
		}
	}
	return out, rows.Err()
}

// TrustBundle is what devices pin: every active CA, with a version derived
// from the set so a device can tell whether anything changed.
type TrustBundle struct {
	Version string   `json:"version"`
	CAs     []string `json:"ca_pems"`
}

func (s *Service) TrustBundle(ctx context.Context, q directory.Querier, tenantID string) (*TrustBundle, error) {
	cas, err := s.ActiveCAs(ctx, q, tenantID)
	if err != nil {
		return nil, err
	}
	var pems []string
	for _, c := range cas {
		if c.RetiredAt == nil {
			pems = append(pems, c.CertPEM)
		}
	}
	sorted := append([]string{}, pems...)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return &TrustBundle{Version: hex.EncodeToString(h[:8]), CAs: pems}, nil
}

// NewestCA loads the CA that issues new certificates.
func (s *Service) NewestCA(ctx context.Context, tx pgx.Tx, tenantID string) (string, *pki.CA, error) {
	var id, certPEM string
	var sealed []byte
	err := tx.QueryRow(ctx, `SELECT id, cert_pem, key_sealed FROM ca_keys WHERE tenant_id=$1 AND purpose='ca' AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&id, &certPEM, &sealed)
	if err != nil {
		return "", nil, err
	}
	key, err := s.Provider.Open(sealed, []byte(tenantID+"/ca"))
	if err != nil {
		return "", nil, err
	}
	ca, err := pki.LoadCA([]byte(certPEM), key)
	return id, ca, err
}

// OldestCA loads the oldest active CA. The server's own certificate is
// issued from it, because it is the one every enrolled device already pins;
// only when it is retired does the server certificate move to the next.
func (s *Service) OldestCA(ctx context.Context, q directory.Querier, tenantID string) (string, *pki.CA, error) {
	var id, certPEM string
	var sealed []byte
	err := q.QueryRow(ctx, `SELECT id, cert_pem, key_sealed FROM ca_keys WHERE tenant_id=$1 AND purpose='ca' AND retired_at IS NULL ORDER BY created_at ASC LIMIT 1`, tenantID).Scan(&id, &certPEM, &sealed)
	if err != nil {
		return "", nil, err
	}
	key, err := s.Provider.Open(sealed, []byte(tenantID+"/ca"))
	if err != nil {
		return "", nil, err
	}
	ca, err := pki.LoadCA([]byte(certPEM), key)
	return id, ca, err
}

// Rotate creates a new CA alongside the existing ones. Nothing else changes
// until devices renew and the old CA is retired.
func (s *Service) Rotate(ctx context.Context, tx pgx.Tx, tenantID, tenantName string, actor directory.Actor) (*CAInfo, error) {
	ca, err := pki.NewCA(tenantName)
	if err != nil {
		return nil, err
	}
	key, err := ca.KeyPKCS8()
	if err != nil {
		return nil, err
	}
	sealed, err := s.Provider.Seal(key, []byte(tenantID+"/ca"))
	if err != nil {
		return nil, err
	}
	id := ids.New("key")
	if _, err := tx.Exec(ctx, `INSERT INTO ca_keys (tenant_id, id, purpose, algorithm, public_pem, cert_pem, key_sealed) VALUES ($1,$2,'ca','ecdsa-p256',$3,$3,$4)`,
		tenantID, id, string(ca.CertPEM()), sealed); err != nil {
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "ca.rotate", TargetType: "ca", TargetID: id,
		Outcome: "ok", Detail: map[string]any{"subject": ca.Cert.Subject.CommonName}, CorrelationID: actor.CorrelationID}); err != nil {
		return nil, err
	}
	return &CAInfo{ID: id, Subject: ca.Cert.Subject.CommonName, NotAfter: ca.Cert.NotAfter, Newest: true, CertPEM: string(ca.CertPEM())}, nil
}

// Retire marks a CA retired. Refused while any active device still holds a
// certificate it issued, unless force is set (audited as an override).
func (s *Service) Retire(ctx context.Context, tx pgx.Tx, tenantID, caID string, force bool, actor directory.Actor) error {
	var active int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM ca_keys WHERE tenant_id=$1 AND purpose='ca' AND retired_at IS NULL`, tenantID).Scan(&active); err != nil {
		return err
	}
	if active <= 1 {
		return directory.Err("ca.last_active")
	}
	var dependents int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id=$1 AND ca_key_id=$2 AND lifecycle IN ('enrolled','trusted')`, tenantID, caID).Scan(&dependents); err != nil {
		return err
	}
	if dependents > 0 && !force {
		return directory.Err("ca.in_use", "devices", dependents)
	}
	tag, err := tx.Exec(ctx, `UPDATE ca_keys SET retired_at=now() WHERE tenant_id=$1 AND id=$2 AND purpose='ca' AND retired_at IS NULL`, tenantID, caID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return directory.Err("request.not_found", "type", "ca")
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "ca.retire", TargetType: "ca", TargetID: caID,
		Outcome: "ok", Detail: map[string]any{"forced": force, "dependent_devices": dependents}, CorrelationID: actor.CorrelationID})
	return err
}

// Renew issues a fresh certificate for the device from the newest CA and
// keeps the previous fingerprint valid for PrevGrace.
func (s *Service) Renew(ctx context.Context, tx pgx.Tx, tenantID, principalID string, csrPEM []byte) (certPEM []byte, notAfter time.Time, err error) {
	caID, ca, err := s.NewestCA(ctx, tx, tenantID)
	if err != nil {
		return nil, time.Time{}, err
	}
	cert, pem, err := ca.IssueDevice(csrPEM, principalID, CertLifetime)
	if err != nil {
		return nil, time.Time{}, directory.Err("request.malformed", "field", "csr_pem", "detail", err.Error())
	}
	_, err = tx.Exec(ctx, `UPDATE devices SET prev_fingerprint=cert_fingerprint, prev_valid_until=now() + $3::interval,
		cert_fingerprint=$4, cert_serial=$5, cert_not_after=$6, ca_key_id=$7, cert_renewed_at=now()
		WHERE tenant_id=$1 AND principal_id=$2`, tenantID, principalID, PrevGrace.String(), pki.Fingerprint(cert), cert.SerialNumber.String(), cert.NotAfter, caID)
	if err != nil {
		return nil, time.Time{}, err
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: "device", ActorID: principalID, Action: "device.cert_renew", TargetType: "device", TargetID: principalID,
		CredentialType: "device_certificate", Outcome: "ok", Detail: map[string]any{"ca_key_id": caID, "not_after": cert.NotAfter}, CorrelationID: ids.New("corr")})
	return pem, cert.NotAfter, err
}

// RecordTrust notes which bundle version a device last confirmed.
func RecordTrust(ctx context.Context, q directory.Querier, tenantID, principalID, version string) error {
	_, err := q.Exec(ctx, `UPDATE devices SET trust_version=$3, last_seen_at=now() WHERE tenant_id=$1 AND principal_id=$2`, tenantID, principalID, version)
	return err
}

// ShouldRenew tells a device whether to renew now: expiry near, or its
// certificate was issued by a CA that is no longer the newest active one.
func ShouldRenew(notAfter time.Time, issuerID, newestID string) bool {
	return time.Until(notAfter) < RenewWithin || (issuerID != "" && newestID != "" && issuerID != newestID)
}

var _ = errors.New
var _ = json.Marshal
