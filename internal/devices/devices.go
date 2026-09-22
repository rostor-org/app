// Package devices implements enrollment (spec §5, D3): an admin mints a
// single-use enrollment token; the device presents it with a CSR; the core
// creates a device principal, registers the matching resource, and issues a
// client certificate from the tenant CA. The certificate is the device's
// credential for every later call.
package devices

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/crypto"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
	"rostor.org/app/internal/pki"
)

const DeviceCertLifetime = 365 * 24 * time.Hour

type Service struct {
	Provider crypto.Provider
}

// ---- CA storage -------------------------------------------------------------

// EnsureCA loads the tenant CA, creating it on first use. The private key is
// sealed by the crypto provider with the tenant ID as associated data.
func (s *Service) EnsureCA(ctx context.Context, tx pgx.Tx, tenantID, tenantName string) (*pki.CA, error) {
	var certPEM string
	var sealed []byte
	err := tx.QueryRow(ctx, `SELECT cert_pem, key_sealed FROM ca_keys WHERE tenant_id=$1 AND purpose='ca' AND retired_at IS NULL ORDER BY created_at DESC LIMIT 1`, tenantID).Scan(&certPEM, &sealed)
	if err == nil {
		key, err := s.Provider.Open(sealed, []byte(tenantID+"/ca"))
		if err != nil {
			return nil, err
		}
		return pki.LoadCA([]byte(certPEM), key)
	}
	if err != pgx.ErrNoRows {
		return nil, err
	}
	ca, err := pki.NewCA(tenantName)
	if err != nil {
		return nil, err
	}
	key, err := ca.KeyPKCS8()
	if err != nil {
		return nil, err
	}
	sealed, err = s.Provider.Seal(key, []byte(tenantID+"/ca"))
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ca_keys (tenant_id, id, purpose, algorithm, public_pem, cert_pem, key_sealed) VALUES ($1,$2,'ca','ecdsa-p256',$3,$3,$4)`,
		tenantID, ids.New("key"), string(ca.CertPEM()), sealed)
	if err != nil {
		return nil, err
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: "system", ActorID: "core", Action: "ca.create", Outcome: "ok",
		Detail: map[string]any{"subject": ca.Cert.Subject.CommonName}, CorrelationID: ids.New("corr")})
	return ca, err
}

// ---- Enrollment tokens ------------------------------------------------------

func (s *Service) MintEnrollmentToken(ctx context.Context, tx pgx.Tx, tenantID string, actor directory.Actor, resourceType string, ttl time.Duration) (string, error) {
	tok := "enr_" + ids.Token(24)
	h := sha256.Sum256([]byte(tok))
	id := ids.New("etk")
	if _, err := tx.Exec(ctx, `INSERT INTO enrollment_tokens (tenant_id, id, token_hash, resource_type, created_by, expires_at) VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID, id, h[:], resourceType, actor.ID, time.Now().UTC().Add(ttl)); err != nil {
		return "", err
	}
	_, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "enrollment_token.create",
		TargetType: "enrollment_token", TargetID: id, Outcome: "ok", Detail: map[string]any{"resource_type": resourceType}, CorrelationID: actor.CorrelationID})
	return tok, err
}

// ---- Enrollment -------------------------------------------------------------

type EnrollRequest struct {
	Token   string
	CSRPEM  []byte
	Posture map[string]any
}

type Enrolled struct {
	DeviceID     string
	CertPEM      []byte
	CAPEM        []byte
	ResourceType string
	ResourceID   string
}

// Enroll consumes the token atomically (the UPDATE … WHERE used_at IS NULL is
// the single-use guarantee), creates the device principal and its resource,
// and issues the certificate.
func (s *Service) Enroll(ctx context.Context, tx pgx.Tx, ca *pki.CA, tenantID string, req EnrollRequest) (*Enrolled, error) {
	h := sha256.Sum256([]byte(req.Token))
	var tokID, resourceType string
	err := tx.QueryRow(ctx, `UPDATE enrollment_tokens SET used_at=now() WHERE tenant_id=$1 AND token_hash=$2 AND used_at IS NULL AND expires_at > now()
		RETURNING id, resource_type`, tenantID, h[:]).Scan(&tokID, &resourceType)
	if err == pgx.ErrNoRows {
		return nil, directory.Err("enrollment.token_invalid")
	}
	if err != nil {
		return nil, err
	}
	hostname, _ := req.Posture["hostname"].(string)
	if hostname == "" {
		return nil, directory.Err("request.malformed", "field", "posture.hostname")
	}
	actor := directory.Actor{Kind: "system", ID: "enrollment:" + tokID, CorrelationID: ids.New("corr")}
	p, err := directory.CreatePrincipal(ctx, tx, tenantID, actor, directory.Principal{Kind: "device", State: "active",
		DisplayName: map[string]string{"en": hostname}, Attributes: map[string]any{"resource_type": resourceType, "hostname": hostname}})
	if err != nil {
		return nil, err
	}
	// The workstation resource shares the device's hostname as its ID so the
	// agent can name it without a lookup (contract §1.1).
	if err := directory.CreateResource(ctx, tx, tenantID, actor, directory.Resource{Type: resourceType, ID: hostname,
		ParentType: resourceType + "s", ParentID: "all", Attributes: map[string]any{"device_id": p.ID}}); err != nil {
		if code, _ := directory.CodeOf(err); code != "request.conflict" {
			return nil, err
		}
	}
	cert, certPEM, err := ca.IssueDevice(req.CSRPEM, p.ID, DeviceCertLifetime)
	if err != nil {
		return nil, directory.Err("request.malformed", "field", "csr_pem", "detail", err.Error())
	}
	posture, _ := json.Marshal(req.Posture)
	if _, err := tx.Exec(ctx, `INSERT INTO devices (tenant_id, principal_id, lifecycle, cert_serial, cert_fingerprint, cert_not_after, posture, last_seen_at)
		VALUES ($1,$2,'trusted',$3,$4,$5,$6,now())`, tenantID, p.ID, cert.SerialNumber.String(), pki.Fingerprint(cert), cert.NotAfter, posture); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET used_by=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, tokID, p.ID); err != nil {
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: "device", ActorID: p.ID, Action: "device.enroll",
		TargetType: "device", TargetID: p.ID, CredentialType: "enrollment_token", Outcome: "ok",
		Detail: map[string]any{"resource": resourceType + ":" + hostname, "cert_serial": cert.SerialNumber.String()}, CorrelationID: actor.CorrelationID}); err != nil {
		return nil, err
	}
	return &Enrolled{DeviceID: p.ID, CertPEM: certPEM, CAPEM: ca.CertPEM(), ResourceType: resourceType, ResourceID: hostname}, nil
}

// ---- Resolution by certificate ---------------------------------------------

type Device struct {
	Principal *directory.Principal
	Lifecycle string
}

// ByFingerprint maps a presented client certificate to its device. Lifecycle
// is returned rather than enforced so the API layer can produce the exact
// reason code (device.not_trusted vs device.unknown).
func ByFingerprint(ctx context.Context, q directory.Querier, fp []byte) (tenantID string, d *Device, err error) {
	var principalID, lifecycle string
	err = q.QueryRow(ctx, `SELECT tenant_id, principal_id, lifecycle FROM devices WHERE cert_fingerprint=$1`, fp).Scan(&tenantID, &principalID, &lifecycle)
	if err == pgx.ErrNoRows {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	p, err := directory.GetPrincipal(ctx, q, tenantID, principalID)
	if err != nil {
		return "", nil, err
	}
	return tenantID, &Device{Principal: p, Lifecycle: lifecycle}, nil
}

func UpdatePosture(ctx context.Context, q directory.Querier, tenantID, principalID string, posture map[string]any) error {
	raw, _ := json.Marshal(posture)
	_, err := q.Exec(ctx, `UPDATE devices SET posture = posture || $3::jsonb, last_seen_at=now() WHERE tenant_id=$1 AND principal_id=$2`, tenantID, principalID, raw)
	return err
}
