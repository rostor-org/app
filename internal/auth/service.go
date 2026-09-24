package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/crypto"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
)

type Service struct {
	Provider crypto.Provider
	methods  map[string]Method
}

func NewService(p crypto.Provider, methods ...Method) *Service {
	s := &Service{Provider: p, methods: map[string]Method{}}
	for _, m := range methods {
		s.methods[m.Describe().Method] = m
	}
	return s
}

func (s *Service) Method(name string) (Method, bool) {
	m, ok := s.methods[name]
	return m, ok
}

// ---- Bindings & sealed store -----------------------------------------------

type Binding struct {
	ID          string    `json:"id"`
	PrincipalID string    `json:"principal_id"`
	Method      string    `json:"method"`
	Properties  []string  `json:"properties"`
	Label       string    `json:"label,omitempty"`
	State       string    `json:"state"`
	CreatedAt   time.Time `json:"created_at"`
}

// Enroll runs a method's enrollment and stores the resulting material sealed
// under the binding ID as associated data, so material can never be swapped
// between bindings even by someone with database access.
func (s *Service) Enroll(ctx context.Context, tx pgx.Tx, tenantID string, actor directory.Actor, principalID, method, label string, in StepInput) (*Binding, error) {
	m, ok := s.methods[method]
	if !ok {
		return nil, directory.Err("auth.method_unavailable", "method", method)
	}
	mat, idents, err := m.Enroll(ctx, in)
	if err != nil {
		return nil, directory.Err("request.malformed", "field", method, "detail", err.Error())
	}
	props := m.Describe().Properties
	if method == "badge" && strings.TrimSpace(in.Fields["pin"]) != "" {
		props = append(append([]string{}, props...), "knowledge")
	}
	b := &Binding{ID: ids.New("bnd"), PrincipalID: principalID, Method: method, Properties: props, Label: label, State: "active"}
	sealed, err := s.Provider.Seal(mat, []byte(tenantID+"/"+b.ID))
	if err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO authenticator_bindings (tenant_id, id, principal_id, method, properties, label)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')) RETURNING created_at`, tenantID, b.ID, principalID, method, b.Properties, label).Scan(&b.CreatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credential_material (tenant_id, binding_id, sealed) VALUES ($1,$2,$3)`, tenantID, b.ID, sealed); err != nil {
		return nil, err
	}
	for _, id := range idents {
		if _, err := tx.Exec(ctx, `INSERT INTO credential_identifiers (tenant_id, binding_id, kind, value) VALUES ($1,$2,$3,$4)`, tenantID, b.ID, id.Kind, id.Value); err != nil {
			if strings.Contains(err.Error(), "23505") {
				// The same card (or credential) is already registered to someone.
				return nil, directory.Err("request.conflict", "field", "credential", "kind", id.Kind)
			}
			return nil, err
		}
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "binding.enroll",
		TargetType: "principal", TargetID: principalID, Outcome: "ok",
		Detail: map[string]any{"binding_id": b.ID, "method": method, "properties": b.Properties}, CorrelationID: actor.CorrelationID})
	return b, err
}

func (s *Service) RevokeBinding(ctx context.Context, tx pgx.Tx, tenantID string, actor directory.Actor, bindingID string) error {
	var principalID string
	err := tx.QueryRow(ctx, `UPDATE authenticator_bindings SET state='revoked', revoked_at=now()
		WHERE tenant_id=$1 AND id=$2 AND state='active' RETURNING principal_id`, tenantID, bindingID).Scan(&principalID)
	if err == pgx.ErrNoRows {
		return directory.Err("request.not_found", "type", "binding")
	}
	if err != nil {
		return err
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "binding.revoke",
		TargetType: "principal", TargetID: principalID, Outcome: "ok",
		Detail: map[string]any{"binding_id": bindingID}, CorrelationID: actor.CorrelationID})
	return err
}

type sealedRow struct {
	s         *Service
	tx        pgx.Tx
	tenantID  string
	bindingID string
}

func (r sealedRow) Read(ctx context.Context) ([]byte, error) {
	var sealed []byte
	if err := r.tx.QueryRow(ctx, `SELECT sealed FROM credential_material WHERE tenant_id=$1 AND binding_id=$2`, r.tenantID, r.bindingID).Scan(&sealed); err != nil {
		return nil, err
	}
	return r.s.Provider.Open(sealed, []byte(r.tenantID+"/"+r.bindingID))
}

// ---- Lockout (core-owned, cross-method; §7.6) -------------------------------

type LockoutPolicy struct {
	Threshold int
	Duration  time.Duration
}

var DefaultLockout = LockoutPolicy{Threshold: 5, Duration: 15 * time.Minute}

func (s *Service) lockedUntil(ctx context.Context, tx pgx.Tx, tenantID, principalID string) (time.Time, error) {
	var until *time.Time
	err := tx.QueryRow(ctx, `SELECT locked_until FROM auth_failures WHERE tenant_id=$1 AND principal_id=$2 FOR UPDATE`, tenantID, principalID).Scan(&until)
	if err == pgx.ErrNoRows || until == nil {
		return time.Time{}, nil
	}
	return *until, err
}

func (s *Service) recordFailure(ctx context.Context, tx pgx.Tx, tenantID, principalID string, pol LockoutPolicy) error {
	_, err := tx.Exec(ctx, `INSERT INTO auth_failures (tenant_id, principal_id, failed_count, locked_until, updated_at)
		VALUES ($1,$2,1,NULL,now())
		ON CONFLICT (tenant_id, principal_id) DO UPDATE SET
		  failed_count = auth_failures.failed_count + 1,
		  locked_until = CASE WHEN auth_failures.failed_count + 1 >= $3 THEN now() + $4::interval ELSE auth_failures.locked_until END,
		  updated_at = now()`, tenantID, principalID, pol.Threshold, pol.Duration.String())
	return err
}

func (s *Service) clearFailures(ctx context.Context, tx pgx.Tx, tenantID, principalID string) error {
	_, err := tx.Exec(ctx, `DELETE FROM auth_failures WHERE tenant_id=$1 AND principal_id=$2`, tenantID, principalID)
	return err
}

// ---- Ceremonies -------------------------------------------------------------

// Outcome of an identifier-first inline ceremony. Only one of Assertion or
// Code is set. Code is a stable reason (auth.failed | auth.locked |
// auth.method_unavailable). Principal is set whenever it could be resolved so
// the caller can audit the target even on failure.
type Outcome struct {
	Assertion *Assertion
	Principal *directory.Principal
	Code      string
	Params    map[string]any
}

// AuthenticateInline runs a complete single-step inline ceremony (§7.6): the
// core resolves the identifier, discovers an active binding of the requested
// method, checks cross-method lockout, delegates verification to the method,
// and records the ceremony. It returns auth.failed for an unknown identifier
// too, after a dummy verification, so timing does not reveal existence.
func (s *Service) AuthenticateInline(ctx context.Context, tx pgx.Tx, tenantID, method, identifier string, in StepInput, pol LockoutPolicy) (*Outcome, error) {
	m, ok := s.methods[method]
	if !ok {
		return &Outcome{Code: "auth.method_unavailable", Params: map[string]any{"method": method}}, nil
	}
	cer := ids.New("cer")
	p, err := directory.GetPrincipalByUsername(ctx, tx, tenantID, identifier)
	if err != nil {
		if code, ok := directory.CodeOf(err); ok && code == "principal.not_found" {
			s.burn(ctx, m, in)
			return s.finish(ctx, tx, tenantID, cer, method, "", "failed", &Outcome{Code: "auth.failed", Params: map[string]any{}})
		}
		return nil, err
	}
	if until, err := s.lockedUntil(ctx, tx, tenantID, p.ID); err != nil {
		return nil, err
	} else if until.After(time.Now()) {
		mins := int(time.Until(until).Minutes()) + 1
		return s.finish(ctx, tx, tenantID, cer, method, p.ID, "failed", &Outcome{Principal: p, Code: "auth.locked", Params: map[string]any{"minutes": mins}})
	}
	var bindingID string
	err = tx.QueryRow(ctx, `SELECT id FROM authenticator_bindings WHERE tenant_id=$1 AND principal_id=$2 AND method=$3 AND state='active'
		ORDER BY created_at DESC LIMIT 1`, tenantID, p.ID, method).Scan(&bindingID)
	if err == pgx.ErrNoRows {
		s.burn(ctx, m, in)
		if err := s.recordFailure(ctx, tx, tenantID, p.ID, pol); err != nil {
			return nil, err
		}
		return s.finish(ctx, tx, tenantID, cer, method, p.ID, "failed", &Outcome{Principal: p, Code: "auth.failed", Params: map[string]any{}})
	}
	if err != nil {
		return nil, err
	}
	res, err := m.Authenticate(ctx, bindingID, sealedRow{s, tx, tenantID, bindingID}, in, nil)
	if err != nil {
		return nil, err
	}
	if res.Failed || res.Assertion == nil {
		if err := s.recordFailure(ctx, tx, tenantID, p.ID, pol); err != nil {
			return nil, err
		}
		return s.finish(ctx, tx, tenantID, cer, method, p.ID, "failed", &Outcome{Principal: p, Code: "auth.failed", Params: map[string]any{}})
	}
	if err := s.clearFailures(ctx, tx, tenantID, p.ID); err != nil {
		return nil, err
	}
	if err := s.touchBinding(ctx, tx, tenantID, bindingID, res.Assertion); err != nil {
		return nil, err
	}
	return s.finish(ctx, tx, tenantID, cer, method, p.ID, "completed", &Outcome{Principal: p, Assertion: res.Assertion})
}

// touchBinding records use and re-seals any material the method updated
// (a passkey's sign counter). Methods return material; only the core writes it.
func (s *Service) touchBinding(ctx context.Context, tx pgx.Tx, tenantID, bindingID string, a *Assertion) error {
	if _, err := tx.Exec(ctx, `UPDATE authenticator_bindings SET last_used_at=now() WHERE tenant_id=$1 AND id=$2`, tenantID, bindingID); err != nil {
		return err
	}
	if a != nil && a.UpdatedMaterial != nil {
		sealed, err := s.Provider.Seal(a.UpdatedMaterial, []byte(tenantID+"/"+bindingID))
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE credential_material SET sealed=$3 WHERE tenant_id=$1 AND binding_id=$2`, tenantID, bindingID, sealed); err != nil {
			return err
		}
	}
	return nil
}

// NeedsInput marks an outcome where the credential matched but the method
// needs one more thing from the presenter (a PIN). Code is "auth.continue"
// and Params carries what is needed.
const CodeContinue = "auth.continue"

// AuthenticateByCredential runs an inline ceremony for a method whose
// credential identifies the user (badge, discoverable passkey): the core
// looks the presented identifiers up, finds the binding and its principal,
// applies lockout, and delegates verification. Unknown credentials and
// failed verifications both yield auth.failed.
func (s *Service) AuthenticateByCredential(ctx context.Context, tx pgx.Tx, tenantID, method string, in StepInput, pol LockoutPolicy) (*Outcome, error) {
	m, ok := s.methods[method]
	if !ok {
		return &Outcome{Code: "auth.method_unavailable", Params: map[string]any{"method": method}}, nil
	}
	cer := ids.New("cer")
	presented := m.Identify(in)
	if len(presented) == 0 {
		return s.finish(ctx, tx, tenantID, cer, method, "", "failed", &Outcome{Code: "auth.failed", Params: map[string]any{}})
	}
	kinds := make([]string, len(presented))
	values := make([]string, len(presented))
	for i, id := range presented {
		kinds[i], values[i] = id.Kind, id.Value
	}
	var bindingID, principalID string
	err := tx.QueryRow(ctx, `SELECT b.id, b.principal_id FROM credential_identifiers ci
		JOIN authenticator_bindings b ON b.tenant_id=ci.tenant_id AND b.id=ci.binding_id AND b.state='active' AND b.method=$2
		WHERE ci.tenant_id=$1 AND (ci.kind, ci.value) IN (SELECT * FROM unnest($3::text[], $4::text[])) LIMIT 1`,
		tenantID, method, kinds, values).Scan(&bindingID, &principalID)
	if err == pgx.ErrNoRows {
		s.burn(ctx, m, in)
		return s.finish(ctx, tx, tenantID, cer, method, "", "failed", &Outcome{Code: "auth.failed", Params: map[string]any{}})
	}
	if err != nil {
		return nil, err
	}
	p, err := directory.GetPrincipal(ctx, tx, tenantID, principalID)
	if err != nil {
		return nil, err
	}
	if until, err := s.lockedUntil(ctx, tx, tenantID, p.ID); err != nil {
		return nil, err
	} else if until.After(time.Now()) {
		mins := int(time.Until(until).Minutes()) + 1
		return s.finish(ctx, tx, tenantID, cer, method, p.ID, "failed", &Outcome{Principal: p, Code: "auth.locked", Params: map[string]any{"minutes": mins}})
	}
	res, err := m.Authenticate(ctx, bindingID, sealedRow{s, tx, tenantID, bindingID}, in, nil)
	if err != nil {
		return nil, err
	}
	if res.Continue != nil {
		// Not a failure: the presenter must supply more (e.g. the PIN).
		return s.finish(ctx, tx, tenantID, cer, method, p.ID, "pending", &Outcome{Principal: p, Code: CodeContinue, Params: res.Continue})
	}
	if res.Failed || res.Assertion == nil {
		if err := s.recordFailure(ctx, tx, tenantID, p.ID, pol); err != nil {
			return nil, err
		}
		return s.finish(ctx, tx, tenantID, cer, method, p.ID, "failed", &Outcome{Principal: p, Code: "auth.failed", Params: map[string]any{}})
	}
	if err := s.clearFailures(ctx, tx, tenantID, p.ID); err != nil {
		return nil, err
	}
	if err := s.touchBinding(ctx, tx, tenantID, bindingID, res.Assertion); err != nil {
		return nil, err
	}
	return s.finish(ctx, tx, tenantID, cer, method, p.ID, "completed", &Outcome{Principal: p, Assertion: res.Assertion})
}

// burn performs a dummy verification so a missing principal or binding costs
// the same as a wrong secret.
func (s *Service) burn(ctx context.Context, m Method, in StepInput) {
	if m.Describe().Method != "password" {
		// Non-password methods do constant-cost lookups; nothing to burn.
		return
	}
	_, _ = m.Authenticate(ctx, "", constMaterial(dummyMaterial(s.Provider)), in, nil)
}

var dummy []byte

func dummyMaterial(p crypto.Provider) []byte {
	if dummy == nil {
		dummy, _ = p.PasswordHash([]byte("rostor-dummy-material"))
	}
	return dummy
}

type constMaterial []byte

func (c constMaterial) Read(context.Context) ([]byte, error) { return []byte(c), nil }

func (s *Service) finish(ctx context.Context, tx pgx.Tx, tenantID, cer, method, principalID, state string, o *Outcome) (*Outcome, error) {
	data, _ := json.Marshal(map[string]any{"code": o.Code})
	_, err := tx.Exec(ctx, `INSERT INTO ceremonies (tenant_id, id, method, mode, principal_id, state, data, expires_at, completed_at)
		VALUES ($1,$2,$3,'inline',NULLIF($4,''),$5,$6,now() + interval '5 minutes', now())`, tenantID, cer, method, principalID, state, data)
	return o, err
}

// ---- Sessions ---------------------------------------------------------------

type Session struct {
	ID          string    `json:"id"`
	PrincipalID string    `json:"principal_id"`
	Token       string    `json:"token,omitempty"` // only on creation
	Assurance   string    `json:"assurance"`
	Properties  []string  `json:"properties"`
	DeviceID    string    `json:"device_id,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// MintSession is Immediate-class (§13). TTL comes from effective session
// policy; the caller passes it so this package stays policy-agnostic.
func (s *Service) MintSession(ctx context.Context, tx pgx.Tx, tenantID string, a *Assertion, principalID, deviceID string, ttl time.Duration) (*Session, error) {
	tok := ids.Token(32)
	h := sha256.Sum256([]byte(tok))
	ses := &Session{ID: ids.New("ses"), PrincipalID: principalID, Token: tok, Assurance: a.Assurance, Properties: a.Properties,
		DeviceID: deviceID, ExpiresAt: time.Now().UTC().Add(ttl)}
	_, err := tx.Exec(ctx, `INSERT INTO sessions (tenant_id, id, principal_id, token_hash, assurance, properties, device_id, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,NULLIF($7,''),$8)`, tenantID, ses.ID, principalID, h[:], ses.Assurance, ses.Properties, deviceID, ses.ExpiresAt)
	return ses, err
}

// ---- API tokens (service accounts) ------------------------------------------

func (s *Service) MintAPIToken(ctx context.Context, tx pgx.Tx, tenantID string, actor directory.Actor, principalID, label string, ttl time.Duration) (string, error) {
	tok := "rst_" + ids.Token(32)
	h := sha256.Sum256([]byte(tok))
	var exp *time.Time
	if ttl > 0 {
		t := time.Now().UTC().Add(ttl)
		exp = &t
	}
	id := ids.New("tok")
	if _, err := tx.Exec(ctx, `INSERT INTO api_tokens (tenant_id, id, principal_id, token_hash, label, expires_at) VALUES ($1,$2,$3,$4,NULLIF($5,''),$6)`,
		tenantID, id, principalID, h[:], label, exp); err != nil {
		return "", err
	}
	// §7.5: a long-lived static secret is an explicit, audited exception.
	_, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "api_token.create",
		TargetType: "principal", TargetID: principalID, Outcome: "ok",
		Detail: map[string]any{"token_id": id, "label": label, "long_lived": ttl == 0, "exception": "static-secret"}, CorrelationID: actor.CorrelationID})
	return tok, err
}

// ResolveAPIToken returns the principal for a bearer token, or nil.
func ResolveAPIToken(ctx context.Context, q directory.Querier, token string) (tenantID, principalID string, err error) {
	h := sha256.Sum256([]byte(token))
	err = q.QueryRow(ctx, `SELECT tenant_id, principal_id FROM api_tokens WHERE token_hash=$1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`, h[:]).
		Scan(&tenantID, &principalID)
	if err == pgx.ErrNoRows {
		return "", "", nil
	}
	return
}

// ---- Two-step ceremonies (WebAuthn) ------------------------------------------

// StartCeremony persists opaque method state under a new ceremony ID. The
// principal is empty for discoverable (identifier-less) logins.
func (s *Service) StartCeremony(ctx context.Context, tx pgx.Tx, tenantID, method, principalID string, state []byte, ttl time.Duration) (string, error) {
	id := ids.New("cer")
	sealed, err := s.Provider.Seal(state, []byte(tenantID+"/"+id))
	if err != nil {
		return "", err
	}
	data, _ := json.Marshal(map[string]any{"state": sealed})
	_, err = tx.Exec(ctx, `INSERT INTO ceremonies (tenant_id, id, method, mode, principal_id, state, data, expires_at)
		VALUES ($1,$2,$3,'inline',NULLIF($4,''),'pending',$5,now() + $6::interval)`, tenantID, id, method, principalID, data, ttl.String())
	return id, err
}

// TakeCeremony returns and consumes a pending ceremony's state. A ceremony
// can be finished exactly once and only before it expires.
func (s *Service) TakeCeremony(ctx context.Context, tx pgx.Tx, tenantID, method, id string) (principalID string, state []byte, err error) {
	var data []byte
	var pid *string
	err = tx.QueryRow(ctx, `UPDATE ceremonies SET state='completed', completed_at=now()
		WHERE tenant_id=$1 AND id=$2 AND method=$3 AND state='pending' AND expires_at > now()
		RETURNING principal_id, data`, tenantID, id, method).Scan(&pid, &data)
	if err == pgx.ErrNoRows {
		return "", nil, directory.Err("auth.failed")
	}
	if err != nil {
		return "", nil, err
	}
	var d struct {
		State []byte `json:"state"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return "", nil, err
	}
	state, err = s.Provider.Open(d.State, []byte(tenantID+"/"+id))
	if pid != nil {
		principalID = *pid
	}
	return principalID, state, err
}

// EnrollPrepared stores material and identifiers a two-step ceremony
// produced (FinishRegistration), like Enroll but without calling the method.
func (s *Service) EnrollPrepared(ctx context.Context, tx pgx.Tx, tenantID string, actor directory.Actor, principalID, method, label string, material []byte, idents []Identifier) (*Binding, error) {
	m, ok := s.methods[method]
	if !ok {
		return nil, directory.Err("auth.method_unavailable", "method", method)
	}
	b := &Binding{ID: ids.New("bnd"), PrincipalID: principalID, Method: method, Properties: m.Describe().Properties, Label: label, State: "active"}
	sealed, err := s.Provider.Seal(material, []byte(tenantID+"/"+b.ID))
	if err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `INSERT INTO authenticator_bindings (tenant_id, id, principal_id, method, properties, label)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,'')) RETURNING created_at`, tenantID, b.ID, principalID, method, b.Properties, label).Scan(&b.CreatedAt); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO credential_material (tenant_id, binding_id, sealed) VALUES ($1,$2,$3)`, tenantID, b.ID, sealed); err != nil {
		return nil, err
	}
	for _, id := range idents {
		if _, err := tx.Exec(ctx, `INSERT INTO credential_identifiers (tenant_id, binding_id, kind, value) VALUES ($1,$2,$3,$4)`, tenantID, b.ID, id.Kind, id.Value); err != nil {
			if strings.Contains(err.Error(), "23505") {
				return nil, directory.Err("request.conflict", "field", "credential", "kind", id.Kind)
			}
			return nil, err
		}
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "binding.enroll",
		TargetType: "principal", TargetID: principalID, Outcome: "ok",
		Detail: map[string]any{"binding_id": b.ID, "method": method, "properties": b.Properties}, CorrelationID: actor.CorrelationID})
	return b, err
}

// MaterialsFor returns the opened material of every active binding of a
// method for a principal (for passkey exclusion lists / allow lists).
func (s *Service) MaterialsFor(ctx context.Context, q directory.Querier, tenantID, principalID, method string) ([][]byte, error) {
	rows, err := q.Query(ctx, `SELECT b.id, c.sealed FROM authenticator_bindings b JOIN credential_material c ON c.tenant_id=b.tenant_id AND c.binding_id=b.id
		WHERE b.tenant_id=$1 AND b.principal_id=$2 AND b.method=$3 AND b.state='active'`, tenantID, principalID, method)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var id string
		var sealed []byte
		if err := rows.Scan(&id, &sealed); err != nil {
			return nil, err
		}
		raw, err := s.Provider.Open(sealed, []byte(tenantID+"/"+id))
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}

// SetBadgePIN re-seals a badge binding's material with a new PIN. The
// binding must belong to principalID.
func (s *Service) SetBadgePIN(ctx context.Context, tx pgx.Tx, tenantID string, actor directory.Actor, principalID, bindingID, pin string) error {
	m, ok := s.methods["badge"].(*BadgeMethod)
	if !ok {
		return directory.Err("auth.method_unavailable", "method", "badge")
	}
	var owner, method string
	var sealed []byte
	err := tx.QueryRow(ctx, `SELECT b.principal_id, b.method, c.sealed FROM authenticator_bindings b JOIN credential_material c ON c.tenant_id=b.tenant_id AND c.binding_id=b.id
		WHERE b.tenant_id=$1 AND b.id=$2 AND b.state='active'`, tenantID, bindingID).Scan(&owner, &method, &sealed)
	if err == pgx.ErrNoRows || owner != principalID || method != "badge" {
		return directory.Err("request.not_found", "type", "binding")
	}
	if err != nil {
		return err
	}
	raw, err := s.Provider.Open(sealed, []byte(tenantID+"/"+bindingID))
	if err != nil {
		return err
	}
	updated, err := m.SetPIN(raw, pin)
	if err != nil {
		return directory.Err("request.malformed", "field", "pin", "detail", err.Error())
	}
	resealed, err := s.Provider.Seal(updated, []byte(tenantID+"/"+bindingID))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE credential_material SET sealed=$3 WHERE tenant_id=$1 AND binding_id=$2`, tenantID, bindingID, resealed); err != nil {
		return err
	}
	// The binding's declared properties say what it proves (D26): with a
	// PIN it is possession + knowledge.
	props := []string{"possession", "can-identify-user"}
	if strings.TrimSpace(pin) != "" {
		props = append(props, "knowledge")
	}
	if _, err := tx.Exec(ctx, `UPDATE authenticator_bindings SET properties=$3 WHERE tenant_id=$1 AND id=$2`, tenantID, bindingID, props); err != nil {
		return err
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: "binding.pin_set",
		TargetType: "principal", TargetID: principalID, Outcome: "ok", Detail: map[string]any{"binding_id": bindingID, "has_pin": pin != ""}, CorrelationID: actor.CorrelationID})
	return err
}
