package api

// Passkey (WebAuthn) ceremonies and the relying-party setting. Registration
// is self-service for the signed-in person; sign-in is discoverable
// (identifier-less) by default with an identifier-first fallback.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
)

const ceremonyTTL = 3 * time.Minute

// RelyingParty reads the tenant's passkey settings from the auth policy
// domain (tenant-wide policy "auth"): webauthn.rp_id, webauthn.display_name,
// webauthn.origins. Nothing is hardcoded; an unset domain disables passkeys
// with a clear error.
func (s *Server) RelyingParty(ctx context.Context) (auth.RelyingParty, error) {
	pol, _, err := directory.EffectivePolicy(ctx, s.DB, s.TenantID, "auth", "")
	if err != nil {
		return auth.RelyingParty{}, err
	}
	rp := auth.RelyingParty{}
	rp.ID, _ = pol["webauthn.rp_id"].(string)
	rp.DisplayName, _ = pol["webauthn.display_name"].(string)
	if rp.DisplayName == "" {
		_ = s.DB.QueryRow(ctx, `SELECT name FROM tenants WHERE id=$1`, s.TenantID).Scan(&rp.DisplayName)
	}
	if o, ok := pol["webauthn.origins"].([]any); ok {
		for _, v := range o {
			if str, ok := v.(string); ok {
				rp.Origins = append(rp.Origins, str)
			}
		}
	}
	return rp, nil
}

func (s *Server) webauthn() (*auth.WebAuthnMethod, bool) {
	m, ok := s.Auth.Method("webauthn")
	if !ok {
		return nil, false
	}
	w, ok := m.(*auth.WebAuthnMethod)
	return w, ok
}

func (s *Server) storedPasskeys(ctx context.Context, principalID string) ([]webauthn.Credential, error) {
	mats, err := s.Auth.MaterialsFor(ctx, s.DB, s.TenantID, principalID, "webauthn")
	if err != nil {
		return nil, err
	}
	var out []webauthn.Credential
	for _, raw := range mats {
		if c, err := auth.StoredCredential(raw); err == nil {
			out = append(out, *c)
		}
	}
	return out, nil
}

// ---- settings ---------------------------------------------------------------

func (s *Server) handleGetAuthSettings(w http.ResponseWriter, r *http.Request) {
	rp, err := s.RelyingParty(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var enrolled int
	_ = s.DB.QueryRow(r.Context(), `SELECT count(*) FROM authenticator_bindings WHERE tenant_id=$1 AND method='webauthn' AND state='active'`, s.TenantID).Scan(&enrolled)
	s.writeJSON(w, 200, map[string]any{"webauthn": map[string]any{"rp_id": rp.ID, "display_name": rp.DisplayName, "origins": rp.Origins, "enrolled_passkeys": enrolled}})
}

// handlePutAuthSettings writes the tenant-wide auth policy (priority 0). It
// is the one settings-shaped write in the API and it is still a policy:
// group-scoped auth policies at higher priority override it per §4.
func (s *Server) handlePutAuthSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WebAuthn struct {
			RPID        string   `json:"rp_id"`
			DisplayName string   `json:"display_name"`
			Origins     []string `json:"origins"`
		} `json:"webauthn"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	rpID := strings.ToLower(strings.TrimSpace(req.WebAuthn.RPID))
	if rpID != "" && (strings.Contains(rpID, "/") || strings.Contains(rpID, ":")) {
		s.fail(w, r, directory.Err("request.malformed", "field", "webauthn.rp_id"))
		return
	}
	for _, o := range req.WebAuthn.Origins {
		if !strings.HasPrefix(o, "https://") {
			s.fail(w, r, directory.Err("request.malformed", "field", "webauthn.origins"))
			return
		}
	}
	doc := map[string]any{"webauthn.rp_id": rpID, "webauthn.display_name": req.WebAuthn.DisplayName, "webauthn.origins": req.WebAuthn.Origins}
	err := s.tx(r, func(tx pgx.Tx) error {
		// Replace the tenant-wide auth policy in place so there is exactly one.
		raw, _ := json.Marshal(doc)
		tag, err := tx.Exec(r.Context(), `UPDATE policies p SET document=$3 FROM policy_assignments a
			WHERE p.tenant_id=$1 AND p.id=a.policy_id AND a.tenant_id=p.tenant_id AND a.group_id IS NULL AND p.domain='auth' AND p.priority=0 AND p.name=$2`,
			s.TenantID, "tenant-auth", raw)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			if _, err := directory.CreatePolicy(r.Context(), tx, s.TenantID, actorOf(r), "tenant-auth", "auth", 0, doc, ""); err != nil {
				return err
			}
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "policy.update",
			TargetType: "policy", TargetID: "tenant-auth", Outcome: "ok", Detail: doc, CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.handleGetAuthSettings(w, r)
}

// ---- registration (signed-in person, own passkeys) ------------------------

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	p, _, err := s.sessionPrincipal(r.Context(), r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p == nil {
		s.writeErr(w, r, 401, "request.unauthorized", nil)
		return
	}
	wm, ok := s.webauthn()
	if !ok {
		s.writeErr(w, r, 400, "auth.method_unavailable", map[string]any{"method": "webauthn"})
		return
	}
	existing, err := s.storedPasskeys(r.Context(), p.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	opts, state, err := wm.BeginRegistration(r.Context(), p.ID, p.Username, displayName(p, locale(r)), existing)
	if err != nil {
		s.writeErr(w, r, 400, "auth.passkeys_unconfigured", map[string]any{"detail": err.Error()})
		return
	}
	var cer string
	if err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		cer, err = s.Auth.StartCeremony(r.Context(), tx, s.TenantID, "webauthn", p.ID, state, ceremonyTTL)
		return err
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"ceremony_id": cer, "options": opts})
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	p, _, err := s.sessionPrincipal(r.Context(), r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p == nil {
		s.writeErr(w, r, 401, "request.unauthorized", nil)
		return
	}
	if !isConsoleMutation(r) {
		s.writeErr(w, r, 403, "request.forbidden", map[string]any{"reason": "csrf"})
		return
	}
	var req struct {
		CeremonyID string          `json:"ceremony_id"`
		Label      string          `json:"label"`
		Response   json.RawMessage `json:"response"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	wm, _ := s.webauthn()
	var b *auth.Binding
	err = s.tx(r, func(tx pgx.Tx) error {
		pid, state, err := s.Auth.TakeCeremony(r.Context(), tx, s.TenantID, "webauthn", req.CeremonyID)
		if err != nil {
			return err
		}
		if pid != p.ID {
			return directory.Err("auth.failed")
		}
		mat, idents, err := wm.FinishRegistration(r.Context(), p.ID, p.Username, displayName(p, locale(r)), state, req.Response)
		if err != nil {
			return directory.Err("auth.passkey_rejected", "detail", err.Error())
		}
		actor := directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)}
		b, err = s.Auth.EnrollPrepared(r.Context(), tx, s.TenantID, actor, p.ID, "webauthn", req.Label, mat, idents)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, b)
}

// ---- sign-in ----------------------------------------------------------------

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string `json:"identifier"`
	}
	if r.ContentLength > 0 {
		if err := decode(r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	wm, ok := s.webauthn()
	if !ok {
		s.writeErr(w, r, 400, "auth.method_unavailable", map[string]any{"method": "webauthn"})
		return
	}
	var allowed []webauthn.Credential
	principalID := ""
	if req.Identifier != "" {
		// Identifier-first: only that person's passkeys are allowed. An
		// unknown identifier still gets a challenge, so existence isn't leaked.
		if p, err := directory.GetPrincipalByUsername(r.Context(), s.DB, s.TenantID, req.Identifier); err == nil {
			principalID = p.ID
			allowed, _ = s.storedPasskeys(r.Context(), p.ID)
		}
	}
	opts, state, err := wm.BeginLogin(r.Context(), allowed)
	if err != nil {
		s.writeErr(w, r, 400, "auth.passkeys_unconfigured", map[string]any{"detail": err.Error()})
		return
	}
	var cer string
	if err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		cer, err = s.Auth.StartCeremony(r.Context(), tx, s.TenantID, "webauthn", principalID, state, ceremonyTTL)
		return err
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"ceremony_id": cer, "options": opts})
}

func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CeremonyID string          `json:"ceremony_id"`
		Response   json.RawMessage `json:"response"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	corr := corrOf(r)
	var out *auth.Outcome
	var ses *auth.Session
	err := s.tx(r, func(tx pgx.Tx) error {
		pid, state, err := s.Auth.TakeCeremony(r.Context(), tx, s.TenantID, "webauthn", req.CeremonyID)
		if err != nil {
			out = &auth.Outcome{Code: "auth.failed", Params: map[string]any{}}
			return nil
		}
		in := auth.StepInput{Fields: map[string]string{"state": string(state), "response": string(req.Response)}}
		// The user handle in the assertion names the principal; the core
		// resolves the binding by credential ID and checks they agree.
		out, err = s.Auth.AuthenticateByCredential(r.Context(), tx, s.TenantID, "webauthn", withUserHandle(in, pid), auth.DefaultLockout)
		if err != nil || out.Assertion == nil || out.Principal.State != "active" {
			return err
		}
		ses, err = s.Auth.MintSession(r.Context(), tx, s.TenantID, out.Assertion, out.Principal.ID, "", 12*time.Hour)
		if err != nil {
			return err
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: out.Principal.Kind, ActorID: out.Principal.ID, Action: "session.create",
			TargetType: "principal", TargetID: out.Principal.ID, CredentialType: "webauthn", Assurance: out.Assertion.Assurance, Outcome: "allow",
			Detail: map[string]any{"session_id": ses.ID, "client": "console"}, CorrelationID: corr})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out.Assertion == nil || ses == nil {
		code := out.Code
		if out.Assertion != nil { // authenticated but not active
			code = "principal.not_active"
			if out.Principal.State == "suspended" {
				code = "principal.suspended"
			}
		}
		pid := ""
		if out.Principal != nil {
			pid = out.Principal.ID
		}
		s.auditEvent(r.Context(), audit.Event{ActorKind: "system", ActorID: "console", Action: "session.create", TargetType: "principal", TargetID: pid,
			CredentialType: "webauthn", Outcome: "deny", Detail: map[string]any{"reason": code}, CorrelationID: corr})
		s.writeJSON(w, 200, map[string]any{"code": code, "params": out.Params, "message": s.Catalog.Render(locale(r), code, out.Params)})
		return
	}
	s.setSessionCookie(w, r, ses.Token, ses.ExpiresAt)
	s.writeJSON(w, 200, s.sessionView(r, out.Principal, ses))
}

// withUserHandle passes the ceremony's principal (if identifier-first) so a
// discoverable assertion for someone else cannot complete another's ceremony.
func withUserHandle(in auth.StepInput, pid string) auth.StepInput {
	if pid != "" {
		in.Fields["expect_principal"] = pid
	}
	return in
}

var _ = ids.New
