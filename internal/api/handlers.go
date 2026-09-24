package api

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/update"
)

// ---- Devices ----------------------------------------------------------------

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EnrollmentToken string         `json:"enrollment_token"`
		CSRPEM          string         `json:"csr_pem"`
		Posture         map[string]any `json:"posture"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var out *devices.Enrolled
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		out, err = s.Devices.Enroll(r.Context(), tx, s.CA, s.TenantID, devices.EnrollRequest{Token: req.EnrollmentToken, CSRPEM: []byte(req.CSRPEM), Posture: req.Posture})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, map[string]any{
		"device_id": out.DeviceID, "certificate_pem": string(out.CertPEM), "ca_pem": string(out.CAPEM),
		"resource": map[string]string{"type": out.ResourceType, "id": out.ResourceID},
	})
}

func (s *Server) handlePosture(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	var posture map[string]any
	if err := decode(r, &posture); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := devices.UpdatePosture(r.Context(), s.DB, s.TenantID, d.Principal.ID, posture); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// ---- Verify (spec §6.2): credential presentation → principal + decision ----

type verifyRequest struct {
	Credential struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
		Secret     string `json:"secret"`
		// badge presentations: any of these forms, plus an optional pin
		UID      string `json:"uid"`
		Number   string `json:"number"`
		Facility string `json:"facility"`
		Card     string `json:"card"`
		PIN      string `json:"pin"`
	} `json:"credential"`
	Action   string `json:"action"`
	Resource struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Locale string `json:"locale"`
}

type verifyResponse struct {
	Decision  string         `json:"decision"`
	Principal map[string]any `json:"principal,omitempty"`
	Assurance string         `json:"assurance,omitempty"`
	Reason    []authz.Reason `json:"reason"`
	Session   map[string]any `json:"session,omitempty"`
	Message   string         `json:"message,omitempty"`
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	dev := r.Context().Value(ctxDevice).(*devices.Device)
	var req verifyRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Locale == "" {
		req.Locale = locale(r)
	}
	corr := corrOf(r)
	deny := func(code string, params map[string]any, principalID string) {
		if params == nil {
			params = map[string]any{}
		}
		s.auditEvent(r.Context(), audit.Event{ActorKind: "device", ActorID: dev.Principal.ID, Action: "verify",
			TargetType: req.Resource.Type, TargetID: req.Resource.ID, CredentialType: req.Credential.Type, Outcome: "deny",
			Detail:        map[string]any{"action": req.Action, "identifier": req.Credential.Identifier, "principal_id": principalID, "reason": code},
			CorrelationID: corr})
		s.writeJSON(w, 200, verifyResponse{Decision: "DENY", Reason: []authz.Reason{{Code: code, Params: params}},
			Message: s.Catalog.Render(req.Locale, code, params)})
	}

	if dev.Lifecycle != "trusted" && dev.Lifecycle != "enrolled" {
		deny("device.not_trusted", nil, "")
		return
	}
	// A device may only verify against resources it is bound to: the
	// workstation named in its own enrollment. Anything else is a
	// misconfigured or hostile client.
	if rt, _ := dev.Principal.Attributes["resource_type"].(string); rt != req.Resource.Type ||
		dev.Principal.Attributes["hostname"] != req.Resource.ID {
		deny("request.forbidden", map[string]any{"reason": "resource_not_bound_to_device"}, "")
		return
	}
	if req.Credential.Type == "" || req.Action == "" || req.Resource.Type == "" || req.Resource.ID == "" {
		s.fail(w, r, directory.Err("request.malformed", "field", "verify"))
		return
	}

	var out *auth.Outcome
	var decision *authz.Decision
	var session *auth.Session
	err := s.tx(r, func(tx pgx.Tx) error {
		// Lockout parameters are tenant defaults in this slice. Reading them
		// from the auth policy domain needs the principal, which is only known
		// after resolution; that plumbing lands with the policy engine (M3).
		var err error
		switch req.Credential.Type {
		case "badge":
			out, err = s.Auth.AuthenticateByCredential(r.Context(), tx, s.TenantID, "badge", auth.StepInput{Fields: map[string]string{
				"uid": req.Credential.UID, "number": req.Credential.Number, "facility": req.Credential.Facility, "card": req.Credential.Card,
				"pin": req.Credential.PIN}}, auth.DefaultLockout)
		default:
			out, err = s.Auth.AuthenticateInline(r.Context(), tx, s.TenantID, req.Credential.Type, req.Credential.Identifier,
				auth.StepInput{Fields: map[string]string{"password": req.Credential.Secret}}, auth.DefaultLockout)
		}
		if err != nil || out.Assertion == nil {
			return err
		}
		decision, err = s.Authz.Check(r.Context(), tx, s.TenantID, out.Principal, req.Action, req.Resource.Type, req.Resource.ID,
			authz.Presented{Assurance: out.Assertion.Assurance, Properties: out.Assertion.Properties})
		if err != nil || !decision.Allow {
			return err
		}
		ttl := 8 * time.Hour
		if sp, _, err := directory.EffectivePolicy(r.Context(), tx, s.TenantID, "session", out.Principal.ID); err == nil {
			if v, ok := sp["ttl_seconds"].(float64); ok {
				ttl = time.Duration(v) * time.Second
			}
		}
		session, err = s.Auth.MintSession(r.Context(), tx, s.TenantID, out.Assertion, out.Principal.ID, dev.Principal.ID, ttl)
		if err != nil {
			return err
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: "device", ActorID: dev.Principal.ID, Action: "verify",
			TargetType: req.Resource.Type, TargetID: req.Resource.ID, CredentialType: req.Credential.Type, Assurance: out.Assertion.Assurance,
			Outcome: "allow", Detail: map[string]any{"action": req.Action, "principal_id": out.Principal.ID, "grant_id": decision.GrantID,
				"binding_id": out.Assertion.BindingID, "session_id": session.ID}, CorrelationID: corr})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out.Assertion == nil {
		pid := ""
		if out.Principal != nil {
			pid = out.Principal.ID
		}
		if out.Code == auth.CodeContinue {
			// Card matched; the presenter must add a PIN. Not audited as a
			// deny: nothing has been decided yet.
			s.writeJSON(w, 200, verifyResponse{Decision: "CONTINUE", Reason: []authz.Reason{{Code: out.Code, Params: out.Params}},
				Message: s.Catalog.Render(req.Locale, out.Code, out.Params)})
			return
		}
		deny(out.Code, out.Params, pid)
		return
	}
	if !decision.Allow {
		deny(decision.Reasons[0].Code, decision.Reasons[0].Params, out.Principal.ID)
		return
	}
	p := out.Principal
	s.writeJSON(w, 200, verifyResponse{
		Decision:  "ALLOW",
		Principal: map[string]any{"id": p.ID, "username": p.Username, "display_name": displayName(p, req.Locale)},
		Assurance: out.Assertion.Assurance,
		Reason:    decision.Reasons,
		Session:   map[string]any{"token": session.Token, "expires_at": session.ExpiresAt},
	})
}

func displayName(p *directory.Principal, locale string) string {
	if v, ok := p.DisplayName[locale]; ok {
		return v
	}
	if v, ok := p.DisplayName["en"]; ok {
		return v
	}
	return p.Username
}

// ---- Admin ------------------------------------------------------------------

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string            `json:"username"`
		DisplayName map[string]string `json:"display_name"`
		State       string            `json:"state"`
		Attributes  map[string]any    `json:"attributes"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var p *directory.Principal
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		p, err = directory.CreatePrincipal(r.Context(), tx, s.TenantID, actorOf(r), directory.Principal{Kind: "user",
			Username: req.Username, DisplayName: req.DisplayName, State: req.State, Attributes: req.Attributes})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, p)
}

func (s *Server) handleUserState(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	id := r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		p, err := s.resolveUser(r, tx, id)
		if err != nil {
			return err
		}
		id = p.ID
		return directory.SetPrincipalState(r.Context(), tx, s.TenantID, actorOf(r), p.ID, req.State)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]string{"id": id, "state": req.State})
}

// resolveUser accepts either a principal ID or a username in the path.
func (s *Server) resolveUser(r *http.Request, q directory.Querier, idOrName string) (*directory.Principal, error) {
	p, err := directory.GetPrincipal(r.Context(), q, s.TenantID, idOrName)
	if code, _ := directory.CodeOf(err); code == "principal.not_found" {
		return directory.GetPrincipalByUsername(r.Context(), q, s.TenantID, idOrName)
	}
	return p, err
}

func (s *Server) handleEnrollBinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Method string            `json:"method"`
		Label  string            `json:"label"`
		Fields map[string]string `json:"fields"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var b *auth.Binding
	err := s.tx(r, func(tx pgx.Tx) error {
		p, err := s.resolveUser(r, tx, r.PathValue("id"))
		if err != nil {
			return err
		}
		b, err = s.Auth.Enroll(r.Context(), tx, s.TenantID, actorOf(r), p.ID, req.Method, req.Label, auth.StepInput{Fields: req.Fields})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, b)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string            `json:"name"`
		DisplayName map[string]string `json:"display_name"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var g *directory.Group
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		g, err = directory.CreateGroup(r.Context(), tx, s.TenantID, actorOf(r), req.Name, req.DisplayName)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, g)
}

func (s *Server) memberChange(w http.ResponseWriter, r *http.Request, remove bool) {
	var req struct {
		MemberKind string `json:"member_kind"` // principal | group
		Member     string `json:"member"`      // principal id, username, or group name
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	err := s.tx(r, func(tx pgx.Tx) error {
		g, err := directory.GetGroupByName(r.Context(), tx, s.TenantID, r.PathValue("name"))
		if err != nil {
			return err
		}
		memberID := req.Member
		switch req.MemberKind {
		case "principal":
			p, err := s.resolveUser(r, tx, req.Member)
			if err != nil {
				return err
			}
			memberID = p.ID
		case "group":
			mg, err := directory.GetGroupByName(r.Context(), tx, s.TenantID, req.Member)
			if err != nil {
				return err
			}
			memberID = mg.ID
		default:
			return directory.Err("request.malformed", "field", "member_kind")
		}
		if remove {
			return directory.RemoveGroupMember(r.Context(), tx, s.TenantID, actorOf(r), g.ID, req.MemberKind, memberID)
		}
		return directory.AddGroupMember(r.Context(), tx, s.TenantID, actorOf(r), g.ID, req.MemberKind, memberID)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request) { s.memberChange(w, r, false) }
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	s.memberChange(w, r, true)
}

func (s *Server) handleCreateResource(w http.ResponseWriter, r *http.Request) {
	var res directory.Resource
	if err := decode(r, &res); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.tx(r, func(tx pgx.Tx) error { return directory.CreateResource(r.Context(), tx, s.TenantID, actorOf(r), res) }); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, res)
}

func (s *Server) handleUpsertRole(w http.ResponseWriter, r *http.Request) {
	var role directory.Role
	if err := decode(r, &role); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.tx(r, func(tx pgx.Tx) error { return directory.UpsertRole(r.Context(), tx, s.TenantID, actorOf(r), role) }); err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, role)
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SubjectKind  string     `json:"subject_kind"`
		Subject      string     `json:"subject"` // principal id/username or group name
		Role         string     `json:"role"`
		ResourceType string     `json:"resource_type"`
		ResourceID   string     `json:"resource_id"`
		Condition    string     `json:"condition"`
		NotBefore    *time.Time `json:"not_before"`
		ExpiresAt    *time.Time `json:"expires_at"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var g *directory.Grant
	err := s.tx(r, func(tx pgx.Tx) error {
		subjectID := req.Subject
		switch req.SubjectKind {
		case "principal":
			p, err := s.resolveUser(r, tx, req.Subject)
			if err != nil {
				return err
			}
			subjectID = p.ID
		case "group":
			mg, err := directory.GetGroupByName(r.Context(), tx, s.TenantID, req.Subject)
			if err != nil {
				return err
			}
			subjectID = mg.ID
		}
		var err error
		g, err = directory.CreateGrant(r.Context(), tx, s.TenantID, actorOf(r), directory.Grant{SubjectKind: req.SubjectKind, SubjectID: subjectID,
			Role: req.Role, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Condition: req.Condition,
			NotBefore: req.NotBefore, ExpiresAt: req.ExpiresAt}, s.Authz)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, g)
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request) {
	if err := s.tx(r, func(tx pgx.Tx) error {
		return directory.RevokeGrant(r.Context(), tx, s.TenantID, actorOf(r), r.PathValue("id"))
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ResourceType string `json:"resource_type"`
		TTLSeconds   int    `json:"ttl_seconds"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ResourceType == "" {
		req.ResourceType = "workstation"
	}
	if req.TTLSeconds <= 0 {
		req.TTLSeconds = 3600
	}
	var tok string
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		tok, err = s.Devices.MintEnrollmentToken(r.Context(), tx, s.TenantID, actorOf(r), req.ResourceType, time.Duration(req.TTLSeconds)*time.Second)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, map[string]any{"enrollment_token": tok, "expires_in": req.TTLSeconds})
}

func (s *Server) handleWhy(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p, err := s.resolveUser(r, s.DB, q.Get("principal"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	assurance := q.Get("assurance")
	if assurance == "" {
		assurance = "AL1"
	}
	ex, err := s.Authz.Why(r.Context(), s.DB, s.TenantID, p, q.Get("action"), q.Get("resource_type"), q.Get("resource_id"), authz.Presented{Assurance: assurance})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// §14: reads of sensitive data are logged too.
	s.auditEvent(r.Context(), audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "why", TargetType: "principal", TargetID: p.ID,
		Outcome: "ok", Detail: map[string]any{"action": q.Get("action"), "resource": q.Get("resource_type") + ":" + q.Get("resource_id")}, CorrelationID: corrOf(r)})
	s.writeJSON(w, 200, ex)
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	bad, err := audit.VerifyChain(r.Context(), s.DB, s.TenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"intact": bad == 0, "first_bad_seq": bad})
}

// ---- Updates (Staged class, §13): the core reports and requests; the
// privileged updater (systemd) does the work. -----------------------------

func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	st := update.LoadState(s.StateDir)
	if st.Current == "" {
		st.Current = s.Version
	}
	s.writeJSON(w, 200, st)
}

func (s *Server) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	st := update.LoadState(s.StateDir)
	if st.Available == "" {
		s.writeErr(w, r, 409, "request.conflict", map[string]any{"reason": "no_update_available"})
		return
	}
	if err := update.RequestApply(s.StateDir); err != nil {
		s.fail(w, r, err)
		return
	}
	a := actorOf(r)
	s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "update.apply_requested",
		TargetType: "release", TargetID: st.Available, Outcome: "ok",
		Detail: map[string]any{"from": s.Version, "to": st.Available, "channel": st.Channel}, CorrelationID: corrOf(r)})
	st.Requested = true
	s.writeJSON(w, 202, st)
}
