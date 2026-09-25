package api

// SPEC-agents: agents are principals of kind `agent`, owned by a person.
// Everything below is ordinary API under the caller's identity; what makes an
// agent safe to hand a credential to is the engine's owner leg (authz), not
// anything here. The owner may manage their own agents without being an
// admin: create, name, issue or rotate the token, suspend, and hand over
// rights they hold themselves.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/directory"
)

// caller resolves the signed-in principal (bearer token or console cookie)
// with the assurance it presented, without any authorization check. Cookie
// mutations must carry the CSRF marker, as everywhere else.
func (s *Server) caller(w http.ResponseWriter, r *http.Request) (*directory.Principal, authz.Presented, bool) {
	if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" && tok != r.Header.Get("Authorization") {
		tenantID, pid, err := auth.ResolveAPIToken(r.Context(), s.DB, tok)
		if err != nil {
			s.fail(w, r, err)
			return nil, authz.Presented{}, false
		}
		if pid == "" || tenantID != s.TenantID {
			s.writeErr(w, r, 401, "request.unauthorized", nil)
			return nil, authz.Presented{}, false
		}
		p, err := directory.GetPrincipal(r.Context(), s.DB, tenantID, pid)
		if err != nil {
			s.fail(w, r, err)
			return nil, authz.Presented{}, false
		}
		pres := authz.Presented{Assurance: "AL1", Properties: []string{"possession"}}
		s.capAgentAssurance(r.Context(), p, &pres)
		return p, pres, true
	}
	p, ses, err := s.sessionPrincipal(r.Context(), r)
	if err != nil {
		s.fail(w, r, err)
		return nil, authz.Presented{}, false
	}
	if p == nil {
		s.writeErr(w, r, 401, "request.unauthorized", nil)
		return nil, authz.Presented{}, false
	}
	if r.Method != "GET" && r.Method != "HEAD" && !isConsoleMutation(r) {
		s.writeErr(w, r, 403, "request.forbidden", map[string]any{"reason": "csrf"})
		return nil, authz.Presented{}, false
	}
	return p, authz.Presented{Assurance: ses.Assurance, Properties: ses.Properties}, true
}

// capAgentAssurance keeps an agent from counting for more than its owner
// could: the credential's own assurance, capped at the strongest the owner
// has enrolled.
func (s *Server) capAgentAssurance(ctx context.Context, p *directory.Principal, pres *authz.Presented) {
	if p.Kind != "agent" {
		return
	}
	cap := s.potentialAssurance(ctx, directory.OwnerID(p))
	if assuranceRank(cap) < assuranceRank(pres.Assurance) {
		pres.Assurance = cap
	}
}

func assuranceRank(a string) int { return map[string]int{"AL0": 0, "AL1": 1, "AL2": 2, "AL3": 3}[a] }

// potentialAssurance is the strongest assurance a principal's active
// bindings could produce (the person-detail "effective security" rule).
func (s *Server) potentialAssurance(ctx context.Context, principalID string) string {
	rows, err := s.DB.Query(ctx, `SELECT method, properties FROM authenticator_bindings WHERE tenant_id=$1 AND principal_id=$2 AND state='active'`, s.TenantID, principalID)
	if err != nil {
		return "AL0"
	}
	defer rows.Close()
	best := "AL0"
	for rows.Next() {
		var method string
		var props []string
		if err := rows.Scan(&method, &props); err != nil {
			return "AL0"
		}
		a := "AL1"
		if md, ok := s.Auth.Method(method); ok {
			a = md.Describe().Assurance
		}
		if method == "badge" {
			for _, pr := range props {
				if pr == "knowledge" {
					a = "AL2"
				}
			}
		}
		if assuranceRank(a) > assuranceRank(best) {
			best = a
		}
	}
	return best
}

// ownerOrAdmin admits an admin (the named action on directory:root) or, for
// paths naming an agent, its owner. The handler learns which through
// ctxAgentAdmin so it can scope lists and grants.
func (s *Server) ownerOrAdmin(action string, next http.HandlerFunc) http.HandlerFunc {
	s.noteAction(action)
	return func(w http.ResponseWriter, r *http.Request) {
		p, pres, ok := s.caller(w, r)
		if !ok {
			return
		}
		actor := directory.Actor{Kind: p.Kind, ID: p.ID, CorrelationID: corrOf(r)}
		ctx := context.WithValue(r.Context(), ctxActor, actor)
		ctx = context.WithValue(ctx, ctxCaller, p)
		ctx = context.WithValue(ctx, ctxPresented, pres)
		d, err := s.Authz.Check(r.Context(), s.DB, s.TenantID, p, action, "directory", "root", pres)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if d.Allow {
			next(w, r.WithContext(context.WithValue(ctx, ctxAgentAdmin, true)))
			return
		}
		if id := r.PathValue("id"); id != "" {
			agent, err := s.resolveUser(r, s.DB, id)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if agent.Kind != "agent" || directory.OwnerID(agent) != p.ID {
				s.writeErr(w, r, 403, "agent.not_owned", nil)
				return
			}
		}
		next(w, r.WithContext(context.WithValue(ctx, ctxAgentAdmin, false)))
	}
}

func isAgentAdmin(r *http.Request) bool { v, _ := r.Context().Value(ctxAgentAdmin).(bool); return v }

// mayOwnAgents is the gate for creating an agent, issuing it a token or
// handing it a right: admins always; anyone else needs agents.own on the
// directory (the built-in agent-owner role). Reading, revoking and
// suspending stay open to the owner so a person who lost the permission
// can still wind their agents down.
func (s *Server) mayOwnAgents(w http.ResponseWriter, r *http.Request) bool {
	if isAgentAdmin(r) {
		return true
	}
	pres, _ := r.Context().Value(ctxPresented).(authz.Presented)
	d, err := s.Authz.Check(r.Context(), s.DB, s.TenantID, callerOf(r), "agents.own", "directory", "root", pres)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if !d.Allow {
		s.writeErr(w, r, 403, "agent.not_allowed", map[string]any{"reason": d.Reasons[0].Code})
		return false
	}
	return true
}
func callerOf(r *http.Request) *directory.Principal {
	p, _ := r.Context().Value(ctxCaller).(*directory.Principal)
	return p
}

// loadAgent fetches the agent named by {id} (id or username), refusing other kinds.
func (s *Server) loadAgent(r *http.Request, q directory.Querier) (*directory.Principal, error) {
	p, err := s.resolveUser(r, q, r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if p.Kind != "agent" {
		return nil, directory.Err("principal.not_found")
	}
	return p, nil
}

type ownerRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Server) ownerRef(ctx context.Context, ownerID string) *ownerRef {
	if ownerID == "" {
		return nil
	}
	var name string
	_ = s.DB.QueryRow(ctx, `SELECT coalesce(nullif(display_name->>'en',''), username, '') FROM principals WHERE tenant_id=$1 AND id=$2`, s.TenantID, ownerID).Scan(&name)
	return &ownerRef{ID: ownerID, Name: name}
}

type tokenState struct {
	Active   bool       `json:"active"`
	IssuedAt *time.Time `json:"issued_at,omitempty"`
}

func (s *Server) tokenState(ctx context.Context, principalID string) tokenState {
	var at *time.Time
	err := s.DB.QueryRow(ctx, `SELECT created_at FROM api_tokens WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now()) ORDER BY created_at DESC LIMIT 1`,
		s.TenantID, principalID).Scan(&at)
	if err != nil {
		return tokenState{}
	}
	return tokenState{Active: true, IssuedAt: at}
}

func (s *Server) agentRow(ctx context.Context, p *directory.Principal, loc string) map[string]any {
	var grants int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM grants WHERE tenant_id=$1 AND subject_kind='principal' AND subject_id=$2 AND revoked_at IS NULL`, s.TenantID, p.ID).Scan(&grants)
	dn, _ := json.Marshal(p.DisplayName)
	return map[string]any{"id": p.ID, "username": p.Username, "kind": p.Kind, "display_name": displayFrom(dn, p.Username, loc),
		"state": p.State, "owner": s.ownerRef(ctx, directory.OwnerID(p)), "token": s.tokenState(ctx, p.ID), "grant_count": grants, "created_at": p.CreatedAt}
}

// POST /v1/admin/agents {username, display_name, owner}. A non-admin can only
// create agents they own; the owner defaults to the caller.
func (s *Server) handleCreateAgent(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username    string            `json:"username"`
		DisplayName map[string]string `json:"display_name"`
		Owner       string            `json:"owner"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.mayOwnAgents(w, r) {
		return
	}
	c := callerOf(r)
	ownerID := c.ID
	if req.Owner != "" && (isAgentAdmin(r) || req.Owner == c.ID || strings.EqualFold(req.Owner, c.Username)) {
		o, err := s.resolveUser(r, s.DB, req.Owner)
		if code, _ := directory.CodeOf(err); code == "principal.not_found" {
			s.writeErr(w, r, 400, "agent.owner_invalid", map[string]any{"owner": req.Owner})
			return
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		ownerID = o.ID
	} else if req.Owner != "" {
		s.writeErr(w, r, 403, "agent.not_owned", nil)
		return
	}
	var p *directory.Principal
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		p, err = directory.CreatePrincipal(r.Context(), tx, s.TenantID, actorOf(r), directory.Principal{Kind: "agent",
			Username: req.Username, DisplayName: req.DisplayName, Attributes: map[string]any{"owner_id": ownerID}})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, s.agentRow(r.Context(), p, locale(r)))
}

// GET /v1/admin/agents[?owner=] — admins see all (optionally one owner's);
// everyone else sees their own.
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	if !isAgentAdmin(r) {
		owner = callerOf(r).ID
	} else if owner != "" {
		if o, err := s.resolveUser(r, s.DB, owner); err == nil {
			owner = o.ID
		}
	}
	rows, err := s.DB.Query(r.Context(), `SELECT id FROM principals WHERE tenant_id=$1 AND kind='agent' AND ($2='' OR attributes->>'owner_id'=$2) ORDER BY lower(coalesce(username,''))`, s.TenantID, owner)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	items := []map[string]any{}
	for _, id := range ids {
		p, err := directory.GetPrincipal(r.Context(), s.DB, s.TenantID, id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, s.agentRow(r.Context(), p, locale(r)))
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

// GET /v1/admin/agents/{id}: the row plus its grants and what its owner could hand it.
func (s *Server) handleGetAgent(w http.ResponseWriter, r *http.Request) {
	p, err := s.loadAgent(r, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := s.agentRow(r.Context(), p, locale(r))
	grants, err := s.grantRows(r, "g.subject_kind='principal' AND g.subject_id=$2", p.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out["grants"] = grants
	held, err := s.heldRights(r.Context(), directory.OwnerID(p))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out["grantable"] = held
	s.writeJSON(w, 200, out)
}

type heldRight struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Role         string `json:"role"`
	Via          string `json:"via"`
}

// heldRights lists the (resource, role) pairs a person holds through direct
// or group grants: exactly what they may hand to an agent they own.
func (s *Server) heldRights(ctx context.Context, principalID string) ([]heldRight, error) {
	paths, err := directory.GroupPaths(ctx, s.DB, s.TenantID, principalID)
	if err != nil {
		return nil, err
	}
	subjects := []string{principalID}
	for g := range paths {
		subjects = append(subjects, g)
	}
	rows, err := s.DB.Query(ctx, `SELECT DISTINCT g.resource_type, g.resource_id, g.role, g.subject_kind, g.subject_id FROM grants g
		WHERE g.tenant_id=$1 AND g.revoked_at IS NULL AND g.subject_id = ANY($2)
		AND (g.not_before IS NULL OR g.not_before <= now()) AND (g.expires_at IS NULL OR g.expires_at > now())
		ORDER BY g.resource_type, g.resource_id, g.role`, s.TenantID, subjects)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []heldRight{}
	seen := map[string]bool{}
	for rows.Next() {
		var h heldRight
		var sk, sid string
		if err := rows.Scan(&h.ResourceType, &h.ResourceID, &h.Role, &sk, &sid); err != nil {
			return nil, err
		}
		key := h.ResourceType + ":" + h.ResourceID + ":" + h.Role
		// The right to own agents is never handed to an agent: agents cannot own agents.
		if seen[key] || (h.ResourceType == "directory" && h.Role == "agent-owner") {
			continue
		}
		seen[key] = true
		h.Via = "direct"
		if sk == "group" {
			h.Via = "group:" + strings.Join(paths[sid], "/")
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// POST /v1/admin/agents/{id}/token: issue a fresh bearer token, shown once;
// any earlier token stops working.
func (s *Server) handleAgentToken(w http.ResponseWriter, r *http.Request) {
	if !s.mayOwnAgents(w, r) {
		return
	}
	p, err := s.loadAgent(r, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var tok string
	err = s.tx(r, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `UPDATE api_tokens SET revoked_at=now() WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL`, s.TenantID, p.ID); err != nil {
			return err
		}
		var err error
		tok, err = s.Auth.MintAPIToken(r.Context(), tx, s.TenantID, actorOf(r), p.ID, "agent", 0)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	now := time.Now().UTC()
	s.writeJSON(w, 201, map[string]any{"token": tok, "issued_at": now})
}

// DELETE /v1/admin/agents/{id}/token: the agent can no longer sign in.
func (s *Server) handleAgentTokenRevoke(w http.ResponseWriter, r *http.Request) {
	p, err := s.loadAgent(r, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a := actorOf(r)
	err = s.tx(r, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `UPDATE api_tokens SET revoked_at=now() WHERE tenant_id=$1 AND principal_id=$2 AND revoked_at IS NULL`, s.TenantID, p.ID); err != nil {
			return err
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "api_token.revoke",
			TargetType: "principal", TargetID: p.ID, Outcome: "ok", Detail: map[string]any{"principal_id": p.ID}, CorrelationID: a.CorrelationID})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// POST /v1/admin/agents/{id}/state {state: active|suspended}.
func (s *Server) handleAgentState(w http.ResponseWriter, r *http.Request) {
	var req struct {
		State string `json:"state"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.State != "active" && req.State != "suspended" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "state"})
		return
	}
	p, err := s.loadAgent(r, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.tx(r, func(tx pgx.Tx) error {
		return directory.SetPrincipalState(r.Context(), tx, s.TenantID, actorOf(r), p.ID, req.State)
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// POST /v1/admin/agents/{id}/grants: hand the agent a right. An owner may
// only hand over what they hold (the engine would refuse anything wider at
// check time anyway; refusing here keeps the Access screen honest).
func (s *Server) handleAgentGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role         string     `json:"role"`
		ResourceType string     `json:"resource_type"`
		ResourceID   string     `json:"resource_id"`
		Condition    string     `json:"condition"`
		ExpiresAt    *time.Time `json:"expires_at"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.mayOwnAgents(w, r) {
		return
	}
	p, err := s.loadAgent(r, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !isAgentAdmin(r) {
		held, err := s.heldRights(r.Context(), directory.OwnerID(p))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		ok := false
		for _, h := range held {
			if h.ResourceType == req.ResourceType && h.ResourceID == req.ResourceID && h.Role == req.Role {
				ok = true
			}
		}
		if !ok {
			s.writeErr(w, r, 403, "agent.grant_not_held", map[string]any{"role": req.Role, "resource": req.ResourceType + ":" + req.ResourceID})
			return
		}
	}
	var g *directory.Grant
	err = s.tx(r, func(tx pgx.Tx) error {
		var err error
		g, err = directory.CreateGrant(r.Context(), tx, s.TenantID, actorOf(r), directory.Grant{SubjectKind: "principal", SubjectID: p.ID,
			Role: req.Role, ResourceType: req.ResourceType, ResourceID: req.ResourceID, Condition: req.Condition, ExpiresAt: req.ExpiresAt}, s.Authz)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, g)
}

// DELETE /v1/admin/agents/{id}/grants/{gid}: only grants whose subject is this agent.
func (s *Server) handleAgentGrantRevoke(w http.ResponseWriter, r *http.Request) {
	p, err := s.loadAgent(r, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var subject string
	if err := s.DB.QueryRow(r.Context(), `SELECT subject_id FROM grants WHERE tenant_id=$1 AND id=$2 AND subject_kind='principal' AND revoked_at IS NULL`, s.TenantID, r.PathValue("gid")).Scan(&subject); err != nil || subject != p.ID {
		s.writeErr(w, r, 404, "request.not_found", map[string]any{"type": "grant"})
		return
	}
	if err := s.tx(r, func(tx pgx.Tx) error {
		return directory.RevokeGrant(r.Context(), tx, s.TenantID, actorOf(r), r.PathValue("gid"))
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}
