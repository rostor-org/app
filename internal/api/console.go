package api

// Console-facing endpoints: catalog, brand, cookie sessions and the
// identifier-first login (spec §7.6). The console is just another client of
// the admin API; these endpoints only add the session transport and the
// data a browser needs before it can call anything else.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

const sessionCookie = "rostor_session"

// ---- catalog & brand --------------------------------------------------------

// handleCatalog serves the strings with a content ETag and no freshness
// window, so a browser revalidates on every load and a new release never
// shows stale strings (v0.3.2 showed raw codes for five minutes after an
// update because the catalog was cached).
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	loc := locale(r)
	strs, resolved := s.Catalog.Strings(loc)
	body, _ := json.Marshal(map[string]any{"locale": resolved, "strings": strs})
	sum := sha256.Sum256(append([]byte(s.Version+"|"), body...))
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	_, _ = w.Write(body)
}

func (s *Server) handleBrand(w http.ResponseWriter, r *http.Request) {
	var name string
	_ = s.DB.QueryRow(r.Context(), `SELECT name FROM tenants WHERE id=$1`, s.TenantID).Scan(&name)
	// Tokens are the brand's (project/brand/brand.md). A tenant theme object
	// (D25) will override these later; the shape is what the console binds to.
	s.writeJSON(w, 200, map[string]any{"tenant_name": name, "tokens": map[string]string{
		"ink": "#14161a", "paper": "#f4f2ee", "signal": "#e07a24", "surface": "#0f1114", "hairline": "#23262b"}})
}

// ---- sessions ---------------------------------------------------------------

// sessionPrincipal resolves the console cookie to a principal, or nil.
func (s *Server) sessionPrincipal(ctx context.Context, r *http.Request) (*directory.Principal, *auth.Session, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return nil, nil, nil
	}
	h := sha256.Sum256([]byte(c.Value))
	var ses auth.Session
	err = s.DB.QueryRow(ctx, `SELECT id, principal_id, assurance, properties, coalesce(device_id,''), expires_at FROM sessions
		WHERE tenant_id=$1 AND token_hash=$2 AND revoked_at IS NULL AND expires_at > now()`, s.TenantID, h[:]).
		Scan(&ses.ID, &ses.PrincipalID, &ses.Assurance, &ses.Properties, &ses.DeviceID, &ses.ExpiresAt)
	if err == pgx.ErrNoRows {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	p, err := directory.GetPrincipal(ctx, s.DB, s.TenantID, ses.PrincipalID)
	if err != nil {
		return nil, nil, err
	}
	return p, &ses, nil
}

func (s *Server) setSessionCookie(w http.ResponseWriter, r *http.Request, token string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", Expires: exp})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Identifier string            `json:"identifier"`
		Method     string            `json:"method"`
		Fields     map[string]string `json:"fields"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Method == "" {
		req.Method = "password"
	}
	corr := corrOf(r)
	var out *auth.Outcome
	var ses *auth.Session
	err := s.tx(r, func(tx pgx.Tx) error {
		var err error
		if m, ok := s.Auth.Method(req.Method); ok && req.Identifier == "" && m.Identify(auth.StepInput{Fields: req.Fields}) != nil {
			// The credential names the person (badge, discoverable passkey).
			out, err = s.Auth.AuthenticateByCredential(r.Context(), tx, s.TenantID, req.Method, auth.StepInput{Fields: req.Fields}, auth.DefaultLockout)
		} else {
			out, err = s.Auth.AuthenticateInline(r.Context(), tx, s.TenantID, req.Method, req.Identifier, auth.StepInput{Fields: req.Fields}, auth.DefaultLockout)
		}
		if err != nil || out.Assertion == nil {
			return err
		}
		if out.Principal.State != "active" {
			return nil
		}
		ttl := 12 * time.Hour
		if sp, _, err := directory.EffectivePolicy(r.Context(), tx, s.TenantID, "session", out.Principal.ID); err == nil {
			if v, ok := sp["ttl_seconds"].(float64); ok {
				ttl = time.Duration(v) * time.Second
			}
		}
		ses, err = s.Auth.MintSession(r.Context(), tx, s.TenantID, out.Assertion, out.Principal.ID, "", ttl)
		if err != nil {
			return err
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: out.Principal.Kind, ActorID: out.Principal.ID, Action: "session.create",
			TargetType: "principal", TargetID: out.Principal.ID, CredentialType: req.Method, Assurance: out.Assertion.Assurance, Outcome: "allow",
			Detail: map[string]any{"session_id": ses.ID, "client": "console"}, CorrelationID: corr})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	deny := func(code string, params map[string]any, pid string) {
		if params == nil {
			params = map[string]any{}
		}
		s.auditEvent(r.Context(), audit.Event{ActorKind: "system", ActorID: "console", Action: "session.create", TargetType: "principal", TargetID: pid,
			CredentialType: req.Method, Outcome: "deny", Detail: map[string]any{"identifier": req.Identifier, "reason": code}, CorrelationID: corr})
		s.writeJSON(w, 200, map[string]any{"code": code, "params": params, "message": s.Catalog.Render(locale(r), code, params)})
	}
	if out.Assertion == nil {
		pid := ""
		if out.Principal != nil {
			pid = out.Principal.ID
		}
		if out.Code == auth.CodeContinue {
			s.writeJSON(w, 200, map[string]any{"code": out.Code, "params": out.Params, "message": s.Catalog.Render(locale(r), out.Code, out.Params)})
			return
		}
		deny(out.Code, out.Params, pid)
		return
	}
	if ses == nil { // authenticated but not active (suspended etc.)
		code := "principal.not_active"
		if out.Principal.State == "suspended" {
			code = "principal.suspended"
		}
		deny(code, map[string]any{"state": out.Principal.State}, out.Principal.ID)
		return
	}
	s.setSessionCookie(w, r, ses.Token, ses.ExpiresAt)
	s.writeJSON(w, 200, s.sessionView(r, out.Principal, ses))
}

func (s *Server) sessionView(r *http.Request, p *directory.Principal, ses *auth.Session) map[string]any {
	perms := s.permissionsOn(r.Context(), p, ses.Assurance)
	return map[string]any{
		"principal":   map[string]any{"id": p.ID, "username": p.Username, "display_name": displayName(p, locale(r)), "kind": p.Kind},
		"assurance":   ses.Assurance,
		"expires_at":  ses.ExpiresAt,
		"permissions": perms,
	}
}

// permissionsOn lists the actions the principal may perform on
// directory:root, so the console can hide what it cannot do. "*" means all.
func (s *Server) permissionsOn(ctx context.Context, p *directory.Principal, assurance string) []string {
	if d, err := s.Authz.Check(ctx, s.DB, s.TenantID, p, "*", "directory", "root", authz.Presented{Assurance: assurance}); err == nil && d.Allow {
		return []string{"*"}
	}
	var out []string
	for _, a := range adminActions {
		if d, err := s.Authz.Check(ctx, s.DB, s.TenantID, p, a, "directory", "root", authz.Presented{Assurance: assurance}); err == nil && d.Allow {
			out = append(out, a)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

var adminActions = []string{"users.read", "users.write", "credentials.write", "groups.read", "groups.write", "resources.write",
	"roles.write", "grants.read", "grants.write", "devices.read", "devices.write", "authz.read", "audit.read", "updates.read", "updates.write", "system.read", "plugins.read", "agents.own", "scripts.read", "scripts.write"}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	p, ses, err := s.sessionPrincipal(r.Context(), r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p == nil {
		s.writeErr(w, r, 401, "request.unauthorized", nil)
		return
	}
	s.writeJSON(w, 200, s.sessionView(r, p, ses))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		h := sha256.Sum256([]byte(c.Value))
		_, _ = s.DB.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE tenant_id=$1 AND token_hash=$2 AND revoked_at IS NULL`, s.TenantID, h[:])
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1})
	w.WriteHeader(204)
}

// isConsoleMutation reports whether a cookie-authenticated request carries
// the CSRF marker the SPA always sends.
func isConsoleMutation(r *http.Request) bool {
	return r.Method != "GET" && r.Method != "HEAD" && strings.EqualFold(r.Header.Get("X-Requested-With"), "rostor-console")
}
