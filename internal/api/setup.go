package api

// First-administrator setup and single-action credential changes.

import (
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/directory"
)

// handleSetupStatus is public: the sign-in page asks whether the install
// still needs its first human administrator.
func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	exists, err := directory.HumanAdminExists(r.Context(), s.DB, s.TenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"needed": !exists})
}

// handleSetup creates the first human administrator. It is gated by the
// bootstrap token (a service-account API token holding admin on the
// directory), works only while no human admin exists, and signs the new
// person in. Once used, the sign-in page stops offering it.
func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		BootstrapToken string `json:"bootstrap_token"`
		Username       string `json:"username"`
		DisplayName    string `json:"display_name"`
		Password       string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	tenantID, pid, err := auth.ResolveAPIToken(r.Context(), s.DB, strings.TrimSpace(req.BootstrapToken))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if pid == "" || tenantID != s.TenantID {
		s.writeErr(w, r, 401, "setup.token_invalid", nil)
		return
	}
	var p *directory.Principal
	var ses *auth.Session
	err = s.tx(r, func(tx pgx.Tx) error {
		exists, err := directory.HumanAdminExists(r.Context(), tx, s.TenantID)
		if err != nil {
			return err
		}
		if exists {
			return directory.Err("setup.already_done")
		}
		actor := directory.Actor{Kind: "service", ID: pid, CorrelationID: corrOf(r)}
		p, err = directory.CreatePrincipal(r.Context(), tx, s.TenantID, actor, directory.Principal{Kind: "user", Username: req.Username,
			DisplayName: map[string]string{"en": req.DisplayName}})
		if err != nil {
			return err
		}
		if _, err := s.Auth.Enroll(r.Context(), tx, s.TenantID, actor, p.ID, "password", "", auth.StepInput{Fields: map[string]string{"password": req.Password}}); err != nil {
			return err
		}
		g, err := directory.GetGroupByName(r.Context(), tx, s.TenantID, directory.AdminsGroup)
		if err != nil {
			return err
		}
		if err := directory.AddGroupMember(r.Context(), tx, s.TenantID, actor, g.ID, "principal", p.ID); err != nil {
			return err
		}
		if _, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: "service", ActorID: pid, Action: "setup.first_admin",
			TargetType: "principal", TargetID: p.ID, Outcome: "ok", CorrelationID: corrOf(r)}); err != nil {
			return err
		}
		a := &auth.Assertion{Method: "password", At: time.Now().UTC(), Properties: []string{"knowledge"}, Assurance: "AL1"}
		ses, err = s.Auth.MintSession(r.Context(), tx, s.TenantID, a, p.ID, "", 12*time.Hour)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.setSessionCookie(w, r, ses.Token, ses.ExpiresAt)
	s.writeJSON(w, 201, s.sessionView(r, p, ses))
}

// handleChangePassword replaces the person's password in one action. A
// person changing their own must present the current one; an admin acting
// on someone else does not (that is a reset, audited as such).
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	actor := actorOf(r)
	err := s.tx(r, func(tx pgx.Tx) error {
		p, err := s.resolveUser(r, tx, r.PathValue("id"))
		if err != nil {
			return err
		}
		self := actor.ID == p.ID
		if self {
			out, err := s.Auth.AuthenticateInline(r.Context(), tx, s.TenantID, "password", p.Username, auth.StepInput{Fields: map[string]string{"password": req.Current}}, auth.DefaultLockout)
			if err != nil {
				return err
			}
			if out.Assertion == nil {
				return directory.Err(out.Code)
			}
		}
		rows, err := tx.Query(r.Context(), `SELECT id FROM authenticator_bindings WHERE tenant_id=$1 AND principal_id=$2 AND method='password' AND state='active'`, s.TenantID, p.ID)
		if err != nil {
			return err
		}
		var old []string
		for rows.Next() {
			var id string
			_ = rows.Scan(&id)
			old = append(old, id)
		}
		rows.Close()
		if _, err := s.Auth.Enroll(r.Context(), tx, s.TenantID, actor, p.ID, "password", "", auth.StepInput{Fields: map[string]string{"password": req.New}}); err != nil {
			return err
		}
		for _, id := range old {
			if err := s.Auth.RevokeBinding(r.Context(), tx, s.TenantID, actor, id); err != nil {
				return err
			}
		}
		action := "password.change"
		if !self {
			action = "password.reset"
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID, Action: action,
			TargetType: "principal", TargetID: p.ID, Outcome: "ok", CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// handleSetPIN sets or changes the PIN on a badge binding.
func (s *Server) handleSetPIN(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PIN string `json:"pin"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	actor := actorOf(r)
	err := s.tx(r, func(tx pgx.Tx) error {
		p, err := s.resolveUser(r, tx, r.PathValue("id"))
		if err != nil {
			return err
		}
		return s.Auth.SetBadgePIN(r.Context(), tx, s.TenantID, actor, p.ID, r.PathValue("bid"), req.PIN)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}
