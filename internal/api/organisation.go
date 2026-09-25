package api

// The organisation's name is what the console header, the sign-in page,
// the portal, passkeys' relying-party display name and the workstation
// tiles all show. It is one field on the tenant, set at bootstrap and
// editable here.

import (
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
)

// GET /v1/admin/settings/organisation
func (s *Server) handleGetOrganisation(w http.ResponseWriter, r *http.Request) {
	var name string
	_ = s.DB.QueryRow(r.Context(), `SELECT name FROM tenants WHERE id=$1`, s.TenantID).Scan(&name)
	s.writeJSON(w, 200, map[string]any{"name": name})
}

// PUT /v1/admin/settings/organisation {name}
func (s *Server) handlePutOrganisation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" || len(name) > 80 {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "name"})
		return
	}
	var old string
	err := s.tx(r, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `UPDATE tenants SET name=$2 WHERE id=$1 RETURNING (SELECT name FROM tenants t2 WHERE t2.id=$1)`, s.TenantID, name).Scan(&old); err != nil {
			return err
		}
		a := actorOf(r)
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "tenant.rename", TargetType: "tenant", TargetID: s.TenantID,
			Outcome: "ok", Detail: map[string]any{"from": old, "to": name}, CorrelationID: a.CorrelationID})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"name": name})
}
