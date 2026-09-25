package api

// Sign-in policy for people and devices alike: the tenant-wide auth policy
// can be overridden per group (people and device principals both belong
// to groups), and a device reads its effective policy on the heartbeat.

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
)

// GET /v1/devices/self/policy: the auth policy as it applies to this device.
func (s *Server) handleDevicePolicy(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	pol, _, err := directory.EffectivePolicy(r.Context(), s.DB, s.TenantID, "auth", d.Principal.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	method := "password"
	switch m, _ := pol["login.default_method"].(string); m {
	case "badge", "passkey", "password":
		method = m
	}
	format := "none"
	if f, _ := pol["badge.format"].(string); f == "wiegand26" {
		format = f
	}
	s.writeJSON(w, 200, map[string]any{"login": map[string]string{"default_method": method}, "badge": map[string]string{"format": format}})
}

func (s *Server) overrideRows(r *http.Request) ([]map[string]any, error) {
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.document, p.created_at, g.id, g.name FROM policies p
		JOIN policy_assignments a ON a.tenant_id=p.tenant_id AND a.policy_id=p.id AND a.group_id IS NOT NULL
		JOIN groups g ON g.tenant_id=p.tenant_id AND g.id=a.group_id
		WHERE p.tenant_id=$1 AND p.domain='auth' AND p.priority > 0 ORDER BY p.created_at`, s.TenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var pid, gid, gname string
		var doc map[string]any
		var created time.Time
		if err := rows.Scan(&pid, &doc, &created, &gid, &gname); err != nil {
			return nil, err
		}
		method, _ := doc["login.default_method"].(string)
		out = append(out, map[string]any{"policy_id": pid, "group": map[string]string{"id": gid, "name": gname},
			"login": map[string]string{"default_method": method}, "created_at": created})
	}
	return out, rows.Err()
}

// GET /v1/admin/settings/auth/overrides
func (s *Server) handleListAuthOverrides(w http.ResponseWriter, r *http.Request) {
	items, err := s.overrideRows(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

// PUT /v1/admin/settings/auth/overrides/{group} {login:{default_method}}.
// Each override gets its own priority above every earlier one, so a
// principal in several overridden groups follows the newest.
func (s *Server) handlePutAuthOverride(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Login struct {
			DefaultMethod string `json:"default_method"`
		} `json:"login"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	switch req.Login.DefaultMethod {
	case "password", "passkey", "badge":
	default:
		s.fail(w, r, directory.Err("request.malformed", "field", "login.default_method"))
		return
	}
	g, err := directory.GetGroupByName(r.Context(), s.DB, s.TenantID, r.PathValue("group"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name := "auth:" + g.Name
	doc := map[string]any{"login.default_method": req.Login.DefaultMethod}
	err = s.tx(r, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `DELETE FROM policies WHERE tenant_id=$1 AND domain='auth' AND name=$2`, s.TenantID, name); err != nil {
			return err
		}
		var next int
		if err := tx.QueryRow(r.Context(), `SELECT coalesce(max(priority),0)+1 FROM policies WHERE tenant_id=$1 AND domain='auth'`, s.TenantID).Scan(&next); err != nil {
			return err
		}
		if _, err := directory.CreatePolicy(r.Context(), tx, s.TenantID, actorOf(r), name, "auth", next, doc, g.ID); err != nil {
			return err
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "policy.update",
			TargetType: "policy", TargetID: name, Outcome: "ok", Detail: map[string]any{"group": g.Name, "login.default_method": req.Login.DefaultMethod}, CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.overrideRows(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, it := range items {
		if it["group"].(map[string]string)["id"] == g.ID {
			s.writeJSON(w, 200, it)
			return
		}
	}
	s.writeErr(w, r, 404, "request.not_found", map[string]any{"type": "policy"})
}

// DELETE /v1/admin/settings/auth/overrides/{group}
func (s *Server) handleDeleteAuthOverride(w http.ResponseWriter, r *http.Request) {
	g, err := directory.GetGroupByName(r.Context(), s.DB, s.TenantID, r.PathValue("group"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name := "auth:" + g.Name
	err = s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM policies WHERE tenant_id=$1 AND domain='auth' AND name=$2`, s.TenantID, name)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return directory.Err("request.not_found", "type", "policy")
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "policy.delete",
			TargetType: "policy", TargetID: name, Outcome: "ok", Detail: map[string]any{"group": g.Name}, CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}
