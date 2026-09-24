package api

// Read endpoints for the console (docs/contracts/console-api.md). Plain
// queries shaped for screens; no authorization logic lives here.

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/auth"
	"rostor.org/app/internal/directory"
)

type page struct {
	Limit, Offset int
	Q             string
}

func pageOf(r *http.Request) page {
	p := page{Limit: 50}
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 500 {
		p.Limit = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v >= 0 {
		p.Offset = v
	}
	p.Q = strings.TrimSpace(r.URL.Query().Get("q"))
	return p
}

func like(q string) string { return "%" + strings.ToLower(q) + "%" }

// ---- summary ----------------------------------------------------------------

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{}
	var active, suspended, applicants, services, groups, grants int
	_ = s.DB.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE kind='user' AND state='active'),
		count(*) FILTER (WHERE kind='user' AND state='suspended'),
		count(*) FILTER (WHERE kind='user' AND state='applicant'),
		count(*) FILTER (WHERE kind='service')
		FROM principals WHERE tenant_id=$1`, s.TenantID).Scan(&active, &suspended, &applicants, &services)
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM groups WHERE tenant_id=$1`, s.TenantID).Scan(&groups)
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM grants WHERE tenant_id=$1 AND revoked_at IS NULL`, s.TenantID).Scan(&grants)
	devices := map[string]int{}
	rows, err := s.DB.Query(ctx, `SELECT lifecycle, count(*) FROM devices WHERE tenant_id=$1 GROUP BY lifecycle`, s.TenantID)
	if err == nil {
		for rows.Next() {
			var l string
			var n int
			_ = rows.Scan(&l, &n)
			devices[l] = n
		}
		rows.Close()
	}
	out["people"] = map[string]int{"active": active, "suspended": suspended, "applicants": applicants, "service_accounts": services}
	out["groups"] = groups
	out["grants"] = grants
	out["devices"] = devices
	out["offline_points"] = 0
	out["oldest_snapshot_age_seconds"] = nil
	s.writeJSON(w, 200, out)
}

// ---- people -----------------------------------------------------------------

type userRow struct {
	ID          string         `json:"id"`
	Username    string         `json:"username"`
	Kind        string         `json:"kind"`
	DisplayName string         `json:"display_name"`
	State       string         `json:"state"`
	Groups      []nameRef      `json:"groups"`
	Methods     []methodRef    `json:"methods"`
	LastSignIn  *lastSignIn    `json:"last_sign_in"`
	Attributes  map[string]any `json:"attributes,omitempty"`
}
type nameRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type methodRef struct {
	Method    string `json:"method"`
	Assurance string `json:"assurance"`
}
type lastSignIn struct {
	TS       time.Time `json:"ts"`
	Resource string    `json:"resource"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pg := pageOf(r)
	rows, err := s.DB.Query(ctx, `SELECT p.id, coalesce(p.username,''), p.kind, p.display_name, p.state, p.attributes,
		coalesce((SELECT json_agg(json_build_object('id', g.id, 'name', g.name) ORDER BY g.name) FROM group_members gm JOIN groups g ON g.tenant_id=gm.tenant_id AND g.id=gm.group_id
			WHERE gm.tenant_id=p.tenant_id AND gm.member_kind='principal' AND gm.member_id=p.id), '[]'::json),
		coalesce((SELECT json_agg(DISTINCT b.method) FROM authenticator_bindings b WHERE b.tenant_id=p.tenant_id AND b.principal_id=p.id AND b.state='active'), '[]'::json),
		(SELECT json_build_object('ts', a.ts, 'resource', coalesce(a.target_type,'') || ':' || coalesce(a.target_id,''))
			FROM audit_events a WHERE a.tenant_id=p.tenant_id AND a.outcome='allow' AND a.action IN ('verify','session.create')
			AND a.detail->>'principal_id' = p.id ORDER BY a.seq DESC LIMIT 1),
		count(*) OVER()
		FROM principals p WHERE p.tenant_id=$1 AND p.kind IN ('user','service')
		AND ($2 = '' OR lower(coalesce(p.username,'')) LIKE $3 OR lower(p.display_name::text) LIKE $3)
		ORDER BY p.kind, lower(coalesce(p.username,'')) LIMIT $4 OFFSET $5`, s.TenantID, pg.Q, like(pg.Q), pg.Limit, pg.Offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	items := []userRow{}
	total := 0
	for rows.Next() {
		var u userRow
		var dn, attrs, groups, methods, last []byte
		if err := rows.Scan(&u.ID, &u.Username, &u.Kind, &dn, &u.State, &attrs, &groups, &methods, &last, &total); err != nil {
			s.fail(w, r, err)
			return
		}
		u.DisplayName = displayFrom(dn, u.Username, locale(r))
		_ = json.Unmarshal(groups, &u.Groups)
		var ms []string
		_ = json.Unmarshal(methods, &ms)
		u.Methods = []methodRef{}
		for _, m := range ms {
			a := "AL1"
			if md, ok := s.Auth.Method(m); ok {
				a = md.Describe().Assurance
			}
			u.Methods = append(u.Methods, methodRef{Method: m, Assurance: a})
		}
		if len(last) > 0 && string(last) != "null" {
			var l lastSignIn
			if json.Unmarshal(last, &l) == nil {
				u.LastSignIn = &l
			}
		}
		_ = json.Unmarshal(attrs, &u.Attributes)
		items = append(items, u)
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

func displayFrom(dn []byte, fallback, loc string) string {
	m := map[string]string{}
	_ = json.Unmarshal(dn, &m)
	if v, ok := m[loc]; ok && v != "" {
		return v
	}
	if v, ok := m["en"]; ok && v != "" {
		return v
	}
	return fallback
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.resolveUser(r, s.DB, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"id": p.ID, "username": p.Username, "kind": p.Kind, "display_name": displayName(p, locale(r)),
		"state": p.State, "attributes": p.Attributes, "created_at": p.CreatedAt}
	// groups with paths
	paths, _ := directory.GroupPaths(ctx, s.DB, s.TenantID, p.ID)
	groups := []map[string]any{}
	for gid, path := range paths {
		var name string
		_ = s.DB.QueryRow(ctx, `SELECT name FROM groups WHERE tenant_id=$1 AND id=$2`, s.TenantID, gid).Scan(&name)
		groups = append(groups, map[string]any{"id": gid, "name": name, "direct": len(path) == 1})
	}
	out["groups"] = groups
	// bindings
	brows, err := s.DB.Query(ctx, `SELECT id, method, properties, coalesce(label,''), state, created_at, last_used_at FROM authenticator_bindings
		WHERE tenant_id=$1 AND principal_id=$2 ORDER BY created_at`, s.TenantID, p.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	bindings := []map[string]any{}
	best := "AL0"
	rank := map[string]int{"AL0": 0, "AL1": 1, "AL2": 2, "AL3": 3}
	for brows.Next() {
		var b auth.Binding
		var last *time.Time
		if err := brows.Scan(&b.ID, &b.Method, &b.Properties, &b.Label, &b.State, &b.CreatedAt, &last); err != nil {
			brows.Close()
			s.fail(w, r, err)
			return
		}
		a := "AL1"
		if md, ok := s.Auth.Method(b.Method); ok {
			a = md.Describe().Assurance
		}
		if b.Method == "badge" {
			for _, pr := range b.Properties {
				if pr == "knowledge" {
					a = "AL2"
				}
			}
		}
		if b.State == "active" && rank[a] > rank[best] {
			best = a
		}
		bindings = append(bindings, map[string]any{"id": b.ID, "method": b.Method, "properties": b.Properties, "label": b.Label,
			"state": b.State, "assurance": a, "created_at": b.CreatedAt, "last_used_at": last})
	}
	brows.Close()
	out["bindings"] = bindings
	// D26: effective security = min over bindings and recovery paths; with no
	// recovery bindings yet, that is simply the strongest active binding and
	// an explicit "no recovery path" flag.
	out["effective_security"] = map[string]any{"assurance": best, "bindings": len(bindings), "recovery_paths": 0}
	out["recent"] = s.recentAudit(ctx, p.ID, 10)
	s.writeJSON(w, 200, out)
}

func (s *Server) recentAudit(ctx context.Context, principalID string, n int) []map[string]any {
	rows, err := s.DB.Query(ctx, `SELECT seq, ts, actor_kind, actor_id, action, coalesce(target_type,''), coalesce(target_id,''),
		coalesce(credential_type,''), coalesce(assurance,''), outcome, detail FROM audit_events
		WHERE tenant_id=$1 AND (target_id=$2 OR detail->>'principal_id'=$2 OR actor_id=$2) ORDER BY seq DESC LIMIT $3`, s.TenantID, principalID, n)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	items := scanAudit(rows)
	s.nameAudit(ctx, items)
	return items
}

func scanAudit(rows pgx.Rows) []map[string]any {
	out := []map[string]any{}
	for rows.Next() {
		var seq int64
		var ts time.Time
		var ak, aid, action, tt, tid, ct, as, outcome string
		var detail json.RawMessage
		if err := rows.Scan(&seq, &ts, &ak, &aid, &action, &tt, &tid, &ct, &as, &outcome, &detail); err != nil {
			break
		}
		out = append(out, map[string]any{"seq": seq, "ts": ts, "actor": map[string]string{"kind": ak, "id": aid}, "action": action,
			"target": map[string]string{"type": tt, "id": tid}, "credential_type": ct, "assurance": as, "outcome": outcome, "detail": detail})
	}
	return out
}

// nameAudit adds human names to audit rows: actor.name and target.name for
// principals, groups and devices, plus detail.principal_name when the detail
// carries a principal_id (verify events). IDs stay; names sit beside them
// so the console can lead with the name and keep the ID secondary.
func (s *Server) nameAudit(ctx context.Context, items []map[string]any) {
	cache := map[string]string{}
	lookup := func(kind, id string) string {
		if id == "" {
			return ""
		}
		key := kind + ":" + id
		if v, ok := cache[key]; ok {
			return v
		}
		var name string
		switch kind {
		case "principal", "user", "service", "device":
			_ = s.DB.QueryRow(ctx, `SELECT coalesce(nullif(display_name->>'en',''), username, '') FROM principals WHERE tenant_id=$1 AND id=$2`, s.TenantID, id).Scan(&name)
		case "group":
			_ = s.DB.QueryRow(ctx, `SELECT name FROM groups WHERE tenant_id=$1 AND id=$2`, s.TenantID, id).Scan(&name)
		}
		cache[key] = name
		return name
	}
	for _, it := range items {
		if a, ok := it["actor"].(map[string]string); ok {
			if n := lookup(a["kind"], a["id"]); n != "" {
				a["name"] = n
			}
		}
		if t, ok := it["target"].(map[string]string); ok {
			if n := lookup(t["type"], t["id"]); n != "" {
				t["name"] = n
			}
		}
		if raw, ok := it["detail"].(json.RawMessage); ok && len(raw) > 0 {
			var d map[string]any
			if json.Unmarshal(raw, &d) == nil {
				if pid, ok := d["principal_id"].(string); ok && pid != "" {
					if n := lookup("principal", pid); n != "" {
						d["principal_name"] = n
						if b, err := json.Marshal(d); err == nil {
							it["detail"] = json.RawMessage(b)
						}
					}
				}
			}
		}
	}
}

// ---- groups -----------------------------------------------------------------

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	pg := pageOf(r)
	rows, err := s.DB.Query(r.Context(), `SELECT g.id, g.name, g.display_name, g.kind,
		(SELECT count(*) FROM group_members m WHERE m.tenant_id=g.tenant_id AND m.group_id=g.id),
		(SELECT count(*) FROM grants x WHERE x.tenant_id=g.tenant_id AND x.subject_kind='group' AND x.subject_id=g.id AND x.revoked_at IS NULL),
		count(*) OVER()
		FROM groups g WHERE g.tenant_id=$1 AND ($2='' OR lower(g.name) LIKE $3) ORDER BY g.name LIMIT $4 OFFSET $5`,
		s.TenantID, pg.Q, like(pg.Q), pg.Limit, pg.Offset)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	total := 0
	for rows.Next() {
		var id, name, kind string
		var dn []byte
		var members, grants int
		if err := rows.Scan(&id, &name, &dn, &kind, &members, &grants, &total); err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "display_name": displayFrom(dn, name, locale(r)), "kind": kind,
			"member_count": members, "grant_count": grants})
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": total})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	g, err := directory.GetGroupByName(ctx, s.DB, s.TenantID, r.PathValue("name"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"id": g.ID, "name": g.Name, "display_name": g.DisplayName, "kind": g.Kind}
	rows, err := s.DB.Query(ctx, `SELECT m.member_kind, m.member_id,
		CASE WHEN m.member_kind='principal' THEN coalesce(p.username,'') ELSE gg.name END,
		CASE WHEN m.member_kind='principal' THEN p.display_name ELSE gg.display_name END,
		CASE WHEN m.member_kind='principal' THEN p.state ELSE '' END
		FROM group_members m
		LEFT JOIN principals p ON m.member_kind='principal' AND p.tenant_id=m.tenant_id AND p.id=m.member_id
		LEFT JOIN groups gg ON m.member_kind='group' AND gg.tenant_id=m.tenant_id AND gg.id=m.member_id
		WHERE m.tenant_id=$1 AND m.group_id=$2 ORDER BY m.member_kind, 3`, s.TenantID, g.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	members := []map[string]any{}
	for rows.Next() {
		var kind, id, name, state string
		var dn []byte
		if err := rows.Scan(&kind, &id, &name, &dn, &state); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		members = append(members, map[string]any{"kind": kind, "id": id, "name": name, "display_name": displayFrom(dn, name, locale(r)), "state": state})
	}
	rows.Close()
	out["members"] = members
	out["grants"] = s.grantRows(r, "g.subject_kind='group' AND g.subject_id=$2", g.ID)
	s.writeJSON(w, 200, out)
}

// ---- grants -----------------------------------------------------------------

func (s *Server) grantRows(r *http.Request, where string, arg any) []map[string]any {
	q := `SELECT g.id, g.subject_kind, g.subject_id,
		CASE WHEN g.subject_kind='group' THEN (SELECT name FROM groups x WHERE x.tenant_id=g.tenant_id AND x.id=g.subject_id)
		     ELSE (SELECT coalesce(username, id) FROM principals x WHERE x.tenant_id=g.tenant_id AND x.id=g.subject_id) END,
		g.role, g.resource_type, g.resource_id, coalesce(g.condition,''), g.condition_class, g.not_before, g.expires_at, g.created_at
		FROM grants g WHERE g.tenant_id=$1 AND g.revoked_at IS NULL AND ` + where + ` ORDER BY g.created_at DESC`
	args := []any{s.TenantID}
	if arg != nil {
		args = append(args, arg)
	}
	rows, err := s.DB.Query(r.Context(), q, args...)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, sk, sid, sname, role, rt, rid, cond, class string
		var nb, exp *time.Time
		var created time.Time
		if err := rows.Scan(&id, &sk, &sid, &sname, &role, &rt, &rid, &cond, &class, &nb, &exp, &created); err != nil {
			break
		}
		out = append(out, map[string]any{"id": id, "subject": map[string]string{"kind": sk, "id": sid, "name": sname}, "role": role,
			"resource": map[string]string{"type": rt, "id": rid}, "condition": cond, "condition_class": class,
			"not_before": nb, "expires_at": exp, "created_at": created})
	}
	return out
}

func (s *Server) handleListGrants(w http.ResponseWriter, r *http.Request) {
	pg := pageOf(r)
	items := s.grantRows(r, `($2='' OR lower(g.role) LIKE $3 OR lower(g.resource_type||':'||g.resource_id) LIKE $3)`, nil)
	_ = pg
	// Filter by subject name client-side would be wrong; do it here cheaply.
	if pg.Q != "" {
		q := strings.ToLower(pg.Q)
		filtered := items[:0]
		for _, g := range items {
			sub := g["subject"].(map[string]string)
			res := g["resource"].(map[string]string)
			if strings.Contains(strings.ToLower(sub["name"]), q) || strings.Contains(strings.ToLower(g["role"].(string)), q) ||
				strings.Contains(strings.ToLower(res["type"]+":"+res["id"]), q) {
				filtered = append(filtered, g)
			}
		}
		items = filtered
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

// ---- devices ----------------------------------------------------------------

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.display_name, p.attributes, d.lifecycle, d.last_seen_at, d.posture, d.cert_not_after
		FROM devices d JOIN principals p ON p.tenant_id=d.tenant_id AND p.id=d.principal_id WHERE d.tenant_id=$1 ORDER BY p.display_name::text`, s.TenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, lifecycle string
		var dn, attrs, posture []byte
		var last *time.Time
		var notAfter time.Time
		if err := rows.Scan(&id, &dn, &attrs, &lifecycle, &last, &posture, &notAfter); err != nil {
			s.fail(w, r, err)
			return
		}
		a := map[string]any{}
		_ = json.Unmarshal(attrs, &a)
		rt, _ := a["resource_type"].(string)
		host, _ := a["hostname"].(string)
		items = append(items, map[string]any{"id": id, "display_name": displayFrom(dn, host, locale(r)),
			"resource": map[string]string{"type": rt, "id": host}, "lifecycle": lifecycle, "last_seen_at": last,
			"posture": json.RawMessage(posture), "cert_not_after": notAfter})
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

// ---- audit (paged, newest first) ---------------------------------------------

func (s *Server) handleAuditList(w http.ResponseWriter, r *http.Request) {
	pg := pageOf(r)
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	if before <= 0 {
		before = 1 << 62
	}
	rows, err := s.DB.Query(r.Context(), `SELECT seq, ts, actor_kind, actor_id, action, coalesce(target_type,''), coalesce(target_id,''),
		coalesce(credential_type,''), coalesce(assurance,''), outcome, detail FROM audit_events
		WHERE tenant_id=$1 AND seq < $2 AND ($3='' OR lower(action) LIKE $4 OR lower(actor_id) LIKE $4 OR lower(coalesce(target_id,'')) LIKE $4 OR lower(detail::text) LIKE $4)
		ORDER BY seq DESC LIMIT $5`, s.TenantID, before, pg.Q, like(pg.Q), pg.Limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := scanAudit(rows)
	rows.Close()
	s.nameAudit(r.Context(), items)
	var head int64
	_ = s.DB.QueryRow(r.Context(), `SELECT seq FROM audit_heads WHERE tenant_id=$1`, s.TenantID).Scan(&head)
	s.writeJSON(w, 200, map[string]any{"items": items, "head": map[string]int64{"seq": head}})
}

// ---- system & plugins -------------------------------------------------------

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var tname string
	_ = s.DB.QueryRow(ctx, `SELECT name FROM tenants WHERE id=$1`, s.TenantID).Scan(&tname)
	var dbSize int64
	_ = s.DB.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&dbSize)
	s.writeJSON(w, 200, map[string]any{
		"version": s.Version, "tenant": map[string]string{"id": s.TenantID, "name": tname},
		"uptime_seconds":          int(time.Since(s.Started).Seconds()),
		"db":                      map[string]any{"size_bytes": dbSize},
		"ca":                      map[string]any{"subject": s.CA.Cert.Subject.CommonName, "not_after": s.CA.Cert.NotAfter},
		"release_key_fingerprint": s.ReleaseKeyFP, "profile": "standard",
	})
}

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]any{"items": []any{}, "total": 0})
}

// ---- binding revoke ---------------------------------------------------------

func (s *Server) handleRevokeBinding(w http.ResponseWriter, r *http.Request) {
	err := s.tx(r, func(tx pgx.Tx) error {
		p, err := s.resolveUser(r, tx, r.PathValue("id"))
		if err != nil {
			return err
		}
		var owner string
		if err := tx.QueryRow(r.Context(), `SELECT principal_id FROM authenticator_bindings WHERE tenant_id=$1 AND id=$2`, s.TenantID, r.PathValue("bid")).Scan(&owner); err != nil || owner != p.ID {
			return directory.Err("request.not_found", "type", "binding")
		}
		// A person may not lock themselves out: their last active method
		// stays until another exists. Admins acting on someone else may
		// (offboarding); the recovery floor policy will refine this (§7.6).
		if actorOf(r).ID == p.ID {
			var active int
			if err := tx.QueryRow(r.Context(), `SELECT count(*) FROM authenticator_bindings WHERE tenant_id=$1 AND principal_id=$2 AND state='active'`, s.TenantID, p.ID).Scan(&active); err != nil {
				return err
			}
			if active <= 1 {
				return directory.Err("binding.last_method")
			}
		}
		return s.Auth.RevokeBinding(r.Context(), tx, s.TenantID, actorOf(r), r.PathValue("bid"))
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), `SELECT resource_type, name, permissions FROM roles WHERE tenant_id=$1 ORDER BY resource_type, name`, s.TenantID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	items := []directory.Role{}
	for rows.Next() {
		var ro directory.Role
		if err := rows.Scan(&ro.ResourceType, &ro.Name, &ro.Permissions); err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, ro)
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}
