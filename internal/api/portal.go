package api

// SPEC-portal: the landing page is a set of tiles. A built-in tile is a
// console screen shown to whoever holds its permission; an admin-made tile
// is a link shown to whoever holds a `view` grant on it (the built-in
// `everyone` group makes a tile public, anonymous visitors included).

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/directory"
)

type tile struct {
	ID          string
	Attributes  map[string]any
	Public      bool
	GrantsCount int
}

var tileIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,63}$`)

func (s *Server) loadTiles(ctx context.Context) ([]tile, string, error) {
	var everyone string
	_ = s.DB.QueryRow(ctx, `SELECT id FROM groups WHERE tenant_id=$1 AND name=$2`, s.TenantID, directory.EveryoneGroup).Scan(&everyone)
	rows, err := s.DB.Query(ctx, `SELECT r.id, r.attributes,
		(SELECT count(*) FROM grants g WHERE g.tenant_id=r.tenant_id AND g.resource_type='portal.tile' AND g.resource_id=r.id AND g.revoked_at IS NULL),
		EXISTS(SELECT 1 FROM grants g WHERE g.tenant_id=r.tenant_id AND g.resource_type='portal.tile' AND g.resource_id=r.id AND g.revoked_at IS NULL
			AND g.subject_kind='group' AND g.subject_id=$2)
		FROM resources r WHERE r.tenant_id=$1 AND r.type='portal.tile'`, s.TenantID, everyone)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []tile
	for rows.Next() {
		var t tile
		var attrs []byte
		if err := rows.Scan(&t.ID, &attrs, &t.GrantsCount, &t.Public); err != nil {
			return nil, "", err
		}
		_ = json.Unmarshal(attrs, &t.Attributes)
		if t.Attributes == nil {
			t.Attributes = map[string]any{}
		}
		out = append(out, t)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ci, cj := str(out[i].Attributes, "category"), str(out[j].Attributes, "category")
		if ci != cj {
			return ci < cj
		}
		oi, _ := out[i].Attributes["order"].(float64)
		oj, _ := out[j].Attributes["order"].(float64)
		if oi != oj {
			return oi < oj
		}
		return out[i].ID < out[j].ID
	})
	return out, everyone, rows.Err()
}

func (s *Server) tileView(loc string, t tile) map[string]any {
	a := t.Attributes
	title, desc := str(a, "title"), str(a, "description")
	if code := str(a, "title_code"); code != "" {
		title = s.Catalog.Render(loc, code, nil)
	}
	if code := str(a, "description_code"); code != "" {
		desc = s.Catalog.Render(loc, code, nil)
	}
	order, _ := a["order"].(float64)
	builtin, _ := a["builtin"].(bool)
	return map[string]any{"id": t.ID, "kind": str(a, "kind"), "href": str(a, "href"), "category": str(a, "category"), "order": int(order),
		"icon": str(a, "icon"), "title": title, "description": desc, "public": t.Public, "builtin": builtin, "requires": str(a, "requires"), "grants": t.GrantsCount}
}

// GET /v1/portal: the tiles the caller may see. Anonymous callers see
// public tiles; a session sees screens it holds the permission for plus
// every tile a grant allows it to view.
func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	tiles, _, err := s.loadTiles(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	loc := locale(r)
	var p *directory.Principal
	var pres authz.Presented
	if tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); tok != "" && tok != r.Header.Get("Authorization") {
		p, pres, _ = s.caller(&discardWriter{}, r)
	} else if sp, ses, err := s.sessionPrincipal(r.Context(), r); err == nil && sp != nil {
		p, pres = sp, authz.Presented{Assurance: ses.Assurance, Properties: ses.Properties}
	}
	var perms map[string]bool
	if p != nil {
		perms = map[string]bool{}
		for _, a := range s.permissionsOn(r.Context(), p, pres.Assurance) {
			perms[a] = true
		}
	}
	out := []map[string]any{}
	for _, t := range tiles {
		visible := t.Public
		if !visible && p != nil {
			switch req := str(t.Attributes, "requires"); {
			case perms["*"]:
				// A directory admin manages tiles, so sees them all.
				visible = true
			case req == "session":
				visible = true
			case req != "" && (perms["*"] || perms[req]):
				visible = true
			}
			if !visible {
				if d, err := s.Authz.Check(r.Context(), s.DB, s.TenantID, p, "view", "portal.tile", t.ID, pres); err == nil && d.Allow {
					visible = true
				}
			}
		}
		if visible {
			out = append(out, s.tileView(loc, t))
		}
	}
	s.writeJSON(w, 200, map[string]any{"signed_in": p != nil, "tiles": out})
}

// discardWriter lets caller() run for a bearer on the public portal without
// its 401 reaching the client: an unknown token simply sees the public view.
type discardWriter struct{ http.ResponseWriter }

func (discardWriter) Header() http.Header         { return http.Header{} }
func (discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (discardWriter) WriteHeader(int)             {}

// GET /v1/admin/portal/tiles: every tile, for the System screen.
func (s *Server) handleListTiles(w http.ResponseWriter, r *http.Request) {
	tiles, _, err := s.loadTiles(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := []map[string]any{}
	for _, t := range tiles {
		items = append(items, s.tileView(locale(r), t))
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

type tileInput struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Href        string `json:"href"`
	Category    string `json:"category"`
	Icon        string `json:"icon"`
	Order       int    `json:"order"`
	Public      *bool  `json:"public"`
}

func slug(title string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(strings.TrimSpace(title)) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == ' ' || c == '-' || c == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// setPublic grants or revokes `view` for everyone on a tile.
func (s *Server) setPublic(ctx context.Context, tx pgx.Tx, actor directory.Actor, tileID string, public bool) error {
	g, err := directory.GetGroupByName(ctx, tx, s.TenantID, directory.EveryoneGroup)
	if err != nil {
		return err
	}
	var existing string
	err = tx.QueryRow(ctx, `SELECT id FROM grants WHERE tenant_id=$1 AND subject_kind='group' AND subject_id=$2 AND resource_type='portal.tile' AND resource_id=$3 AND role='viewer' AND revoked_at IS NULL`,
		s.TenantID, g.ID, tileID).Scan(&existing)
	switch {
	case public && err == pgx.ErrNoRows:
		_, err = directory.CreateGrant(ctx, tx, s.TenantID, actor, directory.Grant{SubjectKind: "group", SubjectID: g.ID, Role: "viewer", ResourceType: "portal.tile", ResourceID: tileID}, s.Authz)
		return err
	case !public && err == nil:
		return directory.RevokeGrant(ctx, tx, s.TenantID, actor, existing)
	case err != nil && err != pgx.ErrNoRows:
		return err
	}
	return nil
}

// POST /v1/admin/portal/tiles: a link tile.
func (s *Server) handleCreateTile(w http.ResponseWriter, r *http.Request) {
	var req tileInput
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Title = strings.TrimSpace(req.Title)
	req.Href = strings.TrimSpace(req.Href)
	if req.ID == "" {
		req.ID = slug(req.Title)
	}
	if !tileIDRe.MatchString(req.ID) || req.Title == "" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "title"})
		return
	}
	if !strings.HasPrefix(req.Href, "https://") && !strings.HasPrefix(req.Href, "http://") && !strings.HasPrefix(req.Href, "/") {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "href"})
		return
	}
	if req.Category == "" {
		req.Category = "links"
	}
	if req.Order == 0 {
		req.Order = 100
	}
	attrs := map[string]any{"kind": "link", "href": req.Href, "category": req.Category, "order": req.Order, "icon": strings.TrimSpace(req.Icon),
		"title": req.Title, "description": strings.TrimSpace(req.Description), "builtin": false}
	err := s.tx(r, func(tx pgx.Tx) error {
		if err := directory.CreateResource(r.Context(), tx, s.TenantID, actorOf(r), directory.Resource{Type: "portal.tile", ID: req.ID, ParentType: "portal", ParentID: "root", Attributes: attrs}); err != nil {
			return err
		}
		if req.Public != nil && *req.Public {
			if err := s.setPublic(r.Context(), tx, actorOf(r), req.ID, true); err != nil {
				return err
			}
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "tile.create", TargetType: "portal.tile", TargetID: req.ID,
			Outcome: "ok", Detail: map[string]any{"title": req.Title, "href": req.Href}, CorrelationID: actorOf(r).CorrelationID})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondTile(w, r, req.ID, 201)
}

func (s *Server) respondTile(w http.ResponseWriter, r *http.Request, id string, status int) {
	tiles, _, err := s.loadTiles(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, t := range tiles {
		if t.ID == id {
			s.writeJSON(w, status, s.tileView(locale(r), t))
			return
		}
	}
	s.writeErr(w, r, 404, "request.not_found", map[string]any{"type": "tile"})
}

// PUT /v1/admin/portal/tiles/{id}: title, description, href, category,
// icon, order and public; built-in tiles accept only category, order and public.
func (s *Server) handleUpdateTile(w http.ResponseWriter, r *http.Request) {
	var req tileInput
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	id := r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), `SELECT attributes FROM resources WHERE tenant_id=$1 AND type='portal.tile' AND id=$2 FOR UPDATE`, s.TenantID, id).Scan(&raw); err != nil {
			if err == pgx.ErrNoRows {
				return directory.Err("request.not_found", "type", "tile")
			}
			return err
		}
		attrs := map[string]any{}
		_ = json.Unmarshal(raw, &attrs)
		builtin, _ := attrs["builtin"].(bool)
		if !builtin {
			if t := strings.TrimSpace(req.Title); t != "" {
				attrs["title"] = t
			}
			if req.Description != "" {
				attrs["description"] = strings.TrimSpace(req.Description)
			}
			if h := strings.TrimSpace(req.Href); h != "" {
				if !strings.HasPrefix(h, "https://") && !strings.HasPrefix(h, "http://") && !strings.HasPrefix(h, "/") {
					return directory.Err("request.malformed", "field", "href")
				}
				attrs["href"] = h
			}
			if req.Icon != "" {
				attrs["icon"] = strings.TrimSpace(req.Icon)
			}
		}
		if req.Category != "" {
			attrs["category"] = req.Category
		}
		if req.Order != 0 {
			attrs["order"] = req.Order
		}
		b, _ := json.Marshal(attrs)
		if _, err := tx.Exec(r.Context(), `UPDATE resources SET attributes=$3 WHERE tenant_id=$1 AND type='portal.tile' AND id=$2`, s.TenantID, id, b); err != nil {
			return err
		}
		if req.Public != nil {
			if err := s.setPublic(r.Context(), tx, actorOf(r), id, *req.Public); err != nil {
				return err
			}
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "tile.update", TargetType: "portal.tile", TargetID: id,
			Outcome: "ok", Detail: map[string]any{}, CorrelationID: actorOf(r).CorrelationID})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.respondTile(w, r, id, 200)
}

// DELETE /v1/admin/portal/tiles/{id}: link tiles only; grants on it are revoked.
func (s *Server) handleDeleteTile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(r.Context(), `SELECT attributes FROM resources WHERE tenant_id=$1 AND type='portal.tile' AND id=$2`, s.TenantID, id).Scan(&raw); err != nil {
			if err == pgx.ErrNoRows {
				return directory.Err("request.not_found", "type", "tile")
			}
			return err
		}
		attrs := map[string]any{}
		_ = json.Unmarshal(raw, &attrs)
		if b, _ := attrs["builtin"].(bool); b {
			return directory.Err("request.forbidden", "reason", "builtin_tile")
		}
		if _, err := tx.Exec(r.Context(), `UPDATE grants SET revoked_at=now() WHERE tenant_id=$1 AND resource_type='portal.tile' AND resource_id=$2 AND revoked_at IS NULL`, s.TenantID, id); err != nil {
			return err
		}
		if _, err := tx.Exec(r.Context(), `DELETE FROM resources WHERE tenant_id=$1 AND type='portal.tile' AND id=$2`, s.TenantID, id); err != nil {
			return err
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "tile.delete", TargetType: "portal.tile", TargetID: id,
			Outcome: "ok", Detail: map[string]any{}, CorrelationID: actorOf(r).CorrelationID})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}
