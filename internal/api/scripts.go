package api

// SPEC-scripts: scripts are text objects assigned to device groups (or to
// every device of a type) and run by the agent in position order. The core
// signs what it delivers with the newest CA key so a device runs only what
// the core issued; every run comes back as a record and an audit row.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/authz"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
	"rostor.org/app/internal/ids"
)

// requireAL2 is the floor for anything that changes what runs on every
// workstation as SYSTEM: whatever the grant says, the session must have
// presented two factors.
func (s *Server) requireAL2(w http.ResponseWriter, r *http.Request) bool {
	pres, _ := r.Context().Value(ctxPresented).(authz.Presented)
	if assuranceRank(pres.Assurance) < 2 {
		s.writeErr(w, r, 403, "request.assurance_required", map[string]any{"required": "AL2"})
		return false
	}
	return true
}

type scriptRow struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Language    string    `json:"language"`
	Position    int       `json:"position"`
	Version     int       `json:"version"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   ownerRef  `json:"updated_by"`
	Body        string    `json:"body,omitempty"`
}

func (s *Server) scanScripts(ctx context.Context, where string, args ...any) ([]scriptRow, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, name, description, language, position, version, updated_at, updated_by, body
		FROM scripts WHERE tenant_id=$1 `+where+` ORDER BY position, lower(name), id`, append([]any{s.TenantID}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []scriptRow{}
	for rows.Next() {
		var sc scriptRow
		var by string
		if err := rows.Scan(&sc.ID, &sc.Name, &sc.Description, &sc.Language, &sc.Position, &sc.Version, &sc.UpdatedAt, &by, &sc.Body); err != nil {
			return nil, err
		}
		if ref := s.ownerRef(ctx, by); ref != nil {
			sc.UpdatedBy = *ref
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

func (s *Server) scriptAssignments(ctx context.Context, scriptID string) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT a.id, a.target_kind, a.target_id, a.mode, coalesce(g.name,'')
		FROM script_assignments a LEFT JOIN groups g ON g.tenant_id=a.tenant_id AND g.id=a.target_id AND a.target_kind='group'
		WHERE a.tenant_id=$1 AND a.script_id=$2 ORDER BY a.created_at`, s.TenantID, scriptID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, kind, target, mode, gname string
		if err := rows.Scan(&id, &kind, &target, &mode, &gname); err != nil {
			return nil, err
		}
		name := target
		if kind == "group" {
			name = gname
		}
		out = append(out, map[string]any{"id": id, "target": map[string]string{"kind": kind, "id": target, "name": name}, "mode": mode})
	}
	return out, rows.Err()
}

func (s *Server) scriptRuns(ctx context.Context, scriptID string, limit int) ([]map[string]any, error) {
	rows, err := s.DB.Query(ctx, `SELECT r.id, r.device_id, coalesce(nullif(dp.display_name->>'en',''), dp.id, r.device_id), coalesce(r.principal_id,''),
		coalesce(nullif(pp.display_name->>'en',''), pp.username, ''), r.version, r.mode, r.started_at, r.finished_at, r.exit_code, r.status, r.output_tail
		FROM script_runs r
		LEFT JOIN principals dp ON dp.tenant_id=r.tenant_id AND dp.id=r.device_id
		LEFT JOIN principals pp ON pp.tenant_id=r.tenant_id AND pp.id=r.principal_id
		WHERE r.tenant_id=$1 AND r.script_id=$2 ORDER BY r.created_at DESC LIMIT $3`, s.TenantID, scriptID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, devID, devName, pid, pname, mode, status, tail string
		var version, exit int
		var started, finished time.Time
		if err := rows.Scan(&id, &devID, &devName, &pid, &pname, &version, &mode, &started, &finished, &exit, &status, &tail); err != nil {
			return nil, err
		}
		var principal any
		if pid != "" {
			principal = map[string]string{"id": pid, "name": pname}
		}
		out = append(out, map[string]any{"id": id, "device": map[string]string{"id": devID, "name": devName}, "principal": principal,
			"version": version, "mode": mode, "started_at": started, "finished_at": finished, "exit_code": exit, "status": status, "output_tail": tail})
	}
	return out, rows.Err()
}

func (s *Server) scriptView(ctx context.Context, sc scriptRow, withBody bool) (map[string]any, error) {
	as, err := s.scriptAssignments(ctx, sc.ID)
	if err != nil {
		return nil, err
	}
	last, err := s.scriptRuns(ctx, sc.ID, 1)
	if err != nil {
		return nil, err
	}
	var lastRun any
	if len(last) == 1 {
		lastRun = map[string]any{"at": last[0]["finished_at"], "exit_code": last[0]["exit_code"], "status": last[0]["status"], "device": last[0]["device"]}
	}
	out := map[string]any{"id": sc.ID, "name": sc.Name, "description": sc.Description, "language": sc.Language, "position": sc.Position,
		"version": sc.Version, "updated_at": sc.UpdatedAt, "updated_by": sc.UpdatedBy, "assignments": as, "last_run": lastRun}
	if withBody {
		out["body"] = sc.Body
	}
	return out, nil
}

func (s *Server) auditScript(r *http.Request, action, scriptID string, detail map[string]any) {
	a := actorOf(r)
	s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: action, TargetType: "script", TargetID: scriptID,
		Outcome: "ok", Detail: detail, CorrelationID: a.CorrelationID})
}

// GET /v1/admin/scripts
func (s *Server) handleListScripts(w http.ResponseWriter, r *http.Request) {
	scripts, err := s.scanScripts(r.Context(), "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := []map[string]any{}
	for _, sc := range scripts {
		v, err := s.scriptView(r.Context(), sc, false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, v)
	}
	s.writeJSON(w, 200, map[string]any{"items": items, "total": len(items)})
}

type scriptInput struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Language    *string `json:"language"`
	Body        *string `json:"body"`
}

// POST /v1/admin/scripts
func (s *Server) handleCreateScript(w http.ResponseWriter, r *http.Request) {
	if !s.requireAL2(w, r) {
		return
	}
	var req scriptInput
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name := ""
	if req.Name != nil {
		name = strings.TrimSpace(*req.Name)
	}
	if name == "" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "name"})
		return
	}
	if req.Body == nil || strings.TrimSpace(*req.Body) == "" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "body"})
		return
	}
	lang := "powershell"
	if req.Language != nil && *req.Language != "" {
		lang = *req.Language
	}
	if lang != "powershell" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "language"})
		return
	}
	desc := ""
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	id := ids.New("scr")
	var pos int
	err := s.tx(r, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `SELECT coalesce(max(position),0)+10 FROM scripts WHERE tenant_id=$1`, s.TenantID).Scan(&pos); err != nil {
			return err
		}
		_, err := tx.Exec(r.Context(), `INSERT INTO scripts (tenant_id, id, name, description, language, body, version, position, updated_by)
			VALUES ($1,$2,$3,$4,$5,$6,1,$7,$8)`, s.TenantID, id, name, desc, lang, *req.Body, pos, actorOf(r).ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditScript(r, "script.create", id, map[string]any{"name": name, "version": 1})
	s.respondScript(w, r, id, 201)
}

func (s *Server) respondScript(w http.ResponseWriter, r *http.Request, id string, status int) {
	scripts, err := s.scanScripts(r.Context(), "AND id=$2", id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(scripts) == 0 {
		s.writeErr(w, r, 404, "request.not_found", map[string]any{"type": "script"})
		return
	}
	v, err := s.scriptView(r.Context(), scripts[0], true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs, err := s.scriptRuns(r.Context(), id, 50)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v["runs"] = runs
	s.writeJSON(w, status, v)
}

// GET /v1/admin/scripts/{id}
func (s *Server) handleGetScript(w http.ResponseWriter, r *http.Request) {
	s.respondScript(w, r, r.PathValue("id"), 200)
}

// PUT /v1/admin/scripts/{id}: the version increments when the body changes.
func (s *Server) handleUpdateScript(w http.ResponseWriter, r *http.Request) {
	if !s.requireAL2(w, r) {
		return
	}
	var req scriptInput
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	id := r.PathValue("id")
	var version int
	var bumped bool
	err := s.tx(r, func(tx pgx.Tx) error {
		var name, desc, body string
		if err := tx.QueryRow(r.Context(), `SELECT name, description, body, version FROM scripts WHERE tenant_id=$1 AND id=$2 FOR UPDATE`, s.TenantID, id).Scan(&name, &desc, &body, &version); err != nil {
			if err == pgx.ErrNoRows {
				return directory.Err("request.not_found", "type", "script")
			}
			return err
		}
		if req.Name != nil && strings.TrimSpace(*req.Name) != "" {
			name = strings.TrimSpace(*req.Name)
		}
		if req.Description != nil {
			desc = strings.TrimSpace(*req.Description)
		}
		if req.Body != nil && strings.TrimSpace(*req.Body) != "" && *req.Body != body {
			body = *req.Body
			version++
			bumped = true
		}
		_, err := tx.Exec(r.Context(), `UPDATE scripts SET name=$3, description=$4, body=$5, version=$6, updated_at=now(), updated_by=$7 WHERE tenant_id=$1 AND id=$2`,
			s.TenantID, id, name, desc, body, version, actorOf(r).ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditScript(r, "script.update", id, map[string]any{"version": version, "body_changed": bumped})
	s.respondScript(w, r, id, 200)
}

// DELETE /v1/admin/scripts/{id}: assignments go with it; runs stay.
func (s *Server) handleDeleteScript(w http.ResponseWriter, r *http.Request) {
	if !s.requireAL2(w, r) {
		return
	}
	id := r.PathValue("id")
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM scripts WHERE tenant_id=$1 AND id=$2`, s.TenantID, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return directory.Err("request.not_found", "type", "script")
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditScript(r, "script.delete", id, map[string]any{})
	w.WriteHeader(204)
}

// PUT /v1/admin/scripts/order {ids}: positions follow the list; scripts not
// named keep their relative order after the named ones.
func (s *Server) handleOrderScripts(w http.ResponseWriter, r *http.Request) {
	if !s.requireAL2(w, r) {
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	err := s.tx(r, func(tx pgx.Tx) error {
		pos := 10
		seen := map[string]bool{}
		for _, id := range req.IDs {
			if seen[id] {
				continue
			}
			seen[id] = true
			if _, err := tx.Exec(r.Context(), `UPDATE scripts SET position=$3 WHERE tenant_id=$1 AND id=$2`, s.TenantID, id, pos); err != nil {
				return err
			}
			pos += 10
		}
		rows, err := tx.Query(r.Context(), `SELECT id FROM scripts WHERE tenant_id=$1 ORDER BY position, lower(name), id`, s.TenantID)
		if err != nil {
			return err
		}
		var rest []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			if !seen[id] {
				rest = append(rest, id)
			}
		}
		rows.Close()
		for _, id := range rest {
			if _, err := tx.Exec(r.Context(), `UPDATE scripts SET position=$3 WHERE tenant_id=$1 AND id=$2`, s.TenantID, id, pos); err != nil {
				return err
			}
			pos += 10
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditScript(r, "script.order", "", map[string]any{"ids": req.IDs})
	w.WriteHeader(204)
}

// POST /v1/admin/scripts/{id}/assignments {target_kind, target, mode}
func (s *Server) handleAssignScript(w http.ResponseWriter, r *http.Request) {
	if !s.requireAL2(w, r) {
		return
	}
	var req struct {
		TargetKind string `json:"target_kind"`
		Target     string `json:"target"`
		Mode       string `json:"mode"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Mode != "immediate" && req.Mode != "signin" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "mode"})
		return
	}
	id := r.PathValue("id")
	targetID, targetName := "", ""
	switch req.TargetKind {
	case "all":
		targetID = strings.TrimSpace(req.Target)
		if targetID == "" {
			targetID = "workstation"
		}
		targetName = targetID
	case "group":
		g, err := directory.GetGroupByName(r.Context(), s.DB, s.TenantID, req.Target)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		targetID, targetName = g.ID, g.Name
	default:
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "target_kind"})
		return
	}
	aid := ids.New("sas")
	err := s.tx(r, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM scripts WHERE tenant_id=$1 AND id=$2)`, s.TenantID, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return directory.Err("request.not_found", "type", "script")
		}
		_, err := tx.Exec(r.Context(), `INSERT INTO script_assignments (tenant_id, id, script_id, target_kind, target_id, mode) VALUES ($1,$2,$3,$4,$5,$6)`,
			s.TenantID, aid, id, req.TargetKind, targetID, req.Mode)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditScript(r, "script.assign", id, map[string]any{"assignment": aid, "target": req.TargetKind + ":" + targetName, "mode": req.Mode})
	s.writeJSON(w, 201, map[string]any{"id": aid, "target": map[string]string{"kind": req.TargetKind, "id": targetID, "name": targetName}, "mode": req.Mode})
}

// DELETE /v1/admin/scripts/{id}/assignments/{aid}
func (s *Server) handleUnassignScript(w http.ResponseWriter, r *http.Request) {
	if !s.requireAL2(w, r) {
		return
	}
	id, aid := r.PathValue("id"), r.PathValue("aid")
	err := s.tx(r, func(tx pgx.Tx) error {
		tag, err := tx.Exec(r.Context(), `DELETE FROM script_assignments WHERE tenant_id=$1 AND script_id=$2 AND id=$3`, s.TenantID, id, aid)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return directory.Err("request.not_found", "type", "assignment")
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.auditScript(r, "script.unassign", id, map[string]any{"assignment": aid})
	w.WriteHeader(204)
}

// GET /v1/admin/scripts/{id}/runs
func (s *Server) handleScriptRuns(w http.ResponseWriter, r *http.Request) {
	pg := pageOf(r)
	runs, err := s.scriptRuns(r.Context(), r.PathValue("id"), pg.Limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"items": runs, "total": len(runs)})
}

// ---- device side ----------------------------------------------------------------

// scriptSigningInput is what the signature covers: id, version and body,
// newline-separated, so neither the text nor the version can be swapped.
func scriptSigningInput(id string, version int, body string) []byte {
	return []byte(id + "\n" + strconv.Itoa(version) + "\n" + body)
}

// GET /v1/devices/self/scripts: everything assigned to this device, by
// type or by group membership, in position order, each signed.
func (s *Server) handleDeviceScripts(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	rt, _ := d.Principal.Attributes["resource_type"].(string)
	paths, err := directory.GroupPaths(r.Context(), s.DB, s.TenantID, d.Principal.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	groups := []string{}
	for g := range paths {
		groups = append(groups, g)
	}
	rows, err := s.DB.Query(r.Context(), `SELECT DISTINCT sc.id, sc.name, sc.language, sc.version, sc.position, sc.body, a.mode
		FROM script_assignments a JOIN scripts sc ON sc.tenant_id=a.tenant_id AND sc.id=a.script_id
		WHERE a.tenant_id=$1 AND ((a.target_kind='all' AND a.target_id=$2) OR (a.target_kind='group' AND a.target_id = ANY($3)))
		ORDER BY sc.position, sc.id, a.mode`, s.TenantID, rt, groups)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type entry struct {
		id, name, lang, body, mode string
		version, position          int
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.name, &e.lang, &e.version, &e.position, &e.body, &e.mode); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		entries = append(entries, e)
	}
	rows.Close()
	var caID string
	var key *ecdsa.PrivateKey
	if err := s.DB.Tx(r.Context(), func(tx pgx.Tx) error {
		id, ca, err := s.Devices.NewestCA(r.Context(), tx, s.TenantID)
		if err != nil {
			return err
		}
		caID, key = id, ca.Key
		return nil
	}); err != nil {
		s.fail(w, r, err)
		return
	}
	out := []map[string]any{}
	for _, e := range entries {
		sum := sha256.Sum256(scriptSigningInput(e.id, e.version, e.body))
		sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, map[string]any{"id": e.id, "name": e.name, "language": e.lang, "version": e.version, "position": e.position,
			"mode": e.mode, "body": e.body, "signature": base64.StdEncoding.EncodeToString(sig), "signer": caID})
	}
	s.writeJSON(w, 200, map[string]any{"scripts": out})
}

// POST /v1/devices/self/scripts/{id}/runs
func (s *Server) handleDeviceScriptRun(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	var req struct {
		Version     int       `json:"version"`
		Mode        string    `json:"mode"`
		PrincipalID string    `json:"principal_id"`
		StartedAt   time.Time `json:"started_at"`
		FinishedAt  time.Time `json:"finished_at"`
		ExitCode    int       `json:"exit_code"`
		Status      string    `json:"status"`
		OutputTail  string    `json:"output_tail"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	switch req.Status {
	case "ok", "failed", "timeout", "error":
	default:
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "status"})
		return
	}
	if req.Mode != "immediate" && req.Mode != "signin" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "mode"})
		return
	}
	if len(req.OutputTail) > 4096 {
		req.OutputTail = req.OutputTail[len(req.OutputTail)-4096:]
	}
	id := r.PathValue("id")
	runID := ids.New("run")
	err := s.tx(r, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM scripts WHERE tenant_id=$1 AND id=$2)`, s.TenantID, id).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return directory.Err("request.not_found", "type", "script")
		}
		if _, err := tx.Exec(r.Context(), `INSERT INTO script_runs (tenant_id, id, script_id, version, device_id, principal_id, mode, started_at, finished_at, exit_code, status, output_tail)
			VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),$7,$8,$9,$10,$11,$12)`,
			s.TenantID, runID, id, req.Version, d.Principal.ID, req.PrincipalID, req.Mode, req.StartedAt, req.FinishedAt, req.ExitCode, req.Status, req.OutputTail); err != nil {
			return err
		}
		outcome := "ok"
		if req.Status != "ok" {
			outcome = "error"
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: "device", ActorID: d.Principal.ID, Action: "script.run",
			TargetType: "script", TargetID: id, Outcome: outcome, Detail: map[string]any{"run": runID, "version": req.Version, "mode": req.Mode,
				"principal_id": req.PrincipalID, "exit_code": req.ExitCode, "status": req.Status}, CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 201, map[string]any{"id": runID})
}
