package api

// Deputy self-update from the console. The wanted version is always the
// core's own; policy decides whether every outdated device is told (auto)
// or only the ones an admin marked (manual). The core serves the bundle it
// already caches and signs its hash with the CA key, so a device installs
// only what this core vouched for; the device reports the outcome.

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/devices"
	"rostor.org/app/internal/directory"
)

// deputyUpdatePolicy is the tenant's `deputy.update` (devices domain): auto | manual.
func (s *Server) deputyUpdatePolicy(ctx context.Context) string {
	pol, _, err := directory.EffectivePolicy(ctx, s.DB, s.TenantID, "devices", "")
	if err != nil {
		return "manual"
	}
	if v, _ := pol["deputy.update"].(string); v == "auto" {
		return v
	}
	return "manual"
}

// GET /v1/admin/settings/devices
func (s *Server) handleGetDeviceSettings(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, 200, map[string]any{"deputy": map[string]string{"update": s.deputyUpdatePolicy(r.Context())}})
}

// PUT /v1/admin/settings/devices {deputy:{update}}
func (s *Server) handlePutDeviceSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Deputy struct {
			Update string `json:"update"`
		} `json:"deputy"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	switch req.Deputy.Update {
	case "auto", "manual":
	default:
		s.fail(w, r, directory.Err("request.malformed", "field", "deputy.update"))
		return
	}
	doc := map[string]any{"deputy.update": req.Deputy.Update}
	err := s.tx(r, func(tx pgx.Tx) error {
		raw, _ := json.Marshal(doc)
		tag, err := tx.Exec(r.Context(), `UPDATE policies p SET document=$3 FROM policy_assignments a
			WHERE p.tenant_id=$1 AND p.id=a.policy_id AND a.tenant_id=p.tenant_id AND a.group_id IS NULL AND p.domain='devices' AND p.priority=0 AND p.name=$2`,
			s.TenantID, "tenant-devices", raw)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			if _, err := directory.CreatePolicy(r.Context(), tx, s.TenantID, actorOf(r), "tenant-devices", "devices", 0, doc, ""); err != nil {
				return err
			}
		}
		_, err = audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: actorOf(r).Kind, ActorID: actorOf(r).ID, Action: "policy.update",
			TargetType: "policy", TargetID: "tenant-devices", Outcome: "ok", Detail: doc, CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.handleGetDeviceSettings(w, r)
}

func (s *Server) setUpdateWanted(ctx context.Context, q directory.Querier, principalID string, wanted bool) error {
	raw, _ := json.Marshal(map[string]any{"update_wanted": wanted})
	_, err := q.Exec(ctx, `UPDATE principals SET attributes = attributes || $3::jsonb, updated_at=now() WHERE tenant_id=$1 AND id=$2 AND kind='device'`, s.TenantID, principalID, raw)
	return err
}

// POST /v1/admin/devices/{id}/update: mark one device.
func (s *Server) handleMarkDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	p, err := s.resolveUser(r, s.DB, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p.Kind != "device" {
		s.writeErr(w, r, 404, "request.not_found", map[string]any{"type": "device"})
		return
	}
	if err := s.setUpdateWanted(r.Context(), s.DB, p.ID, true); err != nil {
		s.fail(w, r, err)
		return
	}
	a := actorOf(r)
	s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "device.update_marked", TargetType: "device", TargetID: p.ID,
		Outcome: "ok", Detail: map[string]any{"version": s.Version}, CorrelationID: a.CorrelationID})
	w.WriteHeader(202)
}

// DELETE /v1/admin/devices/{id}/update: take back a queued update.
func (s *Server) handleUnmarkDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	p, err := s.resolveUser(r, s.DB, r.PathValue("id"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p.Kind != "device" {
		s.writeErr(w, r, 404, "request.not_found", map[string]any{"type": "device"})
		return
	}
	if err := s.setUpdateWanted(r.Context(), s.DB, p.ID, false); err != nil {
		s.fail(w, r, err)
		return
	}
	a := actorOf(r)
	s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "device.update_cancelled", TargetType: "device", TargetID: p.ID,
		Outcome: "ok", Detail: map[string]any{}, CorrelationID: a.CorrelationID})
	w.WriteHeader(204)
}

// POST /v1/admin/devices/update-all: every trusted device on another version.
func (s *Server) handleMarkAllDeviceUpdates(w http.ResponseWriter, r *http.Request) {
	// Deputies from before v0.14.0 report a bare "0.1.0" and have no updater:
	// marking them would only show "updating" forever. They need one manual install.
	rows, err := s.DB.Query(r.Context(), `SELECT d.principal_id FROM devices d WHERE d.tenant_id=$1 AND d.lifecycle IN ('enrolled','trusted')
		AND coalesce(d.posture->>'deputy_version', d.posture->>'agent_version', '') <> $2
		AND coalesce(d.posture->>'deputy_version', '') LIKE 'v%'`, s.TenantID, s.Version)
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
	a := actorOf(r)
	for _, id := range ids {
		if err := s.setUpdateWanted(r.Context(), s.DB, id, true); err != nil {
			s.fail(w, r, err)
			return
		}
		s.auditEvent(r.Context(), audit.Event{ActorKind: a.Kind, ActorID: a.ID, Action: "device.update_marked", TargetType: "device", TargetID: id,
			Outcome: "ok", Detail: map[string]any{"version": s.Version, "all": true}, CorrelationID: a.CorrelationID})
	}
	s.writeJSON(w, 200, map[string]any{"marked": len(ids)})
}

// bundleDigest caches the sha256 and size of the cached bundle per file
// identity, so a heartbeat from every device does not rehash 3 MB.
type bundleDigest struct {
	mu   sync.Mutex
	path string
	mod  time.Time
	size int64
	sum  string
}

var digests bundleDigest

func hashFile(path string) (sum string, size int64, err error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", 0, err
	}
	digests.mu.Lock()
	defer digests.mu.Unlock()
	if digests.path == path && digests.mod.Equal(st.ModTime()) && digests.size == st.Size() {
		return digests.sum, digests.size, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", 0, err
	}
	digests.path, digests.mod, digests.size, digests.sum = path, st.ModTime(), st.Size(), hex.EncodeToString(h.Sum(nil))
	return digests.sum, digests.size, nil
}

func bundleSigningInput(version, sum string) []byte { return []byte("bundle\n" + version + "\n" + sum) }

func deputyVersionOf(posture map[string]any) string {
	if v, _ := posture["deputy_version"].(string); v != "" {
		return v
	}
	v, _ := posture["agent_version"].(string) // deputies from before the rename
	return v
}

// GET /v1/devices/self/update
func (s *Server) handleDeviceUpdate(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	var posture map[string]any
	var raw []byte
	if err := s.DB.QueryRow(r.Context(), `SELECT posture FROM devices WHERE tenant_id=$1 AND principal_id=$2`, s.TenantID, d.Principal.ID).Scan(&raw); err == nil {
		_ = json.Unmarshal(raw, &posture)
	}
	wanted, _ := d.Principal.Attributes["update_wanted"].(bool)
	if !wanted && s.deputyUpdatePolicy(r.Context()) == "auto" && deputyVersionOf(posture) != s.Version {
		wanted = true
	}
	if !wanted || deputyVersionOf(posture) == s.Version {
		s.writeJSON(w, 200, map[string]any{"update": nil})
		return
	}
	path, err := s.ensureBundle(r.Context(), windowsBundle)
	if err != nil {
		s.writeErr(w, r, 502, "download.unavailable", map[string]any{"detail": err.Error()})
		return
	}
	sum, size, err := hashFile(path)
	if err != nil {
		s.fail(w, r, err)
		return
	}
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
	digest := sha256.Sum256(bundleSigningInput(s.Version, sum))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeJSON(w, 200, map[string]any{"update": map[string]any{"version": s.Version, "sha256": sum, "size": size,
		"signature": base64.StdEncoding.EncodeToString(sig), "signer": caID}})
}

// GET /v1/devices/self/update/bundle
func (s *Server) handleDeviceUpdateBundle(w http.ResponseWriter, r *http.Request) {
	path, err := s.ensureBundle(r.Context(), windowsBundle)
	if err != nil {
		s.writeErr(w, r, 502, "download.unavailable", map[string]any{"detail": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	http.ServeFile(w, r, path)
}

// POST /v1/devices/self/update/runs
func (s *Server) handleDeviceUpdateRun(w http.ResponseWriter, r *http.Request) {
	d := r.Context().Value(ctxDevice).(*devices.Device)
	var req struct {
		Version     string `json:"version"`
		Status      string `json:"status"`
		FromVersion string `json:"from_version"`
		OutputTail  string `json:"output_tail"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Status != "ok" && req.Status != "failed" {
		s.writeErr(w, r, 400, "request.malformed", map[string]any{"field": "status"})
		return
	}
	if len(req.OutputTail) > 4096 {
		req.OutputTail = req.OutputTail[len(req.OutputTail)-4096:]
	}
	now := time.Now().UTC()
	result := map[string]any{"version": req.Version, "status": req.Status, "at": now, "from_version": req.FromVersion, "output_tail": strings.TrimSpace(req.OutputTail)}
	err := s.tx(r, func(tx pgx.Tx) error {
		if err := devices.UpdatePosture(r.Context(), tx, s.TenantID, d.Principal.ID, map[string]any{"deputy_update": result}); err != nil {
			return err
		}
		// One attempt per mark, whatever the outcome; an admin marks again to retry.
		if err := s.setUpdateWanted(r.Context(), tx, d.Principal.ID, false); err != nil {
			return err
		}
		outcome := "ok"
		if req.Status != "ok" {
			outcome = "error"
		}
		_, err := audit.Append(r.Context(), tx, s.TenantID, audit.Event{ActorKind: "device", ActorID: d.Principal.ID, Action: "deputy.update",
			TargetType: "release", TargetID: req.Version, Outcome: outcome, Detail: map[string]any{"status": req.Status, "from_version": req.FromVersion}, CorrelationID: corrOf(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(201)
}
