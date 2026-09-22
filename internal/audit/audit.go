// Package audit is the tamper-evident, hash-chained audit log (spec §14).
// Every entry links to the previous one per tenant; the database refuses
// updates and deletes. Appends happen inside the caller's transaction so an
// audited mutation and its audit record commit or roll back together.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type Event struct {
	ActorKind      string // user | service | device | system
	ActorID        string
	Action         string // e.g. "verify", "user.create", "grant.create"
	TargetType     string
	TargetID       string
	CredentialType string // set on every authenticated act (§14)
	Assurance      string
	Outcome        string // allow | deny | ok | error
	Detail         map[string]any
	CorrelationID  string
}

// Append writes one event to the chain within tx. The per-tenant head row is
// locked so sequence numbers are gap-free under concurrency.
func Append(ctx context.Context, tx pgx.Tx, tenantID string, e Event) (int64, error) {
	var seq int64
	var prev []byte
	err := tx.QueryRow(ctx, `SELECT seq, hash FROM audit_heads WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&seq, &prev)
	if err == pgx.ErrNoRows {
		seq, prev = 0, make([]byte, 32)
		if _, err := tx.Exec(ctx, `INSERT INTO audit_heads(tenant_id, seq, hash) VALUES($1, 0, $2)`, tenantID, prev); err != nil {
			return 0, err
		}
	} else if err != nil {
		return 0, err
	}
	seq++
	// Postgres keeps microseconds; hash what will be stored.
	ts := time.Now().UTC().Truncate(time.Microsecond)
	if e.Detail == nil {
		e.Detail = map[string]any{}
	}
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return 0, err
	}
	h := chainHash(prev, tenantID, seq, ts, e, detail)

	_, err = tx.Exec(ctx, `INSERT INTO audit_events
		(tenant_id, seq, ts, actor_kind, actor_id, action, target_type, target_id,
		 credential_type, assurance, outcome, detail, correlation_id, prev_hash, hash)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		tenantID, seq, ts, e.ActorKind, e.ActorID, e.Action, nz(e.TargetType), nz(e.TargetID),
		nz(e.CredentialType), nz(e.Assurance), e.Outcome, detail, e.CorrelationID, prev, h)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_heads SET seq=$2, hash=$3 WHERE tenant_id=$1`, tenantID, seq, h); err != nil {
		return 0, err
	}
	return seq, nil
}

// chainHash covers every stored column so any edit breaks the chain.
func chainHash(prev []byte, tenantID string, seq int64, ts time.Time, e Event, detail []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	h.Write([]byte(tenantID))
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(seq)))
	h.Write(binary.BigEndian.AppendUint64(nil, uint64(ts.UnixNano())))
	for _, s := range []string{e.ActorKind, e.ActorID, e.Action, e.TargetType, e.TargetID, e.CredentialType, e.Assurance, e.Outcome, e.CorrelationID} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	h.Write(detail)
	return h.Sum(nil)
}

func nz(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// VerifyChain recomputes every hash for a tenant and reports the first
// sequence number that fails, or 0 if the chain is intact.
func VerifyChain(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, tenantID string) (int64, error) {
	rows, err := q.Query(ctx, `SELECT seq, ts, actor_kind, actor_id, action,
		coalesce(target_type,''), coalesce(target_id,''), coalesce(credential_type,''), coalesce(assurance,''),
		outcome, detail, correlation_id, prev_hash, hash
		FROM audit_events WHERE tenant_id=$1 ORDER BY seq`, tenantID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	prev := make([]byte, 32)
	for rows.Next() {
		var seq int64
		var ts time.Time
		var e Event
		var detail, prevHash, hash []byte
		if err := rows.Scan(&seq, &ts, &e.ActorKind, &e.ActorID, &e.Action, &e.TargetType, &e.TargetID,
			&e.CredentialType, &e.Assurance, &e.Outcome, &detail, &e.CorrelationID, &prevHash, &hash); err != nil {
			return 0, err
		}
		if string(prevHash) != string(prev) || string(chainHash(prev, tenantID, seq, ts, e, detail)) != string(hash) {
			return seq, nil
		}
		prev = hash
	}
	return 0, rows.Err()
}
