// Package directory owns the core object model (spec §2): principals, groups,
// resources, roles, grants and policies. It is storage plus invariants; it
// never evaluates permissions (that is package authz) and never verifies
// credentials (that is package auth).
package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"rostor.org/app/internal/audit"
	"rostor.org/app/internal/ids"
)

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ErrCode is a stable machine-readable error (spec §9). The HTTP layer maps
// it to a status; the catalog renders it for humans.
type ErrCode struct {
	Code   string
	Params map[string]any
}

func (e *ErrCode) Error() string { return e.Code }

func Err(code string, kv ...any) error {
	p := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		p[fmt.Sprint(kv[i])] = kv[i+1]
	}
	return &ErrCode{Code: code, Params: p}
}

func CodeOf(err error) (string, bool) {
	var e *ErrCode
	if errors.As(err, &e) {
		return e.Code, true
	}
	return "", false
}

// Actor identifies who is performing a mutation, for audit.
type Actor struct {
	Kind          string
	ID            string
	CorrelationID string
}

func (a Actor) corr() string {
	if a.CorrelationID == "" {
		return ids.New("corr")
	}
	return a.CorrelationID
}

// ---- Principals -------------------------------------------------------------

type Principal struct {
	ID          string            `json:"id"`
	Kind        string            `json:"kind"`
	Username    string            `json:"username,omitempty"`
	DisplayName map[string]string `json:"display_name"`
	State       string            `json:"state"`
	Attributes  map[string]any    `json:"attributes"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// usernameRe is deliberately conservative: it is also the shape the Windows
// agent derives a local account name from (contract §3).
var usernameRe = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)

func ValidUsername(u string) bool { return usernameRe.MatchString(u) }

func CreatePrincipal(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, p Principal) (*Principal, error) {
	switch p.Kind {
	case "user", "service", "device":
	default:
		return nil, Err("request.malformed", "field", "kind")
	}
	p.Username = strings.ToLower(strings.TrimSpace(p.Username))
	if p.Kind == "user" && !ValidUsername(p.Username) {
		return nil, Err("request.malformed", "field", "username")
	}
	if p.State == "" {
		p.State = "active"
	}
	if p.DisplayName == nil {
		p.DisplayName = map[string]string{}
	}
	if p.Attributes == nil {
		p.Attributes = map[string]any{}
	}
	p.ID = ids.New(map[string]string{"user": "usr", "service": "svc", "device": "dev"}[p.Kind])
	dn, _ := json.Marshal(p.DisplayName)
	attrs, _ := json.Marshal(p.Attributes)
	err := tx.QueryRow(ctx, `INSERT INTO principals (tenant_id, id, kind, username, display_name, state, attributes)
		VALUES ($1,$2,$3,NULLIF($4,''),$5,$6,$7) RETURNING created_at, updated_at`,
		tenantID, p.ID, p.Kind, p.Username, dn, p.State, attrs).Scan(&p.CreatedAt, &p.UpdatedAt)
	if isUnique(err) {
		return nil, Err("request.conflict", "field", "username")
	}
	if err != nil {
		return nil, err
	}
	_, err = audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "principal.create", TargetType: "principal", TargetID: p.ID, Outcome: "ok",
		Detail: map[string]any{"kind": p.Kind, "username": p.Username}, CorrelationID: actor.corr()})
	if err != nil {
		return nil, err
	}
	if err := emit(ctx, tx, tenantID, p.Kind+".created", actor.ID, "principal", p.ID, nil, actor.corr()); err != nil {
		return nil, err
	}
	return &p, nil
}

func GetPrincipal(ctx context.Context, q Querier, tenantID, id string) (*Principal, error) {
	return scanPrincipal(q.QueryRow(ctx, `SELECT id, kind, coalesce(username,''), display_name, state, attributes, created_at, updated_at
		FROM principals WHERE tenant_id=$1 AND id=$2`, tenantID, id))
}

func GetPrincipalByUsername(ctx context.Context, q Querier, tenantID, username string) (*Principal, error) {
	return scanPrincipal(q.QueryRow(ctx, `SELECT id, kind, coalesce(username,''), display_name, state, attributes, created_at, updated_at
		FROM principals WHERE tenant_id=$1 AND lower(username)=lower($2)`, tenantID, username))
}

func scanPrincipal(row pgx.Row) (*Principal, error) {
	var p Principal
	var dn, attrs []byte
	err := row.Scan(&p.ID, &p.Kind, &p.Username, &dn, &p.State, &attrs, &p.CreatedAt, &p.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, Err("principal.not_found")
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(dn, &p.DisplayName)
	_ = json.Unmarshal(attrs, &p.Attributes)
	return &p, nil
}

// SetPrincipalState performs a lifecycle transition. Suspension is the one
// deny escape hatch (§3.2) and is audited as such; in this single-node slice
// it is Immediate, which is stricter than the Priority class the spec bounds.
func SetPrincipalState(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, id, state string) error {
	switch state {
	case "applicant", "invited", "active", "suspended", "deprovisioned", "archived":
	default:
		return Err("request.malformed", "field", "state")
	}
	var before string
	err := tx.QueryRow(ctx, `UPDATE principals SET state=$3, updated_at=now() WHERE tenant_id=$1 AND id=$2
		RETURNING (SELECT state FROM principals WHERE tenant_id=$1 AND id=$2)`, tenantID, id, state).Scan(&before)
	if err == pgx.ErrNoRows {
		return Err("principal.not_found")
	}
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "principal.state", TargetType: "principal", TargetID: id, Outcome: "ok",
		Detail: map[string]any{"before": before, "after": state}, CorrelationID: actor.corr()}); err != nil {
		return err
	}
	evt := "user.state_changed"
	if state == "suspended" {
		evt = "user.suspended"
	}
	return emit(ctx, tx, tenantID, evt, actor.ID, "principal", id, map[string]any{"before": before, "after": state}, actor.corr())
}

// ---- Groups -----------------------------------------------------------------

type Group struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	DisplayName map[string]string `json:"display_name"`
	Kind        string            `json:"kind"`
}

func CreateGroup(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, name string, display map[string]string) (*Group, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !usernameRe.MatchString(name) {
		return nil, Err("request.malformed", "field", "name")
	}
	if display == nil {
		display = map[string]string{}
	}
	g := &Group{ID: ids.New("grp"), Name: name, DisplayName: display, Kind: "static"}
	dn, _ := json.Marshal(display)
	if _, err := tx.Exec(ctx, `INSERT INTO groups (tenant_id, id, name, display_name) VALUES ($1,$2,$3,$4)`, tenantID, g.ID, name, dn); err != nil {
		if isUnique(err) {
			return nil, Err("request.conflict", "field", "name")
		}
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "group.create", TargetType: "group", TargetID: g.ID, Outcome: "ok",
		Detail: map[string]any{"name": name}, CorrelationID: actor.corr()}); err != nil {
		return nil, err
	}
	return g, emit(ctx, tx, tenantID, "group.created", actor.ID, "group", g.ID, nil, actor.corr())
}

func GetGroupByName(ctx context.Context, q Querier, tenantID, name string) (*Group, error) {
	var g Group
	var dn []byte
	err := q.QueryRow(ctx, `SELECT id, name, display_name, kind FROM groups WHERE tenant_id=$1 AND name=$2`, tenantID, strings.ToLower(name)).
		Scan(&g.ID, &g.Name, &dn, &g.Kind)
	if err == pgx.ErrNoRows {
		return nil, Err("request.not_found", "type", "group")
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(dn, &g.DisplayName)
	return &g, nil
}

// AddGroupMember adds a principal or group. Nested groups are allowed; cycles
// are rejected at write time (§2.2) by checking whether the group being added
// already contains the target group transitively.
func AddGroupMember(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, groupID, memberKind, memberID string) error {
	if memberKind != "principal" && memberKind != "group" {
		return Err("request.malformed", "field", "member_kind")
	}
	if memberKind == "group" {
		if memberID == groupID {
			return Err("request.conflict", "reason", "cycle")
		}
		closure, err := GroupClosure(ctx, tx, tenantID, "group", groupID)
		if err != nil {
			return err
		}
		for _, g := range closure {
			if g == memberID {
				return Err("request.conflict", "reason", "cycle")
			}
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO group_members (tenant_id, group_id, member_kind, member_id) VALUES ($1,$2,$3,$4)
		ON CONFLICT DO NOTHING`, tenantID, groupID, memberKind, memberID)
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "group.member_add", TargetType: "group", TargetID: groupID, Outcome: "ok",
		Detail: map[string]any{"member_kind": memberKind, "member_id": memberID}, CorrelationID: actor.corr()}); err != nil {
		return err
	}
	return emit(ctx, tx, tenantID, "group.member_added", actor.ID, "group", groupID,
		map[string]any{"member_kind": memberKind, "member_id": memberID}, actor.corr())
}

func RemoveGroupMember(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, groupID, memberKind, memberID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM group_members WHERE tenant_id=$1 AND group_id=$2 AND member_kind=$3 AND member_id=$4`,
		tenantID, groupID, memberKind, memberID); err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "group.member_remove", TargetType: "group", TargetID: groupID, Outcome: "ok",
		Detail: map[string]any{"member_kind": memberKind, "member_id": memberID}, CorrelationID: actor.corr()}); err != nil {
		return err
	}
	return emit(ctx, tx, tenantID, "group.member_removed", actor.ID, "group", groupID,
		map[string]any{"member_kind": memberKind, "member_id": memberID}, actor.corr())
}

// GroupClosure returns every group the member belongs to, directly or through
// nesting. The path information for Why() is produced by GroupPaths.
func GroupClosure(ctx context.Context, q Querier, tenantID, memberKind, memberID string) ([]string, error) {
	rows, err := q.Query(ctx, `WITH RECURSIVE up AS (
			SELECT group_id FROM group_members WHERE tenant_id=$1 AND member_kind=$2 AND member_id=$3
			UNION
			SELECT gm.group_id FROM group_members gm JOIN up ON gm.member_kind='group' AND gm.member_id=up.group_id WHERE gm.tenant_id=$1
		) SELECT group_id FROM up`, tenantID, memberKind, memberID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupPaths returns, for each group in the closure, one membership path from
// the principal (e.g. ["grp_a","grp_b"] means principal ∈ a ⊂ b).
func GroupPaths(ctx context.Context, q Querier, tenantID, principalID string) (map[string][]string, error) {
	rows, err := q.Query(ctx, `WITH RECURSIVE up AS (
			SELECT group_id, ARRAY[group_id] AS path FROM group_members WHERE tenant_id=$1 AND member_kind='principal' AND member_id=$2
			UNION ALL
			SELECT gm.group_id, up.path || gm.group_id FROM group_members gm JOIN up ON gm.member_kind='group' AND gm.member_id=up.group_id
			WHERE gm.tenant_id=$1 AND NOT gm.group_id = ANY(up.path)
		) SELECT DISTINCT ON (group_id) group_id, path FROM up ORDER BY group_id, array_length(path,1)`, tenantID, principalID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var g string
		var path []string
		if err := rows.Scan(&g, &path); err != nil {
			return nil, err
		}
		out[g] = path
	}
	return out, rows.Err()
}

// ---- Resources & roles ------------------------------------------------------

type Resource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	ParentType string         `json:"parent_type,omitempty"`
	ParentID   string         `json:"parent_id,omitempty"`
	Attributes map[string]any `json:"attributes"`
}

func CreateResource(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, r Resource) error {
	if r.Type == "" || r.ID == "" {
		return Err("request.malformed", "field", "resource")
	}
	if r.Attributes == nil {
		r.Attributes = map[string]any{}
	}
	attrs, _ := json.Marshal(r.Attributes)
	_, err := tx.Exec(ctx, `INSERT INTO resources (tenant_id, type, id, parent_type, parent_id, attributes)
		VALUES ($1,$2,$3,NULLIF($4,''),NULLIF($5,''),$6)`, tenantID, r.Type, r.ID, r.ParentType, r.ParentID, attrs)
	if isUnique(err) {
		return Err("request.conflict", "field", "resource")
	}
	if err != nil {
		return err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "resource.create", TargetType: r.Type, TargetID: r.ID, Outcome: "ok", CorrelationID: actor.corr()}); err != nil {
		return err
	}
	return emit(ctx, tx, tenantID, "resource.created", actor.ID, r.Type, r.ID, nil, actor.corr())
}

// ResourceChain returns the resource and its ancestors, nearest first. An
// unregistered resource is returned as a single synthetic element so a grant
// on a registered parent still cannot apply (there is no parent to find).
func ResourceChain(ctx context.Context, q Querier, tenantID, typ, id string) ([]Resource, error) {
	var chain []Resource
	seen := map[string]bool{}
	for typ != "" && id != "" && !seen[typ+"/"+id] {
		seen[typ+"/"+id] = true
		var r Resource
		var pt, pid *string
		var attrs []byte
		err := q.QueryRow(ctx, `SELECT type, id, parent_type, parent_id, attributes FROM resources WHERE tenant_id=$1 AND type=$2 AND id=$3`,
			tenantID, typ, id).Scan(&r.Type, &r.ID, &pt, &pid, &attrs)
		if err == pgx.ErrNoRows {
			if len(chain) == 0 {
				return []Resource{{Type: typ, ID: id, Attributes: map[string]any{}}}, nil
			}
			return chain, nil
		}
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal(attrs, &r.Attributes)
		if pt != nil {
			r.ParentType = *pt
		}
		if pid != nil {
			r.ParentID = *pid
		}
		chain = append(chain, r)
		typ, id = r.ParentType, r.ParentID
	}
	return chain, nil
}

type Role struct {
	ResourceType string   `json:"resource_type"`
	Name         string   `json:"name"`
	Permissions  []string `json:"permissions"`
}

func UpsertRole(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, r Role) error {
	if r.ResourceType == "" || r.Name == "" || len(r.Permissions) == 0 {
		return Err("request.malformed", "field", "role")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO roles (tenant_id, resource_type, name, permissions) VALUES ($1,$2,$3,$4)
		ON CONFLICT (tenant_id, resource_type, name) DO UPDATE SET permissions=EXCLUDED.permissions`,
		tenantID, r.ResourceType, r.Name, r.Permissions); err != nil {
		return err
	}
	_, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "role.upsert", TargetType: "role", TargetID: r.ResourceType + ":" + r.Name, Outcome: "ok",
		Detail: map[string]any{"permissions": r.Permissions}, CorrelationID: actor.corr()})
	return err
}

// RolesGranting returns the role names on a resource type whose permission
// set includes action (or the wildcard "*").
func RolesGranting(ctx context.Context, q Querier, tenantID, resourceType, action string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT name FROM roles WHERE tenant_id=$1 AND resource_type=$2 AND (permissions @> ARRAY[$3]::text[] OR permissions @> ARRAY['*']::text[])`,
		tenantID, resourceType, action)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---- Grants -----------------------------------------------------------------

type Grant struct {
	ID             string     `json:"id"`
	SubjectKind    string     `json:"subject_kind"`
	SubjectID      string     `json:"subject_id"`
	Role           string     `json:"role"`
	ResourceType   string     `json:"resource_type"`
	ResourceID     string     `json:"resource_id"`
	Condition      string     `json:"condition,omitempty"`
	ConditionClass string     `json:"condition_class"`
	NotBefore      *time.Time `json:"not_before,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ConditionValidator lets package authz own CEL parsing and classification
// without a dependency cycle: directory asks it to validate and classify at
// write time (§3.1 "classified at definition time").
type ConditionValidator interface {
	ValidateCondition(expr string) (class string, err error)
}

func CreateGrant(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, g Grant, cv ConditionValidator) (*Grant, error) {
	if g.SubjectKind != "principal" && g.SubjectKind != "group" {
		return nil, Err("request.malformed", "field", "subject_kind")
	}
	if g.SubjectID == "" || g.Role == "" || g.ResourceType == "" || g.ResourceID == "" {
		return nil, Err("request.malformed", "field", "grant")
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM roles WHERE tenant_id=$1 AND resource_type=$2 AND name=$3)`,
		tenantID, g.ResourceType, g.Role).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, Err("request.not_found", "type", "role")
	}
	g.ConditionClass = "offline"
	if strings.TrimSpace(g.Condition) != "" {
		class, err := cv.ValidateCondition(g.Condition)
		if err != nil {
			return nil, Err("request.malformed", "field", "condition", "detail", err.Error())
		}
		g.ConditionClass = class
	}
	g.ID = ids.New("grt")
	err := tx.QueryRow(ctx, `INSERT INTO grants (tenant_id, id, subject_kind, subject_id, role, resource_type, resource_id,
		condition, condition_class, not_before, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NULLIF($8,''),$9,$10,$11,$12) RETURNING created_at`,
		tenantID, g.ID, g.SubjectKind, g.SubjectID, g.Role, g.ResourceType, g.ResourceID,
		g.Condition, g.ConditionClass, g.NotBefore, g.ExpiresAt, actor.ID).Scan(&g.CreatedAt)
	if err != nil {
		return nil, err
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "grant.create", TargetType: "grant", TargetID: g.ID, Outcome: "ok",
		Detail: map[string]any{"subject": g.SubjectKind + ":" + g.SubjectID, "role": g.Role,
			"resource": g.ResourceType + ":" + g.ResourceID, "condition_class": g.ConditionClass}, CorrelationID: actor.corr()}); err != nil {
		return nil, err
	}
	return &g, emit(ctx, tx, tenantID, "grant.created", actor.ID, "grant", g.ID, nil, actor.corr())
}

func RevokeGrant(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, id string) error {
	tag, err := tx.Exec(ctx, `UPDATE grants SET revoked_at=now() WHERE tenant_id=$1 AND id=$2 AND revoked_at IS NULL`, tenantID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return Err("request.not_found", "type", "grant")
	}
	if _, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "grant.revoke", TargetType: "grant", TargetID: id, Outcome: "ok", CorrelationID: actor.corr()}); err != nil {
		return err
	}
	return emit(ctx, tx, tenantID, "grant.revoked", actor.ID, "grant", id, nil, actor.corr())
}

// CandidateGrants returns live grants whose subject is one of subjects and
// whose resource is one of the (type,id) pairs in chain, restricted to roles.
func CandidateGrants(ctx context.Context, q Querier, tenantID string, subjects []Subject, chain []Resource, roles []string, now time.Time) ([]Grant, error) {
	if len(subjects) == 0 || len(chain) == 0 || len(roles) == 0 {
		return nil, nil
	}
	sk := make([]string, len(subjects))
	sid := make([]string, len(subjects))
	for i, s := range subjects {
		sk[i], sid[i] = s.Kind, s.ID
	}
	rt := make([]string, len(chain))
	rid := make([]string, len(chain))
	for i, r := range chain {
		rt[i], rid[i] = r.Type, r.ID
	}
	rows, err := q.Query(ctx, `SELECT id, subject_kind, subject_id, role, resource_type, resource_id, coalesce(condition,''),
			condition_class, not_before, expires_at, created_at
		FROM grants g
		WHERE tenant_id=$1 AND revoked_at IS NULL
		  AND (subject_kind, subject_id) IN (SELECT * FROM unnest($2::text[], $3::text[]))
		  AND (resource_type, resource_id) IN (SELECT * FROM unnest($4::text[], $5::text[]))
		  AND role = ANY($6::text[])
		  AND (not_before IS NULL OR not_before <= $7)
		  AND (expires_at IS NULL OR expires_at > $7)
		ORDER BY created_at`, tenantID, sk, sid, rt, rid, roles, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.ID, &g.SubjectKind, &g.SubjectID, &g.Role, &g.ResourceType, &g.ResourceID, &g.Condition,
			&g.ConditionClass, &g.NotBefore, &g.ExpiresAt, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

type Subject struct{ Kind, ID string }

// ---- Policies ---------------------------------------------------------------

// EffectivePolicy merges every policy in domain assigned tenant-wide or to a
// group the principal is in: per setting, highest priority wins (§4). Ties at
// the same priority for the same key are a validation error at assignment
// time in the full design; this slice reports them as a conflict at read time
// so they are never silently resolved.
func EffectivePolicy(ctx context.Context, q Querier, tenantID, domain, principalID string) (map[string]any, map[string]string, error) {
	groups, err := GroupClosure(ctx, q, tenantID, "principal", principalID)
	if err != nil {
		return nil, nil, err
	}
	if groups == nil {
		groups = []string{}
	}
	rows, err := q.Query(ctx, `SELECT p.id, p.priority, p.document FROM policies p JOIN policy_assignments a
		ON a.tenant_id=p.tenant_id AND a.policy_id=p.id
		WHERE p.tenant_id=$1 AND p.domain=$2 AND (a.group_id IS NULL OR a.group_id = ANY($3::text[]))
		ORDER BY p.priority ASC`, tenantID, domain, groups)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	effective := map[string]any{}
	source := map[string]string{}
	prio := map[string]int{}
	for rows.Next() {
		var id string
		var priority int
		var doc []byte
		if err := rows.Scan(&id, &priority, &doc); err != nil {
			return nil, nil, err
		}
		m := map[string]any{}
		if err := json.Unmarshal(doc, &m); err != nil {
			return nil, nil, err
		}
		for k, v := range m {
			if p, ok := prio[k]; ok && p == priority {
				return nil, nil, Err("request.conflict", "reason", "policy_priority_tie", "key", k)
			}
			effective[k] = v
			source[k] = id
			prio[k] = priority
		}
	}
	return effective, source, rows.Err()
}

func CreatePolicy(ctx context.Context, tx pgx.Tx, tenantID string, actor Actor, name, domain string, priority int, doc map[string]any, groupID string) (string, error) {
	id := ids.New("pol")
	raw, _ := json.Marshal(doc)
	if _, err := tx.Exec(ctx, `INSERT INTO policies (tenant_id, id, name, domain, priority, document) VALUES ($1,$2,$3,$4,$5,$6)`,
		tenantID, id, name, domain, priority, raw); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO policy_assignments (tenant_id, policy_id, group_id) VALUES ($1,$2,NULLIF($3,''))`,
		tenantID, id, groupID); err != nil {
		return "", err
	}
	_, err := audit.Append(ctx, tx, tenantID, audit.Event{ActorKind: actor.Kind, ActorID: actor.ID,
		Action: "policy.create", TargetType: "policy", TargetID: id, Outcome: "ok",
		Detail: map[string]any{"domain": domain, "priority": priority, "group_id": groupID}, CorrelationID: actor.corr()})
	return id, err
}

// ---- helpers ----------------------------------------------------------------

func emit(ctx context.Context, tx pgx.Tx, tenantID, typ, actorID, targetType, targetID string, payload map[string]any, corr string) error {
	if payload == nil {
		payload = map[string]any{}
	}
	raw, _ := json.Marshal(payload)
	_, err := tx.Exec(ctx, `INSERT INTO events (tenant_id, type, actor_id, target_type, target_id, payload, correlation_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, tenantID, typ, actorID, targetType, targetID, raw, corr)
	return err
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "23505")
}
