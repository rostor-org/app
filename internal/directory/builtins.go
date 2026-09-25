package directory

import (
	"context"

	"github.com/jackc/pgx/v5"

	"rostor.org/app/internal/ids"
)

// ConditionValidator is needed to create the built-in admin grant.

// EnsureBuiltins makes the directory's own resources, roles and the
// directory-admins group exist. It runs at bootstrap and on every start, so
// an install upgraded from before a built-in existed gains it without a
// migration step. Everything here is idempotent and audited on first
// creation only.
func EnsureBuiltins(ctx context.Context, tx pgx.Tx, tenantID string, cv ConditionValidator) error {
	sys := Actor{Kind: "system", ID: "builtins", CorrelationID: ids.New("corr")}
	// Existence is checked first: a failed INSERT aborts the surrounding
	// transaction in PostgreSQL, so insert-and-catch is not idempotent.
	ensureResource := func(typ, id string) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE tenant_id=$1 AND type=$2 AND id=$3)`, tenantID, typ, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
		return CreateResource(ctx, tx, tenantID, sys, Resource{Type: typ, ID: id})
	}
	if err := ensureResource("directory", "root"); err != nil {
		return err
	}
	if err := ensureResource("workstations", "all"); err != nil {
		return err
	}
	for _, r := range []Role{
		{ResourceType: "directory", Name: "admin", Permissions: []string{"*"}},
		// SPEC-agents: who may have agents is a grant of this role; closed by default.
		{ResourceType: "directory", Name: "agent-owner", Permissions: []string{"agents.own"}},
		{ResourceType: "workstation", Name: "user", Permissions: []string{"logon"}},
		{ResourceType: "workstations", Name: "user", Permissions: []string{"logon"}},
	} {
		if err := UpsertRole(ctx, tx, tenantID, sys, r); err != nil {
			return err
		}
	}
	// directory-admins: the group whose members administer the directory
	// (§3.3). Membership is the whole story; the grant never changes.
	g, err := GetGroupByName(ctx, tx, tenantID, AdminsGroup)
	if code, _ := CodeOf(err); code == "request.not_found" {
		g, err = CreateGroup(ctx, tx, tenantID, sys, AdminsGroup, map[string]string{"en": "Directory administrators"})
	}
	if err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM grants WHERE tenant_id=$1 AND subject_kind='group' AND subject_id=$2 AND role='admin'
		AND resource_type='directory' AND resource_id='root' AND revoked_at IS NULL`, tenantID, g.ID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := CreateGrant(ctx, tx, tenantID, sys, Grant{SubjectKind: "group", SubjectID: g.ID, Role: "admin", ResourceType: "directory", ResourceID: "root"}, cv); err != nil {
			return err
		}
	}
	// agent-owners (SPEC-agents): the group whose members may have agents.
	// Created empty; an admin adds people or nests a group such as members.
	ao, err := GetGroupByName(ctx, tx, tenantID, AgentOwnersGroup)
	if code, _ := CodeOf(err); code == "request.not_found" {
		ao, err = CreateGroup(ctx, tx, tenantID, sys, AgentOwnersGroup, map[string]string{"en": "May own agents"})
	}
	if err != nil {
		return err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM grants WHERE tenant_id=$1 AND subject_kind='group' AND subject_id=$2 AND role='agent-owner'
		AND resource_type='directory' AND resource_id='root' AND revoked_at IS NULL`, tenantID, ao.ID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := CreateGrant(ctx, tx, tenantID, sys, Grant{SubjectKind: "group", SubjectID: ao.ID, Role: "agent-owner", ResourceType: "directory", ResourceID: "root"}, cv); err != nil {
			return err
		}
	}
	return nil
}

// AdminsGroup is the built-in administrators group name.
const AdminsGroup = "directory-admins"

// AgentOwnersGroup is the built-in group whose members may have agents.
const AgentOwnersGroup = "agent-owners"

// HumanAdminExists reports whether any active *user* is in directory-admins
// (directly or through nesting). Service accounts do not count: the first
// administrator setup is about a person.
func HumanAdminExists(ctx context.Context, q Querier, tenantID string) (bool, error) {
	g, err := GetGroupByName(ctx, q, tenantID, AdminsGroup)
	if err != nil {
		if code, _ := CodeOf(err); code == "request.not_found" {
			return false, nil
		}
		return false, err
	}
	var n int
	err = q.QueryRow(ctx, `WITH RECURSIVE down AS (
			SELECT member_kind, member_id FROM group_members WHERE tenant_id=$1 AND group_id=$2
			UNION
			SELECT gm.member_kind, gm.member_id FROM group_members gm JOIN down ON down.member_kind='group' AND gm.group_id=down.member_id WHERE gm.tenant_id=$1
		) SELECT count(*) FROM down d JOIN principals p ON p.tenant_id=$1 AND p.id=d.member_id
		WHERE d.member_kind='principal' AND p.kind='user' AND p.state='active'`, tenantID, g.ID).Scan(&n)
	return n > 0, err
}
