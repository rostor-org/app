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
	// SPEC-portal: the portal and its built-in tiles. A tile is a resource
	// whose visibility is either a permission the caller holds (screens)
	// or a grant of the viewer role (links, public tiles).
	if err := ensureResource("portal", "root"); err != nil {
		return err
	}
	for _, t := range BuiltinTiles {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resources WHERE tenant_id=$1 AND type='portal.tile' AND id=$2)`, tenantID, t.ID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		if err := CreateResource(ctx, tx, tenantID, sys, Resource{Type: "portal.tile", ID: t.ID, ParentType: "portal", ParentID: "root",
			Attributes: map[string]any{"kind": "screen", "href": t.Href, "category": t.Category, "order": t.Order, "icon": t.Icon,
				"title_code": "ui.tile." + t.ID, "description_code": "ui.tile." + t.ID + ".desc", "requires": t.Requires, "builtin": true}}); err != nil {
			return err
		}
	}
	for _, r := range []Role{
		{ResourceType: "directory", Name: "admin", Permissions: []string{"*"}},
		// SPEC-agents: who may have agents is a grant of this role; closed by default.
		{ResourceType: "directory", Name: "agent-owner", Permissions: []string{"agents.own"}},
		{ResourceType: "workstation", Name: "user", Permissions: []string{"logon"}},
		{ResourceType: "workstations", Name: "user", Permissions: []string{"logon"}},
		// SPEC-portal: who may see a tile (or every tile, on portal:root).
		{ResourceType: "portal.tile", Name: "viewer", Permissions: []string{"view"}},
		{ResourceType: "portal", Name: "viewer", Permissions: []string{"view"}},
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
	// everyone (SPEC-portal): the implicit group of every principal, and of
	// anonymous visitors for the portal. Membership is never stored; the
	// engine adds it to every principal's paths.
	if _, err := GetGroupByName(ctx, tx, tenantID, EveryoneGroup); err != nil {
		if code, _ := CodeOf(err); code != "request.not_found" {
			return err
		}
		if _, err := CreateGroup(ctx, tx, tenantID, sys, EveryoneGroup, map[string]string{"en": "Everyone"}); err != nil {
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

// EveryoneGroup is the built-in group every principal is implicitly in, and
// that anonymous portal visitors count as (SPEC-portal).
const EveryoneGroup = "everyone"

// BuiltinTile describes a console screen as a portal tile. Titles and
// descriptions are catalog codes ui.tile.<id> and ui.tile.<id>.desc.
type BuiltinTile struct {
	ID, Href, Category, Icon, Requires string
	Order                              int
}

// BuiltinTiles are the console's screens. Requires is the permission on the
// directory that shows the tile ("session" = any signed-in principal).
var BuiltinTiles = []BuiltinTile{
	{ID: "my-account", Href: "/me", Category: "you", Icon: "me", Requires: "session", Order: 10},
	{ID: "people", Href: "/people", Category: "admin", Icon: "people", Requires: "users.read", Order: 10},
	{ID: "groups", Href: "/groups", Category: "admin", Icon: "groups", Requires: "groups.read", Order: 20},
	{ID: "access", Href: "/access", Category: "admin", Icon: "access", Requires: "grants.read", Order: 30},
	{ID: "devices", Href: "/devices", Category: "admin", Icon: "devices", Requires: "devices.read", Order: 40},
	{ID: "scripts", Href: "/scripts", Category: "admin", Icon: "scripts", Requires: "scripts.read", Order: 50},
	{ID: "audit", Href: "/audit", Category: "admin", Icon: "audit", Requires: "audit.read", Order: 60},
	{ID: "plugins", Href: "/plugins", Category: "admin", Icon: "plugins", Requires: "plugins.read", Order: 70},
	{ID: "system", Href: "/system", Category: "admin", Icon: "system", Requires: "system.read", Order: 80},
}

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
