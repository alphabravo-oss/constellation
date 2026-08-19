package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ---- A2: scope-aware group->role mapping store (sso_role_mappings, migration 125) ----
//
// The org-scope group->role map lives in auth_servers.role_mapping (JSONB). This file is the
// store for the NARROWER cluster/namespace grants that migration 125 adds, keyed by
// auth_server_id. A row is one scoped grant (group -> role @ (cluster, namespace)); the loader
// collapses the rows into the RoleMapping.ScopedRules shape the resolver consumes.

// ScopedRoleMappingRow is one persisted scoped grant (a sso_role_mappings row).
type ScopedRoleMappingRow struct {
	Group     string     // IdP group/attribute value (lower-cased on write)
	Role      string     // Constellation role name
	ClusterID *uuid.UUID // nil => all clusters (org scope)
	Namespace string     // "" => whole cluster/org
}

// scopeMapStore is the minimal pgx surface the scoped-mapping store needs.
type scopeMapStore interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadScopedRoleMappings reads the scoped grants for one auth server and returns them collapsed
// into the map[group][]ScopedRole shape RoleMapping.WithScopedRules expects. Group keys are
// lower-cased so they match the case-insensitive lookup MapScopedRoles performs. An auth server
// with no scoped rows yields an empty map (its mapping stays org-scope-only).
func LoadScopedRoleMappings(ctx context.Context, s scopeMapStore, authServerID uuid.UUID) (map[string][]ScopedRole, error) {
	rows, err := s.Query(ctx, `
SELECT group_value, role, scope_cluster_id, scope_namespace
  FROM sso_role_mappings
 WHERE auth_server_id = $1
 ORDER BY group_value, role, scope_namespace`, authServerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]ScopedRole{}
	for rows.Next() {
		var group, role, ns string
		var cluster *uuid.UUID
		if err := rows.Scan(&group, &role, &cluster, &ns); err != nil {
			return nil, err
		}
		key := strings.ToLower(strings.TrimSpace(group))
		clusterID := ""
		if cluster != nil {
			clusterID = cluster.String()
		}
		out[key] = append(out[key], ScopedRole{
			Role:  role,
			Scope: RoleScope{ClusterID: clusterID, Namespace: ns},
		})
	}
	return out, rows.Err()
}

// ---- P0-10: REST CRUD store for the scoped grants ----
//
// LoadScopedRoleMappings (above) is the READ path the login resolver consumes; the functions below
// are the WRITE path the admin CRUD handler uses so the sso_role_mappings table finally has a data
// source in a real deployment. reconcileJITRoles then materialises MapScopedRoles' cluster/namespace
// grants into role_assignments at JIT login. A mutation bumps the parent auth_server's revision so
// the ProviderSet poller reloads the scoped rules on every replica (LoadScopedRoleMappings runs in
// Reload), the same no-restart mechanism the auth-server CRUD relies on.

// ScopedRoleMapping is a full sso_role_mappings row (carries id/org for the CRUD surface, unlike the
// resolver-facing ScopedRoleMappingRow which the loader collapses into ScopedRole).
type ScopedRoleMapping struct {
	ID           uuid.UUID  `json:"id"`
	OrgID        uuid.UUID  `json:"org_id"`
	AuthServerID uuid.UUID  `json:"auth_server_id"`
	Group        string     `json:"group"`
	Role         string     `json:"role"`
	ClusterID    *uuid.UUID `json:"cluster_id,omitempty"` // nil => all clusters (org scope)
	Namespace    string     `json:"namespace"`            // "" => whole cluster/org
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
}

// ErrScopedMappingExists is returned when a create collides with the unique
// (auth_server_id, group_value, role, scope_cluster_id, scope_namespace) key.
var ErrScopedMappingExists = errors.New("scoped role mapping: an identical grant already exists")

// ListScopedRoleMappings returns one auth server's scoped grants (scoped to org) for the CRUD list.
func ListScopedRoleMappings(ctx context.Context, s store, orgID, authServerID uuid.UUID) ([]ScopedRoleMapping, error) {
	rows, err := s.Query(ctx, `
SELECT id, org_id, auth_server_id, group_value, role, scope_cluster_id, scope_namespace, created_by
  FROM sso_role_mappings
 WHERE org_id = $1 AND auth_server_id = $2
 ORDER BY group_value, role, scope_namespace`, orgID, authServerID)
	if err != nil {
		return nil, fmt.Errorf("scoped role mappings: list: %w", err)
	}
	defer rows.Close()
	var out []ScopedRoleMapping
	for rows.Next() {
		var m ScopedRoleMapping
		if err := rows.Scan(&m.ID, &m.OrgID, &m.AuthServerID, &m.Group, &m.Role, &m.ClusterID, &m.Namespace, &m.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CreateScopedRoleMapping inserts one scoped grant (group_value lower-cased to match the
// case-insensitive resolver lookup) and bumps the parent auth server's revision so the poller
// reloads. A duplicate surfaces as ErrScopedMappingExists.
func CreateScopedRoleMapping(ctx context.Context, s store, m ScopedRoleMapping) (ScopedRoleMapping, error) {
	m.Group = strings.ToLower(strings.TrimSpace(m.Group))
	err := s.QueryRow(ctx, `
INSERT INTO sso_role_mappings (org_id, auth_server_id, group_value, role, scope_cluster_id, scope_namespace, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id`,
		m.OrgID, m.AuthServerID, m.Group, m.Role, m.ClusterID, m.Namespace, m.CreatedBy).Scan(&m.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ScopedRoleMapping{}, ErrScopedMappingExists
		}
		return ScopedRoleMapping{}, fmt.Errorf("scoped role mappings: create: %w", err)
	}
	bumpAuthServerRevision(ctx, s, m.OrgID, m.AuthServerID)
	return m, nil
}

// DeleteScopedRoleMapping removes one scoped grant (scoped to org + auth server) and bumps the
// parent auth server's revision. Returns pgx.ErrNoRows when nothing was deleted.
func DeleteScopedRoleMapping(ctx context.Context, s store, orgID, authServerID, id uuid.UUID) error {
	ct, err := s.Exec(ctx,
		`DELETE FROM sso_role_mappings WHERE org_id = $1 AND auth_server_id = $2 AND id = $3`,
		orgID, authServerID, id)
	if err != nil {
		return fmt.Errorf("scoped role mappings: delete: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	bumpAuthServerRevision(ctx, s, orgID, authServerID)
	return nil
}

// bumpAuthServerRevision advances the auth server's revision so the ProviderSet poller (which keys
// on MaxRevision) rebuilds and re-attaches the scoped rules on every replica after a CRUD change.
// Best-effort: a failure here only delays cross-replica pickup to the writing replica's own reload.
func bumpAuthServerRevision(ctx context.Context, s store, orgID, authServerID uuid.UUID) {
	_, _ = s.Exec(ctx,
		`UPDATE auth_servers SET revision = revision + 1, updated_at = now() WHERE org_id = $1 AND id = $2`,
		orgID, authServerID)
}
