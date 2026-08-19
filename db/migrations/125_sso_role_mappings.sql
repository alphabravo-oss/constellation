-- +goose Up
-- +goose StatementBegin
-- A2 — scope-aware group->role mapping.
--
-- internal/auth.RoleMapping.Rules maps an IdP/LDAP group to a role NAME applied at ORG
-- scope only. This table adds a SCOPE dimension so a group can map to a role at a specific
-- cluster and/or namespace, mirroring NeuVector's GroupRoleMapping.RoleDomains (group ->
-- role -> domains, where a "domain" is a namespace; we generalise to (cluster, namespace)).
--
-- Each row is one scoped grant: members of `group_value` (a lower-cased IdP group/attribute
-- value, resolved per auth_server) get `role` at the scope described by the nullable
-- scope columns:
--   * scope_cluster_id IS NULL         => all clusters (org-wide)
--   * scope_cluster_id set, namespace ''=> whole cluster
--   * scope_cluster_id set, namespace set => that namespace on that cluster
-- The historical org-scope mapping continues to live in auth_servers.role_mapping (JSONB);
-- this table carries ONLY the narrower cluster/namespace grants so an upgrade adds scope
-- without rewriting existing org-scope config.
CREATE TABLE IF NOT EXISTS sso_role_mappings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    auth_server_id   UUID NOT NULL REFERENCES auth_servers(id) ON DELETE CASCADE,
    group_value      TEXT NOT NULL,
    role             TEXT NOT NULL,
    scope_cluster_id UUID,                       -- NULL => all clusters (org scope)
    scope_namespace  TEXT NOT NULL DEFAULT '',   -- '' => whole cluster/org
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by       UUID,
    -- COALESCE the nullable cluster so (group, role, all-clusters, ns) is unique too:
    -- NULLs are never equal under a plain UNIQUE, which would let dup org-scope rows in.
    UNIQUE (auth_server_id, group_value, role, scope_cluster_id, scope_namespace)
);

CREATE INDEX IF NOT EXISTS sso_role_mappings_server_idx
    ON sso_role_mappings (auth_server_id, group_value);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sso_role_mappings;
-- +goose StatementEnd
