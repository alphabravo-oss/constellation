-- +goose Up
-- +goose StatementBegin
-- P0-10 — namespace-scoped role assignments.
--
-- role_assignments carried only scope_org_id/scope_cluster_id/scope_project_id, so the JIT/SSO
-- materialiser (reconcileJITRoles) had nowhere to land a group->role grant scoped to a single
-- NAMESPACE and dropped it rather than over-grant the whole cluster. This column mirrors
-- sso_role_mappings.scope_namespace so a namespace-bearing grant materialises faithfully:
--   * scope_cluster_id set, scope_namespace ''  => whole cluster (unchanged)
--   * scope_cluster_id set, scope_namespace set => that namespace on that cluster
-- '' (not NULL) keeps the existing cluster/org rows valid and their (role, cluster, ns) key stable.
ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS scope_namespace TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE role_assignments
    DROP COLUMN IF EXISTS scope_namespace;
-- +goose StatementEnd
