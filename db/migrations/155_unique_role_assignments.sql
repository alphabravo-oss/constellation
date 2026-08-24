-- +goose Up
-- +goose StatementBegin
-- Exact duplicate role assignments multiply UI role chips and waste authz work. Keep the
-- oldest row for each effective assignment, then enforce that shape at the database layer.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY user_id,
                            role,
                            scope_org_id,
                            COALESCE(scope_cluster_id, '00000000-0000-0000-0000-000000000000'::uuid),
                            COALESCE(scope_project_id, '00000000-0000-0000-0000-000000000000'::uuid),
                            scope_namespace,
                            COALESCE(binding_id, '00000000-0000-0000-0000-000000000000'::uuid),
                            COALESCE(expires_at, 'infinity'::timestamptz)
               ORDER BY created_at, id::text
           ) AS rn
      FROM role_assignments
)
DELETE FROM role_assignments ra
 USING ranked r
 WHERE ra.id = r.id
   AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_role_assignments_effective_unique
    ON role_assignments (
        user_id,
        role,
        scope_org_id,
        COALESCE(scope_cluster_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(scope_project_id, '00000000-0000-0000-0000-000000000000'::uuid),
        scope_namespace,
        COALESCE(binding_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(expires_at, 'infinity'::timestamptz)
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_role_assignments_effective_unique;
-- +goose StatementEnd
