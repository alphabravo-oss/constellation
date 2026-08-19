-- +goose Up
-- +goose StatementBegin
-- The original UNIQUE(org_id, cluster_id, component, hostname) permits
-- duplicates when cluster_id is NULL. Control-plane and current scanner
-- heartbeats often omit cluster_id, so collapse duplicate rows before adding a
-- NULL-safe expression index.
WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid),
                            COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid),
                            component,
                            hostname
               ORDER BY last_seen_at DESC, first_seen_at DESC, id DESC
           ) AS rn
      FROM component_heartbeats
)
DELETE FROM component_heartbeats ch
 USING ranked r
 WHERE ch.id = r.id
   AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_component_heartbeats_unique_nullsafe
    ON component_heartbeats (
        COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid),
        COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid),
        component,
        hostname
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_component_heartbeats_unique_nullsafe;
-- +goose StatementEnd
