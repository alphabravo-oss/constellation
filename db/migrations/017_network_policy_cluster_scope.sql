-- +goose Up
-- +goose StatementBegin
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_rollback_refs
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;

UPDATE network_policy_lifecycle_states s
   SET cluster_id = (
      SELECT id FROM clusters
       WHERE org_id = s.org_id
       ORDER BY last_heartbeat_at DESC NULLS LAST, created_at ASC
       LIMIT 1
  )
 WHERE s.cluster_id IS NULL;

UPDATE network_policy_lifecycle_actions a
   SET cluster_id = (
      SELECT id FROM clusters
       WHERE org_id = a.org_id
       ORDER BY last_heartbeat_at DESC NULLS LAST, created_at ASC
       LIMIT 1
  )
 WHERE a.cluster_id IS NULL;

UPDATE network_policy_rollback_refs r
   SET cluster_id = (
      SELECT id FROM clusters
       WHERE org_id = r.org_id
       ORDER BY last_heartbeat_at DESC NULLS LAST, created_at ASC
       LIMIT 1
  )
 WHERE r.cluster_id IS NULL;

ALTER TABLE network_policy_lifecycle_states
    DROP CONSTRAINT IF EXISTS network_policy_lifecycle_states_org_id_workload_key;
ALTER TABLE network_policy_rollback_refs
    DROP CONSTRAINT IF EXISTS network_policy_rollback_refs_org_id_rollback_ref_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_lifecycle_org_cluster_workload
    ON network_policy_lifecycle_states(org_id, cluster_id, workload);
CREATE INDEX IF NOT EXISTS idx_network_policy_actions_org_cluster_workload
    ON network_policy_lifecycle_actions(org_id, cluster_id, workload, created_at DESC);
DROP INDEX IF EXISTS idx_network_policy_actions_idempotency;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_actions_cluster_idempotency
    ON network_policy_lifecycle_actions(org_id, cluster_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_rollback_refs_org_cluster_ref
    ON network_policy_rollback_refs(org_id, cluster_id, rollback_ref);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_network_policy_rollback_refs_org_cluster_ref;
DROP INDEX IF EXISTS idx_network_policy_actions_cluster_idempotency;
DROP INDEX IF EXISTS idx_network_policy_actions_org_cluster_workload;
DROP INDEX IF EXISTS idx_network_policy_lifecycle_org_cluster_workload;

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_actions_idempotency
    ON network_policy_lifecycle_actions(org_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

ALTER TABLE network_policy_lifecycle_states
    ADD CONSTRAINT network_policy_lifecycle_states_org_id_workload_key UNIQUE (org_id, workload);

ALTER TABLE network_policy_rollback_refs
    DROP COLUMN IF EXISTS cluster_id;
ALTER TABLE network_policy_lifecycle_actions
    DROP COLUMN IF EXISTS cluster_id;
ALTER TABLE network_policy_lifecycle_states
    DROP COLUMN IF EXISTS cluster_id;
-- +goose StatementEnd
