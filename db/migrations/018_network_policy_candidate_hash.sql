-- +goose Up
-- +goose StatementBegin
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS candidate_hash TEXT;

ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS candidate_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_network_policy_lifecycle_candidate_hash
    ON network_policy_lifecycle_states(org_id, cluster_id, candidate_hash)
    WHERE candidate_hash IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_network_policy_lifecycle_candidate_hash;

ALTER TABLE network_policy_lifecycle_actions
    DROP COLUMN IF EXISTS candidate_hash;

ALTER TABLE network_policy_lifecycle_states
    DROP COLUMN IF EXISTS candidate_hash;
-- +goose StatementEnd
