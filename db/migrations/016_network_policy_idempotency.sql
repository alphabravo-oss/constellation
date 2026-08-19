-- +goose Up
-- +goose StatementBegin
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_actions_idempotency
    ON network_policy_lifecycle_actions(org_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_network_policy_actions_idempotency;
ALTER TABLE network_policy_lifecycle_actions
    DROP COLUMN IF EXISTS idempotency_key;
-- +goose StatementEnd
