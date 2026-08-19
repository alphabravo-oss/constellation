-- +goose Up
-- +goose StatementBegin
-- ENT-2 federation: extend fed replication to response-rule overrides and admission
-- policies. Admission policies already live in `policies` (which carries cfg_type from
-- migration 091), so they need no schema change. The v1 response-rule override store
-- gains cfg_type to mark master-authored (read-only) overrides replicated to joints,
-- mirroring policies.cfg_type / groups.cfg_type. 'user' is the local default; 'fed'
-- rows are owned by the joint poller and replaced/tombstoned on each sync.
ALTER TABLE response_rule_overrides ADD COLUMN IF NOT EXISTS cfg_type TEXT NOT NULL DEFAULT 'user';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE response_rule_overrides DROP COLUMN IF EXISTS cfg_type;
-- +goose StatementEnd
