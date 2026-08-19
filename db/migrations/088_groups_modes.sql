-- +goose Up
-- +goose StatementBegin
-- NeuVector parity: a group carries the policy/profile MODE (CLUSGroup.PolicyMode/
-- ProfileMode). Triad spelled lowercase to match netpolicy modes elsewhere:
--   discover = NV Learn, monitor = NV Monitor, protect = NV Enforce.
-- NOT NULL DEFAULT backfills existing rows safely.
ALTER TABLE groups
  ADD COLUMN IF NOT EXISTS policy_mode  TEXT NOT NULL DEFAULT 'monitor'
    CHECK (policy_mode  IN ('discover','monitor','protect')),
  ADD COLUMN IF NOT EXISTS profile_mode TEXT NOT NULL DEFAULT 'monitor'
    CHECK (profile_mode IN ('discover','monitor','protect'));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE groups
  DROP COLUMN IF EXISTS policy_mode,
  DROP COLUMN IF EXISTS profile_mode;
-- +goose StatementEnd
