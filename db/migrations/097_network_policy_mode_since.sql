-- +goose Up
-- +goose StatementBegin
-- NET-4 — Persist when a workload last entered its current lifecycle mode so the
-- elevation engine can evaluate real time-in-Monitor for Monitor->Protect
-- transitions instead of re-seeding Discover/first-observation every request.
-- NeuVector's CLUSGroup carries a durable PolicyMode + mode-since equivalent
-- (share/clus_apis.go); this is the Constellation analog. Backfill existing rows
-- from updated_at so live state keeps a sane (non-zero) clock.
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS mode_since TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE network_policy_lifecycle_states
   SET mode_since = updated_at
 WHERE mode_since > updated_at;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE network_policy_lifecycle_states
    DROP COLUMN IF EXISTS mode_since;
-- +goose StatementEnd
