-- +goose Up
-- +goose StatementBegin
-- A7 — per-session last-activity timestamp for the idle/inactivity timeout.
-- The auth middleware stamps last_seen_at on every authenticated request and
-- rejects a session whose last activity is older than the configured idle
-- window (alongside the existing absolute JWT TTL). Backfilled to created_at
-- for any pre-existing rows so an already-live session isn't instantly expired.
ALTER TABLE user_sessions
    ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE user_sessions SET last_seen_at = created_at WHERE last_seen_at < created_at;
CREATE INDEX IF NOT EXISTS user_sessions_last_seen_idx
    ON user_sessions (last_seen_at);

-- A7 — service-account-attached PATs. api_tokens.user_id was created NOT NULL
-- (migration 002) but migration 020 added service_account_id without relaxing it,
-- so a SA-attached token (user_id NULL, service_account_id set) could never be
-- minted. Relax user_id to NULL and enforce that exactly one principal is set so
-- the least-privilege service-account token path actually works.
ALTER TABLE api_tokens ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_principal_chk;
ALTER TABLE api_tokens ADD CONSTRAINT api_tokens_principal_chk
    CHECK ((user_id IS NOT NULL) <> (service_account_id IS NOT NULL));
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE api_tokens DROP CONSTRAINT IF EXISTS api_tokens_principal_chk;
DROP INDEX IF EXISTS user_sessions_last_seen_idx;
ALTER TABLE user_sessions DROP COLUMN IF EXISTS last_seen_at;
-- +goose StatementEnd
