-- +goose Up
-- +goose StatementBegin
-- A4 — password history (reuse rejection) + A3 — concurrent-session tracking.
--
-- password_history stores the last K Argon2id hashes per user so a password
-- change can reject reuse of a recent password. The handler keeps only the most
-- recent K rows (K = the active profile's history depth); older rows are pruned
-- on each change. password_changed_at on users backs the max-age policy.
CREATE TABLE IF NOT EXISTS password_history (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS password_history_user_idx
    ON password_history (user_id, created_at DESC);

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;

-- user_sessions tracks every live JWT session so the login path can enforce a
-- per-user concurrent-session cap (A3): on a new login we record the session
-- (keyed by the JWT id / jti), evict the oldest rows beyond the cap, and the auth
-- middleware rejects a JWT whose session row no longer exists (evicted session).
-- Eviction is a session bump that is independent of session_epoch so a single
-- evicted session does not invalidate every other live session for the user.
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id  UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS user_sessions_user_idx
    ON user_sessions (user_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS password_history;
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
-- +goose StatementEnd
