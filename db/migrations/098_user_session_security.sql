-- +goose Up
-- +goose StatementBegin
-- A1/A2/A4 — session-revocation epoch + brute-force lockout + forced-reset columns.
--
-- session_epoch is the DB-backed token-revocation primitive (A1): every minted
-- session JWT embeds the user's current epoch; the auth middleware re-reads the row
-- on each request and rejects any token whose embedded epoch is below it. Bumping the
-- epoch (logout, disable, delete, password-change, role-change) therefore invalidates
-- every previously-issued session for that user consistently across API replicas — no
-- in-process session store or cross-replica kick needed.
--
-- failed_login_count / block_login_since back the brute-force lockout (A2): once
-- failed_login_count reaches the threshold, block_login_since is (re)stamped to now() and
-- the account is locked for the configured window. The count does NOT decay over time — it
-- is cleared (and the block lifted) ONLY by a successful authentication. A continuing flood
-- of bad attempts therefore keeps the account locked; the window only governs how long after
-- the LAST failure the lock persists once attempts stop.
--
-- must_change_password backs forced first-login / admin-reset (A4); added here so the
-- users table is migrated once for the whole Workstream-A column set.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS session_epoch         BIGINT      NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS failed_login_count    INT         NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS block_login_since      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS must_change_password   BOOLEAN     NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE users
    DROP COLUMN IF EXISTS session_epoch,
    DROP COLUMN IF EXISTS failed_login_count,
    DROP COLUMN IF EXISTS block_login_since,
    DROP COLUMN IF EXISTS must_change_password;
-- +goose StatementEnd
