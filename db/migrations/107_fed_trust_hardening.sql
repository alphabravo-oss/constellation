-- +goose Up
-- +goose StatementBegin
-- D1 hardening — durable kick + single-use join tokens.
--
-- Closes two federation-trust bypasses found in review of migration 105:
--   1. A kicked joint could re-admit itself by replaying a still-valid join
--      credential (POST /federation/join cleared revoked_at, bumped the epoch and
--      flipped fed_members.status kicked->pending). We now TOMBSTONE the kick with
--      fed_members.kicked_at so Join refuses a kicked cluster_id unless the operator
--      mints a FRESH join token AFTER the kick (a signed token whose issued-at is
--      newer than kicked_at). A pre-shared/fixed GitOps token can never silently
--      undo a kick.
--   2. A master-minted join token was a replayable bearer: it carried a jti but the
--      jti was never persisted/consumed, so a captured token could be replayed within
--      its TTL to mint per-cluster secrets for arbitrary cluster ids. We now persist
--      each minted jti and consume it on first successful exchange, making minted
--      join tokens single-use.

-- Tombstone the moment a member was kicked. Join compares a re-admitting join token's
-- issued-at against this so a stale credential cannot reverse a kick. NULL = never
-- kicked (or re-admitted).
ALTER TABLE fed_members ADD COLUMN IF NOT EXISTS kicked_at TIMESTAMPTZ;

-- One row per master-minted join token. MintJoinToken inserts the jti; the first
-- successful Join consumes it (sets consumed_at). A replayed token finds its jti
-- already consumed and is rejected. The pre-shared fixed/GitOps token is intentionally
-- NOT tracked here (it is reusable by design); only signed, minted tokens are single-use.
CREATE TABLE IF NOT EXISTS fed_join_tokens (
    jti         UUID PRIMARY KEY,
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    expires_at  TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fed_join_tokens_org ON fed_join_tokens(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS fed_join_tokens;
ALTER TABLE fed_members DROP COLUMN IF EXISTS kicked_at;
-- +goose StatementEnd
