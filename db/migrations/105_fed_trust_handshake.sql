-- +goose Up
-- +goose StatementBegin
-- D1 — federation trust handshake.
--
-- Replaces the single static CONSTELLATION_FED_MASTER_TOKEN (any read-findings
-- principal could pull the whole fed rule log) with a real issuance/exchange flow:
--   1. the master mints a short-lived RS256-SIGNED join token (fed_signing_keys),
--   2. a joint exchanges that join token for a PER-CLUSTER secret (fed_credentials,
--      stored HASHED like api_tokens),
--   3. every GET /federation/sync poll re-validates the per-cluster signed ticket,
--   4. kick/leave bumps the per-cluster epoch to revoke the joint (mirrors A1's
--      users.session_epoch DB-backed revocation primitive).

-- Dedicated RS256 signing keypair for federation join tokens + per-cluster sync
-- tickets. Master-side material; mirrors session_signing_keys (migration 100). A
-- separate key (not the session signer) so federation trust is isolated from user
-- session signing: rotating one never invalidates the other, and a fed verifier
-- never accepts a user JWT (different key) — that is what rejects a generic
-- read-findings JWT presented on /sync.
CREATE TABLE IF NOT EXISTS fed_signing_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm   TEXT NOT NULL DEFAULT 'RS256',
    private_pem TEXT NOT NULL,
    public_pem  TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fed_signing_keys_created_idx
    ON fed_signing_keys (created_at DESC);

-- Per-cluster federation credential, issued by the master when a joint exchanges a
-- valid join token. The raw per-cluster secret (a signed sync ticket) is returned to
-- the joint once and stored here only as sha256(secret), exactly like
-- api_tokens.token_hash / runtime_agent_tokens.token_hash. Every /sync poll
-- re-validates the presented ticket: signature (fed_signing_keys) + this row's
-- liveness (not revoked, not expired) + epoch (ticket.epoch >= epoch). Bumping epoch
-- on kick/leave invalidates the joint's already-issued ticket on its next poll,
-- mirroring the A1 users.session_epoch revocation model.
CREATE TABLE IF NOT EXISTS fed_credentials (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id   TEXT NOT NULL,
    secret_hash  TEXT NOT NULL,
    epoch        BIGINT NOT NULL DEFAULT 0,
    revoked_at   TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    UNIQUE (org_id, cluster_id)
);
CREATE INDEX IF NOT EXISTS idx_fed_credentials_org ON fed_credentials(org_id);

-- A joint persists the per-cluster secret it received from its master so the
-- background poller authenticates each /sync with it instead of the old static
-- shared token. One row per (joint) org. Kept separate from federation_state so the
-- secret is never returned by the GET /federation/state read surface.
CREATE TABLE IF NOT EXISTS fed_joint_secret (
    org_id      UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  TEXT NOT NULL DEFAULT '',
    secret      TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS fed_joint_secret;
DROP TABLE IF EXISTS fed_credentials;
DROP TABLE IF EXISTS fed_signing_keys;
-- +goose StatementEnd
