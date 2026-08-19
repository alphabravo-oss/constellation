-- +goose Up
-- +goose StatementBegin
-- Wave N1: cluster init-bundle table. An admin pre-mints a bundle on the control plane
-- (via /api/v1/cluster-init-bundles or `constellationctl cluster create`), encrypts the
-- raw bundle payload (TLS material + scanner_token + runtime_agent_token + audit HMAC)
-- with a per-install KEK, persists the ciphertext here, then ships the rendered YAML to
-- ops who installs it on a remote cluster.
--
-- The raw bundle YAML is shown to the admin exactly once at mint time; subsequent reads
-- decrypt the ciphertext but enforce one-time-download semantics (downloaded_at).
--
-- Lifecycle:
--   active           — revoked_at IS NULL AND expires_at > NOW()
--   expired          — revoked_at IS NULL AND expires_at <= NOW()
--   revoked          — revoked_at IS NOT NULL
--
-- Rotate = mark current row revoked, mint a new row with same (org_id, name). Tokens on
-- the revoked row are cascaded to revoked_at = NOW() via the matching scanner_token_id /
-- runtime_agent_token_id columns; the new bundle gets fresh tokens.
CREATE TABLE IF NOT EXISTS cluster_init_bundles (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                   UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id               UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name                     TEXT NOT NULL,
    distro                   TEXT NOT NULL DEFAULT 'kubernetes',
    region                   TEXT,
    expires_at               TIMESTAMPTZ NOT NULL,
    revoked_at               TIMESTAMPTZ,
    downloaded_at            TIMESTAMPTZ,
    created_by               UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scanner_token_id         UUID REFERENCES scanner_tokens(id) ON DELETE SET NULL,
    runtime_agent_token_id   UUID REFERENCES runtime_agent_tokens(id) ON DELETE SET NULL,
    kek_fingerprint          TEXT NOT NULL,                  -- sha256(hex(kek))[:16] for verification
    contents_encrypted       BYTEA NOT NULL                  -- AES-256-GCM(nonce||ciphertext) of the bundle YAML
);

CREATE INDEX IF NOT EXISTS idx_cluster_init_bundles_org ON cluster_init_bundles(org_id);
CREATE INDEX IF NOT EXISTS idx_cluster_init_bundles_cluster ON cluster_init_bundles(cluster_id);
CREATE INDEX IF NOT EXISTS idx_cluster_init_bundles_active
    ON cluster_init_bundles(org_id, name)
 WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_cluster_init_bundles_active;
DROP INDEX IF EXISTS idx_cluster_init_bundles_cluster;
DROP INDEX IF EXISTS idx_cluster_init_bundles_org;
DROP TABLE IF EXISTS cluster_init_bundles;
-- +goose StatementEnd
