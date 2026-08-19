-- +goose Up
-- +goose StatementBegin
-- D2 — per-joint mTLS for federation.
--
-- Builds on D1's trust handshake (migration 105). D1 made fed traffic a per-cluster
-- signed bearer (sync ticket), but that bearer travels over an unpinned TLS connection:
-- a leaked ticket alone impersonates a joint. D2 binds each per-cluster credential to a
-- per-joint X.509 CLIENT CERTIFICATE issued by a master-held federation CA. The master
-- verifies the client cert against the CA AND matches its fingerprint to the per-cluster
-- credential on every /sync poll, so a leaked bearer WITHOUT the matching client key is
-- rejected. The joint pins the master CA on its outbound poll connection.

-- Federation CA. Master-side root that signs every per-joint client certificate. The
-- private key is the most sensitive fed material, so it is stored ENCRYPTED at rest
-- (AES-256-GCM under the install KEK, exactly like registries.auth_secret) in key_enc;
-- cert_pem is the public CA certificate (handed to joints at join so they pin the master,
-- and used by the master to verify presented client certs). Auto-generated on first boot
-- via auth.LoadFedCA — mirrors fed_signing_keys (105) / session_signing_keys (100).
CREATE TABLE IF NOT EXISTS fed_ca (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_pem   TEXT NOT NULL,
    key_enc    BYTEA NOT NULL,
    active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS fed_ca_created_idx ON fed_ca (created_at DESC);

-- Bind the per-joint client certificate to the per-cluster credential (D1). At join the
-- master mints a client cert (CN = cluster_id) and records sha256(DER) here. Every /sync
-- poll then requires a verified client cert whose fingerprint equals this value, so the
-- bearer ticket alone (no client key) cannot authenticate. Empty = a pre-D2 (D1-only)
-- credential that predates mTLS issuance; the middleware then skips the cert check for
-- backward compatibility.
ALTER TABLE fed_credentials ADD COLUMN IF NOT EXISTS cert_fingerprint TEXT NOT NULL DEFAULT '';

-- Joint-side material the background poller presents/pins on its outbound /sync
-- connection: the per-joint client certificate (public), its private key (ENCRYPTED at
-- rest under the install KEK, like registry secrets), and the master CA cert it pins so a
-- MITM cannot impersonate the master. One row per joint org (extends D1's fed_joint_secret
-- so the secret + cert material live together, off the GET /federation/state read surface).
ALTER TABLE fed_joint_secret ADD COLUMN IF NOT EXISTS client_cert_pem TEXT NOT NULL DEFAULT '';
ALTER TABLE fed_joint_secret ADD COLUMN IF NOT EXISTS client_key_enc  BYTEA;
ALTER TABLE fed_joint_secret ADD COLUMN IF NOT EXISTS master_ca_pem   TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE fed_joint_secret DROP COLUMN IF EXISTS master_ca_pem;
ALTER TABLE fed_joint_secret DROP COLUMN IF EXISTS client_key_enc;
ALTER TABLE fed_joint_secret DROP COLUMN IF EXISTS client_cert_pem;
ALTER TABLE fed_credentials DROP COLUMN IF EXISTS cert_fingerprint;
DROP TABLE IF EXISTS fed_ca;
-- +goose StatementEnd
