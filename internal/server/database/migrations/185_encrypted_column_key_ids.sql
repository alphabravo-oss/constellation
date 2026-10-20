-- +goose Up
-- Guide ch.06: every encrypted column carries (key_id, algorithm, ciphertext[, nonce]).
-- Column encryption moves from AES-256-GCM under a hex KEK (three ad-hoc
-- implementations) to age X25519 (internal/crypto). key_id is the age recipient
-- of the key that sealed the row; algorithm is 'age-x25519-chacha20poly1305';
-- nonce is NULL for age (the envelope carries its own file key) and exists for
-- any future algorithm that needs one. Reads select the key by key_id;
-- `constellationctl admin rotate-keys` re-seals rows under the current key.
--
-- Hard cutover (pre-release, ADR 0006 data policy): ciphertext sealed under the
-- retired KEK cannot be opened by the new key set, so it is cleared. Operators
-- re-enter registry credentials, git PATs and re-issue init bundles; the
-- federation CA / joint secrets regenerate on next use.
ALTER TABLE registries
    ADD COLUMN IF NOT EXISTS key_id text,
    ADD COLUMN IF NOT EXISTS algorithm text,
    ADD COLUMN IF NOT EXISTS nonce bytea;
UPDATE registries SET auth_secret = NULL WHERE auth_secret IS NOT NULL AND key_id IS NULL;

ALTER TABLE git_connectors
    ADD COLUMN IF NOT EXISTS key_id text,
    ADD COLUMN IF NOT EXISTS algorithm text,
    ADD COLUMN IF NOT EXISTS nonce bytea;
UPDATE git_connectors SET pat_sealed = NULL WHERE pat_sealed IS NOT NULL AND key_id IS NULL;

ALTER TABLE fed_joint_secret
    ADD COLUMN IF NOT EXISTS key_id text,
    ADD COLUMN IF NOT EXISTS algorithm text,
    ADD COLUMN IF NOT EXISTS nonce bytea;
UPDATE fed_joint_secret SET client_key_enc = NULL WHERE client_key_enc IS NOT NULL AND key_id IS NULL;

ALTER TABLE fed_ca
    ADD COLUMN IF NOT EXISTS key_id text,
    ADD COLUMN IF NOT EXISTS algorithm text,
    ADD COLUMN IF NOT EXISTS nonce bytea;
-- key_enc is NOT NULL: retire legacy CA rows instead; a new CA is minted on first use.
UPDATE fed_ca SET active = FALSE WHERE key_id IS NULL;

ALTER TABLE cluster_init_bundles
    ADD COLUMN IF NOT EXISTS key_id text,
    ADD COLUMN IF NOT EXISTS algorithm text,
    ADD COLUMN IF NOT EXISTS nonce bytea;
UPDATE cluster_init_bundles SET revoked_at = COALESCE(revoked_at, NOW()) WHERE key_id IS NULL;

CREATE INDEX IF NOT EXISTS registries_key_id_idx ON registries (key_id) WHERE auth_secret IS NOT NULL;
CREATE INDEX IF NOT EXISTS cluster_init_bundles_key_id_idx ON cluster_init_bundles (key_id) WHERE revoked_at IS NULL;
