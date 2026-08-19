-- +goose Up
-- +goose StatementBegin
-- A5 — session JWT signing keypair, moved off the symmetric HS256 secret onto an
-- RS256/ES256 keypair. The private key (PEM) is persisted here so every API replica
-- shares one signing identity even when no JWT_KEYS env secret is provided, and so a
-- generated fallback survives restarts. A current + previous key are kept (active = the
-- highest created_at) so a rotation keeps already-issued tokens valid until they expire:
-- verifiers accept the previous key's tokens, new tokens are minted with the active key.
CREATE TABLE IF NOT EXISTS session_signing_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    algorithm   TEXT NOT NULL,           -- "RS256" | "ES256"
    private_pem TEXT NOT NULL,           -- PEM-encoded private key (signing material)
    public_pem  TEXT NOT NULL,           -- PEM-encoded public key (verification material)
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS session_signing_keys_created_idx
    ON session_signing_keys (created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS session_signing_keys;
-- +goose StatementEnd
