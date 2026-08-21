-- +goose Up
-- +goose StatementBegin
-- SIG-ROOTS-38: per-org, REST-managed sigstore roots-of-trust. Previously the scanner only
-- accepted additional roots via the process-wide --signature-roots flag; this table lets an
-- org manage its own named roots over the API. Each row maps to one sigverify.RootOfTrust
-- (root_pem => cosign public key; tuf_root => private TUF root.json for air-gapped mirrors),
-- and feeds the same "trusted if ANY root verifies" path as the flag-configured roots.
CREATE TABLE sigstore_roots (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    name        TEXT NOT NULL,
    root_pem    TEXT NOT NULL DEFAULT '',   -- cosign public key material (Mode=public-key)
    tuf_root    TEXT NOT NULL DEFAULT '',   -- TUF root.json bootstrapping a private mirror
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE INDEX idx_sigstore_roots_org ON sigstore_roots(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sigstore_roots;
-- +goose StatementEnd
