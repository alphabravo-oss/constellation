-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_attestation_trust_policies (
    id                         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name                       TEXT NOT NULL,
    description                TEXT NOT NULL DEFAULT '',
    enabled                    BOOLEAN NOT NULL DEFAULT TRUE,
    auto_verify                BOOLEAN NOT NULL DEFAULT TRUE,
    subject_kind               TEXT NOT NULL DEFAULT 'image',
    source_types               TEXT[] NOT NULL DEFAULT ARRAY['repository']::text[],
    repository_ref_patterns    TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
    source_ref_patterns        TEXT[] NOT NULL DEFAULT ARRAY[]::text[],
    predicate_types            TEXT[] NOT NULL,
    allowed_identities         TEXT[] NOT NULL,
    allowed_issuers            TEXT[] NOT NULL,
    require_rekor              BOOLEAN NOT NULL DEFAULT FALSE,
    created_by                 UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by                 UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                 TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (name <> ''),
    CHECK (subject_kind IN ('image', 'repository')),
    CHECK (cardinality(predicate_types) > 0),
    CHECK (cardinality(allowed_identities) > 0),
    CHECK (cardinality(allowed_issuers) > 0),
    CHECK (array_position(predicate_types, '') IS NULL),
    CHECK (array_position(allowed_identities, '') IS NULL),
    CHECK (array_position(allowed_issuers, '') IS NULL),
    CHECK (array_position(source_types, '') IS NULL),
    CHECK (array_position(repository_ref_patterns, '') IS NULL),
    CHECK (array_position(source_ref_patterns, '') IS NULL),
    CHECK (cardinality(source_types) = 0 OR source_types <@ ARRAY['manual','registry','repository','runtime-agent','discoverer','platform','host','serverless']::text[])
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_scan_attestation_trust_policies_name
    ON scan_attestation_trust_policies(org_id, lower(name));

CREATE INDEX IF NOT EXISTS idx_scan_attestation_trust_policies_enabled
    ON scan_attestation_trust_policies(org_id, enabled, auto_verify, updated_at DESC);

ALTER TABLE scan_result_attestations
    ADD COLUMN IF NOT EXISTS trust_policy_id UUID REFERENCES scan_attestation_trust_policies(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS verification_reason TEXT;

CREATE INDEX IF NOT EXISTS idx_scan_result_attestations_trust_policy
    ON scan_result_attestations(org_id, trust_policy_id, verified_at DESC)
    WHERE trust_policy_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_result_attestations_trust_policy;

ALTER TABLE scan_result_attestations
    DROP COLUMN IF EXISTS verification_reason,
    DROP COLUMN IF EXISTS trust_policy_id;

DROP INDEX IF EXISTS idx_scan_attestation_trust_policies_enabled;
DROP INDEX IF EXISTS uniq_scan_attestation_trust_policies_name;
DROP TABLE IF EXISTS scan_attestation_trust_policies;
-- +goose StatementEnd
