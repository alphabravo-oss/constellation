-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_attestation_verifications (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    attestation_id        UUID NOT NULL REFERENCES scan_result_attestations(id) ON DELETE CASCADE,
    trust_policy_id       UUID REFERENCES scan_attestation_trust_policies(id) ON DELETE SET NULL,
    trust_policy_name     TEXT NOT NULL DEFAULT '',
    status                TEXT NOT NULL,
    trusted               BOOLEAN NOT NULL DEFAULT FALSE,
    reason                TEXT NOT NULL DEFAULT '',
    error                 TEXT NOT NULL DEFAULT '',
    signer_identity       TEXT NOT NULL DEFAULT '',
    signer_issuer         TEXT NOT NULL DEFAULT '',
    subject_ref           TEXT NOT NULL DEFAULT '',
    subject_digest        TEXT NOT NULL DEFAULT '',
    predicate_type        TEXT NOT NULL DEFAULT '',
    payload_sha256        TEXT NOT NULL DEFAULT '',
    require_rekor         BOOLEAN NOT NULL DEFAULT FALSE,
    policy_snapshot       JSONB NOT NULL DEFAULT '{}'::jsonb,
    verifier_metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    verified_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    auto_verified         BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (status IN ('trusted', 'untrusted', 'unsigned', 'error', 'unverified')),
    CHECK ((trusted = false) OR status = 'trusted')
);

CREATE INDEX IF NOT EXISTS idx_scan_attestation_verifications_attestation
    ON scan_attestation_verifications(org_id, attestation_id, verified_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_attestation_verifications_policy
    ON scan_attestation_verifications(org_id, trust_policy_id, verified_at DESC)
    WHERE trust_policy_id IS NOT NULL;

CREATE OR REPLACE FUNCTION scan_attestation_verifications_no_modify() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'scan_attestation_verifications is append-only; UPDATE/DELETE forbidden';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER scan_attestation_verifications_no_update
    BEFORE UPDATE ON scan_attestation_verifications
    FOR EACH ROW EXECUTE FUNCTION scan_attestation_verifications_no_modify();

CREATE TRIGGER scan_attestation_verifications_no_delete
    BEFORE DELETE ON scan_attestation_verifications
    FOR EACH ROW EXECUTE FUNCTION scan_attestation_verifications_no_modify();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS scan_attestation_verifications_no_delete ON scan_attestation_verifications;
DROP TRIGGER IF EXISTS scan_attestation_verifications_no_update ON scan_attestation_verifications;
DROP FUNCTION IF EXISTS scan_attestation_verifications_no_modify();
DROP INDEX IF EXISTS idx_scan_attestation_verifications_policy;
DROP INDEX IF EXISTS idx_scan_attestation_verifications_attestation;
DROP TABLE IF EXISTS scan_attestation_verifications;
-- +goose StatementEnd
