-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_result_attestations (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    scan_target_id        UUID NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    scan_job_id           UUID REFERENCES scan_jobs(id) ON DELETE SET NULL,
    scan_evidence_id      UUID REFERENCES scan_evidence(id) ON DELETE SET NULL,
    image_scan_result_id  UUID REFERENCES image_scan_results(id) ON DELETE SET NULL,
    target_type           TEXT NOT NULL,
    target_ref            TEXT NOT NULL,
    source_type           TEXT NOT NULL,
    source_ref            TEXT,
    subject_kind          TEXT NOT NULL,
    subject_ref           TEXT NOT NULL,
    subject_digest        TEXT NOT NULL,
    repository_ref        TEXT,
    repository_url        TEXT,
    commit_sha            TEXT,
    branch                TEXT,
    workflow              TEXT,
    run_id                TEXT,
    run_attempt           TEXT,
    ci_provider           TEXT,
    predicate_type        TEXT NOT NULL,
    format                TEXT NOT NULL,
    payload               JSONB NOT NULL,
    payload_sha256        TEXT NOT NULL,
    envelope              JSONB,
    signature             JSONB,
    verification_status   TEXT NOT NULL,
    trusted               BOOLEAN NOT NULL DEFAULT FALSE,
    signer_identity       TEXT,
    signer_issuer         TEXT,
    verified_at           TIMESTAMPTZ,
    observed_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at            TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata              JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (target_type IN ('image', 'workload', 'host', 'platform', 'registry', 'repository', 'serverless')),
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host', 'serverless')),
    CHECK (subject_kind IN ('image', 'repository')),
    CHECK (subject_digest <> ''),
    CHECK (predicate_type <> ''),
    CHECK (format <> ''),
    CHECK (payload_sha256 LIKE 'sha256:%'),
    CHECK (verification_status IN ('trusted', 'untrusted', 'unsigned', 'error', 'unverified')),
    CHECK ((trusted = false) OR verification_status = 'trusted')
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_scan_result_attestations_subject_payload
    ON scan_result_attestations(org_id, subject_kind, subject_digest, predicate_type, payload_sha256);

CREATE INDEX IF NOT EXISTS idx_scan_result_attestations_target
    ON scan_result_attestations(org_id, scan_target_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_result_attestations_image_result
    ON scan_result_attestations(org_id, image_scan_result_id, observed_at DESC)
    WHERE image_scan_result_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scan_result_attestations_subject_trusted
    ON scan_result_attestations(org_id, subject_kind, subject_digest, observed_at DESC)
    WHERE trusted;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_result_attestations_subject_trusted;
DROP INDEX IF EXISTS idx_scan_result_attestations_image_result;
DROP INDEX IF EXISTS idx_scan_result_attestations_target;
DROP INDEX IF EXISTS uniq_scan_result_attestations_subject_payload;
DROP TABLE IF EXISTS scan_result_attestations;
-- +goose StatementEnd
