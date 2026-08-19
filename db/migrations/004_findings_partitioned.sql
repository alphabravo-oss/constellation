-- +goose Up
-- +goose StatementBegin
-- Findings table is partitioned by month on `first_seen_at` so old findings can be archived cheaply.
CREATE TABLE findings (
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL,
    cluster_id    UUID,
    project_id    UUID,
    asset_id      UUID NOT NULL,
    kind          TEXT NOT NULL,            -- "vulnerability" | "iac" | "license" | "cloud-config" | "drift" | "secret" | "signature" | "ml-model" | "compliance" | "runtime"
    external_id   TEXT,                     -- CVE-XXXX, GHSA-..., rule ID, ...
    title         TEXT NOT NULL,
    description   TEXT,
    severity      TEXT NOT NULL,            -- "info" | "low" | "medium" | "high" | "critical"
    risk_score    INTEGER NOT NULL DEFAULT 0,
    risk_inputs   JSONB NOT NULL DEFAULT '{}'::jsonb,
    lifecycle     TEXT NOT NULL DEFAULT 'open',
    assignee_id   UUID,
    priority      TEXT,
    accepted_until TIMESTAMPTZ,
    engines       JSONB NOT NULL DEFAULT '[]'::jsonb,
    detail_json   JSONB NOT NULL DEFAULT '{}'::jsonb,   -- PII redacted at write time
    attack_techniques TEXT[] NOT NULL DEFAULT '{}',
    embedding     vector(1536),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, first_seen_at)
) PARTITION BY RANGE (first_seen_at);

-- Bootstrap partition for the first month + a default catch-all.
-- The audit-archiver / scheduler creates fresh partitions monthly.
CREATE TABLE findings_p_default PARTITION OF findings DEFAULT;

CREATE INDEX idx_findings_org_kind     ON findings(org_id, kind, lifecycle);
CREATE INDEX idx_findings_asset        ON findings(asset_id);
CREATE INDEX idx_findings_severity     ON findings(org_id, severity, risk_score DESC);
CREATE INDEX idx_findings_external_id  ON findings(external_id) WHERE external_id IS NOT NULL;
CREATE INDEX idx_findings_external_trgm ON findings USING GIN (external_id gin_trgm_ops);

-- Per-image acceptance (image-level accept-risk workflow, FR-26).
CREATE TABLE image_acceptances (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    image_digest TEXT NOT NULL,
    rationale    TEXT NOT NULL,
    approver_id  UUID NOT NULL REFERENCES users(id),
    accepted_until TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ,
    UNIQUE (org_id, image_digest, accepted_until)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS image_acceptances;
DROP TABLE IF EXISTS findings CASCADE;
-- +goose StatementEnd
