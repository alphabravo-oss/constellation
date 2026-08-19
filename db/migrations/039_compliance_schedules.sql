-- +goose Up
-- +goose StatementBegin
-- Wave N8: production-grade compliance — scheduled framework runs + cosign-signed
-- PDF reports + delivery to email/webhook/S3.
--
-- `compliance_schedules` is the cron-driven schedule definition. `cluster_id` is
-- nullable so a schedule can fan out across every cluster in the org (one run row
-- per cluster). `delivery` is an opaque jsonb array of targets shaped like
--   [{"kind":"email","target":"auditor@x"},
--    {"kind":"s3","bucket":"reports","prefix":"compliance/"},
--    {"kind":"webhook","receiver_id":"<uuid>"},
--    {"kind":"file","target":"file:///tmp/compliance-out/"}]
-- so the scheduler can add new delivery kinds without a schema migration.
--
-- `compliance_runs` is the per-run history. `artifact_uri` points to either a
-- local file (file://), an s3:// object, or an embedded data: URI when the run
-- only emits to a webhook receiver. `artifact_signature` is the base64 cosign
-- signature; reviewers verify it via cosign verify-blob.
CREATE TABLE IF NOT EXISTS compliance_schedules (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id          UUID REFERENCES clusters(id) ON DELETE SET NULL,
    name                TEXT NOT NULL,
    description         TEXT NOT NULL DEFAULT '',
    framework           TEXT NOT NULL,
    cron_expression     TEXT NOT NULL,
    timezone            TEXT NOT NULL DEFAULT 'UTC',
    enabled             BOOLEAN NOT NULL DEFAULT TRUE,
    delivery            JSONB NOT NULL DEFAULT '[]'::jsonb,
    report_format       TEXT NOT NULL DEFAULT 'pdf',
    report_template     TEXT NOT NULL DEFAULT 'compliance-detailed',
    last_run_at         TIMESTAMPTZ,
    next_run_at         TIMESTAMPTZ,
    last_status         TEXT,
    last_artifact_uri   TEXT,
    last_error          TEXT,
    created_by          UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_compliance_schedules_org      ON compliance_schedules (org_id);
CREATE INDEX IF NOT EXISTS idx_compliance_schedules_cluster  ON compliance_schedules (cluster_id);
CREATE INDEX IF NOT EXISTS idx_compliance_schedules_due      ON compliance_schedules (next_run_at) WHERE enabled;

CREATE TABLE IF NOT EXISTS compliance_runs (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id            UUID REFERENCES clusters(id) ON DELETE SET NULL,
    schedule_id           UUID REFERENCES compliance_schedules(id) ON DELETE SET NULL,
    framework             TEXT NOT NULL,
    started_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at          TIMESTAMPTZ,
    status                TEXT NOT NULL DEFAULT 'running',  -- running|succeeded|failed
    summary               JSONB NOT NULL DEFAULT '{}'::jsonb, -- {pass, fail, manual, total}
    artifact_uri          TEXT,
    artifact_signature    TEXT,
    artifact_size_bytes   BIGINT,
    triggered_by          TEXT NOT NULL DEFAULT 'schedule',   -- schedule|manual|api
    error_message         TEXT
);

CREATE INDEX IF NOT EXISTS idx_compliance_runs_schedule ON compliance_runs (schedule_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_compliance_runs_org      ON compliance_runs (org_id, started_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS compliance_runs;
DROP TABLE IF EXISTS compliance_schedules;
-- +goose StatementEnd
