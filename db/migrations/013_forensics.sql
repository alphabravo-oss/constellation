-- +goose Up
-- +goose StatementBegin
-- Forensics snapshots — captured when a workload is quarantined or hits a critical alert.
-- Non-kernel forensics: K8s events + pod spec + last-N log lines + recent network flows.
-- Stored compressed; archived to S3 alongside audit on rolling window.
CREATE TABLE IF NOT EXISTS forensics_snapshots (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE CASCADE,
    deployment_id UUID REFERENCES deployments(id) ON DELETE SET NULL,
    pod_name      TEXT,
    namespace     TEXT,
    trigger       TEXT NOT NULL,           -- quarantine | critical-alert | manual
    triggered_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    payload_gzip  BYTEA,                   -- gzipped JSON envelope (events + logs + flows + spec)
    payload_sha256 TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL DEFAULT 0,
    captured_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_forensics_org_at        ON forensics_snapshots(org_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_forensics_deployment    ON forensics_snapshots(deployment_id) WHERE deployment_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS forensics_snapshots;
-- +goose StatementEnd
