-- +goose Up
-- +goose StatementBegin
-- Trend analytics materialized view.
--
-- Aggregates findings by (org, cluster, severity, kind, day) so the dashboard can render
-- 90-day MTTF + fix-rate + violation-velocity charts without scanning the findings table
-- on every page load. Refresh nightly via a CronJob the operator stamps out.
CREATE MATERIALIZED VIEW IF NOT EXISTS metrics_daily AS
SELECT
    org_id,
    DATE_TRUNC('day', last_seen_at)::date AS day,
    severity,
    kind,
    lifecycle,
    COUNT(*) AS finding_count,
    COUNT(*) FILTER (WHERE lifecycle = 'resolved') AS resolved_count,
    AVG(EXTRACT(EPOCH FROM (last_seen_at - first_seen_at))) FILTER (WHERE lifecycle = 'resolved') AS mttr_seconds
FROM findings
GROUP BY 1, 2, 3, 4, 5;

CREATE INDEX IF NOT EXISTS idx_metrics_daily_org_day ON metrics_daily(org_id, day DESC);

-- Backup catalog. Populated by `cmd/constellation-backup` after a successful pg_dump +
-- upload. UI shows "last backup" from this table.
CREATE TABLE IF NOT EXISTS backups (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at      TIMESTAMPTZ,
    status           TEXT NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'succeeded', 'failed')),
    object_uri       TEXT,                       -- s3://bucket/prefix/window/constellation.dump
    sha256           TEXT,
    size_bytes       BIGINT,
    cosign_signature TEXT,                       -- base64 sigstore bundle when signed
    error            TEXT
);

CREATE INDEX IF NOT EXISTS idx_backups_started ON backups(started_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backups;
DROP MATERIALIZED VIEW IF EXISTS metrics_daily;
-- +goose StatementEnd
