-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_job_attempts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    job_id           UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    attempt_number   INT NOT NULL,
    worker_id        TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'running'
                     CHECK (status IN ('running', 'retry_scheduled', 'failed', 'completed', 'canceled')),
    error            TEXT,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at      TIMESTAMPTZ,
    next_attempt_at  TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    UNIQUE (job_id, attempt_number)
);

CREATE INDEX IF NOT EXISTS idx_scan_job_attempts_job
    ON scan_job_attempts(org_id, job_id, attempt_number);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_job_attempts_job;
DROP TABLE IF EXISTS scan_job_attempts;
-- +goose StatementEnd
