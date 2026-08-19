-- +goose Up
-- +goose StatementBegin
-- Scan jobs: control-plane → scanner-worker queue.
--
-- Workers poll /api/v1/scan-jobs/claim which atomically transitions one pending row to
-- "running" + sets claimed_at + sets worker_id. Workers POST results to /complete or
-- /fail. Rows older than retention are pruned by a CronJob.
CREATE TABLE scan_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    image_ref     TEXT NOT NULL,
    platform      TEXT,
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    worker_id     TEXT,
    error         TEXT,
    requested_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    package_count INT,
    finding_count INT,
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at    TIMESTAMPTZ,
    finished_at   TIMESTAMPTZ
);

CREATE INDEX idx_scan_jobs_org_status_requested ON scan_jobs(org_id, status, requested_at DESC);
CREATE INDEX idx_scan_jobs_pending             ON scan_jobs(requested_at) WHERE status = 'pending';

-- Scanner service tokens. Issued by an admin (manage-runtime-rules verb), validated
-- separately from user JWTs because scanner pods are non-user principals with a narrower
-- privilege envelope (scan-job claim + result write only).
CREATE TABLE scanner_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,    -- sha256 of the raw token; never store the raw value
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX idx_scanner_tokens_org ON scanner_tokens(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS scanner_tokens;
DROP TABLE IF EXISTS scan_jobs;
-- +goose StatementEnd
