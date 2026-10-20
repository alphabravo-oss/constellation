-- Durable benchmark execution is additive. Legacy pending/claimed rows and
-- claim paths are deliberately unchanged; old replicas cannot claim queued v2.
-- +goose Up
-- +goose StatementBegin
ALTER TABLE compliance_bench_run_requests
    ADD COLUMN protocol_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN request_key UUID,
    ADD COLUMN request_hash TEXT,
    ADD COLUMN requested_cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    ADD COLUMN revision BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN active_attempt_id UUID,
    ADD COLUMN completed_at TIMESTAMPTZ;
CREATE UNIQUE INDEX compliance_bench_request_key
    ON compliance_bench_run_requests(org_id,request_key) WHERE protocol_version=2;
CREATE INDEX compliance_bench_v2_queue
    ON compliance_bench_run_requests(org_id,profile,requested_at,id) WHERE protocol_version=2 AND status='queued';
CREATE TABLE compliance_bench_attempts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL REFERENCES compliance_bench_run_requests(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    agent_token_id UUID NOT NULL,
    claim_key UUID NOT NULL,
    runner_id UUID NOT NULL,
    node TEXT NOT NULL CHECK(length(node) BETWEEN 1 AND 253),
    attempt_no INTEGER NOT NULL CHECK(attempt_no BETWEEN 1 AND 3),
    status TEXT NOT NULL CHECK(status IN('running','succeeded','failed','interrupted')),
    started_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_expires_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    outcome TEXT NOT NULL DEFAULT '',
    report_sha256 TEXT NOT NULL DEFAULT '',
    rows_ingested INTEGER NOT NULL DEFAULT 0,
    passed INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    manual INTEGER NOT NULL DEFAULT 0,
    not_applicable INTEGER NOT NULL DEFAULT 0,
    UNIQUE(org_id,agent_token_id,claim_key),
    UNIQUE(request_id,attempt_no)
);
-- +goose StatementEnd
