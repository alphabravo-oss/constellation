-- CMP-RUN-31: on-demand host-benchmark (kube-bench / docker-bench) runs.
--
-- NeuVector's handlerKubeBenchRun/handlerDockerBenchRun message the enforcer over
-- gRPC to run the benchmark immediately. Constellation's runner is a thin CronJob
-- that has no inbound control channel, so the control plane instead enqueues a
-- request row here; the runner drains it (POST /compliance/bench/claim) and
-- services it by exec'ing the benchmark and POSTing the report to /compliance/ingest.
--
-- status: pending -> claimed (a runner has taken it and will run the benchmark).

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS compliance_bench_run_requests (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- NULL = org-wide (any runner may claim it); otherwise scoped to one cluster.
    cluster_id   UUID REFERENCES clusters(id) ON DELETE CASCADE,
    -- "kube-bench" | "docker-bench"; selects which runner services the request.
    profile      TEXT NOT NULL DEFAULT 'kube-bench',
    -- Optional CIS benchmark id pin (e.g. eks-1.4.0); empty = runner auto-detects.
    benchmark    TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    requested_by UUID REFERENCES users(id),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claimed_at   TIMESTAMPTZ
);
-- Claim path selects the oldest pending row for an org/profile/cluster.
CREATE INDEX IF NOT EXISTS idx_compliance_bench_run_pending
    ON compliance_bench_run_requests (org_id, profile, requested_at)
    WHERE status = 'pending';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS compliance_bench_run_requests;
-- +goose StatementEnd
