-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS scan_evidence (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    scan_target_id  UUID NOT NULL REFERENCES scan_targets(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE SET NULL,
    target_type     TEXT NOT NULL,
    target_ref      TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_ref      TEXT,
    evidence_type   TEXT NOT NULL,
    inventory_hash  TEXT NOT NULL,
    package_count   INTEGER NOT NULL DEFAULT 0,
    payload         JSONB NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (target_type IN ('image', 'workload', 'host', 'platform', 'registry', 'repository', 'serverless')),
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host')),
    CHECK (evidence_type IN ('package-inventory'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_scan_evidence_target_inventory
    ON scan_evidence(org_id, scan_target_id, evidence_type, inventory_hash);

CREATE INDEX IF NOT EXISTS idx_scan_evidence_target_latest
    ON scan_evidence(org_id, scan_target_id, evidence_type, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_evidence_cluster_target
    ON scan_evidence(org_id, cluster_id, target_type, observed_at DESC)
    WHERE cluster_id IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_evidence_cluster_target;
DROP INDEX IF EXISTS idx_scan_evidence_target_latest;
DROP INDEX IF EXISTS uniq_scan_evidence_target_inventory;
DROP TABLE IF EXISTS scan_evidence;
-- +goose StatementEnd
