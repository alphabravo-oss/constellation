-- Historical host vulnerability table from the pre-scan-target model.
-- Runtime code now stores vulnerability rows in unified findings with
-- target_type='host'. Migration 064 drops this table for existing dev
-- clusters; this file remains only as migration history for databases that
-- have already applied version 053.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_vulnerabilities (
    id              UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node            TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    -- e.g. "CVE-2024-1234" or "GHSA-..." or OSV id.
    vuln_id         TEXT NOT NULL,
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    severity        TEXT,           -- info | low | medium | high | critical
    summary         TEXT,
    -- Comma-joined URLs (advisory, NVD page, etc.).
    refs            TEXT,
    fixed_version   TEXT,
    source          TEXT NOT NULL,  -- osv | trivy | grype | manual
    observed_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Idempotent re-scan: same (cluster, node, package, vuln, source) is
-- a single row. We don't include package_version because OSV may
-- assign one vuln to a range of versions and we don't want duplicate
-- rows for each version transition.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_vuln_target
    ON host_vulnerabilities(cluster_id, node, package_name, vuln_id, source);

CREATE INDEX IF NOT EXISTS idx_host_vuln_org
    ON host_vulnerabilities(org_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_host_vuln_severity
    ON host_vulnerabilities(org_id, severity, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_host_vuln_node
    ON host_vulnerabilities(cluster_id, node);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_vuln_node;
DROP INDEX IF EXISTS idx_host_vuln_severity;
DROP INDEX IF EXISTS idx_host_vuln_org;
DROP INDEX IF EXISTS uniq_host_vuln_target;
DROP TABLE IF EXISTS host_vulnerabilities;
-- +goose StatementEnd
