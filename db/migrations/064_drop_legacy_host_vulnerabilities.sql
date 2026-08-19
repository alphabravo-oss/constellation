-- Retire the pre-scan-target host vulnerability table. Host vulnerability
-- reads now come from unified findings where target_type='host'.

-- +goose Up
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_host_vuln_node;
DROP INDEX IF EXISTS idx_host_vuln_severity;
DROP INDEX IF EXISTS idx_host_vuln_org;
DROP INDEX IF EXISTS uniq_host_vuln_target;
DROP TABLE IF EXISTS host_vulnerabilities;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS host_vulnerabilities (
    id              UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID REFERENCES clusters(id) ON DELETE CASCADE,
    node            TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    vuln_id         TEXT NOT NULL,
    aliases         TEXT[] NOT NULL DEFAULT '{}',
    severity        TEXT,
    summary         TEXT,
    refs            TEXT,
    fixed_version   TEXT,
    source          TEXT NOT NULL,
    observed_at     TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_vuln_target
    ON host_vulnerabilities(cluster_id, node, package_name, vuln_id, source);

CREATE INDEX IF NOT EXISTS idx_host_vuln_org
    ON host_vulnerabilities(org_id, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_host_vuln_severity
    ON host_vulnerabilities(org_id, severity, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_host_vuln_node
    ON host_vulnerabilities(cluster_id, node);
-- +goose StatementEnd
