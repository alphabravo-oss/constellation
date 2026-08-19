-- +goose Up
-- +goose StatementBegin
-- A5 — Asset-centric vuln rollup. NeuVector keeps a local asset-vuln index and
-- recomputes counts when the CVE DB / vuln profile changes without rescanning.
-- Constellation materializes the same here: per-asset severity counts + max risk
-- + the bundle version the counts were computed against. Refreshed on demand by
-- recounting existing findings (and re-matching stored package evidence against a
-- new vulndb bundle) WITHOUT re-pulling or re-scanning images.
CREATE TABLE IF NOT EXISTS asset_vuln_summary (
    asset_id        UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    critical_count  INTEGER NOT NULL DEFAULT 0,
    high_count      INTEGER NOT NULL DEFAULT 0,
    medium_count    INTEGER NOT NULL DEFAULT 0,
    low_count       INTEGER NOT NULL DEFAULT 0,
    info_count      INTEGER NOT NULL DEFAULT 0,
    finding_count   INTEGER NOT NULL DEFAULT 0,
    max_risk_score  INTEGER NOT NULL DEFAULT 0,
    bundle_version  TEXT NOT NULL DEFAULT '',
    -- 'findings' = recounted from stored findings; 'evidence' = re-matched stored
    -- package inventory against the live bundle (no rescan).
    source          TEXT NOT NULL DEFAULT 'findings',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- CVE->affected-assets pivot and "Security Risks" sort both want max-risk-first
-- ordering scoped to an org and bundle version in a single indexed scan.
CREATE INDEX IF NOT EXISTS idx_asset_vuln_summary_org_risk
    ON asset_vuln_summary(org_id, max_risk_score DESC, critical_count DESC, high_count DESC);

CREATE INDEX IF NOT EXISTS idx_asset_vuln_summary_org_bundle
    ON asset_vuln_summary(org_id, bundle_version);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_asset_vuln_summary_org_bundle;
DROP INDEX IF EXISTS idx_asset_vuln_summary_org_risk;
DROP TABLE IF EXISTS asset_vuln_summary;
-- +goose StatementEnd
