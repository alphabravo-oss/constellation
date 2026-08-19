-- +goose Up
-- Wave J2: add nullable cluster_id to the per-cluster configuration tables that
-- predated the cluster-first IA. NULL still means "org-scoped / applies to all
-- clusters" — the API treats it as the wildcard so existing rows keep working.
--
-- Tables touched (response_rules_v2, vuln_profiles, groups, waf_groups, dlp_sensors)
-- are the config tables surfaced by the Runtime sidebar group in cluster mode.
-- The other cluster-mode tables (findings, assets, deployments, compliance_checks,
-- network_flows, events, policies) already carry cluster_id from earlier waves.
--
-- ON DELETE SET NULL on each FK: deleting a cluster doesn't take down its config
-- rules — they fall back to org-wide which the user can re-scope.
ALTER TABLE response_rules_v2 ADD COLUMN cluster_id UUID
    REFERENCES clusters(id) ON DELETE SET NULL;
CREATE INDEX idx_response_rules_v2_cluster ON response_rules_v2(cluster_id)
    WHERE cluster_id IS NOT NULL;

ALTER TABLE vuln_profiles ADD COLUMN cluster_id UUID
    REFERENCES clusters(id) ON DELETE SET NULL;
CREATE INDEX idx_vuln_profiles_cluster ON vuln_profiles(cluster_id)
    WHERE cluster_id IS NOT NULL;

ALTER TABLE groups ADD COLUMN cluster_id UUID
    REFERENCES clusters(id) ON DELETE SET NULL;
CREATE INDEX idx_groups_cluster ON groups(cluster_id)
    WHERE cluster_id IS NOT NULL;

ALTER TABLE waf_groups ADD COLUMN cluster_id UUID
    REFERENCES clusters(id) ON DELETE SET NULL;
CREATE INDEX idx_waf_groups_cluster ON waf_groups(cluster_id)
    WHERE cluster_id IS NOT NULL;

ALTER TABLE dlp_sensors ADD COLUMN cluster_id UUID
    REFERENCES clusters(id) ON DELETE SET NULL;
CREATE INDEX idx_dlp_sensors_cluster ON dlp_sensors(cluster_id)
    WHERE cluster_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_dlp_sensors_cluster;
ALTER TABLE dlp_sensors DROP COLUMN IF EXISTS cluster_id;

DROP INDEX IF EXISTS idx_waf_groups_cluster;
ALTER TABLE waf_groups DROP COLUMN IF EXISTS cluster_id;

DROP INDEX IF EXISTS idx_groups_cluster;
ALTER TABLE groups DROP COLUMN IF EXISTS cluster_id;

DROP INDEX IF EXISTS idx_vuln_profiles_cluster;
ALTER TABLE vuln_profiles DROP COLUMN IF EXISTS cluster_id;

DROP INDEX IF EXISTS idx_response_rules_v2_cluster;
ALTER TABLE response_rules_v2 DROP COLUMN IF EXISTS cluster_id;
