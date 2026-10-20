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
