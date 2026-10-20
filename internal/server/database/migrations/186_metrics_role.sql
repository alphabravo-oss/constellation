-- +goose Up
-- Read-only metrics role for an optional Postgres exporter (metrics.postgresRole
-- in the chart). The migration owns the grants so they survive CNPG reconciles;
-- CNPG managed.roles owns LOGIN and the password (the role is created NOLOGIN
-- here and never carries a password in the schema). Idempotent.
-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'constellation_metrics') THEN
        CREATE ROLE constellation_metrics NOLOGIN;
    END IF;
END
$$;
-- +goose StatementEnd
GRANT USAGE ON SCHEMA public TO constellation_metrics;
GRANT SELECT ON component_heartbeats, cve_feed_checkpoints TO constellation_metrics;
