-- +goose Up
-- Read-only grants for the optional metrics role (chart metrics.postgresRole).
-- The role itself is created by CNPG managed.roles (LOGIN + password Secret):
-- the application role owns the tables but has no CREATEROLE, so this
-- migration only grants, and only when the role exists. The API re-applies the
-- same grants after every migration run (database.EnsureMetricsGrants), so a
-- role created after the first boot is covered on the next start.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'constellation_metrics') THEN
        EXECUTE 'GRANT USAGE ON SCHEMA public TO constellation_metrics';
        EXECUTE 'GRANT SELECT ON component_heartbeats, cve_feed_checkpoints TO constellation_metrics';
    END IF;
END
$$;
-- +goose StatementEnd
