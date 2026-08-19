-- +goose Up
-- +goose StatementBegin
-- Single-row marker tracking which vulndb bundle (by payload hash) has been
-- imported into cve_records. The api's reconciler compares the live bundle's
-- hash to this; on a mismatch it streams the bbolt advisories into cve_records
-- and updates the marker. Covers all bundle-install paths (cronjob direct write,
-- manual /vulndb:import) without a per-path hook.
CREATE TABLE IF NOT EXISTS cve_records_import_state (
    id           BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    bundle_hash  TEXT NOT NULL DEFAULT '',
    record_count INTEGER NOT NULL DEFAULT 0,
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cve_records_import_state;
-- +goose StatementEnd
