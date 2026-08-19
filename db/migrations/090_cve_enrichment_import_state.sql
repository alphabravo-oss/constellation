-- +goose Up
-- +goose StatementBegin
-- Tracks which CVE-enrichment artifact (by payload hash) has been imported into
-- cve_records. The enrichment layer (descriptions today; LLM remediation later)
-- is a SEPARATE, opt-in artifact from the lean matching bundle — delivered only
-- where offline CVE detail is wanted (e.g. air-gapped). The reconciler compares
-- the delivered artifact's hash to this marker and, on a mismatch, streams the
-- enrichment rows into cve_records.
CREATE TABLE IF NOT EXISTS cve_enrichment_import_state (
    id            BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    payload_hash  TEXT NOT NULL DEFAULT '',
    record_count  INTEGER NOT NULL DEFAULT 0,
    imported_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cve_enrichment_import_state;
-- +goose StatementEnd
