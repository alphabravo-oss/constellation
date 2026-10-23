-- +goose Up
-- Destination-specific progress only advances after signed object read-back.
CREATE TABLE audit_archive_progress (
    stream TEXT PRIMARY KEY,
    last_id BIGINT NOT NULL DEFAULT 0 CHECK (last_id >= 0),
    last_hash TEXT NOT NULL DEFAULT repeat('0',64),
    last_manifest TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- No pruning escape hatch: checkpoint-aware hot retention remains a separate
-- design. A role able to disable triggers remains a privileged database owner.
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_events_no_modify();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_no_modify() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only; UPDATE/DELETE/TRUNCATE forbidden';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
