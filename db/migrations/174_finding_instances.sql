-- +goose Up
-- Additive occurrence identity: the existing primary key remains (id,first_seen_at).
ALTER TABLE findings ADD COLUMN revision bigint NOT NULL DEFAULT 1;
-- +goose StatementBegin
CREATE FUNCTION finding_revision_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.revision := OLD.revision + 1;
    RETURN NEW;
END;
$$;
CREATE TRIGGER findings_revision_update BEFORE UPDATE ON findings
FOR EACH ROW EXECUTE FUNCTION finding_revision_update();
-- +goose StatementEnd
-- Existing UUID-only comments retain their original, unresolved history. No
-- backfill guesses which recurrence existed before partition retention.
ALTER TABLE finding_comments ADD COLUMN finding_first_seen_at timestamptz;
CREATE INDEX idx_finding_comments_instance ON finding_comments
(org_id,finding_id,finding_first_seen_at,created_at,id) WHERE deleted_at IS NULL;
-- No finding FK: retained comments must not prevent monthly partition removal.

-- New exact audit scope survives finding partition removal. Existing events
-- remain immutable and are excluded from these additive partial indexes.
CREATE INDEX idx_audit_finding_source_cluster ON audit_events
(org_id,(after->>'finding_source_cluster_id'),id DESC)
WHERE target_kind='finding' AND after ? 'finding_first_seen_at';
CREATE INDEX idx_audit_finding_effective_cluster ON audit_events
(org_id,(COALESCE(after->>'finding_target_cluster_id',after->>'finding_source_cluster_id')),id DESC)
WHERE target_kind='finding' AND after ? 'finding_first_seen_at';
