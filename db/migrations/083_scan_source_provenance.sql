-- +goose Up
-- +goose StatementBegin
ALTER TABLE scan_targets
    DROP CONSTRAINT IF EXISTS scan_targets_source_type_check;

ALTER TABLE scan_targets
    ADD CONSTRAINT scan_targets_source_type_check
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host', 'serverless'));

ALTER TABLE scan_evidence
    DROP CONSTRAINT IF EXISTS scan_evidence_source_type_check;

ALTER TABLE scan_evidence
    ADD CONSTRAINT scan_evidence_source_type_check
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host', 'serverless'));

ALTER TABLE image_scan_results
    ADD COLUMN IF NOT EXISTS source_type TEXT,
    ADD COLUMN IF NOT EXISTS source_ref TEXT;

UPDATE image_scan_results r
   SET source_type = COALESCE(NULLIF(r.source_type, ''), NULLIF(st.source_type, '')),
       source_ref = COALESCE(NULLIF(r.source_ref, ''), NULLIF(st.source_ref, ''))
  FROM scan_targets st
 WHERE r.scan_target_id = st.id
   AND (r.source_type IS NULL OR r.source_type = '' OR r.source_ref IS NULL OR r.source_ref = '');

ALTER TABLE image_scan_results
    DROP CONSTRAINT IF EXISTS image_scan_results_source_type_check;

ALTER TABLE image_scan_results
    ADD CONSTRAINT image_scan_results_source_type_check
    CHECK (source_type IS NULL OR source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host', 'serverless'));

CREATE INDEX IF NOT EXISTS idx_image_scan_results_source
    ON image_scan_results(org_id, source_type, source_ref, last_scanned_at DESC)
    WHERE source_type IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_image_scan_results_source;

ALTER TABLE image_scan_results
    DROP CONSTRAINT IF EXISTS image_scan_results_source_type_check,
    DROP COLUMN IF EXISTS source_ref,
    DROP COLUMN IF EXISTS source_type;

ALTER TABLE scan_evidence
    DROP CONSTRAINT IF EXISTS scan_evidence_source_type_check;

ALTER TABLE scan_evidence
    ADD CONSTRAINT scan_evidence_source_type_check
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host'));

ALTER TABLE scan_targets
    DROP CONSTRAINT IF EXISTS scan_targets_source_type_check;

ALTER TABLE scan_targets
    ADD CONSTRAINT scan_targets_source_type_check
    CHECK (source_type IN ('manual', 'registry', 'repository', 'runtime-agent', 'discoverer', 'platform', 'host'));
-- +goose StatementEnd
