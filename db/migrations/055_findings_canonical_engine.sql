-- +goose Up
-- +goose StatementBegin
ALTER TABLE findings
  ADD COLUMN IF NOT EXISTS canonical_engine TEXT;

UPDATE findings
   SET canonical_engine = NULLIF(detail_json->>'canonical_engine', '')
 WHERE canonical_engine IS NULL
   AND detail_json ? 'canonical_engine';

CREATE INDEX IF NOT EXISTS idx_findings_canonical_engine
  ON findings(org_id, canonical_engine)
  WHERE canonical_engine IS NOT NULL;
-- +goose StatementEnd
