-- +goose Up
-- +goose StatementBegin
-- B2b — operator-managed response-rule provenance.
--
-- The constellation-operator reconciles policy CRs directly into the policy store with the
-- CR as the source of truth. The policies table already records authoring provenance via
-- the StackRox-inspired source column (migration 027: 'imperative' = UI/API, 'declarative' =
-- committed as YAML and reconciled by the operator), so admission rules reuse source=
-- 'declarative' with no schema change. The response_rules table (migration 103) has no such
-- column yet — add the same provenance marker so the operator's finalizer only deletes rows
-- it owns (source='declarative') and drift correction only overwrites rows the CR owns.
-- Existing rows default to 'imperative' (REST-authored), matching the policies convention.
ALTER TABLE response_rules
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'imperative';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'response_rules_source_chk'
    ) THEN
        ALTER TABLE response_rules
            ADD CONSTRAINT response_rules_source_chk
            CHECK (source IN ('imperative', 'declarative'));
    END IF;
END$$;

CREATE INDEX IF NOT EXISTS idx_response_rules_source ON response_rules(org_id, source);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_response_rules_source;
ALTER TABLE response_rules
    DROP CONSTRAINT IF EXISTS response_rules_source_chk,
    DROP COLUMN IF EXISTS source;
-- +goose StatementEnd
