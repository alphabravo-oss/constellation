-- +goose Up
-- +goose StatementBegin
-- Wave C: extend the policies table with the StackRox-inspired metadata required
-- by the new boolean policy DSL. Existing rows continue to work via NULL/default
-- values; the new DSL engine consumes these columns when policy.engine='dsl'.
ALTER TABLE policies
    ADD COLUMN IF NOT EXISTS scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS exclusions JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'imperative',
    ADD COLUMN IF NOT EXISTS lifecycle_stages TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS mitre_attack_vectors TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS criteria_locked BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS mitre_vectors_locked BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS severity TEXT NOT NULL DEFAULT 'medium',
    ADD COLUMN IF NOT EXISTS enforcement_actions TEXT[] NOT NULL DEFAULT '{}';

-- Enforce a check constraint for source even on legacy rows.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'policies_source_chk'
    ) THEN
        ALTER TABLE policies
            ADD CONSTRAINT policies_source_chk
            CHECK (source IN ('imperative', 'declarative'));
    END IF;
END$$;

-- Findings: per-finding risk subfactor decomposition.
-- (Composed by pkg/risk.Decompose at ingest; cached here for the detail endpoint.)
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS risk_factors JSONB NOT NULL DEFAULT '[]'::jsonb;

CREATE INDEX IF NOT EXISTS idx_policies_lifecycle_stages ON policies USING GIN (lifecycle_stages);
CREATE INDEX IF NOT EXISTS idx_policies_source ON policies(org_id, source);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_policies_source;
DROP INDEX IF EXISTS idx_policies_lifecycle_stages;
ALTER TABLE findings
    DROP COLUMN IF EXISTS risk_factors;
ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_source_chk,
    DROP COLUMN IF EXISTS enforcement_actions,
    DROP COLUMN IF EXISTS severity,
    DROP COLUMN IF EXISTS mitre_vectors_locked,
    DROP COLUMN IF EXISTS criteria_locked,
    DROP COLUMN IF EXISTS mitre_attack_vectors,
    DROP COLUMN IF EXISTS lifecycle_stages,
    DROP COLUMN IF EXISTS source,
    DROP COLUMN IF EXISTS exclusions,
    DROP COLUMN IF EXISTS scopes;
-- +goose StatementEnd
