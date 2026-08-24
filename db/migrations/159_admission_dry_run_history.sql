-- Persist admission dry-run assessments so operators can review and export the
-- same evidence across browsers and users. The live admission webhook remains
-- unchanged; this table records explicit console/API dry-runs only.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS admission_dry_run_history (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id       UUID REFERENCES clusters(id) ON DELETE SET NULL,
    actor_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    image            TEXT NOT NULL,
    namespace        TEXT,
    decision         TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
    enforcement_mode TEXT NOT NULL DEFAULT 'none',
    current_outcome  TEXT,
    protect_outcome  TEXT,
    matches          JSONB NOT NULL DEFAULT '[]'::jsonb,
    request          JSONB NOT NULL DEFAULT '{}'::jsonb,
    response         JSONB NOT NULL DEFAULT '{}'::jsonb,
    assessed_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_admission_dry_run_history_org_cluster_at
    ON admission_dry_run_history(org_id, cluster_id, assessed_at DESC);

CREATE INDEX IF NOT EXISTS idx_admission_dry_run_history_org_at
    ON admission_dry_run_history(org_id, assessed_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_admission_dry_run_history_org_at;
DROP INDEX IF EXISTS idx_admission_dry_run_history_org_cluster_at;
DROP TABLE IF EXISTS admission_dry_run_history;
-- +goose StatementEnd
