-- +goose Up
-- +goose StatementBegin
-- E1 — declarative response-rule engine (NeuVector CLUSResponseRule parity).
--
-- Today quarantine is an imperative call with no declarative rule model. This table is
-- the typed, RBAC-gated store for response rules: each row binds a runtime event_type
-- (process|file|network|admission|scan) + a set of conditions (field/op/value) to an
-- ordered set of actions (quarantine|suppress_log|webhook|tag). Rules are evaluated
-- server-side on the ingest path and pulled by the runtime-agent via the :sync bundle.
--
-- Distinct from response_rules_v2 (migration 021), which is the NeuVector-style typed
-- *condition-catalog* engine (typed discriminators: name/level/cve_critical/proc) wired
-- to the notify/quarantine data plane. This E1 engine is the generic field/op condition
-- model with explicit priority ordering — the CLUSResponseRule shape the runtime-agent
-- stream evaluator will consume. The two coexist (gated by different RBAC verbs).
--
-- priority orders evaluation: lower number = higher precedence (evaluated first), matching
-- NeuVector's rule-id ordering. conditions/actions are validated JSONB blobs (a typed Go
-- struct in pkg/responserule is the gatekeeper), so new fields don't need a migration.
CREATE TABLE IF NOT EXISTS response_rules (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    priority    INTEGER NOT NULL DEFAULT 1000,              -- lower = evaluated first
    event_type  TEXT NOT NULL,                              -- process|file|network|admission|scan
    conditions  JSONB NOT NULL DEFAULT '[]'::jsonb,         -- [{field,op,value}, ...]
    actions     JSONB NOT NULL DEFAULT '[]'::jsonb,         -- [{type,params{...}}, ...]
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- The sync bundle + ingest evaluator both load "enabled rules for an org, ordered by
-- priority"; this index serves that hot path.
CREATE INDEX IF NOT EXISTS idx_response_rules_org_enabled_priority
    ON response_rules(org_id, enabled, priority);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS response_rules;
-- +goose StatementEnd
