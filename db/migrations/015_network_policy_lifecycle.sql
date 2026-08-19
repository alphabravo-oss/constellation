-- +goose Up
-- +goose StatementBegin
CREATE TABLE network_policy_lifecycle_states (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    workload           TEXT NOT NULL,
    namespace          TEXT NOT NULL,
    current_mode       TEXT NOT NULL CHECK (current_mode IN ('discover', 'monitor', 'protect')),
    target_mode        TEXT CHECK (target_mode IN ('monitor', 'protect')),
    approval_status    TEXT NOT NULL,
    reason             TEXT NOT NULL,
    preview_yaml        TEXT NOT NULL DEFAULT '',
    diff                JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_available BOOLEAN NOT NULL DEFAULT FALSE,
    rollback_refs      JSONB NOT NULL DEFAULT '{}'::jsonb,
    audit_trail        JSONB NOT NULL DEFAULT '[]'::jsonb,
    applied_ref         TEXT,
    rollback_ref        TEXT,
    last_applied_at    TIMESTAMPTZ,
    created_by         UUID REFERENCES users(id),
    updated_by         UUID REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, workload)
);

CREATE INDEX idx_network_policy_lifecycle_org_namespace ON network_policy_lifecycle_states(org_id, namespace, updated_at DESC);
CREATE INDEX idx_network_policy_lifecycle_org_status ON network_policy_lifecycle_states(org_id, approval_status, updated_at DESC);
CREATE INDEX idx_network_policy_lifecycle_org_mode ON network_policy_lifecycle_states(org_id, current_mode, updated_at DESC);

CREATE TABLE network_policy_lifecycle_actions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    workload       TEXT NOT NULL,
    namespace      TEXT NOT NULL,
    action         TEXT NOT NULL,
    previous_mode  TEXT NOT NULL,
    next_mode      TEXT NOT NULL,
    reason         TEXT NOT NULL,
    preview_yaml   TEXT NOT NULL DEFAULT '',
    preview_refs   JSONB NOT NULL DEFAULT '{}'::jsonb,
    diff           JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_ref   TEXT,
    idempotency_key TEXT,
    actor_id       UUID REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_network_policy_actions_org_workload ON network_policy_lifecycle_actions(org_id, workload, created_at DESC);
CREATE UNIQUE INDEX idx_network_policy_actions_idempotency ON network_policy_lifecycle_actions(org_id, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE TABLE network_policy_rollback_refs (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    workload       TEXT NOT NULL,
    namespace      TEXT NOT NULL,
    rollback_ref   TEXT NOT NULL,
    previous_mode  TEXT NOT NULL,
    restore_mode   TEXT NOT NULL,
    preview_yaml   TEXT NOT NULL DEFAULT '',
    preview_refs   JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by     UUID REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, rollback_ref)
);

CREATE INDEX idx_network_policy_rollback_refs_org_workload ON network_policy_rollback_refs(org_id, workload, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_policy_rollback_refs;
DROP TABLE IF EXISTS network_policy_lifecycle_actions;
DROP TABLE IF EXISTS network_policy_lifecycle_states;
-- +goose StatementEnd
