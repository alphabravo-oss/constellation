-- Persist process-baseline lifecycle state so workload detail and the
-- baseline kanban read the same learn -> monitor -> enforce policy state.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS process_baseline_states (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id         UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload_id        TEXT NOT NULL,
    namespace          TEXT NOT NULL,
    name               TEXT NOT NULL,
    mode               TEXT NOT NULL CHECK (mode IN ('learn', 'monitor', 'enforce')),
    learn_started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    monitor_started_at TIMESTAMPTZ,
    enforce_started_at TIMESTAMPTZ,
    created_by         UUID REFERENCES users(id),
    updated_by         UUID REFERENCES users(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload_id)
);

CREATE TABLE IF NOT EXISTS process_baseline_transitions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload_id TEXT NOT NULL,
    from_mode   TEXT NOT NULL CHECK (from_mode IN ('learn', 'monitor', 'enforce')),
    to_mode     TEXT NOT NULL CHECK (to_mode IN ('learn', 'monitor', 'enforce')),
    reason      TEXT NOT NULL,
    actor_id    UUID REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_process_baseline_states_cluster_mode
    ON process_baseline_states(org_id, cluster_id, mode, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_process_baseline_transitions_workload
    ON process_baseline_transitions(org_id, cluster_id, workload_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_process_baseline_transitions_workload;
DROP INDEX IF EXISTS idx_process_baseline_states_cluster_mode;
DROP TABLE IF EXISTS process_baseline_transitions;
DROP TABLE IF EXISTS process_baseline_states;
-- +goose StatementEnd
