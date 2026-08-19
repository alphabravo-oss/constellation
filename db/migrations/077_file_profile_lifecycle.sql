-- Persist workload file-monitor lifecycle state. File profiles are separate from
-- process baselines because file behavior needs its own observed-path evidence,
-- sensitive-path review, and future allow/deny exception model.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS file_profile_states (
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

CREATE TABLE IF NOT EXISTS file_profile_transitions (
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

CREATE INDEX IF NOT EXISTS idx_file_profile_states_cluster_mode
    ON file_profile_states(org_id, cluster_id, mode, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_file_profile_transitions_workload
    ON file_profile_transitions(org_id, cluster_id, workload_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_file_open_workload
    ON events(org_id, cluster_id, workload_id, at DESC)
    WHERE kind = 'file_open';

CREATE INDEX IF NOT EXISTS idx_events_file_open_path
    ON events(org_id, cluster_id, (payload->>'path'), at DESC)
    WHERE kind = 'file_open';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_events_file_open_path;
DROP INDEX IF EXISTS idx_events_file_open_workload;
DROP INDEX IF EXISTS idx_file_profile_transitions_workload;
DROP INDEX IF EXISTS idx_file_profile_states_cluster_mode;
DROP TABLE IF EXISTS file_profile_transitions;
DROP TABLE IF EXISTS file_profile_states;
-- +goose StatementEnd
