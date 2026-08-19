-- +goose Up
-- +goose StatementBegin
-- P1-1: group->group network rule edges.
--
-- A row here is a rule authored as a directed edge between two groups (by name,
-- resolved against the `groups` table): members of from_group may initiate to
-- members of to_group on `ports`. Unlike the per-workload runtime_policies rows,
-- an edge applies to ALL current and future members — expansion to concrete
-- per-workload rules is recomputed whenever group membership changes (via the
-- existing group sync). Mirrors NeuVector's CLUSPolicyRule.From/To group edges.
--
-- SAFETY: mode defaults to 'monitor' so a freshly-authored edge is observed,
-- never enforced, until an operator explicitly promotes it.
CREATE TABLE IF NOT EXISTS group_rule_edges (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id   UUID NOT NULL,
    from_group   TEXT NOT NULL,
    to_group     TEXT NOT NULL,
    -- ports: [{protocol, port}] ; empty array means "all ports"
    ports        JSONB NOT NULL DEFAULT '[]'::jsonb,
    mode         TEXT NOT NULL DEFAULT 'monitor'
                 CHECK (mode IN ('discover','monitor','protect')),
    comment      TEXT NOT NULL DEFAULT '',
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by   UUID,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, from_group, to_group)
);

CREATE INDEX IF NOT EXISTS idx_group_rule_edges_org_cluster
    ON group_rule_edges(org_id, cluster_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS group_rule_edges;
-- +goose StatementEnd
