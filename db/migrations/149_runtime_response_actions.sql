-- +goose Up
-- RT-KILL-02 producer queue: targeted kill_process / kill_session response actions
-- the runtime-agent responder pulls and executes (cmd/constellation-runtime-agent/
-- response_actions.go). A response RULE with a kill action enqueues a row here
-- (workload-scoped); the agent's pull-poller GETs pending rows for its node/cluster,
-- SIGKILLs the pid / deletes the conntrack entry, then POSTs the outcome back into
-- the result sink which flips state to done|failed. Distinct from the CNI/netpolicy
-- enforcement tables (network_enforcement_actions, quarantine_entries): this severs a
-- single live process/session rather than isolating a workload's whole network.
CREATE TABLE IF NOT EXISTS runtime_response_actions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    cluster_id   UUID,
    node         TEXT NOT NULL DEFAULT '',      -- target node; '' = offered to every node in the cluster
    type         TEXT NOT NULL,                 -- 'kill_process' | 'kill_session'
    workload_id  TEXT NOT NULL DEFAULT '',
    container_id TEXT NOT NULL DEFAULT '',
    pid          INTEGER NOT NULL DEFAULT 0,
    comm         TEXT NOT NULL DEFAULT '',
    protocol     TEXT NOT NULL DEFAULT '',      -- kill_session 5-tuple
    src_ip       TEXT NOT NULL DEFAULT '',
    src_port     INTEGER NOT NULL DEFAULT 0,
    dst_ip       TEXT NOT NULL DEFAULT '',
    dst_port     INTEGER NOT NULL DEFAULT 0,
    state        TEXT NOT NULL DEFAULT 'pending', -- 'pending' | 'done' | 'failed'
    result       TEXT NOT NULL DEFAULT '',        -- agent-reported reason on success
    error        TEXT NOT NULL DEFAULT '',        -- agent-reported reason on failure
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
-- The pull-poller selects pending rows for a (cluster_id, node) each interval.
CREATE INDEX IF NOT EXISTS idx_runtime_response_actions_poll
    ON runtime_response_actions (cluster_id, node, state);

-- +goose Down
DROP TABLE IF EXISTS runtime_response_actions;
