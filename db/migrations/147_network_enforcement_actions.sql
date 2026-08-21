-- +goose Up
-- Phase 1 network enforcement: direct block/isolate actions taken from the network map.
-- Rows are reconciled to the cluster by the network-policy-applier (apply active,
-- delete lifting). This is the CNI-enforced Tier-1 datapath (no dp inline required):
--   isolate  -> native NetworkPolicy default-deny selecting the target workload's pods
--   block_ip -> CiliumNetworkPolicy egressDeny/ingressDeny toCIDR scoped to one workload
CREATE TABLE IF NOT EXISTS network_enforcement_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    cluster_id      UUID,
    kind            TEXT NOT NULL,                 -- 'isolate' | 'block_ip'
    target          TEXT NOT NULL,                 -- workload 'ns/name' (isolate) or CIDR (block_ip)
    namespace       TEXT NOT NULL DEFAULT '',      -- k8s namespace the manifest lives in
    workload        TEXT NOT NULL DEFAULT '',      -- source workload (block_ip scopes the deny to it)
    direction       TEXT NOT NULL DEFAULT 'both',  -- 'egress' | 'ingress' | 'both' (block_ip)
    manifest_flavor TEXT NOT NULL,                 -- 'native' | 'cilium'
    manifest        TEXT NOT NULL,                 -- rendered manifest (JSON, valid YAML)
    resource_ref    TEXT NOT NULL DEFAULT '',      -- apiVersion/Kind:ns/name
    state           TEXT NOT NULL DEFAULT 'active',-- 'active' | 'lifting' | 'removed'
    reason          TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL DEFAULT '',
    last_status     TEXT NOT NULL DEFAULT '',      -- reconcile outcome: 'ok' | 'error' | ''
    last_error      TEXT NOT NULL DEFAULT '',
    last_applied_at TIMESTAMPTZ,
    last_deleted_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_net_enforce_cluster_state ON network_enforcement_actions (cluster_id, state);
CREATE INDEX IF NOT EXISTS idx_net_enforce_org ON network_enforcement_actions (org_id);

-- +goose Down
DROP TABLE IF EXISTS network_enforcement_actions;
