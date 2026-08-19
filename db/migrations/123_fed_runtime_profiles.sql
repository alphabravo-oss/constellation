-- +goose Up
-- +goose StatementBegin
-- P2-3 federation: broaden federated rule types beyond policy/group/admission/
-- response-override to the per-workload runtime profiles that previously stayed
-- per-cluster (so runtime protection drifted across a fleet). Mirrors NeuVector's
-- FedFileMonitorProfilesType / FedProcessProfilesType / FedNetworkRulesType.
--
-- The existing federated rule kinds replicate into their own org-scoped tables
-- (policies/groups/response_rule_overrides) which the joint marks cfg_type='fed'.
-- The runtime profile tables (file_profile_rules, process_baseline_states,
-- network policies) are per-cluster runtime STATE with a NOT NULL cluster_id FK,
-- so a joint has no matching cluster to key a master-authored fed row against.
-- Following NeuVector, master-authored fed profiles are fleet-wide, group-keyed
-- templates stored opaquely by (kind, key) rather than bound to one cluster; the
-- joint's agents consult them read-only across every cluster. One generic table
-- holds all three new kinds keyed by (org_id, rule_kind, rule_key); the payload
-- is the master's rule body verbatim.
--
-- cfg_type is always 'fed' here (the table only ever holds master-authored,
-- read-only rows) but is carried as a column so the leave/demote purge and any
-- future read-only guards select on the same cfg_type='fed' predicate the other
-- federated tables use.
CREATE TABLE IF NOT EXISTS fed_runtime_profiles (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    -- file_profile | host_process_profile | network_policy
    rule_kind  TEXT NOT NULL,
    -- Stable identity of the master rule (group name / selector / rule name).
    rule_key   TEXT NOT NULL,
    payload    JSONB NOT NULL,
    cfg_type   TEXT NOT NULL DEFAULT 'fed',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, rule_kind, rule_key)
);

CREATE INDEX IF NOT EXISTS idx_fed_runtime_profiles_org_kind
    ON fed_runtime_profiles(org_id, rule_kind, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_fed_runtime_profiles_org_kind;
DROP TABLE IF EXISTS fed_runtime_profiles;
-- +goose StatementEnd
