-- +goose Up
-- +goose StatementBegin
-- B6: cross-namespace network boundary enforcement (NBE) toggle.
--
-- NeuVector's "Network Boundary Enforcement" is a per-namespace (per-domain)
-- flag — RESTDomain.Nbe in controller/api/apis.go — that flags, and under
-- protect mode denies, any flow that crosses a namespace boundary. It is the
-- coarse "namespaces are isolation domains" guardrail that sits above the
-- per-workload learned rules.
--
-- This table stores that flag per (org, cluster, namespace). The netpolicy_
-- settings table (migration 120) is per-(org,cluster) and already owned by the
-- cluster-wide enforcement master switch; NBE is namespace-granular, so it gets
-- its own table rather than widening that row.
--
--   mode = 'off'      -> cross-namespace flows are not flagged (default: the
--                        feature ships disabled, byte-for-byte unchanged behaviour)
--        = 'observe'  -> cross-namespace flows are flagged (nbe=true) but allowed
--        = 'protect'  -> cross-namespace flows are flagged AND denied
--
-- SAFETY: the ABSENCE of a row means 'off' (the whole feature is opt-in), and a
-- freshly-inserted row defaults to 'observe' — it flags but never blocks until
-- an operator explicitly promotes it to 'protect'. No namespace is ever forced
-- into 'protect'. Mirrors the "seeded rows ship in monitor" rule.
CREATE TABLE IF NOT EXISTS netpolicy_nbe_settings (
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  UUID NOT NULL,
    namespace   TEXT NOT NULL,
    mode        TEXT NOT NULL DEFAULT 'observe'
                CHECK (mode IN ('off','observe','protect')),
    updated_by  UUID,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id, namespace)
);

CREATE INDEX IF NOT EXISTS idx_netpolicy_nbe_org_cluster
    ON netpolicy_nbe_settings(org_id, cluster_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS netpolicy_nbe_settings;
-- +goose StatementEnd
