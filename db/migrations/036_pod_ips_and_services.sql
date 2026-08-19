-- +goose Up
-- +goose StatementBegin
-- Wave M2: resolve raw IPs in the Network Map into named workloads.
--
-- `pod_ips`         — every running Pod's IP -> owning workload (Deployment /
--                    StatefulSet / DaemonSet name walked from owner refs;
--                    standalone Pods record their own name).
-- `cluster_services`— every Service's ClusterIP(s) -> namespace/name; headless
--                    Services (`ClusterIP: None`) are skipped.
--
-- The control-plane network-flow ingest path uses these tables to rewrite
-- `src_workload` / `dst_workload` from "cluster/<ip>" into "<ns>/<deployment>"
-- or "<ns>/<svc-name>" at insert time. Stale rows are swept by the discoverer
-- (`last_seen_at < now() - 2 * RECONCILE_INTERVAL`) every reconcile pass so a
-- pod IP that gets recycled doesn't continue to resolve to the dead workload.
--
-- We intentionally do NOT backfill existing network_flows rows in this
-- migration — the table is partitioned and 24h of rows can be tens of
-- millions. The operator runs `constellationctl network-flows backfill
-- --hours=24` (cmd/constellationctl/network_flows.go) when ready.
CREATE TABLE IF NOT EXISTS pod_ips (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    namespace       TEXT NOT NULL,
    pod_name        TEXT NOT NULL,
    deployment      TEXT,                          -- resolved workload name (owner-ref walk)
    kind            TEXT NOT NULL DEFAULT 'Pod',   -- 'Deployment'|'StatefulSet'|'DaemonSet'|'Pod'
    ip              INET NOT NULL,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, ip)
);

CREATE INDEX IF NOT EXISTS idx_pod_ips_org_ip      ON pod_ips (org_id, ip);
CREATE INDEX IF NOT EXISTS idx_pod_ips_cluster_ns  ON pod_ips (cluster_id, namespace);

CREATE TABLE IF NOT EXISTS cluster_services (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id      UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    namespace       TEXT NOT NULL,
    name            TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'Service',
    cluster_ip      INET NOT NULL,
    ports           JSONB NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, cluster_ip)
);

CREATE INDEX IF NOT EXISTS idx_cluster_services_org_ip     ON cluster_services (org_id, cluster_ip);
CREATE INDEX IF NOT EXISTS idx_cluster_services_cluster_ns ON cluster_services (cluster_id, namespace);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS cluster_services;
DROP TABLE IF EXISTS pod_ips;
-- +goose StatementEnd
