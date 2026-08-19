-- Runtime identity (Phase A): retain pod_ips history so a network flow can be
-- resolved to its workload even after the pod is gone or its IP is reused.
--
-- Before this, pod_ips was UNIQUE(org_id, cluster_id, ip) and swept at 2x the
-- discoverer interval (~60s), so it held only currently-running pods. A flow
-- from a short-lived pod, or one that raced the discoverer, resolved to nothing
-- and was stamped "cluster/<ip>" permanently. Keying on (pod_uid, ip) instead of
-- (ip) lets a reused IP keep one row per pod generation, and the resolver picks
-- the row whose [first_seen_at, last_seen_at] window brackets the flow's time —
-- correct across pod churn and IP reuse. The discoverer now retains rows for a
-- longer resolution horizon and the api auto-backfills late-resolved flows.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE pod_ips DROP CONSTRAINT IF EXISTS pod_ips_org_id_cluster_id_ip_key;
-- One row per (pod generation, ip). Reused IPs become distinct historical rows.
ALTER TABLE pod_ips ADD CONSTRAINT pod_ips_org_cluster_uid_ip_key
    UNIQUE (org_id, cluster_id, pod_uid, ip);
-- Resolution fetches all rows for an (org, ip) then time-brackets on the window.
CREATE INDEX IF NOT EXISTS idx_pod_ips_resolve
    ON pod_ips (org_id, ip, last_seen_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_pod_ips_resolve;
ALTER TABLE pod_ips DROP CONSTRAINT IF EXISTS pod_ips_org_cluster_uid_ip_key;
-- Best-effort restore of the current-only unique (may fail if history rows exist).
-- ALTER TABLE pod_ips ADD CONSTRAINT pod_ips_org_id_cluster_id_ip_key UNIQUE (org_id, cluster_id, ip);
-- +goose StatementEnd
