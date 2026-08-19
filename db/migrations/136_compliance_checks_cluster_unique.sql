-- +goose Up
-- +goose StatementBegin
-- CMP-CLOBBER-03: multi-cluster CIS results overwrote each other.
--
-- The host-compliance ingest (internal/handler/compliance Ingest) keyed its upsert on
-- the partial unique index (org_id, framework, control_id) WHERE cluster_id IS NULL
-- (migration 110), so two clusters (or two nodes) in one org clobbered each other's
-- kube-bench/docker-bench rows — the second scan refreshed the single org-wide row in
-- place. Re-key host-compliance rows on (org_id, cluster_id, node, framework, control_id)
-- so each cluster/node keeps its own results (matching the host_cis dedup pattern).
--
-- The k8s-object collector (cmd/constellation-k8s-compliance-collector) legitimately
-- stores many rows per (cluster_id, framework, control_id) — one per evaluated object —
-- and de-dupes itself with DELETE+reinsert; it never sets `node`. Scoping the new unique
-- index to WHERE node IS NOT NULL keeps the collector path unconstrained (its rows have
-- node NULL, and NULLs are excluded from a partial index) while enforcing one row per
-- control per (cluster, node) for the host-compliance path, which always sets node
-- (empty string when the node is unknown, e.g. a cluster-level kube-bench run).

ALTER TABLE compliance_checks ADD COLUMN IF NOT EXISTS node TEXT;

-- Drop the old partial index that clobbered multi-cluster host-bench results.
DROP INDEX IF EXISTS idx_compliance_checks_hostbench_unique;

-- The pre-existing org-wide host-bench rows (cluster_id IS NULL, node NULL) can't be
-- attributed to a cluster after the fact; drop them so the next scan repopulates cleanly
-- per-cluster. Collector rows always carry a non-NULL cluster_id and are left untouched.
DELETE FROM compliance_checks WHERE cluster_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_checks_hostbench_unique
    ON compliance_checks (
        org_id,
        COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid),
        node, framework, control_id
    )
    WHERE node IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_compliance_checks_hostbench_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_compliance_checks_hostbench_unique
    ON compliance_checks (org_id, framework, control_id)
    WHERE cluster_id IS NULL;
ALTER TABLE compliance_checks DROP COLUMN IF EXISTS node;
-- +goose StatementEnd
