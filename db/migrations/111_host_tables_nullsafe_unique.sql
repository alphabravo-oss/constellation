-- NULL-safe uniqueness for the host_* snapshot tables.
--
-- The runtime-agent upserts one row per (cluster_id, node) for each of
-- host_facts / host_processes / host_containers / host_packages / host_cis.
-- The original unique index was on (cluster_id, node). In Postgres NULLs
-- are distinct in a UNIQUE index, so when the ingest handler could not
-- resolve a cluster_id it wrote cluster_id=NULL and the ON CONFLICT
-- (cluster_id, node) arbiter NEVER fired — every agent report inserted a
-- brand-new row, growing the table unbounded for the same node.
--
-- This migration replaces each (cluster_id, node) unique index with a
-- NULL-safe expression index on
--     (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node)
-- so the NULL-cluster case dedups on (org_id, node) instead of duplicating,
-- while a real cluster_id still keys per (cluster_id, node) (org_id is
-- redundant-but-harmless there since a cluster_id maps to exactly one org).
-- The all-zero "nil" UUID is the COALESCE sentinel; gen_random_uuid()
-- never produces it so it cannot collide with a real cluster id.
--
-- The ingest handlers are updated in the same change to (a) resolve the
-- reporting node's real cluster via the init-bundle that minted the agent
-- token and (b) target this expression in their ON CONFLICT clause.

-- +goose Up
-- +goose StatementBegin

-- Collapse any pre-existing NULL-cluster duplicates (produced by the old
-- unbounded-growth bug) down to the most recent row per logical key before
-- the unique index is built, otherwise CREATE UNIQUE INDEX would fail.

-- host_facts
DELETE FROM host_facts a USING host_facts b
 WHERE a.org_id = b.org_id AND a.node = b.node
   AND COALESCE(a.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
     = COALESCE(b.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
   AND (a.observed_at, a.id) < (b.observed_at, b.id);
DROP INDEX IF EXISTS uniq_host_facts_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_facts_org_cluster_node
    ON host_facts (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node);

-- host_processes
DELETE FROM host_processes a USING host_processes b
 WHERE a.org_id = b.org_id AND a.node = b.node
   AND COALESCE(a.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
     = COALESCE(b.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
   AND (a.observed_at, a.id) < (b.observed_at, b.id);
DROP INDEX IF EXISTS uniq_host_processes_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_processes_org_cluster_node
    ON host_processes (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node);

-- host_containers
DELETE FROM host_containers a USING host_containers b
 WHERE a.org_id = b.org_id AND a.node = b.node
   AND COALESCE(a.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
     = COALESCE(b.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
   AND (a.observed_at, a.id) < (b.observed_at, b.id);
DROP INDEX IF EXISTS uniq_host_containers_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_containers_org_cluster_node
    ON host_containers (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node);

-- host_packages
DELETE FROM host_packages a USING host_packages b
 WHERE a.org_id = b.org_id AND a.node = b.node
   AND COALESCE(a.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
     = COALESCE(b.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
   AND (a.observed_at, a.id) < (b.observed_at, b.id);
DROP INDEX IF EXISTS uniq_host_packages_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_packages_org_cluster_node
    ON host_packages (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node);

-- host_cis
DELETE FROM host_cis a USING host_cis b
 WHERE a.org_id = b.org_id AND a.node = b.node
   AND COALESCE(a.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
     = COALESCE(b.cluster_id, '00000000-0000-0000-0000-000000000000'::uuid)
   AND (a.observed_at, a.id) < (b.observed_at, b.id);
DROP INDEX IF EXISTS uniq_host_cis_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_cis_org_cluster_node
    ON host_cis (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

DROP INDEX IF EXISTS uniq_host_cis_org_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_cis_cluster_node
    ON host_cis(cluster_id, node);

DROP INDEX IF EXISTS uniq_host_packages_org_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_packages_cluster_node
    ON host_packages(cluster_id, node);

DROP INDEX IF EXISTS uniq_host_containers_org_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_containers_cluster_node
    ON host_containers(cluster_id, node);

DROP INDEX IF EXISTS uniq_host_processes_org_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_processes_cluster_node
    ON host_processes(cluster_id, node);

DROP INDEX IF EXISTS uniq_host_facts_org_cluster_node;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_host_facts_cluster_node
    ON host_facts(cluster_id, node);

-- +goose StatementEnd
