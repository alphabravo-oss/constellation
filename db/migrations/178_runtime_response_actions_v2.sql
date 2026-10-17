-- +goose Up
-- Isolated from legacy149: old replicas must never offer exact process actions
-- to agents without source-start identity, pidfd validation and durable receipts.
ALTER TABLE clusters ADD CONSTRAINT clusters_response_owner_unique UNIQUE (org_id, id);
CREATE TABLE runtime_response_actions_v2 (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 action_token UUID NOT NULL DEFAULT gen_random_uuid(),
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 cluster_id UUID NOT NULL,
 node TEXT NOT NULL CHECK (btrim(node) <> '' AND octet_length(node) <= 253),
 type TEXT NOT NULL DEFAULT 'kill_process' CHECK (type = 'kill_process'),
 workload_id TEXT NOT NULL CHECK (btrim(workload_id) <> '' AND octet_length(workload_id) <= 4096),
 container_id TEXT NOT NULL DEFAULT '' CHECK (octet_length(container_id) <= 256),
 pid INTEGER NOT NULL CHECK (pid > 1),
 comm TEXT NOT NULL CHECK (btrim(comm) <> '' AND octet_length(comm) <= 16),
 boot_id UUID NOT NULL,
 process_start_ticks BIGINT NOT NULL CHECK (process_start_ticks > 0),
 start_boot_ns NUMERIC(20,0) NOT NULL CHECK (start_boot_ns > 0 AND start_boot_ns <= 18446744073709551615),
 source_at TIMESTAMPTZ NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','done','failed','uncertain')),
 result_body JSONB,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 completed_at TIMESTAMPTZ,
 FOREIGN KEY (org_id,cluster_id) REFERENCES clusters(org_id,id) ON DELETE CASCADE
);
CREATE INDEX runtime_response_actions_v2_pending ON runtime_response_actions_v2(org_id,cluster_id,node,created_at,id) WHERE state='pending';
-- +goose Down
DROP TABLE runtime_response_actions_v2;
ALTER TABLE clusters DROP CONSTRAINT clusters_response_owner_unique;
