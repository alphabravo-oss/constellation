-- Full unsigned native threat identifiers. This release requires a controlled
-- stop/replace of old INTEGER readers/writers, not a mixed-version rolling
-- upgrade. ALTER TYPE may rewrite retained tables and requires disk/lock
-- preflight. Prefer roll-forward; Down refuses any unrepresentable state.
-- +goose Up
-- +goose StatementBegin
DO $$ BEGIN
  -- All ingest/fold/prune writers take this lock first. Keep the same order.
  PERFORM 1 FROM network_flow_rollup_state WHERE id = true FOR UPDATE;
  LOCK TABLE runtime_threats, network_flows, network_flow_rollups IN ACCESS EXCLUSIVE MODE;
END $$;
ALTER TABLE network_flow_rollups ADD COLUMN threat_id_complete boolean NOT NULL DEFAULT true;
-- A negative signed MAX proves every non-null input was negative. Nonnegative
-- MAX, including zero, can have hidden a larger unsigned negative input.
UPDATE network_flow_rollups SET threat_id_complete = max_threat_id IS NULL OR max_threat_id < 0;
ALTER TABLE runtime_threats ALTER COLUMN threat_id TYPE bigint
  USING CASE WHEN threat_id < 0 THEN threat_id::bigint + 4294967296 ELSE threat_id::bigint END;
ALTER TABLE network_flows ALTER COLUMN threat_id TYPE bigint
  USING CASE WHEN threat_id < 0 THEN threat_id::bigint + 4294967296 ELSE threat_id::bigint END;
ALTER TABLE network_flow_rollups ALTER COLUMN max_threat_id TYPE bigint
  USING CASE WHEN max_threat_id < 0 THEN max_threat_id::bigint + 4294967296 ELSE max_threat_id::bigint END;
ALTER TABLE runtime_threats ADD CONSTRAINT runtime_threat_id_uint32 CHECK (threat_id BETWEEN 0 AND 4294967295);
ALTER TABLE network_flows ADD CONSTRAINT network_flow_threat_id_uint32 CHECK (threat_id BETWEEN 0 AND 4294967295);
ALTER TABLE network_flow_rollups ADD CONSTRAINT rollup_threat_id_uint32 CHECK (max_threat_id BETWEEN 0 AND 4294967295);
-- Repair metadata only. Never re-add observations or rewrite traffic totals.
-- The retention fence and exact folded count are both required; raw rows newer
-- than the locked watermark must not make an old bucket appear complete.
WITH retained AS (
 SELECT f.org_id,f.cluster_id,f.src_workload,f.dst_workload,f.protocol,
        COALESCE(f.l7_protocol,'') AS l7_protocol,COALESCE(f.dst_port,0) AS dst_port,
        COALESCE(f.verdict,'') AS verdict,date_trunc('hour',f.at) AS bucket,
        COUNT(*)::bigint AS flow_count,MAX(f.threat_id) AS max_threat_id
 FROM network_flows f CROSS JOIN network_flow_rollup_state s
 WHERE s.id=true AND f.at >= s.raw_pruned_before AND f.at <= s.watermark
 GROUP BY f.org_id,f.cluster_id,f.src_workload,f.dst_workload,f.protocol,
          COALESCE(f.l7_protocol,''),COALESCE(f.dst_port,0),COALESCE(f.verdict,''),date_trunc('hour',f.at)
)
UPDATE network_flow_rollups r SET max_threat_id=f.max_threat_id,threat_id_complete=true
FROM retained f,network_flow_rollup_state s
WHERE s.id=true AND r.bucket>=s.raw_pruned_before AND r.flow_count>0 AND r.flow_count=f.flow_count
  AND (r.org_id,r.cluster_id,r.src_workload,r.dst_workload,r.protocol,r.l7_protocol,r.dst_port,r.verdict,r.bucket)
    =(f.org_id,f.cluster_id,f.src_workload,f.dst_workload,f.protocol,f.l7_protocol,f.dst_port,f.verdict,f.bucket);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
  PERFORM 1 FROM network_flow_rollup_state WHERE id = true FOR UPDATE;
  LOCK TABLE runtime_threats, network_flows, network_flow_rollups IN ACCESS EXCLUSIVE MODE;
  IF EXISTS(SELECT 1 FROM runtime_threats WHERE threat_id>2147483647)
     OR EXISTS(SELECT 1 FROM network_flows WHERE threat_id>2147483647)
     OR EXISTS(SELECT 1 FROM network_flow_rollups WHERE max_threat_id>2147483647 OR NOT threat_id_complete) THEN
    RAISE EXCEPTION 'cannot downgrade unsigned threat IDs or incomplete historical maxima; roll forward or restore a qualified backup';
  END IF;
END $$;
ALTER TABLE runtime_threats DROP CONSTRAINT runtime_threat_id_uint32;
ALTER TABLE network_flows DROP CONSTRAINT network_flow_threat_id_uint32;
ALTER TABLE network_flow_rollups DROP CONSTRAINT rollup_threat_id_uint32;
ALTER TABLE runtime_threats ALTER COLUMN threat_id TYPE integer USING threat_id::integer;
ALTER TABLE network_flows ALTER COLUMN threat_id TYPE integer USING threat_id::integer;
ALTER TABLE network_flow_rollups ALTER COLUMN max_threat_id TYPE integer USING max_threat_id::integer;
ALTER TABLE network_flow_rollups DROP COLUMN threat_id_complete;
-- +goose StatementEnd
