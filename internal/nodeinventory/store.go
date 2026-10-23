// Package nodeinventory defines the set-based host inventory read.
package nodeinventory

// SummarySQL joins unique host snapshots and aggregates vulnerabilities/jobs once.
// Parameters are org, cluster, optional node and the source-cluster CVE filter.
const SummarySQL = `
WITH node_names AS (
    SELECT node FROM host_facts WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_packages WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_cis WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_containers WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT node FROM host_processes WHERE org_id = $1 AND cluster_id = $2
    UNION SELECT ref AS node FROM scan_targets WHERE org_id = $1 AND cluster_id = $2 AND type = 'host'
    UNION SELECT target_ref AS node FROM findings WHERE org_id = $1 AND cluster_id = $2 AND target_type = 'host'
    UNION SELECT target_ref AS node FROM findings WHERE org_id = $1 AND COALESCE(target_cluster_id, cluster_id) = $2 AND target_type = 'host'
)
SELECT n.node,
       COALESCE(hf.os_id, ''), COALESCE(hf.os_version_id, ''), COALESCE(hf.kernel_release, ''),
       COALESCE(hf.arch, ''), COALESCE(hf.cni_name, ''), COALESCE(hf.cri_runtime, ''),
       hf.btf_present, hf.nfqueue_capable,
       COALESCE(hf.cpu_count, 0), COALESCE(hf.memory_bytes, 0),
       COALESCE(hp.package_count, 0), COALESCE(hp.source, ''),
       COALESCE(hc.container_count, 0), COALESCE(hpr.process_count, 0),
       COALESCE(cis.profile, ''), COALESCE(cis.passed, 0), COALESCE(cis.failed, 0),
       COALESCE(cis.warned, 0), COALESCE(cis.skipped, 0),
       COALESCE(v.critical, 0), COALESCE(v.high, 0), COALESCE(v.medium, 0), COALESCE(v.low, 0), COALESCE(v.total, 0),
       COALESCE(hb.version, ''), hb.last_seen_at,
       st.id, COALESCE(st.inventory_hash, ''), COALESCE(sj.status, ''), sj.finished_at,
       hf.observed_at, hp.observed_at, hc.observed_at, hpr.observed_at, cis.observed_at,
       GREATEST(
           COALESCE(hf.observed_at, 'epoch'::timestamptz),
           COALESCE(hp.observed_at, 'epoch'::timestamptz),
           COALESCE(hc.observed_at, 'epoch'::timestamptz),
           COALESCE(hpr.observed_at, 'epoch'::timestamptz),
           COALESCE(cis.observed_at, 'epoch'::timestamptz),
           COALESCE(hb.last_seen_at, 'epoch'::timestamptz),
           COALESCE(sj.finished_at, 'epoch'::timestamptz)
       ) AS node_last_seen_at
  FROM node_names n
  LEFT JOIN (SELECT node,os_id,os_version_id,kernel_release,arch,btf_present,nfqueue_capable,cni_name,cri_runtime,observed_at,(facts->'hardware'->>'cpu_count')::int AS cpu_count,(facts->'hardware'->>'memory_bytes')::bigint AS memory_bytes FROM host_facts WHERE org_id=$1 AND cluster_id=$2) hf ON hf.node=n.node
  LEFT JOIN (SELECT node,package_count,source,observed_at FROM host_packages WHERE org_id=$1 AND cluster_id=$2) hp ON hp.node=n.node
  LEFT JOIN (SELECT node,container_count,observed_at FROM host_containers WHERE org_id=$1 AND cluster_id=$2) hc ON hc.node=n.node
  LEFT JOIN (SELECT node,process_count,observed_at FROM host_processes WHERE org_id=$1 AND cluster_id=$2) hpr ON hpr.node=n.node
  LEFT JOIN (SELECT node,profile,passed,failed,warned,skipped,observed_at FROM host_cis WHERE org_id=$1 AND cluster_id=$2) cis ON cis.node=n.node
  LEFT JOIN (
      SELECT target_ref, COUNT(*)::int AS total,
             COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical,
             COUNT(*) FILTER (WHERE severity = 'high')::int AS high,
             COUNT(*) FILTER (WHERE severity = 'medium')::int AS medium,
             COUNT(*) FILTER (WHERE severity = 'low')::int AS low
        FROM findings
       WHERE org_id = $1
         AND target_type = 'host'
         AND kind = 'vulnerability'
         AND lifecycle = 'open'
         AND (cluster_id = $2 OR (NOT $4 AND COALESCE(target_cluster_id, cluster_id) = $2))
 GROUP BY target_ref
  ) v ON v.target_ref=n.node
  LEFT JOIN (SELECT hostname,version,last_seen_at FROM component_heartbeats WHERE org_id=$1 AND cluster_id=$2 AND component='runtime-agent') hb ON hb.hostname=n.node
  LEFT JOIN (SELECT DISTINCT ON(ref) ref,id,inventory_hash FROM scan_targets WHERE org_id=$1 AND cluster_id=$2 AND type='host' ORDER BY ref,last_seen_at DESC,id) st ON st.ref=n.node
  LEFT JOIN (SELECT DISTINCT ON(target_id) target_id,status,finished_at FROM scan_jobs WHERE org_id=$1 ORDER BY target_id,requested_at DESC,id) sj ON sj.target_id=st.id
 WHERE NULLIF(BTRIM(n.node),'') IS NOT NULL AND ($3 = '' OR n.node = $3)
   AND (NOT $4 OR (NULLIF(BTRIM(n.node), '') IS NOT NULL AND EXISTS (
       SELECT 1 FROM findings f
        WHERE f.org_id = $1 AND f.cluster_id = $2 AND f.target_type = 'host'
          AND f.target_ref = n.node AND f.kind = 'vulnerability' AND f.lifecycle = 'open'
   )))`
