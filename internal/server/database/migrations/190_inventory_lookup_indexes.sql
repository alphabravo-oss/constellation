-- +goose Up
-- Snapshot uniqueness uses COALESCE(cluster_id,...) to cover unclustered hosts.
-- Plain cluster equality cannot use that expression's node suffix. Give the hot
-- inventory lookups the exact equality prefix and latest-observation ordering.
CREATE INDEX idx_host_facts_node_latest ON host_facts(org_id,cluster_id,node,observed_at DESC);
CREATE INDEX idx_host_packages_node_latest ON host_packages(org_id,cluster_id,node,observed_at DESC);
CREATE INDEX idx_host_containers_node_latest ON host_containers(org_id,cluster_id,node,observed_at DESC);
CREATE INDEX idx_host_processes_node_latest ON host_processes(org_id,cluster_id,node,observed_at DESC);
CREATE INDEX idx_host_cis_node_latest ON host_cis(org_id,cluster_id,node,observed_at DESC);
CREATE INDEX idx_scan_targets_host_node ON scan_targets(org_id,cluster_id,ref,last_seen_at DESC) WHERE type='host';
CREATE INDEX idx_findings_host_node_open ON findings(org_id,target_ref,cluster_id) INCLUDE(severity,target_cluster_id)
 WHERE target_type='host' AND kind='vulnerability' AND lifecycle='open';
CREATE INDEX idx_scan_jobs_target_latest ON scan_jobs(org_id,target_id,requested_at DESC) INCLUDE(status,finished_at);
-- Evidence joins compare nullable cluster IDs. Put workload before cluster so
-- those joins can find one workload without walking the entire cluster prefix.
CREATE INDEX idx_network_lifecycle_workload_lookup ON network_policy_lifecycle_states(org_id,workload,cluster_id);
CREATE INDEX idx_network_apply_workload_latest ON network_policy_apply_status(org_id,workload,updated_at DESC,flavor);
