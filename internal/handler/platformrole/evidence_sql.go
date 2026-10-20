package platformrole

// EvidencePlatformRoleSQL mirrors EvidencePlatformRoles for inventories that must
// filter platform workloads before counting and paging. Arguments are trusted SQL
// expressions, never request values. Ambiguous deployment ownership is unknown.
func EvidenceSQL(org, cluster, workload, namespace string) string {
	ip := func(value string) string {
		return "((" + value + " ~ '^(0|[1-9][0-9]{0,2})(\\.(0|[1-9][0-9]{0,2})){3}$' OR (strpos(" + value + ", ':')>0 AND strpos(" + value + ", '/')=0 AND strpos(" + value + ", '%')=0)) AND pg_input_is_valid(" + value + ", 'inet'))"
	}
	return `(WITH original AS (SELECT COALESCE(` + workload + `,'')::text AS workload, COALESCE(` + namespace + `,'')::text AS namespace),
 identity AS (SELECT CASE WHEN strpos(workload,'/')=0 AND workload<>'' AND namespace<>'' AND NOT ` + ip("workload") + ` THEN namespace||'/'||workload ELSE workload END AS workload, namespace FROM original),
 parts AS (SELECT workload, string_to_array(workload,'/') AS p, CASE WHEN strpos(workload,'/')>0 THEN split_part(workload,'/',1) ELSE namespace END AS namespace FROM identity)
 SELECT CASE WHEN namespace IN ('external','host','node','cluster') OR ` + ip("p[cardinality(p)]") + ` THEN ''
 WHEN ` + SQL("namespace", "'{}'::jsonb") + `='core' THEN 'core'
 WHEN ` + cluster + ` IS NULL OR ` + cluster + `='00000000-0000-0000-0000-000000000000'::uuid OR p[1]='' OR p[2]='' OR NOT(cardinality(p)=2 OR (cardinality(p)=3 AND p[2]='pod' AND p[3]<>'')) THEN ''
 ELSE COALESCE((SELECT CASE WHEN COUNT(*)=1 THEN min(role) ELSE '' END FROM (
 SELECT d.id, ` + SQL("d.namespace", "d.labels") + ` AS role FROM deployments d
 WHERE d.org_id=` + org + ` AND d.cluster_id=` + cluster + ` AND d.namespace=parts.namespace AND d.name=p[2] AND cardinality(p)=2
 UNION
 SELECT d.id, ` + SQL("d.namespace", "d.labels") + ` AS role FROM pod_workload_links link
 JOIN deployments d ON d.id=link.deployment_id AND d.org_id=` + org + ` AND d.cluster_id=` + cluster + ` AND d.namespace=parts.namespace
 WHERE link.org_id=` + org + ` AND link.cluster_id=` + cluster + ` AND link.namespace=parts.namespace AND link.pod_workload_id=parts.workload AND cardinality(p)=3 AND p[2]='pod'
 ) candidates),'') END FROM parts)`
}
