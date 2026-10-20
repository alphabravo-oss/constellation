package platformrole

import "fmt"

// ScopeSQL validates a presentation scope and wraps a trusted classification.
func ScopeSQL(scope, classification string) (string, error) {
	switch scope {
	case "", "all":
		return "true", nil
	case "application":
		return "NOT (" + classification + ")", nil
	case "constellation":
		return "(" + classification + ")", nil
	default:
		return "", fmt.Errorf("invalid workload_scope")
	}
}

// ConstellationDeploymentSQL identifies chart-managed Constellation workloads for
// presentation only. Labels are not authority to bypass enforcement. Unclassified
// dependencies and customer workloads sharing the namespace remain visible.
func ConstellationDeploymentSQL(alias string) string {
	return `COALESCE((` + alias + `.labels->>'app.kubernetes.io/name'='constellation'
 AND ` + alias + `.labels->>'app.kubernetes.io/part-of'='constellation'
 AND ` + alias + `.labels->>'app.kubernetes.io/managed-by'='Helm'
 AND starts_with(` + alias + `.labels->>'helm.sh/chart','constellation-')),false)`
}

// ConstellationFindingSQL returns true only when every known workload owner is
// Constellation. Shared images and missing ownership stay in the application view.
// Arguments are trusted SQL aliases; request values must never be interpolated.
func ConstellationFindingSQL(alias string) string {
	workload := func(cluster, ref string) string {
		return `(SELECT count(*)>0 AND bool_and(` + ConstellationDeploymentSQL("system_deployment") + `)
 FROM deployments system_deployment WHERE system_deployment.org_id=` + alias + `.org_id
 AND system_deployment.cluster_id=` + cluster + ` AND (
 system_deployment.namespace||'/'||system_deployment.name=` + ref + ` OR EXISTS(
 SELECT 1 FROM pod_workload_links system_pod WHERE system_pod.org_id=` + alias + `.org_id
 AND system_pod.cluster_id=` + cluster + ` AND system_pod.deployment_id=system_deployment.id
 AND system_pod.pod_workload_id=` + ref + `)))`
	}
	return `CASE WHEN ` + alias + `.target_type IN ('image-workload','image') THEN
 (SELECT count(*)>0 AND bool_and(` + ConstellationDeploymentSQL("system_deployment") + `)
 FROM image_workload_links system_link
 LEFT JOIN deployments system_deployment ON system_deployment.id=system_link.deployment_id
 AND system_deployment.org_id=system_link.org_id AND system_deployment.cluster_id=system_link.cluster_id
 WHERE system_link.org_id=` + alias + `.org_id
 AND (` + alias + `.cluster_id IS NULL OR system_link.cluster_id=` + alias + `.cluster_id)
 AND ` + alias + `.target_ref<>'' AND (` + alias + `.target_ref=system_link.image_digest
 OR ` + alias + `.target_ref=system_link.image_ref OR ` + alias + `.target_ref=system_link.image_ref_normalized))
 WHEN ` + alias + `.target_type='workload' THEN ` + workload(alias+".cluster_id", alias+".target_ref") + `
 WHEN COALESCE(` + alias + `.target_type,'')='' THEN COALESCE((SELECT ` + workload("system_asset.cluster_id", "system_asset.name") + `
 FROM assets system_asset WHERE system_asset.id=` + alias + `.asset_id AND system_asset.org_id=` + alias + `.org_id
 AND system_asset.cluster_id IS NOT DISTINCT FROM ` + alias + `.cluster_id
 AND system_asset.kind IN ('workload','deployment')),false)
 ELSE false END`
}
