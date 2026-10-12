package platformrole

// ExactWorkloadPlatformRoleSQL classifies only canonical workload identities in
// an organization-owned cluster. In particular, a namespace-shaped asset name
// cannot make an image, node, or foreign-cluster record a platform workload.
func ExactWorkloadPlatformRoleSQL(org, cluster, workload string) string {
	return `CASE WHEN EXISTS(SELECT 1 FROM clusters role_cluster WHERE role_cluster.id=` + cluster + ` AND role_cluster.org_id=` + org + `) AND (` + workload + ` ~ '^[^/]+/[^/]+$' OR ` + workload + ` ~ '^[^/]+/pod/[^/]+$') THEN ` + EvidenceSQL(org, cluster, workload, "''") + ` ELSE '' END`
}

// AssetPlatformRoleSQL uses workload asset identity, never image labels or links.
// Alias is a trusted SQL alias rather than a request value.
func AssetPlatformRoleSQL(alias string) string {
	return `CASE WHEN ` + alias + `.kind IN ('workload','deployment') THEN ` + ExactWorkloadPlatformRoleSQL(alias+".org_id", alias+".cluster_id", alias+".name") + ` ELSE '' END`
}

// FindingPlatformRoleSQL gives explicit target types precedence. An image-workload
// finding describes an image cohort, not an independently identified workload.
// Legacy findings can inherit only their own tenant/cluster's workload asset.
func FindingPlatformRoleSQL(alias string) string {
	return `CASE WHEN ` + alias + `.target_type='workload' THEN ` + ExactWorkloadPlatformRoleSQL(alias+".org_id", alias+".cluster_id", alias+".target_ref") + `
 WHEN COALESCE(` + alias + `.target_type,'')='' THEN COALESCE((SELECT ` + AssetPlatformRoleSQL("role_asset") + ` FROM assets role_asset WHERE role_asset.id=` + alias + `.asset_id AND role_asset.org_id=` + alias + `.org_id AND role_asset.cluster_id IS NOT DISTINCT FROM ` + alias + `.cluster_id),'') ELSE '' END`
}
