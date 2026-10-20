package findings

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

// All views reuse canonical scan-finding IDs and the legacy digest/ref/repository
// association predicate for links without a digest. A recorded digest is exact
// identity and must never borrow another artifact through a mutable tag/ref.
// Ownership is checked on both sides of every join.
const affectedImageMatch = `((COALESCE(l.image_digest,'')<>'' AND l.image_digest=m.image_digest) OR (COALESCE(l.image_digest,'')='' AND ((m.image_ref<>'' AND l.image_ref=m.image_ref) OR (m.image_ref_normalized<>'' AND l.image_ref_normalized=m.image_ref_normalized) OR (m.image_repository<>'' AND l.image_repository=m.image_repository AND (COALESCE(m.image_tag,'')='' OR l.image_tag=m.image_tag)))))`
const affectedSourcePrefix = `WITH canonical AS (
 SELECT f.id AS finding_id,f.severity,f.risk_score,COALESCE(f.package_ecosystem,'') AS package_ecosystem,COALESCE(f.package_name,'') AS package_name,COALESCE(f.package_version,'') AS package_version,COALESCE(f.package_purl,'') AS package_purl,COALESCE(f.fixed_version,'') AS fixed_version,f.last_seen_at AS finding_last_seen_at,
 r.id AS image_scan_result_id,a.id AS asset_id,r.image_ref,r.image_ref_normalized,r.image_repository,r.image_tag,r.image_digest,r.platform,r.scanner_profile,r.vulndb_bundle_version,r.vulndb_bundle_hash,r.last_scanned_at
 FROM image_scan_findings f JOIN image_scan_results r ON r.id=f.image_scan_result_id AND r.org_id=f.org_id
 LEFT JOIN assets a ON a.id=r.asset_id AND a.org_id=f.org_id
 WHERE f.org_id=$1 AND UPPER(COALESCE(f.external_id,''))=$2 AND ($5::text='' OR f.severity=$5)
), owned_links AS (
 SELECT l.*,c.name AS cluster_name FROM image_workload_links l
 JOIN clusters c ON c.id=l.cluster_id AND c.org_id=$1
 JOIN deployments d ON d.id=l.deployment_id AND d.org_id=$1 AND d.cluster_id=l.cluster_id
 WHERE l.org_id=$1 AND ($3::uuid IS NULL OR l.cluster_id=$3) AND ($4::text='' OR l.namespace=$4)
), scoped_findings AS (
 SELECT m.* FROM canonical m WHERE ($3::uuid IS NULL AND $4::text='') OR EXISTS(SELECT 1 FROM owned_links l WHERE {{match}})
), images AS (
 SELECT image_scan_result_id AS id,asset_id,image_ref,image_ref_normalized,image_repository,image_tag,image_digest,platform,scanner_profile,vulndb_bundle_version,vulndb_bundle_hash,
 count(DISTINCT finding_id)::int AS finding_count,COALESCE(max(risk_score),0)::int AS max_risk_score,
 count(DISTINCT finding_id) FILTER(WHERE severity='critical')::int AS critical,count(DISTINCT finding_id) FILTER(WHERE severity='high')::int AS high,count(DISTINCT finding_id) FILTER(WHERE severity='medium')::int AS medium,count(DISTINCT finding_id) FILTER(WHERE severity='low')::int AS low,count(DISTINCT finding_id) FILTER(WHERE severity='info')::int AS info,
 jsonb_agg(jsonb_build_object('finding_id',finding_id,'package_ecosystem',package_ecosystem,'package_name',package_name,'package_version',package_version,'package_purl',package_purl,'fixed_version',fixed_version,'severity',severity,'risk_score',risk_score) ORDER BY risk_score DESC,package_name,package_version,finding_id) AS packages,
 max(finding_last_seen_at) AS last_seen_at,last_scanned_at
 FROM scoped_findings GROUP BY image_scan_result_id,asset_id,image_ref,image_ref_normalized,image_repository,image_tag,image_digest,platform,scanner_profile,vulndb_bundle_version,vulndb_bundle_hash,last_scanned_at
), workloads AS (
 SELECT jsonb_build_array(l.cluster_id,l.deployment_id,l.workload_id,l.namespace,l.name,l.kind)::text AS id,l.cluster_id,l.cluster_name,l.deployment_id,l.workload_id,l.namespace,l.name,l.kind,
 max(l.image_ref) AS image_ref,max(l.image_ref_normalized) AS image_ref_normalized,COALESCE(max(l.image_repository),'') AS image_repository,COALESCE(max(l.image_tag),'') AS image_tag,COALESCE(max(l.image_digest),'') AS image_digest,
 count(DISTINCT m.finding_id)::int AS finding_count,COALESCE(max(m.risk_score),0)::int AS max_risk_score,count(DISTINCT m.finding_id) FILTER(WHERE m.severity='critical')::int AS critical_count,count(DISTINCT m.finding_id) FILTER(WHERE m.severity='high')::int AS high_count,max(l.last_seen_at) AS last_seen_at,jsonb_agg(DISTINCT jsonb_build_object('image_ref',l.image_ref,'image_ref_normalized',l.image_ref_normalized,'image_repository',COALESCE(l.image_repository,''),'image_tag',COALESCE(l.image_tag,''),'image_digest',COALESCE(l.image_digest,'')) ORDER BY jsonb_build_object('image_ref',l.image_ref,'image_ref_normalized',l.image_ref_normalized,'image_repository',COALESCE(l.image_repository,''),'image_tag',COALESCE(l.image_tag,''),'image_digest',COALESCE(l.image_digest,''))) AS image_evidence
 FROM scoped_findings m JOIN owned_links l ON {{match}}
 GROUP BY l.cluster_id,l.cluster_name,l.deployment_id,l.workload_id,l.namespace,l.name,l.kind
), clusters AS (
 SELECT cluster_id AS id,cluster_name AS name,count(*)::int AS workload_count,sum(finding_count)::bigint AS finding_count,max(max_risk_score)::int AS max_risk_score FROM workloads GROUP BY cluster_id,cluster_name
), packages AS (
 SELECT finding_id AS id,image_scan_result_id,image_ref,image_repository,COALESCE(image_tag,'') AS image_tag,image_digest,package_ecosystem,package_name,package_version,package_purl,fixed_version,severity,risk_score,finding_last_seen_at AS last_seen_at FROM scoped_findings
) `

const affectedImageColumns = "id,asset_id,image_ref,image_ref_normalized,image_repository,image_tag,image_digest,platform,scanner_profile,vulndb_bundle_version,vulndb_bundle_hash,finding_count,max_risk_score,critical,high,medium,low,info,packages,last_seen_at,last_scanned_at"
const affectedWorkloadColumns = "id,cluster_id,cluster_name,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest,finding_count,max_risk_score,critical_count,high_count,last_seen_at,image_evidence"
const affectedClusterColumns = "id,name,workload_count,finding_count,max_risk_score"
const affectedPackageColumns = "id,image_scan_result_id,image_ref,image_repository,image_tag,image_digest,package_ecosystem,package_name,package_version,package_purl,fixed_version,severity,risk_score,last_seen_at"

type affectedInventoryPackage struct {
	RowID string `json:"row_id"`
	cveAffectedPackageDTO
	ImageScanResultID uuid.UUID `json:"image_scan_result_id"`
	ImageRef          string    `json:"image_ref"`
	ImageRepository   string    `json:"image_repository"`
	ImageTag          string    `json:"image_tag"`
	ImageDigest       string    `json:"image_digest"`
	LastSeenAt        time.Time `json:"last_seen_at"`
}
type affectedInventoryImage struct {
	RowID string `json:"row_id"`
	cveAffectedImageDTO
}
type affectedImageEvidence struct {
	ImageRef           string `json:"image_ref"`
	ImageRefNormalized string `json:"image_ref_normalized"`
	ImageRepository    string `json:"image_repository"`
	ImageTag           string `json:"image_tag"`
	ImageDigest        string `json:"image_digest"`
}
type affectedInventoryWorkload struct {
	ImageEvidence []affectedImageEvidence `json:"image_evidence"`
	RowID         string                  `json:"row_id"`
	cveAffectedWorkloadDTO
}
type affectedInventoryCluster struct {
	RowID string `json:"row_id"`
	cveAffectedClusterDTO
}
type affectedInventoryRecord struct {
	Item any
	CSV  []string
}

func affectedInventoryDefinition(r *http.Request, org uuid.UUID, cveID, view string, cluster any) (inventorylist.Definition, inventorylist.Options, error) {
	values, err := inventorylist.Query(r)
	if err != nil {
		return inventorylist.Definition{}, inventorylist.Options{}, err
	}
	for _, key := range []string{"limit", "offset"} {
		if values.Has(key) {
			raw := values.Get(key)
			number, err := strconv.Atoi(raw)
			if err != nil || (key == "limit" && (number < 1 || number > 500)) || (key == "offset" && number < 0) {
				return inventorylist.Definition{}, inventorylist.Options{}, fmt.Errorf("invalid %s", key)
			}
		}
	}
	severity, err := inventorylist.Filter(values, "severity", "critical", "high", "medium", "low", "info")
	if err != nil {
		return inventorylist.Definition{}, inventorylist.Options{}, err
	}
	namespace := strings.TrimSpace(values.Get("namespace"))
	source := strings.ReplaceAll(affectedSourcePrefix, "{{match}}", affectedImageMatch)
	args := []any{org, cveID, cluster, namespace, severity}
	var columns, summary, search string
	defaultSort := "risk"
	var sorts map[string]string
	switch view {
	case "images":
		columns = affectedImageColumns
		search = "concat_ws(' ',image_ref,image_repository,image_tag,image_digest,platform,scanner_profile)"
		summary = `jsonb_build_object('total',count(*),'image_count',count(*),'finding_count',COALESCE(sum(finding_count),0),'max_risk_score',COALESCE(max(max_risk_score),0))`
		sorts = map[string]string{"image": "lower(image_repository||':'||COALESCE(image_tag,''))", "findings": "finding_count", "risk": "max_risk_score", "scanned": "last_scanned_at", "last_seen": "last_seen_at"}
	case "workloads":
		columns = affectedWorkloadColumns
		search = "concat_ws(' ',cluster_name,cluster_id,workload_id,namespace,name,kind,(SELECT string_agg(concat_ws(' ',tuple->>'image_ref',tuple->>'image_ref_normalized',tuple->>'image_repository',tuple->>'image_tag',tuple->>'image_digest'),' ') FROM jsonb_array_elements(image_evidence) tuple))"
		summary = `jsonb_build_object('total',count(*),'workload_count',count(*),'deployment_count',count(DISTINCT deployment_id),'cluster_count',count(DISTINCT cluster_id),'finding_count',COALESCE(sum(finding_count),0),'max_risk_score',COALESCE(max(max_risk_score),0))`
		sorts = map[string]string{"name": "lower(namespace||'/'||name)", "cluster": "lower(cluster_name)", "kind": "kind", "findings": "finding_count", "risk": "max_risk_score", "last_seen": "last_seen_at"}
	case "clusters":
		columns = affectedClusterColumns
		search = "concat_ws(' ',id,name)"
		defaultSort = "workloads"
		summary = `jsonb_build_object('total',count(*),'cluster_count',count(*),'workload_count',COALESCE(sum(workload_count),0),'finding_count',COALESCE(sum(finding_count),0),'max_risk_score',COALESCE(max(max_risk_score),0))`
		sorts = map[string]string{"name": "lower(name)", "workloads": "workload_count", "findings": "finding_count", "risk": "max_risk_score"}
	case "packages":
		columns = affectedPackageColumns
		search = "concat_ws(' ',package_name,package_ecosystem,package_version,package_purl,fixed_version,image_ref,image_repository,image_digest)"
		summary = `jsonb_build_object('total',count(*),'package_count',count(*),'finding_count',count(*),'image_count',count(DISTINCT image_scan_result_id),'max_risk_score',COALESCE(max(risk_score),0))`
		sorts = map[string]string{"package": "lower(package_name)", "image": "lower(image_repository||':'||image_tag)", "severity": "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END", "risk": "risk_score", "version": "package_version", "fixed": "fixed_version", "last_seen": "last_seen_at"}
	default:
		return inventorylist.Definition{}, inventorylist.Options{}, fmt.Errorf("view must be images, workloads, clusters or packages")
	}
	options, err := inventorylist.Parse(values, sorts, defaultSort)
	if err != nil {
		return inventorylist.Definition{}, options, err
	}
	where := "true"
	if q := strings.TrimSpace(values.Get("q")); q != "" {
		args = append(args, q)
		where = "strpos(lower(" + search + "),lower($6::text))>0"
	}
	return inventorylist.Definition{SQL: source + "SELECT " + columns + " FROM " + view, Columns: columns, Args: args, Where: where, Summary: summary}, options, nil
}

func scanAffectedInventory(view string, row inventorylist.Row) (affectedInventoryRecord, error) {
	stamp := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	switch view {
	case "images":
		var image affectedInventoryImage
		var packages []byte
		var critical, high, medium, low, info int
		err := row.Scan(&image.ImageScanResultID, &image.AssetID, &image.ImageRef, &image.ImageRefNormalized, &image.ImageRepository, &image.ImageTag, &image.ImageDigest, &image.Platform, &image.ScannerProfile, &image.VulnDBBundleVersion, &image.VulnDBBundleHash, &image.FindingCount, &image.MaxRiskScore, &critical, &high, &medium, &low, &info, &packages, &image.LastSeenAt, &image.LastScannedAt)
		if err != nil {
			return affectedInventoryRecord{}, err
		}
		image.RowID = image.ImageScanResultID.String()
		image.SeverityCounts = map[string]int{"critical": critical, "high": high, "medium": medium, "low": low, "info": info}
		if err := json.Unmarshal(packages, &image.Packages); err != nil {
			return affectedInventoryRecord{}, err
		}
		tag := ""
		if image.ImageTag != nil {
			tag = *image.ImageTag
		}
		return affectedInventoryRecord{image, []string{image.RowID, image.ImageRepository, tag, image.ImageRef, image.ImageDigest, image.Platform, image.ScannerProfile, strconv.Itoa(image.FindingCount), strconv.Itoa(image.MaxRiskScore), stamp(image.LastScannedAt), stamp(image.LastSeenAt)}}, nil
	case "workloads":
		var workload affectedInventoryWorkload
		var evidence []byte
		err := row.Scan(&workload.RowID, &workload.ClusterID, &workload.ClusterName, &workload.DeploymentID, &workload.WorkloadID, &workload.Namespace, &workload.Name, &workload.Kind, &workload.ImageRef, &workload.ImageRefNormalized, &workload.ImageRepository, &workload.ImageTag, &workload.ImageDigest, &workload.FindingCount, &workload.MaxRiskScore, &workload.CriticalCount, &workload.HighCount, &workload.LastSeenAt, &evidence)
		if err != nil {
			return affectedInventoryRecord{}, err
		}
		if err := json.Unmarshal(evidence, &workload.ImageEvidence); err != nil {
			return affectedInventoryRecord{}, err
		}
		return affectedInventoryRecord{workload, []string{workload.RowID, workload.ClusterID.String(), workload.ClusterName, workload.DeploymentID.String(), workload.WorkloadID, workload.Namespace, workload.Name, workload.Kind, string(evidence), strconv.Itoa(workload.FindingCount), strconv.Itoa(workload.MaxRiskScore), strconv.Itoa(workload.CriticalCount), strconv.Itoa(workload.HighCount), stamp(workload.LastSeenAt)}}, nil
	case "clusters":
		var cluster affectedInventoryCluster
		err := row.Scan(&cluster.ClusterID, &cluster.Name, &cluster.WorkloadCount, &cluster.FindingCount, &cluster.MaxRiskScore)
		if err != nil {
			return affectedInventoryRecord{}, err
		}
		cluster.RowID = cluster.ClusterID.String()
		return affectedInventoryRecord{cluster, []string{cluster.RowID, cluster.Name, strconv.Itoa(cluster.WorkloadCount), strconv.Itoa(cluster.FindingCount), strconv.Itoa(cluster.MaxRiskScore)}}, nil
	case "packages":
		var pkg affectedInventoryPackage
		err := row.Scan(&pkg.FindingID, &pkg.ImageScanResultID, &pkg.ImageRef, &pkg.ImageRepository, &pkg.ImageTag, &pkg.ImageDigest, &pkg.PackageEcosystem, &pkg.PackageName, &pkg.PackageVersion, &pkg.PackagePURL, &pkg.FixedVersion, &pkg.Severity, &pkg.RiskScore, &pkg.LastSeenAt)
		if err != nil {
			return affectedInventoryRecord{}, err
		}
		pkg.RowID = pkg.FindingID.String()
		return affectedInventoryRecord{pkg, []string{pkg.RowID, pkg.ImageScanResultID.String(), pkg.ImageRepository, pkg.ImageRef, pkg.ImageDigest, pkg.PackageEcosystem, pkg.PackageName, pkg.PackageVersion, pkg.PackagePURL, pkg.FixedVersion, pkg.Severity, strconv.Itoa(pkg.RiskScore), stamp(pkg.LastSeenAt)}}, nil
	}
	return affectedInventoryRecord{}, fmt.Errorf("invalid affected inventory view")
}

func (c *CVE) AffectedInventory(w http.ResponseWriter, r *http.Request) {
	c.readAffectedInventory(w, r, false)
}
func (c *CVE) AffectedInventoryCSV(w http.ResponseWriter, r *http.Request) {
	c.readAffectedInventory(w, r, true)
}
func (c *CVE) readAffectedInventory(w http.ResponseWriter, r *http.Request, export bool) {
	fail := func(status int, message string) { apiutil.WriteStatus(r.Context(), w, status, message) }
	subject, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		fail(401, "subject required")
		return
	}
	id := strings.ToUpper(strings.TrimSpace(chi.URLParam(r, "id")))
	if id == "" {
		fail(400, "missing cve id")
		return
	}
	view := chi.URLParam(r, "view")
	values, err := inventorylist.Query(r)
	if err != nil {
		fail(400, "invalid query string")
		return
	}
	var cluster any
	if raw := strings.TrimSpace(values.Get("cluster_id")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			fail(400, "invalid cluster_id")
			return
		}
		var owned bool
		if err := c.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, parsed, subject.OrgID).Scan(&owned); err != nil {
			fail(500, "Affected evidence could not be loaded")
			return
		}
		if !owned {
			fail(404, "cluster not found")
			return
		}
		cluster = parsed
	}
	definition, options, err := affectedInventoryDefinition(r, subject.OrgID, id, view, cluster)
	if err != nil {
		fail(400, err.Error())
		return
	}
	scan := func(row inventorylist.Row) (affectedInventoryRecord, error) { return scanAffectedInventory(view, row) }
	if export {
		headers := map[string][]string{"images": {"Row ID", "Repository", "Tag", "Image ref", "Digest", "Platform", "Scanner profile", "Finding instances", "Max risk", "Last scanned", "Last seen"}, "workloads": {"Row ID", "Cluster ID", "Cluster", "Deployment ID", "Workload ID", "Namespace", "Name", "Kind", "Image evidence (JSON)", "Finding instances", "Max risk", "Critical", "High", "Last seen"}, "clusters": {"Row ID", "Cluster", "Workload associations", "Finding instances", "Max risk"}, "packages": {"Row ID", "Image scan ID", "Repository", "Image ref", "Digest", "Ecosystem", "Package", "Version", "PURL", "Fixed version", "Severity", "Risk", "Last seen"}}
		body, metadata, err := inventorylist.CSV(r.Context(), c.db.Pool(), definition, options, scan, headers[view], func(record affectedInventoryRecord) []string { return record.CSV })
		if err != nil {
			fail(500, "Affected evidence could not be loaded")
			return
		}
		inventorylist.WriteCSV(w, "constellation-cve-affected-"+view+".csv", body, metadata)
		return
	}
	records, metadata, err := inventorylist.Read(r.Context(), c.db.Pool(), definition, options, scan)
	if err != nil {
		fail(500, "Affected evidence could not be loaded")
		return
	}
	items := make([]any, 0, len(records))
	for _, record := range records {
		items = append(items, record.Item)
	}
	httpx.WriteJSON(w, 200, map[string]any{"cve_id": id, "cluster_id": cluster, "view": view, "items": items, "total": metadata.Total, "summary": metadata.Summary, "has_more": metadata.HasMore, "limit": options.Limit, "offset": options.Offset, "sort": options.Sort, "order": options.Order})
}
