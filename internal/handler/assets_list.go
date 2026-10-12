package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	searchdsl "github.com/alphabravocompany/constellation/pkg/search/dsl"
)

const assetInventorySQL = `WITH generic_finding_rollup AS (
             SELECT asset_id,
                    count(*)::int AS finding_count,
                    count(*) FILTER (WHERE severity = 'critical')::int AS critical_findings,
                    count(*) FILTER (WHERE severity = 'high')::int AS high_findings,
                    count(*) FILTER (WHERE lifecycle NOT IN ('resolved', 'suppressed'))::int AS open_findings
               FROM findings
              WHERE org_id = $1
                AND ($2::uuid IS NULL OR cluster_id = $2)
              GROUP BY asset_id
           ), latest_image_results AS (
             SELECT DISTINCT ON (asset_id, image_digest, platform, scanner_profile)
                    id, org_id, asset_id
               FROM image_scan_results
              WHERE org_id = $1 AND asset_id IS NOT NULL
              ORDER BY asset_id, image_digest, platform, scanner_profile, last_scanned_at DESC, id DESC
           ), image_finding_rollup AS (
             SELECT lir.asset_id,
                    count(*)::int AS finding_count,
                    count(*) FILTER (WHERE f.severity = 'critical')::int AS critical_findings,
                    count(*) FILTER (WHERE f.severity = 'high')::int AS high_findings,
                    count(*)::int AS open_findings
               FROM latest_image_results lir
               JOIN image_scan_findings f ON f.image_scan_result_id = lir.id AND f.org_id=lir.org_id
              GROUP BY lir.asset_id
           ), sbom_rollup AS (
             SELECT asset_id, count(DISTINCT format)::int AS sbom_count
               FROM (
                 SELECT lir.asset_id, a.format
                   FROM latest_image_results lir
                   JOIN image_scan_artifacts a
                     ON a.org_id = lir.org_id
                    AND a.image_scan_result_id = lir.id
                    AND a.artifact_type = 'sbom'
                 UNION ALL
                 SELECT d.asset_id, d.format
                   FROM sbom_documents d
                   JOIN assets da ON da.id = d.asset_id
                  WHERE da.org_id = $1
                    AND ($2::uuid IS NULL OR da.cluster_id = $2)
               ) sb
              GROUP BY asset_id
           )
           SELECT a.id, a.cluster_id, a.kind, a.name, ` + assetDisplayNameSQL + `, a.digest, a.labels, a.ai_workload, a.criticality,
                  COALESCE(fr.finding_count, 0), COALESCE(fr.critical_findings, 0),
                  COALESCE(fr.high_findings, 0), COALESCE(fr.open_findings, 0),
                  COALESCE(sr.sbom_count, 0), i.signed, COALESCE(i.registry, ''),
                  COALESCE(i.repository, ''), COALESCE(i.tag, ''), i.size_bytes,
                  a.first_seen_at, a.last_seen_at
             FROM assets a
             LEFT JOIN generic_finding_rollup gfr ON gfr.asset_id = a.id
             LEFT JOIN image_finding_rollup ifr ON ifr.asset_id = a.id
             LEFT JOIN LATERAL (
                 SELECT CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.finding_count, 0)
                             ELSE COALESCE(gfr.finding_count, 0)
                        END AS finding_count,
                        CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.critical_findings, 0)
                             ELSE COALESCE(gfr.critical_findings, 0)
                        END AS critical_findings,
                        CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.high_findings, 0)
                             ELSE COALESCE(gfr.high_findings, 0)
                        END AS high_findings,
                        CASE WHEN a.kind = 'image'
                             THEN COALESCE(ifr.open_findings, 0)
                             ELSE COALESCE(gfr.open_findings, 0)
                        END AS open_findings
             ) fr ON true
             LEFT JOIN sbom_rollup sr ON sr.asset_id = a.id
             LEFT JOIN images i ON i.asset_id = a.id
            WHERE a.org_id = $1
              AND ($2::uuid IS NULL OR a.cluster_id = $2)`

func assetInventoryDefinition(r *http.Request) (inventorylist.Definition, inventorylist.Options, error) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		return inventorylist.Definition{}, inventorylist.Options{}, fmt.Errorf("subject required")
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		return inventorylist.Definition{}, inventorylist.Options{}, err
	}
	o, err := inventorylist.Parse(values, map[string]string{"risk": "ROW(critical_findings,high_findings,finding_count,last_seen_at)", "asset": "lower(display_name)", "kind": "kind", "criticality": "CASE criticality WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END", "last-seen": "last_seen_at", "supply-chain": "sbom_count"}, "risk")
	if err != nil {
		return inventorylist.Definition{}, o, err
	}
	// Existing clients request up to 1,000 assets; keep that bound while pages use100.
	if limit, err := strconv.Atoi(values.Get("limit")); err == nil && limit > 0 && limit <= 1000 {
		o.Limit = limit
	}
	cluster, err := parseClusterIDParam(r)
	if err != nil {
		return inventorylist.Definition{}, o, err
	}
	kind, err := inventorylist.Filter(values, "kind", "image", "workload", "iac-resource", "ml-model", "cloud-resource", "host", "repository", "serverless")
	if err != nil {
		return inventorylist.Definition{}, o, err
	}
	criticality, err := inventorylist.Filter(values, "criticality", "critical", "high", "medium", "low")
	if err != nil {
		return inventorylist.Definition{}, o, err
	}
	compiled, err := searchdsl.Compile(values.Get("q"), assetsSearchSchema)
	if err != nil {
		return inventorylist.Definition{}, o, fmt.Errorf("search: %w", err)
	}
	args := []any{subj.OrgID, cluster}
	sql := assetInventorySQL
	if !compiled.Empty() {
		sql += " AND " + shiftPlaceholders(compiled.Where, len(args))
		args = append(args, compiled.Args...)
	}
	if search := strings.TrimSpace(values.Get("search")); search != "" {
		args = append(args, search)
		sql += " AND strpos(lower(concat_ws(' ',a.name,(" + assetDisplayNameSQL + "),a.kind,a.digest,i.registry,i.repository,i.tag,a.labels::text)),lower($" + strconv.Itoa(len(args)) + "::text))>0"
	}
	where := []string{"true"}
	bind := func(value any) string { args = append(args, value); return "$" + strconv.Itoa(len(args)) }
	if kind != "" {
		where = append(where, "kind="+bind(kind))
	}
	if criticality != "" {
		where = append(where, "criticality="+bind(criticality))
	}
	if raw := values.Get("ai_workload"); raw != "" {
		ai, err := strconv.ParseBool(raw)
		if err != nil {
			return inventorylist.Definition{}, o, fmt.Errorf("invalid ai_workload")
		}
		where = append(where, "ai_workload="+bind(ai))
	}
	return inventorylist.Definition{SQL: sql, Columns: "id,cluster_id,kind,name,display_name,digest,labels,ai_workload,criticality,finding_count,critical_findings,high_findings,open_findings,sbom_count,image_signed,registry,repository,tag,size_bytes,first_seen_at,last_seen_at", Where: strings.Join(where, " AND "), Args: args, Summary: `jsonb_build_object('total',count(*),'images',count(*) FILTER(WHERE kind='image'),'workloads',count(*) FILTER(WHERE kind='workload'),'critical_high',COALESCE(sum(critical_findings+high_findings),0),'open_findings',COALESCE(sum(open_findings),0),'signed_images',count(*) FILTER(WHERE kind='image' AND image_signed=true),'unsigned_images',count(*) FILTER(WHERE kind='image' AND image_signed=false),'signature_unknown',count(*) FILTER(WHERE kind='image' AND image_signed IS NULL),'with_sbom',count(*) FILTER(WHERE sbom_count>0),'missing_sbom',count(*) FILTER(WHERE kind='image' AND sbom_count=0),'ai',count(*) FILTER(WHERE ai_workload))`}, o, nil
}

func scanAssetInventoryRow(row inventorylist.Row) (assetDTO, error) {
	var item assetDTO
	var labels []byte
	err := row.Scan(&item.ID, &item.ClusterID, &item.Kind, &item.Name, &item.DisplayName, &item.Digest, &labels, &item.AIWorkload, &item.Criticality, &item.FindingCount, &item.CriticalFindings, &item.HighFindings, &item.OpenFindings, &item.SBOMCount, &item.ImageSigned, &item.Registry, &item.Repository, &item.Tag, &item.SizeBytes, &item.FirstSeenAt, &item.LastSeenAt)
	item.Labels = json.RawMessage(labels)
	return item, err
}

// assetInventoryScope rejects unavailable or foreign selected clusters before a
// read/export can present an empty inventory as a successful scope resolution.
func (a *Assets) assetInventoryScope(w http.ResponseWriter, r *http.Request) bool {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return false
	}
	cluster, err := parseClusterIDParam(r)
	if err != nil {
		jsonError(w, 400, err.Error())
		return false
	}
	if cluster != nil {
		var owned bool
		if err := a.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, cluster, subj.OrgID).Scan(&owned); err != nil {
			jsonError(w, 500, err.Error())
			return false
		}
		if !owned {
			jsonError(w, 404, "cluster not found")
			return false
		}
	}
	return true
}

func (a *Assets) List(w http.ResponseWriter, r *http.Request) {
	if !a.assetInventoryScope(w, r) {
		return
	}
	d, o, err := assetInventoryDefinition(r)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), a.db.Pool(), d, o, scanAssetInventoryRow)
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"assets": items, "limit": o.Limit, "offset": o.Offset, "total": meta.Total, "has_more": meta.HasMore, "summary": meta.Summary, "sort": o.Sort, "order": o.Order})
}

func (a *Assets) ExportCSV(w http.ResponseWriter, r *http.Request) {
	if !a.assetInventoryScope(w, r) {
		return
	}
	d, o, err := assetInventoryDefinition(r)
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	body, meta, err := inventorylist.CSV(r.Context(), a.db.Pool(), d, o, scanAssetInventoryRow, []string{"ID", "Cluster ID", "Kind", "Name", "Display name", "Digest", "Criticality", "AI workload", "Findings", "Critical findings", "High findings", "Open findings", "SBOM formats", "Image signed", "Registry", "Repository", "Tag", "Size bytes", "First seen", "Last seen", "Labels"}, func(item assetDTO) []string {
		cluster, digest, signed, size := "", "", "", ""
		if item.ClusterID != nil {
			cluster = item.ClusterID.String()
		}
		if item.Digest != nil {
			digest = *item.Digest
		}
		if item.ImageSigned != nil {
			signed = strconv.FormatBool(*item.ImageSigned)
		}
		if item.SizeBytes != nil {
			size = strconv.FormatInt(*item.SizeBytes, 10)
		}
		return []string{item.ID.String(), cluster, item.Kind, item.Name, item.DisplayName, digest, item.Criticality, strconv.FormatBool(item.AIWorkload), strconv.Itoa(item.FindingCount), strconv.Itoa(item.CriticalFindings), strconv.Itoa(item.HighFindings), strconv.Itoa(item.OpenFindings), strconv.Itoa(item.SBOMCount), signed, item.Registry, item.Repository, item.Tag, size, item.FirstSeenAt.UTC().Format(time.RFC3339Nano), item.LastSeenAt.UTC().Format(time.RFC3339Nano), string(item.Labels)}
	})
	if err != nil {
		jsonError(w, 500, err.Error())
		return
	}
	inventorylist.WriteCSV(w, "constellation-assets.csv", body, meta)
}
