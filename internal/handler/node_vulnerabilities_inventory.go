package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// NodeVulnerabilityRow is one finding instance, not a deduplicated CVE. ClusterID
// retains the effective target cluster; SourceClusterID is the reporting cluster.
type NodeVulnerabilityRow struct {
	HostVulnRow
	RowID           string     `json:"row_id"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	ID              uuid.UUID  `json:"id"`
	SourceClusterID *uuid.UUID `json:"source_cluster_id"`
	RiskScore       float64    `json:"risk_score"`
	Fixable         bool       `json:"fixable"`
}

const nodeVulnerabilityColumns = `id,finding_id,first_seen_at,node,cluster_id,source_cluster_id,package_name,package_version,vuln_id,aliases,severity,summary,reference_text,fixed_version,source,observed_at,risk_score,fixable`
const nodeVulnerabilitySQL = `SELECT f.id::text||':'||extract(epoch FROM f.first_seen_at)::text, f.id, f.first_seen_at, f.target_ref, COALESCE(f.target_cluster_id,f.cluster_id), f.cluster_id,
 COALESCE(f.detail_json->'package'->>'name',''), COALESCE(f.detail_json->'package'->>'version',''), COALESCE(f.external_id,''), COALESCE(f.detail_json->'aliases','[]'::jsonb),
 CASE WHEN f.severity IN ('critical','high','medium','low','info') THEN f.severity ELSE 'unknown' END,
 COALESCE(NULLIF(f.description,''),f.title,''),COALESCE(f.detail_json->'references','[]'::jsonb),
 COALESCE(NULLIF(f.detail_json->>'fixed',''),NULLIF(f.detail_json->>'fixed_version',''),f.detail_json->'affected_range'->>'fixed_version',''),
 COALESCE(NULLIF(f.source_type,''),NULLIF(f.canonical_engine,''),'scanner'),f.last_seen_at,COALESCE(f.risk_score,0),
 lower(COALESCE(NULLIF(f.detail_json->>'fixed',''),NULLIF(f.detail_json->>'fixed_version',''),f.detail_json->'affected_range'->>'fixed_version','')) NOT IN ('','false','not-fixed','wont-fix','won''t-fix')
 FROM findings f WHERE f.org_id=$1 AND f.target_ref=$2 AND f.target_type='host' AND f.kind='vulnerability' AND f.lifecycle='open'
 AND (f.cluster_id=$3 OR COALESCE(f.target_cluster_id,f.cluster_id)=$3)`
const nodeVulnerabilitySummary = `jsonb_build_object('total',count(*),'critical',count(*) FILTER(WHERE severity='critical'),'high',count(*) FILTER(WHERE severity='high'),'fixable',count(*) FILTER(WHERE fixable),'unique_cves',count(DISTINCT NULLIF(vuln_id,'')))`

func nodeVulnerabilityDefinition(org, cluster uuid.UUID, node string) inventorylist.Definition {
	return inventorylist.Definition{SQL: nodeVulnerabilitySQL, Columns: nodeVulnerabilityColumns, Args: []any{org, node, cluster}, Summary: nodeVulnerabilitySummary}
}
func scanNodeVulnerability(row inventorylist.Row) (NodeVulnerabilityRow, error) {
	var item NodeVulnerabilityRow
	var aliases, refs []byte
	err := row.Scan(&item.RowID, &item.ID, &item.FirstSeenAt, &item.Node, &item.ClusterID, &item.SourceClusterID, &item.PackageName, &item.PackageVersion, &item.VulnID, &aliases, &item.Severity, &item.Summary, &refs, &item.FixedVersion, &item.Source, &item.ObservedAt, &item.RiskScore, &item.Fixable)
	item.Aliases = decodeStringList(aliases)
	item.References = strings.Join(decodeStringList(refs), ",")
	return item, err
}

func (h *Nodes) Vulnerabilities(w http.ResponseWriter, r *http.Request) {
	h.writeNodeVulnerabilities(w, r, false)
}
func (h *Nodes) VulnerabilitiesCSV(w http.ResponseWriter, r *http.Request) {
	h.writeNodeVulnerabilities(w, r, true)
}
func (h *Nodes) writeNodeVulnerabilities(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, 401, "subject required")
		return
	}
	cluster, ok := h.clusterIDFromRoute(w, r, subj.OrgID)
	if !ok {
		return
	}
	node := strings.TrimSpace(chi.URLParam(r, "node"))
	if node == "" {
		jsonError(w, 400, "node required")
		return
	}
	// Node membership uses the same evidence sources and OR attribution as detail.
	var exists bool
	err := h.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(
 SELECT 1 FROM host_facts WHERE org_id=$1 AND cluster_id=$2 AND node=$3
 UNION ALL SELECT 1 FROM host_packages WHERE org_id=$1 AND cluster_id=$2 AND node=$3
 UNION ALL SELECT 1 FROM host_cis WHERE org_id=$1 AND cluster_id=$2 AND node=$3
 UNION ALL SELECT 1 FROM host_containers WHERE org_id=$1 AND cluster_id=$2 AND node=$3
 UNION ALL SELECT 1 FROM host_processes WHERE org_id=$1 AND cluster_id=$2 AND node=$3
 UNION ALL SELECT 1 FROM scan_targets WHERE org_id=$1 AND cluster_id=$2 AND type='host' AND ref=$3
 UNION ALL SELECT 1 FROM findings WHERE org_id=$1 AND target_type='host' AND target_ref=$3 AND (cluster_id=$2 OR COALESCE(target_cluster_id,cluster_id)=$2))`, subj.OrgID, cluster, node).Scan(&exists)
	if err != nil {
		jsonError(w, 500, "node lookup failed")
		return
	}
	if !exists {
		jsonError(w, 404, "node not found")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, 400, "invalid query string")
		return
	}
	opts, err := inventorylist.Parse(values, map[string]string{"risk": "risk_score", "cve": "lower(vuln_id)", "package": "lower(package_name)", "version": "lower(package_version)", "severity": "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END", "fix": "lower(fixed_version)", "source": "lower(source)", "observed": "observed_at"}, "risk")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	for _, field := range []string{"limit", "offset"} {
		if raw := values.Get(field); raw != "" {
			n, e := strconv.Atoi(raw)
			if e != nil || field == "limit" && (n < 1 || n > 500) || field == "offset" && n < 0 {
				jsonError(w, 400, "invalid "+field)
				return
			}
			if field == "limit" {
				opts.Limit = n
			} else {
				opts.Offset = n
			}
		}
	}
	severity, err := inventorylist.Filter(values, "severity", "critical", "high", "medium", "low", "info", "unknown")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	fixable, err := inventorylist.Filter(values, "fixable", "true", "false")
	if err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	q, source := strings.TrimSpace(values.Get("q")), strings.TrimSpace(values.Get("source"))
	definition := nodeVulnerabilityDefinition(subj.OrgID, cluster, node)
	definition.Args = append(definition.Args, q, severity, fixable, source)
	definition.Where = `($4='' OR strpos(lower(concat_ws(' ',id,vuln_id,aliases,package_name,package_version,summary,reference_text,fixed_version,source)),lower($4))>0) AND ($5='' OR severity=$5) AND ($6='' OR fixable=($6='true')) AND ($7='' OR source=$7)`
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), h.db.Pool(), definition, opts, scanNodeVulnerability, []string{"Instance row ID", "Finding ID", "Node", "Source cluster ID", "Effective target cluster ID", "CVE / advisory", "Package", "Version", "Severity", "Risk", "Fixed version", "Fixable", "Source", "Observed", "Summary", "Aliases", "References", "First seen"}, func(item NodeVulnerabilityRow) []string {
			sourceCluster, targetCluster := "", ""
			if item.SourceClusterID != nil {
				sourceCluster = item.SourceClusterID.String()
			}
			if item.ClusterID != nil {
				targetCluster = item.ClusterID.String()
			}
			return []string{item.RowID, item.ID.String(), item.Node, sourceCluster, targetCluster, item.VulnID, item.PackageName, item.PackageVersion, item.Severity, strconv.FormatFloat(item.RiskScore, 'f', -1, 64), item.FixedVersion, strconv.FormatBool(item.Fixable), item.Source, item.ObservedAt.UTC().Format(time.RFC3339Nano), item.Summary, strings.Join(item.Aliases, "; "), item.References, item.FirstSeenAt.UTC().Format(time.RFC3339Nano)}
		})
		if err != nil {
			jsonError(w, 500, "node vulnerability export failed")
			return
		}
		inventorylist.WriteCSV(w, "constellation-node-host-vulnerabilities.csv", body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), h.db.Pool(), definition, opts, scanNodeVulnerability)
	if err != nil {
		jsonError(w, 500, "node vulnerabilities could not be read")
		return
	}
	writeJSON(w, 200, map[string]any{"node": node, "cluster_id": cluster, "items": items, "total": meta.Total, "summary": meta.Summary, "has_more": meta.HasMore, "limit": opts.Limit, "offset": opts.Offset, "q": q, "severity": severity, "fixable": fixable, "source": source, "sort": opts.Sort, "order": opts.Order})
}
