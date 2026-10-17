package handler

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
)

// DeploymentFindingInstance preserves the physical findings primary key and both
// reporting and effective target clusters. Direct workload records are separate
// from the canonical image scan totals reported by deployment inventory.
type DeploymentFindingInstance struct {
	RowID                    string     `json:"row_id"`
	ID                       uuid.UUID  `json:"id"`
	FirstSeenAt              time.Time  `json:"first_seen_at"`
	LastSeenAt               time.Time  `json:"last_seen_at"`
	Kind                     string     `json:"kind"`
	ExternalID               string     `json:"external_id"`
	Title                    string     `json:"title"`
	Severity                 string     `json:"severity"`
	RiskScore                int        `json:"risk_score"`
	Lifecycle                string     `json:"lifecycle"`
	TargetType               string     `json:"target_type"`
	TargetRef                string     `json:"target_ref"`
	PackageName              string     `json:"package_name"`
	PackageVersion           string     `json:"package_version"`
	FixedVersion             string     `json:"fixed_version"`
	Fixable                  bool       `json:"fixable"`
	SourceClusterID          *uuid.UUID `json:"source_cluster_id"`
	TargetClusterID          *uuid.UUID `json:"target_cluster_id"`
	EffectiveTargetClusterID uuid.UUID  `json:"effective_target_cluster_id"`
	PlatformRole             string     `json:"platform_role"`
	Attribution              string     `json:"attribution"`
	OwnerCount               int        `json:"owner_count"`
	OwnerAmbiguous           bool       `json:"owner_ambiguous"`
}

type deploymentFindingFilters struct {
	Query     string `json:"q"`
	Lifecycle string `json:"lifecycle"`
	Severity  string `json:"severity"`
	Fixable   string `json:"fixable"`
}

type deploymentFindingOptions struct {
	inventorylist.Options
	ClusterID uuid.UUID
	deploymentFindingFilters
}

var deploymentFindingSorts = map[string]string{
	"finding": "lower(title)", "cve": "lower(external_id)", "risk": "risk_score",
	"severity":  "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END",
	"lifecycle": "lifecycle", "kind": "kind", "package": "lower(package_name)",
	"fixed": "lower(fixed_version)", "observed": "last_seen_at", "first_seen": "first_seen_at",
}

func parseDeploymentFindingOptions(values url.Values) (deploymentFindingOptions, error) {
	o := deploymentFindingOptions{}
	for _, entries := range values {
		if len(entries) != 1 {
			return o, fmt.Errorf("duplicate query parameter")
		}
	}
	var err error
	if values.Get("cluster_id") == "" {
		return o, fmt.Errorf("cluster_id is required")
	}
	o.ClusterID, err = uuid.Parse(values.Get("cluster_id"))
	if err != nil {
		return o, fmt.Errorf("invalid cluster_id")
	}
	o.Options, err = inventorylist.Parse(values, deploymentFindingSorts, "risk")
	if err != nil {
		return o, err
	}
	for key, target := range map[string]*int{"limit": &o.Limit, "offset": &o.Offset} {
		if values.Has(key) {
			n, e := strconv.Atoi(values.Get(key))
			if e != nil || n < 0 || key == "limit" && (n < 1 || n > 500) || key == "offset" && n > inventorylist.MaxOffset {
				return o, fmt.Errorf("invalid %s", key)
			}
			*target = n
		}
	}
	o.OrderSQL = deploymentFindingSorts[o.Sort] + " " + strings.ToUpper(o.Order) + " NULLS LAST,finding_id ASC,first_seen_at ASC"
	o.Query = strings.ToLower(strings.TrimSpace(values.Get("q")))
	o.Lifecycle, err = inventorylist.Filter(values, "lifecycle", "open", "triaged", "in_progress", "resolved", "suppressed", "accepted")
	if err != nil {
		return o, err
	}
	if strings.TrimSpace(values.Get("lifecycle")) != "all" && o.Lifecycle == "" {
		o.Lifecycle = "open"
	}
	if o.Lifecycle == "" {
		o.Lifecycle = "all"
	}
	o.Severity, err = inventorylist.Filter(values, "severity", "critical", "high", "medium", "low", "info", "unknown")
	if err != nil {
		return o, err
	}
	o.Fixable, err = inventorylist.Filter(values, "fixable", "true", "false")
	return o, err
}

const deploymentFindingColumns = `id,finding_id,first_seen_at,last_seen_at,kind,external_id,title,severity,risk_score,lifecycle,target_type,target_ref,package_name,package_version,fixed_version,fixable,source_cluster_id,target_cluster_id,effective_target_cluster_id,platform_role,attribution,owner_count,owner_ambiguous`

func deploymentFindingDefinition(org, deployment, cluster uuid.UUID, o deploymentFindingOptions) inventorylist.Definition {
	// Canonical namespace/name identity can be shared by Kubernetes kinds. Keep
	// those records, qualify the ambiguity, and do not select arbitrary labels.
	// Pod references require exact, unique ownership across all matching links;
	// repeated observations of the same owner do not create ambiguity.
	sql := `WITH selected AS (
 SELECT d.* FROM deployments d JOIN clusters c ON c.id=d.cluster_id AND c.org_id=d.org_id
 WHERE d.org_id=$1 AND d.id=$2 AND d.cluster_id=$3
), owners AS (
 SELECT d.id,d.namespace,d.name,d.labels FROM deployments d CROSS JOIN selected s
 WHERE d.org_id=$1 AND d.cluster_id=$3 AND d.namespace=s.namespace AND d.name=s.name
), canonical AS (
 SELECT s.namespace||'/'||s.name AS ref,'canonical'::text AS attribution,count(o.id)::int AS owner_count,
 ` + platformrole.SQL("s.namespace", "CASE WHEN count(o.id)=1 THEN s.labels ELSE '{}'::jsonb END") + ` AS platform_role
 FROM selected s JOIN owners o ON true GROUP BY s.namespace,s.name,s.labels
), pod_candidates AS (
 SELECT DISTINCT l.pod_workload_id AS ref,d.id,d.labels,d.namespace
 FROM pod_workload_links l JOIN deployments d ON d.id=l.deployment_id
 JOIN selected s ON s.namespace=l.namespace
 WHERE l.org_id=$1 AND l.cluster_id=$3 AND d.org_id=$1 AND d.cluster_id=$3 AND d.namespace=l.namespace
 AND l.owner_workload_id=d.namespace||'/'||d.name
 AND l.pod_workload_id=l.namespace||'/pod/'||l.pod_name AND l.pod_name<>''
 AND l.pod_name !~ '[:/]' AND NOT (l.pod_name ~ '^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$' AND pg_input_is_valid(l.pod_name,'inet'))
), unique_pods AS (
 SELECT ref,min(id::text)::uuid AS owner_id FROM pod_candidates GROUP BY ref HAVING count(*)=1
), refs AS (
 SELECT ref,attribution,owner_count,platform_role FROM canonical
 UNION ALL
 SELECT p.ref,'pod',1,` + platformrole.SQL("p.namespace", "p.labels") + `
 FROM unique_pods u JOIN pod_candidates p ON p.ref=u.ref AND p.id=u.owner_id WHERE p.id=$2
), evidence AS (
 SELECT f.id::text||':'||extract(epoch FROM f.first_seen_at)::text AS row_id,f.id,f.first_seen_at,f.last_seen_at,
 f.kind,COALESCE(f.external_id,'') AS external_id,f.title,
 CASE WHEN f.severity IN ('critical','high','medium','low','info') THEN f.severity ELSE 'unknown' END AS severity,
 f.risk_score,f.lifecycle,f.target_type,f.target_ref,
 COALESCE(NULLIF(f.detail_json->'package'->>'name',''),NULLIF(f.detail_json->'package'->>'Name',''),NULLIF(f.detail_json->>'package_name',''),f.detail_json->'affected_range'->>'package_name','') AS package_name,
 COALESCE(NULLIF(f.detail_json->'package'->>'version',''),NULLIF(f.detail_json->'package'->>'Version',''),f.detail_json->>'package_version','') AS package_version,
 COALESCE(NULLIF(f.detail_json->>'fixed',''),NULLIF(f.detail_json->>'fixed_version',''),f.detail_json->'affected_range'->>'fixed_version','') AS fixed_version,
 f.cluster_id AS source_cluster_id,f.target_cluster_id,COALESCE(f.target_cluster_id,f.cluster_id) AS effective_target_cluster_id,
 CASE WHEN f.cluster_id=COALESCE(f.target_cluster_id,f.cluster_id) THEN refs.platform_role ELSE '' END AS platform_role,
 refs.attribution,refs.owner_count,refs.owner_count>1 AS owner_ambiguous
 FROM findings f JOIN refs ON refs.ref=f.target_ref
 WHERE f.org_id=$1 AND f.target_type='workload' AND COALESCE(f.target_cluster_id,f.cluster_id)=$3
)
 SELECT row_id,id,first_seen_at,last_seen_at,kind,external_id,title,severity,risk_score,lifecycle,target_type,target_ref,
 package_name,package_version,fixed_version,
 lower(btrim(fixed_version)) NOT IN ('','false','not-fixed','wont-fix','won''t-fix') AS fixable,
 source_cluster_id,target_cluster_id,effective_target_cluster_id,platform_role,attribution,owner_count,owner_ambiguous FROM evidence`
	return inventorylist.Definition{SQL: sql, Columns: deploymentFindingColumns, Args: []any{org, deployment, cluster, o.Query, o.Lifecycle, o.Severity, o.Fixable},
		Where: `($4::text='' OR strpos(lower(concat_ws(' ',finding_id::text,title,external_id,kind,target_ref,package_name,package_version,fixed_version)),$4)>0)
 AND ($5::text='all' OR lifecycle=$5) AND ($6::text='' OR severity=$6) AND ($7::text='' OR fixable=($7='true'))`,
		Summary: `jsonb_build_object('total',count(*),'critical',count(*) FILTER(WHERE severity='critical'),'high',count(*) FILTER(WHERE severity='high'),
 'fixable',count(*) FILTER(WHERE fixable),'open',count(*) FILTER(WHERE lifecycle='open'),'in_progress',count(*) FILTER(WHERE lifecycle='in_progress'),
 'triaged',count(*) FILTER(WHERE lifecycle='triaged'),'accepted',count(*) FILTER(WHERE lifecycle='accepted'),'suppressed',count(*) FILTER(WHERE lifecycle='suppressed'),
 'resolved',count(*) FILTER(WHERE lifecycle='resolved'),'other_lifecycle',count(*) FILTER(WHERE lifecycle NOT IN ('open','in_progress','triaged','accepted','suppressed','resolved')),
 'canonical',count(*) FILTER(WHERE attribution='canonical'),'pod',count(*) FILTER(WHERE attribution='pod'),
 'ambiguous_owners',count(*) FILTER(WHERE owner_ambiguous))`}
}

func scanDeploymentFinding(row inventorylist.Row) (DeploymentFindingInstance, error) {
	var f DeploymentFindingInstance
	err := row.Scan(&f.RowID, &f.ID, &f.FirstSeenAt, &f.LastSeenAt, &f.Kind, &f.ExternalID, &f.Title, &f.Severity, &f.RiskScore, &f.Lifecycle,
		&f.TargetType, &f.TargetRef, &f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.Fixable, &f.SourceClusterID, &f.TargetClusterID,
		&f.EffectiveTargetClusterID, &f.PlatformRole, &f.Attribution, &f.OwnerCount, &f.OwnerAmbiguous)
	return f, err
}

func (h *Deployments) FindingsInventory(w http.ResponseWriter, r *http.Request) {
	h.writeFindingsInventory(w, r, false)
}
func (h *Deployments) FindingsCSV(w http.ResponseWriter, r *http.Request) {
	h.writeFindingsInventory(w, r, true)
}

func (h *Deployments) writeFindingsInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid deployment id")
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid query string")
		return
	}
	o, err := parseDeploymentFindingOptions(values)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Scope, ownership qualification, counts and rows share one snapshot. A
	// separate preflight lookup must not mislabel rows after an ownership change.
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment findings unavailable")
		return
	}
	defer tx.Rollback(context.WithoutCancel(r.Context()))
	var workload string
	var ownerCount int
	err = tx.QueryRow(r.Context(), `SELECT d.namespace||'/'||d.name,
 (SELECT count(*) FROM deployments o WHERE o.org_id=d.org_id AND o.cluster_id=d.cluster_id AND o.namespace=d.namespace AND o.name=d.name)
 FROM deployments d JOIN clusters c ON c.id=d.cluster_id AND c.org_id=d.org_id
 WHERE d.org_id=$1 AND d.id=$2 AND d.cluster_id=$3`, subj.OrgID, id, o.ClusterID).Scan(&workload, &ownerCount)
	if errors.Is(err, pgx.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "deployment not found in cluster")
		return
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment scope unavailable")
		return
	}
	d := deploymentFindingDefinition(subj.OrgID, id, o.ClusterID, o)
	prefix := "WITH inventory(" + d.Columns + ") AS (" + d.SQL + ") "
	meta := inventorylist.Metadata{}
	var summary []byte
	err = tx.QueryRow(r.Context(), prefix+"SELECT count(*),"+d.Summary+" FROM inventory WHERE "+d.Where, d.Args...).Scan(&meta.Total, &summary)
	if err == nil {
		err = json.Unmarshal(summary, &meta.Summary)
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment findings unavailable")
		return
	}
	page := o.Options
	if export {
		page.Limit, page.Offset = inventorylist.ExportLimit, 0
	}
	args := append(append([]any{}, d.Args...), page.Limit, page.Offset)
	rows, err := tx.Query(r.Context(), fmt.Sprintf("%s SELECT * FROM inventory WHERE %s ORDER BY %s LIMIT $%d OFFSET $%d", prefix, d.Where, page.OrderSQL, len(d.Args)+1, len(d.Args)+2), args...)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment findings unavailable")
		return
	}
	items := make([]DeploymentFindingInstance, 0)
	var body bytes.Buffer
	writer := csv.NewWriter(&body)
	if export {
		err = writer.Write(deploymentFindingCSVHeaders)
	}
	for err == nil && rows.Next() {
		var f DeploymentFindingInstance
		f, err = scanDeploymentFinding(rows)
		if err == nil && export {
			err = writer.Write(deploymentFindingCSVCells(f, id, o.ClusterID, workload))
		} else if err == nil {
			items = append(items, f)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	writer.Flush()
	if err == nil && export {
		err = writer.Error()
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "deployment findings unavailable")
		return
	}
	meta.HasMore = int64(page.Offset) < meta.Total && meta.Total-int64(page.Offset) > int64(page.Limit)
	if export {
		inventorylist.WriteCSV(w, "constellation-deployment-workload-findings.csv", body.Bytes(), meta)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deployment_id": id, "cluster_id": o.ClusterID, "workload_id": workload,
		"owner_count": ownerCount, "owner_ambiguous": ownerCount > 1, "items": items, "total": meta.Total, "summary": meta.Summary,
		"has_more": meta.HasMore, "limit": o.Limit, "offset": o.Offset, "sort": o.Sort, "order": o.Order, "filters": o.deploymentFindingFilters,
		"source_complete": true, "summary_scope": "matching_direct_workload_findings"})
}

var deploymentFindingCSVHeaders = []string{"Instance row ID", "Finding ID", "Deployment ID", "Deployment cluster ID", "Canonical workload", "Target workload", "Attribution", "Owner count", "Ambiguous owners", "Source cluster ID", "Target cluster override ID", "Effective target cluster ID", "Kind", "CVE / advisory", "Title", "Severity", "Risk", "Lifecycle", "Package", "Version", "Fixed version", "Fixable", "First seen", "Last seen", "Platform role"}

func deploymentFindingCSVCells(f DeploymentFindingInstance, deployment, cluster uuid.UUID, workload string) []string {
	clusterText := func(id *uuid.UUID) string {
		if id == nil {
			return ""
		}
		return id.String()
	}
	return []string{f.RowID, f.ID.String(), deployment.String(), cluster.String(), workload, f.TargetRef, f.Attribution, strconv.Itoa(f.OwnerCount), strconv.FormatBool(f.OwnerAmbiguous),
		clusterText(f.SourceClusterID), clusterText(f.TargetClusterID), f.EffectiveTargetClusterID.String(), f.Kind, f.ExternalID, f.Title, f.Severity, strconv.Itoa(f.RiskScore), f.Lifecycle,
		f.PackageName, f.PackageVersion, f.FixedVersion, strconv.FormatBool(f.Fixable), f.FirstSeenAt.UTC().Format(time.RFC3339Nano), f.LastSeenAt.UTC().Format(time.RFC3339Nano), f.PlatformRole}
}
