package handler

import (
	"errors"
	"fmt"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type assetFindingRow struct {
	PlatformRole      string     `json:"platform_role"`
	RowID             string     `json:"row_id"`
	ID                uuid.UUID  `json:"id"`
	Kind              string     `json:"kind"`
	ExternalID        string     `json:"external_id"`
	Title             string     `json:"title"`
	Severity          string     `json:"severity"`
	RiskScore         int        `json:"risk_score"`
	Lifecycle         string     `json:"lifecycle"`
	LastSeenAt        time.Time  `json:"last_seen_at"`
	Source            string     `json:"source"`
	ImageScanResultID *uuid.UUID `json:"image_scan_result_id,omitempty"`
	FindingKey        string     `json:"finding_key,omitempty"`
	FirstSeenAt       *time.Time `json:"first_seen_at,omitempty"`
	Revision          string     `json:"revision,omitempty"`
	SourceClusterID   *uuid.UUID `json:"source_cluster_id"`
	TargetClusterID   *uuid.UUID `json:"target_cluster_id"`
}

func (a *Assets) Findings(w http.ResponseWriter, r *http.Request)    { a.findingsInventory(w, r, false) }
func (a *Assets) FindingsCSV(w http.ResponseWriter, r *http.Request) { a.findingsInventory(w, r, true) }
func (a *Assets) findingsInventory(w http.ResponseWriter, r *http.Request, csv bool) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "unauthorized"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad asset id"})
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid query"})
		return
	}
	var cluster *uuid.UUID
	err = a.db.Pool().QueryRow(r.Context(), `SELECT cluster_id FROM assets WHERE org_id=$1 AND id=$2`, subj.OrgID, id).Scan(&cluster)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, 404, map[string]string{"error": "asset not found"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "asset scope unavailable"})
		return
	}
	if raw := values.Get("cluster_id"); raw != "" {
		requested, e := uuid.Parse(raw)
		if e != nil {
			writeJSON(w, 400, map[string]string{"error": "bad cluster id"})
			return
		}
		var owned bool
		if e = a.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE org_id=$1 AND id=$2)`, subj.OrgID, requested).Scan(&owned); e != nil {
			writeJSON(w, 500, map[string]string{"error": "cluster scope unavailable"})
			return
		}
		if !owned || cluster == nil || *cluster != requested {
			writeJSON(w, 404, map[string]string{"error": "asset not found in cluster"})
			return
		}
	}
	options, err := inventorylist.Parse(values, map[string]string{"finding": "lower(title)", "kind": "kind", "severity": `CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`, "risk": "risk_score", "lifecycle": "lifecycle", "source": "source", "observed": "last_seen_at"}, "risk")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	for _, key := range []string{"limit", "offset"} {
		if raw := values.Get(key); raw != "" {
			n, e := strconv.Atoi(raw)
			if e != nil || n < 0 || key == "limit" && (n < 1 || n > 500) {
				writeJSON(w, 400, map[string]string{"error": "invalid " + key})
				return
			}
		}
	}
	severity, err := inventorylist.Filter(values, "severity", "critical", "high", "medium", "low", "info", "unknown")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	lifecycle, err := inventorylist.Filter(values, "lifecycle", "open", "triaged", "in_progress", "resolved", "suppressed", "accepted")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	source, err := inventorylist.Filter(values, "source", "asset", "image_scan")
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	search := strings.TrimSpace(values.Get("q"))
	// Asset findings retain their original records. Canonical image findings belong
	// to the latest organization-owned scan of this exact image digest. Only
	// assets without a digest fall back to asset-bound scans.
	// These are distinct evidence sources, not a count of unique vulnerabilities.
	// findings has a composite (id,first_seen_at) key; preserve each physical row.
	def := inventorylist.Definition{
		SQL: `WITH scoped_asset AS (SELECT id,kind,digest,cluster_id FROM assets WHERE org_id=$1 AND id=$2 AND cluster_id IS NOT DISTINCT FROM $3::uuid), latest_scan AS (
 SELECT r.id FROM image_scan_results r CROSS JOIN scoped_asset a
 WHERE a.kind='image' AND r.org_id=$1 AND ((COALESCE(a.digest,'')<>'' AND r.image_digest=a.digest) OR (COALESCE(a.digest,'')='' AND r.asset_id=a.id))
 ORDER BY r.last_scanned_at DESC NULLS LAST,r.id DESC LIMIT 1)
 SELECT 'asset:'||f.id::text||':'||extract(epoch FROM f.first_seen_at)::text,f.id,f.kind,COALESCE(f.external_id,''),f.title,f.severity,f.risk_score,f.lifecycle,f.last_seen_at,'asset',NULL::uuid,'',` + platformrole.FindingPlatformRoleSQL("f") + `,f.first_seen_at,f.revision::text,f.cluster_id,f.target_cluster_id
 FROM findings f JOIN scoped_asset a ON a.id=f.asset_id WHERE f.org_id=$1 AND f.cluster_id IS NOT DISTINCT FROM a.cluster_id
 UNION ALL
 SELECT 'image:'||f.id::text,f.id,'vulnerability',COALESCE(f.external_id,''),f.title,f.severity,f.risk_score,'open',f.last_seen_at,'image_scan',f.image_scan_result_id,f.finding_key,'',NULL::timestamptz,'',NULL::uuid,NULL::uuid
 FROM image_scan_findings f JOIN latest_scan r ON r.id=f.image_scan_result_id WHERE f.org_id=$1`,
		Columns: "id,finding_id,kind,external_id,title,severity,risk_score,lifecycle,last_seen_at,source,image_scan_result_id,finding_key,platform_role,first_seen_at,revision,source_cluster_id,target_cluster_id",
		Where:   `($4='' OR strpos(lower(concat_ws(' ',title,external_id,finding_key,finding_id::text)),lower($4))>0) AND ($5='' OR severity=$5) AND ($6='' OR lifecycle=$6) AND ($7='' OR source=$7)`,
		Args:    []any{subj.OrgID, id, cluster, search, severity, lifecycle, source},
		Summary: `json_build_object('total',count(*),'critical',count(*) FILTER(WHERE severity='critical'),'high',count(*) FILTER(WHERE severity='high'),'open',count(*) FILTER(WHERE lifecycle='open'),'asset_findings',count(*) FILTER(WHERE source='asset'),'image_scan_findings',count(*) FILTER(WHERE source='image_scan'))`,
	}
	if csv {
		body, meta, e := inventorylist.CSV(r.Context(), a.db.Pool(), def, options, scanAssetFinding, []string{"row_id", "finding_id", "asset_id", "cluster_id", "title", "external_id", "kind", "severity", "risk_score", "lifecycle", "source", "image_scan_result_id", "finding_key", "last_seen_at", "first_seen_at", "revision", "source_cluster_id", "target_cluster_id", "platform_role"}, func(f assetFindingRow) []string {
			clusterText, resultText := "", ""
			if cluster != nil {
				clusterText = cluster.String()
			}
			if f.ImageScanResultID != nil {
				resultText = f.ImageScanResultID.String()
			}
			firstSeen, sourceCluster, targetCluster := "", "", ""
			if f.FirstSeenAt != nil {
				firstSeen = f.FirstSeenAt.UTC().Format(time.RFC3339Nano)
			}
			if f.SourceClusterID != nil {
				sourceCluster = f.SourceClusterID.String()
			}
			if f.TargetClusterID != nil {
				targetCluster = f.TargetClusterID.String()
			}
			return []string{f.RowID, f.ID.String(), id.String(), clusterText, f.Title, f.ExternalID, f.Kind, f.Severity, strconv.Itoa(f.RiskScore), f.Lifecycle, f.Source, resultText, f.FindingKey, f.LastSeenAt.UTC().Format(time.RFC3339Nano), firstSeen, f.Revision, sourceCluster, targetCluster, f.PlatformRole}
		})
		if e != nil {
			writeJSON(w, 500, map[string]string{"error": "asset findings export unavailable"})
			return
		}
		inventorylist.WriteCSV(w, fmt.Sprintf("asset-%s-findings.csv", id), body, meta)
		return
	}
	items, meta, err := inventorylist.Read(r.Context(), a.db.Pool(), def, options, scanAssetFinding)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "asset findings unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"asset_id": id, "cluster_id": cluster, "items": items, "total": meta.Total, "summary": meta.Summary, "has_more": meta.HasMore, "limit": options.Limit, "offset": options.Offset, "sort": options.Sort, "order": options.Order, "q": search, "severity": severity, "lifecycle": lifecycle, "source": source})
}
func scanAssetFinding(row inventorylist.Row) (assetFindingRow, error) {
	var f assetFindingRow
	err := row.Scan(&f.RowID, &f.ID, &f.Kind, &f.ExternalID, &f.Title, &f.Severity, &f.RiskScore, &f.Lifecycle, &f.LastSeenAt, &f.Source, &f.ImageScanResultID, &f.FindingKey, &f.PlatformRole, &f.FirstSeenAt, &f.Revision, &f.SourceClusterID, &f.TargetClusterID)
	return f, err
}
