package compliance

import (
	"encoding/json"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/google/uuid"
	"net/http"
	"strings"
	"time"
)

const complianceEffectiveRowsSQL = `
SELECT cc.id, cc.cluster_id, cc.asset_id, cc.framework, cc.control_id, cc.title, COALESCE(cc.description,''), cc.status,
       CASE WHEN cc.status='fail' AND ce.id IS NOT NULL THEN 'exempted' ELSE cc.status END AS effective_status,
       cc.severity, COALESCE(cc.evidence,''), cc.evaluated_at, COALESCE(cc.tags_v2, '{}'::jsonb), COALESCE(cc.remediation,''),
       ce.id::text, ce.reason, ce.expires_at
  FROM compliance_checks cc
  LEFT JOIN LATERAL (
        SELECT id, reason, expires_at, cluster_id, created_at
          FROM compliance_exemptions ce
         WHERE ce.org_id = cc.org_id
           AND ce.framework = cc.framework
           AND ce.control_id = cc.control_id
           AND (ce.cluster_id IS NULL OR ce.cluster_id = cc.cluster_id)
           AND (ce.cluster_id IS NULL OR EXISTS (SELECT 1 FROM clusters WHERE id = ce.cluster_id AND org_id = cc.org_id))
           AND ce.revoked_at IS NULL
           AND ce.expires_at > NOW()
         ORDER BY (ce.cluster_id IS NULL), ce.created_at DESC, ce.id DESC
         LIMIT 1
       ) ce ON TRUE
 WHERE cc.org_id = $1
   AND (cc.cluster_id IS NULL OR EXISTS (SELECT 1 FROM clusters WHERE id = cc.cluster_id AND org_id = cc.org_id))
   AND ($2::uuid IS NULL OR cc.cluster_id = $2)`
const complianceInventoryColumns = "id,cluster_id,asset_id,framework,control_id,title,description,status,effective_status,severity,evidence,evaluated_at,tags_v2,remediation,exemption_id,exemption_reason,exemption_expires_at"

type complianceInventoryCheck struct {
	ID              uuid.UUID                     `json:"id"`
	ClusterID       *uuid.UUID                    `json:"cluster_id,omitempty"`
	AssetID         *uuid.UUID                    `json:"asset_id,omitempty"`
	Framework       string                        `json:"framework"`
	ControlID       string                        `json:"control_id"`
	Title           string                        `json:"title"`
	Description     string                        `json:"description"`
	Status          string                        `json:"status"`
	EffectiveStatus string                        `json:"effective_status"`
	Severity        string                        `json:"severity"`
	Evidence        string                        `json:"evidence"`
	EvaluatedAt     time.Time                     `json:"evaluated_at"`
	Tags            json.RawMessage               `json:"tags_v2"`
	Remediation     string                        `json:"remediation"`
	Exemption       *complianceInventoryExemption `json:"exemption,omitempty"`
}
type complianceInventoryExemption struct {
	ID        string    `json:"id"`
	Reason    string    `json:"reason"`
	ExpiresAt time.Time `json:"expires_at"`
}

func scanComplianceInventory(row inventorylist.Row) (complianceInventoryCheck, error) {
	var item complianceInventoryCheck
	var id, reason *string
	var expires *time.Time
	err := row.Scan(&item.ID, &item.ClusterID, &item.AssetID, &item.Framework, &item.ControlID, &item.Title, &item.Description, &item.Status, &item.EffectiveStatus, &item.Severity, &item.Evidence, &item.EvaluatedAt, &item.Tags, &item.Remediation, &id, &reason, &expires)
	if id != nil && reason != nil && expires != nil {
		item.Exemption = &complianceInventoryExemption{ID: *id, Reason: *reason, ExpiresAt: *expires}
	}
	return item, err
}

func (c *Compliance) ChecksCSV(w http.ResponseWriter, r *http.Request) { c.checksInventory(w, r, true) }
func (c *Compliance) checksInventory(w http.ResponseWriter, r *http.Request, export bool) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "subject required"})
		return
	}
	values, err := inventorylist.Query(r)
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": "invalid query string"})
		return
	}
	clusterID, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if clusterID != nil {
		var owned bool
		if err := c.db.Pool().QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM clusters WHERE id=$1 AND org_id=$2)`, clusterID, subj.OrgID).Scan(&owned); err != nil {
			httpx.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if !owned {
			httpx.WriteJSON(w, 404, map[string]string{"error": "cluster not found"})
			return
		}
	}
	opts, err := inventorylist.Parse(values, map[string]string{"framework": "(lower(framework),lower(control_id))", "control": "(lower(control_id),lower(framework))", "title": "lower(title)", "status": "effective_status", "severity": "CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END", "evaluated": "evaluated_at"}, "framework")
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	// Legacy positional clients received up to500 rows in framework/control order.
	if values.Get("limit") == "" {
		opts.Limit = 500
	}
	if values.Get("order") == "" {
		opts.Order = "asc"
		opts.OrderSQL = strings.Replace(opts.OrderSQL, " DESC NULLS LAST", " ASC NULLS LAST", 1)
	}
	status, err := inventorylist.Filter(values, "status", "pass", "fail", "manual", "not_applicable", "exempted", "graded", "ungraded")
	if err != nil {
		httpx.WriteJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	framework := values.Get("framework")
	if framework == "all" {
		framework = ""
	}
	definition := inventorylist.Definition{SQL: complianceEffectiveRowsSQL, Columns: complianceInventoryColumns, Args: []any{subj.OrgID, clusterID, framework, values.Get("profile"), values.Get("control_id"), strings.TrimSpace(values.Get("q")), status},
		Where:   `($3='' OR framework=$3) AND ($4='' OR tags_v2 ? $4) AND ($5='' OR control_id=$5) AND ($6='' OR strpos(lower(framework),lower($6))>0 OR strpos(lower(control_id),lower($6))>0 OR strpos(lower(title),lower($6))>0 OR strpos(lower(description),lower($6))>0 OR strpos(lower(evidence),lower($6))>0) AND ($7='' OR ($7='graded' AND effective_status IN('pass','fail')) OR ($7='ungraded' AND effective_status NOT IN('pass','fail')) OR effective_status=$7)`,
		Summary: `jsonb_build_object('total',count(*),'pass',count(*) FILTER(WHERE effective_status='pass'),'fail',count(*) FILTER(WHERE effective_status='fail'),'manual',count(*) FILTER(WHERE effective_status='manual'),'exempted',count(*) FILTER(WHERE effective_status='exempted'),'not_applicable',count(*) FILTER(WHERE effective_status='not_applicable'),'graded',count(*) FILTER(WHERE effective_status IN('pass','fail')),'ungraded',count(*) FILTER(WHERE effective_status NOT IN('pass','fail')))`}
	if export {
		body, meta, err := inventorylist.CSV(r.Context(), c.db.Pool(), definition, opts, scanComplianceInventory, []string{"Evidence ID", "Cluster ID", "Asset ID", "Framework", "Control", "Title", "Original status", "Effective status", "Severity", "Evidence", "Remediation", "Evaluated at", "Exemption ID", "Exemption expires at"}, func(item complianceInventoryCheck) []string {
			cluster, asset, exemption, expires := "", "", "", ""
			if item.ClusterID != nil {
				cluster = item.ClusterID.String()
			}
			if item.AssetID != nil {
				asset = item.AssetID.String()
			}
			if item.Exemption != nil {
				exemption = item.Exemption.ID
				expires = item.Exemption.ExpiresAt.Format(time.RFC3339)
			}
			return []string{item.ID.String(), cluster, asset, item.Framework, item.ControlID, item.Title, item.Status, item.EffectiveStatus, item.Severity, item.Evidence, item.Remediation, item.EvaluatedAt.Format(time.RFC3339), exemption, expires}
		})
		if err != nil {
			httpx.WriteJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		inventorylist.WriteCSV(w, "constellation-compliance-checks.csv", body, meta)
		return
	}
	rows, meta, err := inventorylist.Read(r.Context(), c.db.Pool(), definition, opts, scanComplianceInventory)
	if err != nil {
		httpx.WriteJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	httpx.WriteJSON(w, 200, map[string]any{"checks": rows, "cluster_id": clusterID, "framework": framework, "profile": values.Get("profile"), "control_id": values.Get("control_id"), "status": status, "q": strings.TrimSpace(values.Get("q")), "sort": opts.Sort, "order": opts.Order, "limit": opts.Limit, "offset": opts.Offset, "total": meta.Total, "has_more": meta.HasMore, "summary": meta.Summary})
}
