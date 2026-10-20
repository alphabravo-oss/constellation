// Report downloads use explicit retained-source scopes. PDF remains an optional
// compatibility rendering of the same HTML evidence, never a separate cohort.
package compliance

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
	"github.com/alphabravocompany/constellation/pkg/report"
)

type Reports struct{ db *db.DB }

func NewReports(d *db.DB) *Reports { return &Reports{db: d} }
func (h *Reports) ComplianceHTML(w http.ResponseWriter, r *http.Request) {
	h.serveCompliance(w, r, false)
}
func (h *Reports) CompliancePDF(w http.ResponseWriter, r *http.Request) {
	h.serveCompliance(w, r, true)
}
func (h *Reports) ExecutiveHTML(w http.ResponseWriter, r *http.Request) {
	h.serveExecutive(w, r, false)
}
func (h *Reports) ExecutivePDF(w http.ResponseWriter, r *http.Request) { h.serveExecutive(w, r, true) }

func reportQuery(r *http.Request) (url.Values, *uuid.UUID, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid query")
	}
	for key, v := range q {
		if len(v) != 1 {
			return nil, nil, fmt.Errorf("duplicate %s", key)
		}
	}
	var cluster *uuid.UUID
	if raw, present := q["cluster_id"]; present {
		parsed, err := uuid.Parse(strings.TrimSpace(raw[0]))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid cluster_id")
		}
		cluster = &parsed
	}
	return q, cluster, nil
}
func reportScope(ctx context.Context, tx pgx.Tx, org uuid.UUID, cluster *uuid.UUID) (string, string, error) {
	var orgName string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name,''),name) FROM orgs WHERE id=$1`, org).Scan(&orgName); err != nil {
		return "", "", err
	}
	scope := "organization-wide owned retained sources"
	if cluster != nil {
		var name string
		if err := tx.QueryRow(ctx, `SELECT name FROM clusters WHERE id=$1 AND org_id=$2`, cluster, org).Scan(&name); err != nil {
			return "", "", err
		}
		scope = "cluster " + name + " (" + cluster.String() + ")"
	}
	return orgName, scope, nil
}

// Scope receipts let current download clients reject responses from older replicas
// that ignored a requested cluster selector. They identify the committed source.
func reportScopeReceipt(w http.ResponseWriter, org uuid.UUID, cluster *uuid.UUID) {
	w.Header().Set("X-Report-Org-ID", org.String())
	scope := "organization"
	if cluster != nil {
		scope = cluster.String()
	}
	w.Header().Set("X-Report-Cluster-ID", scope)
}

func writeReport(ctx context.Context, w http.ResponseWriter, html []byte, asPDF bool, filename string) {
	if asPDF {
		pdf, err := report.HTMLToPDF(ctx, html)
		if err == nil {
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`.pdf"`)
			_, _ = w.Write(pdf)
			return
		}
		if !errors.Is(err, report.ErrPDFToolMissing) {
			http.Error(w, "Report PDF could not be rendered", 500)
			return
		}
		w.Header().Set("X-Constellation-PDF-Fallback", "browser-print")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `inline; filename="`+filename+`.html"`)
	_, _ = w.Write(html)
}

// Counts and rows share a snapshot and the exact effective-exemption source
// used by the current controls inventory. The report cap is explicit.
func reportChecks(ctx context.Context, tx pgx.Tx, org uuid.UUID, cluster *uuid.UUID, framework string) ([]report.ComplianceCheck, report.FrameworkSummary, bool, error) {
	prefix := `WITH effective(` + complianceInventoryColumns + `) AS (` + complianceEffectiveRowsSQL + `) `
	predicate := `($3='' OR framework=$3)`
	args := []any{org, cluster, framework}
	var summary report.FrameworkSummary
	err := tx.QueryRow(ctx, prefix+`SELECT count(*),count(*) FILTER(WHERE effective_status='pass'),count(*) FILTER(WHERE effective_status='fail'),count(*) FILTER(WHERE effective_status NOT IN('pass','fail','exempted','not_applicable')),count(*) FILTER(WHERE effective_status='exempted'),count(*) FILTER(WHERE effective_status='not_applicable') FROM effective WHERE `+predicate, args...).Scan(&summary.Total, &summary.Pass, &summary.Fail, &summary.Manual, &summary.Exempted, &summary.NotApplicable)
	if err != nil {
		return nil, summary, false, err
	}
	rows, err := tx.Query(ctx, prefix+`SELECT * FROM effective WHERE `+predicate+` ORDER BY framework,control_id,cluster_id NULLS LAST,id LIMIT 100000`, args...)
	if err != nil {
		return nil, summary, false, err
	}
	out := []report.ComplianceCheck{}
	for rows.Next() {
		item, err := scanComplianceInventory(rows)
		if err != nil {
			rows.Close()
			return nil, summary, false, err
		}
		title := item.Title
		if item.ClusterID != nil {
			title += " [cluster: " + item.ClusterID.String() + "]"
		}
		if framework == "" {
			title += " [" + item.Framework + "]"
		}
		out = append(out, report.ComplianceCheck{ControlID: item.ControlID, Title: title, Status: item.EffectiveStatus, Severity: item.Severity, Evidence: item.Evidence})
	}
	err = rows.Err()
	rows.Close()
	return out, summary, summary.Total > len(out), err
}
func (h *Reports) serveCompliance(w http.ResponseWriter, r *http.Request, asPDF bool) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	q, cluster, err := reportQuery(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	framework := strings.TrimSpace(q.Get("framework"))
	if framework == "" {
		framework = compliancepkg.FrameworkCISK8s
	}
	if framework == "all" {
		framework = ""
	}
	name := framework
	if name == "" {
		name = "All frameworks"
	}
	for _, f := range compliancepkg.AllFrameworks() {
		if f.ID == framework {
			name = f.Name
		}
	}
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		http.Error(w, "Report source unavailable", 500)
		return
	}
	defer tx.Rollback(r.Context())
	orgName, scope, err := reportScope(r.Context(), tx, sub.OrgID, cluster)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "Report scope not found", 404)
		return
	}
	if err != nil {
		http.Error(w, "Report scope unavailable", 500)
		return
	}
	checks, summary, truncated, err := reportChecks(r.Context(), tx, sub.OrgID, cluster, framework)
	if err != nil {
		http.Error(w, "Compliance report evidence unavailable", 500)
		return
	}
	data := report.ComplianceData{OrgName: orgName, Framework: framework, FrameworkName: name, GeneratedAt: time.Now().UTC(), Checks: checks, Summary: summary, ClusterName: scope, SourceLabel: "Current retained compliance check rows with effective exemptions; " + scope + "; graded rate excludes manual/exempted/not-applicable", SourceTotal: summary.Total, SourceReturned: len(checks), SourceTruncated: truncated}
	html, err := report.ComplianceHTML(data)
	if err != nil {
		http.Error(w, "Report could not be rendered", 500)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "Report source unavailable", 500)
		return
	}
	w.Header().Set("X-Report-Limit", fmt.Sprint(inventorylist.ExportLimit))
	w.Header().Set("X-Report-Total", fmt.Sprint(summary.Total))
	w.Header().Set("X-Report-Truncated", fmt.Sprint(truncated))
	reportScopeReceipt(w, sub.OrgID, cluster)
	writeReport(r.Context(), w, html, asPDF, "constellation-compliance")
}
func (h *Reports) serveExecutive(w http.ResponseWriter, r *http.Request, asPDF bool) {
	sub, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		http.Error(w, "auth required", http.StatusUnauthorized)
		return
	}
	_, cluster, err := reportQuery(r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		http.Error(w, "Report source unavailable", 500)
		return
	}
	defer tx.Rollback(r.Context())
	orgName, scope, err := reportScope(r.Context(), tx, sub.OrgID, cluster)
	if errors.Is(err, pgx.ErrNoRows) {
		http.Error(w, "Report scope not found", 404)
		return
	}
	if err != nil {
		http.Error(w, "Report scope unavailable", 500)
		return
	}
	data := report.ExecutiveData{OrgName: orgName, GeneratedAt: time.Now().UTC(), ScanWindow: "All retained finding instances", SourceLabel: scope + "; counts include all retained lifecycles and kinds, using the actual finding source cluster; top workload rows are the highest 10 reported risks", MTTRSource: "Organization-wide materialized metrics observed in the last 90 days; this source has no cluster dimension and is not the finding-count time window"}
	if err := tx.QueryRow(r.Context(), `SELECT count(*),count(*) FILTER(WHERE severity='critical'),count(*) FILTER(WHERE severity='high'),count(*) FILTER(WHERE lifecycle='suppressed'),count(*) FILTER(WHERE lifecycle='accepted') FROM findings f WHERE org_id=$1 AND ($2::uuid IS NULL OR cluster_id=$2) AND (cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=f.cluster_id AND org_id=$1))`, sub.OrgID, cluster).Scan(&data.TotalFindings, &data.CriticalFindings, &data.HighFindings, &data.SuppressedCount, &data.AcceptedCount); err != nil {
		http.Error(w, "Finding report evidence unavailable", 500)
		return
	}
	rows, err := tx.Query(r.Context(), `SELECT d.name,COALESCE(d.cluster_id::text,''),d.namespace,`+platformrole.SQL("d.namespace", "d.labels")+`,d.risk_score,d.finding_count FROM deployments d WHERE d.org_id=$1 AND ($2::uuid IS NULL OR d.cluster_id=$2) AND (d.cluster_id IS NULL OR EXISTS(SELECT 1 FROM clusters WHERE id=d.cluster_id AND org_id=$1)) ORDER BY d.risk_score DESC,d.id ASC LIMIT 10`, sub.OrgID, cluster)
	if err != nil {
		http.Error(w, "Workload report evidence unavailable", 500)
		return
	}
	for rows.Next() {
		var item report.AssetRow
		if err := rows.Scan(&item.Name, &item.ClusterID, &item.Namespace, &item.PlatformRole, &item.RiskScore, &item.Findings); err != nil {
			rows.Close()
			http.Error(w, "Workload report evidence unavailable", 500)
			return
		}
		data.TopAssets = append(data.TopAssets, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		http.Error(w, "Workload report evidence unavailable", 500)
		return
	}
	mttr, err := tx.Query(r.Context(), `SELECT severity,COALESCE(sum(mttr_seconds*resolved_count)/NULLIF(sum(resolved_count),0),0)/86400.0,COALESCE(sum(resolved_count),0) FROM metrics_daily WHERE org_id=$1 AND day>=CURRENT_DATE-INTERVAL '90 days' GROUP BY severity ORDER BY severity`, sub.OrgID)
	if err != nil {
		http.Error(w, "MTTR report source unavailable", 500)
		return
	}
	for mttr.Next() {
		var item report.MTTRRow
		if err := mttr.Scan(&item.Severity, &item.Days, &item.Resolved); err != nil {
			mttr.Close()
			http.Error(w, "MTTR report source unavailable", 500)
			return
		}
		data.MTTRBySeverity = append(data.MTTRBySeverity, item)
	}
	err = mttr.Err()
	mttr.Close()
	if err != nil {
		http.Error(w, "MTTR report source unavailable", 500)
		return
	}
	fw, err := tx.Query(r.Context(), `WITH effective(`+complianceInventoryColumns+`) AS (`+complianceEffectiveRowsSQL+`) SELECT framework,count(*),count(*) FILTER(WHERE effective_status='pass'),count(*) FILTER(WHERE effective_status='fail'),count(*) FILTER(WHERE effective_status NOT IN('pass','fail','exempted','not_applicable')),count(*) FILTER(WHERE effective_status='exempted'),count(*) FILTER(WHERE effective_status='not_applicable') FROM effective GROUP BY framework ORDER BY framework`, sub.OrgID, cluster)
	if err != nil {
		http.Error(w, "Compliance report source unavailable", 500)
		return
	}
	for fw.Next() {
		var item report.FrameworkSummaryNamed
		if err := fw.Scan(&item.Name, &item.Total, &item.Pass, &item.Fail, &item.Manual, &item.Exempted, &item.NotApplicable); err != nil {
			fw.Close()
			http.Error(w, "Compliance report source unavailable", 500)
			return
		}
		data.FrameworkPass = append(data.FrameworkPass, item)
	}
	err = fw.Err()
	fw.Close()
	if err != nil {
		http.Error(w, "Compliance report source unavailable", 500)
		return
	}
	html, err := report.ExecutiveHTML(data)
	if err != nil {
		http.Error(w, "Report could not be rendered", 500)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		http.Error(w, "Report source unavailable", 500)
		return
	}
	reportScopeReceipt(w, sub.OrgID, cluster)
	writeReport(r.Context(), w, html, asPDF, "constellation-executive")
}
