// Report endpoints — HTML + PDF compliance/executive reports.
//
//	GET /api/v1/reports/compliance.html?framework=<id>   inline HTML preview
//	GET /api/v1/reports/compliance.pdf?framework=<id>    binary PDF (wkhtmltopdf)
//	GET /api/v1/reports/executive.html
//	GET /api/v1/reports/executive.pdf
//
// When wkhtmltopdf isn't installed the PDF endpoints fall through to HTML with a
// Content-Disposition that triggers the browser's print-to-PDF dialog — covers ~95% of
// customers without us bundling a 200MB chromium binary.
package compliance

import (
	"errors"
	"net/http"
	"time"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
	"github.com/alphabravocompany/constellation/pkg/report"
)

type Reports struct{ db *db.DB }

func NewReports(d *db.DB) *Reports { return &Reports{db: d} }

// ComplianceHTML serves the compliance report as HTML (inline preview).
func (h *Reports) ComplianceHTML(w http.ResponseWriter, r *http.Request) {
	h.serveCompliance(w, r, false)
}

// CompliancePDF serves the compliance report as PDF; falls through to HTML when
// wkhtmltopdf is missing.
func (h *Reports) CompliancePDF(w http.ResponseWriter, r *http.Request) {
	h.serveCompliance(w, r, true)
}

func (h *Reports) serveCompliance(w http.ResponseWriter, r *http.Request, asPDF bool) {
	subj, _ := authctx.SubjectFrom(r.Context())
	framework := r.URL.Query().Get("framework")
	if framework == "" {
		framework = compliancepkg.FrameworkCISK8s
	}

	frameworkName := framework
	for _, f := range compliancepkg.AllFrameworks() {
		if f.ID == framework {
			frameworkName = f.Name
		}
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT control_id, title, COALESCE(description,''), status, severity, COALESCE(evidence,'')
  FROM compliance_checks WHERE org_id = $1 AND framework = $2
 ORDER BY control_id LIMIT 500`, subj.OrgID, framework)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()

	data := report.ComplianceData{
		OrgName:       "Demo Org",
		Framework:     framework,
		FrameworkName: frameworkName,
		GeneratedAt:   time.Now(),
	}
	for rows.Next() {
		var c report.ComplianceCheck
		var description string
		if err := rows.Scan(&c.ControlID, &c.Title, &description, &c.Status, &c.Severity, &c.Evidence); err != nil {
			continue
		}
		_ = description
		data.Checks = append(data.Checks, c)
		data.Summary.Total++
		switch c.Status {
		case "pass":
			data.Summary.Pass++
		case "fail":
			data.Summary.Fail++
		case "manual":
			data.Summary.Manual++
		}
	}

	html, err := report.ComplianceHTML(data)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if asPDF {
		pdf, err := report.HTMLToPDF(html)
		if err == nil {
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", `attachment; filename="constellation-compliance-`+framework+`.pdf"`)
			_, _ = w.Write(pdf)
			return
		}
		if !errors.Is(err, report.ErrPDFToolMissing) {
			http.Error(w, err.Error(), 500)
			return
		}
		// Fall through to HTML with print-friendly headers.
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if asPDF {
		w.Header().Set("X-Constellation-PDF-Fallback", "browser-print")
	}
	_, _ = w.Write(html)
}

// ExecutiveHTML / ExecutivePDF render the executive summary.
func (h *Reports) ExecutiveHTML(w http.ResponseWriter, r *http.Request) {
	h.serveExecutive(w, r, false)
}
func (h *Reports) ExecutivePDF(w http.ResponseWriter, r *http.Request) { h.serveExecutive(w, r, true) }

func (h *Reports) serveExecutive(w http.ResponseWriter, r *http.Request, asPDF bool) {
	subj, _ := authctx.SubjectFrom(r.Context())

	var data report.ExecutiveData
	data.OrgName = "Demo Org"
	data.GeneratedAt = time.Now()
	data.ScanWindow = "last 30 days"

	// Top-level counts.
	_ = h.db.Pool().QueryRow(r.Context(), `
SELECT
  COUNT(*),
  COUNT(*) FILTER (WHERE severity = 'critical'),
  COUNT(*) FILTER (WHERE severity = 'high'),
  COUNT(*) FILTER (WHERE lifecycle = 'suppressed'),
  COUNT(*) FILTER (WHERE lifecycle = 'accepted')
  FROM findings WHERE org_id = $1`, subj.OrgID).
		Scan(&data.TotalFindings, &data.CriticalFindings, &data.HighFindings, &data.SuppressedCount, &data.AcceptedCount)

	// Top assets by risk.
	rows, _ := h.db.Pool().Query(r.Context(), `
SELECT name, risk_score, finding_count
  FROM deployments WHERE org_id = $1
 ORDER BY risk_score DESC LIMIT 10`, subj.OrgID)
	for rows.Next() {
		var a report.AssetRow
		if err := rows.Scan(&a.Name, &a.RiskScore, &a.Findings); err == nil {
			data.TopAssets = append(data.TopAssets, a)
		}
	}
	rows.Close()

	// MTTR by severity.
	mttrRows, _ := h.db.Pool().Query(r.Context(), `
SELECT severity,
       COALESCE(AVG(mttr_seconds), 0) / 86400.0 AS mttr_days,
       SUM(resolved_count) AS resolved
  FROM metrics_daily WHERE org_id = $1 AND day >= CURRENT_DATE - INTERVAL '90 days'
 GROUP BY 1 ORDER BY 1`, subj.OrgID)
	for mttrRows.Next() {
		var m report.MTTRRow
		if err := mttrRows.Scan(&m.Severity, &m.Days, &m.Resolved); err == nil {
			data.MTTRBySeverity = append(data.MTTRBySeverity, m)
		}
	}
	mttrRows.Close()

	// Framework pass-rate summary.
	fwRows, _ := h.db.Pool().Query(r.Context(), `
SELECT framework,
       COUNT(*) FILTER (WHERE status = 'pass') AS pass,
       COUNT(*) AS total
  FROM compliance_checks WHERE org_id = $1
 GROUP BY framework ORDER BY framework LIMIT 8`, subj.OrgID)
	for fwRows.Next() {
		var n string
		var p, t int
		if err := fwRows.Scan(&n, &p, &t); err == nil {
			data.FrameworkPass = append(data.FrameworkPass, report.FrameworkSummaryNamed{
				Name: n, FrameworkSummary: report.FrameworkSummary{Pass: p, Total: t},
			})
		}
	}
	fwRows.Close()

	html, err := report.ExecutiveHTML(data)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if asPDF {
		pdf, err := report.HTMLToPDF(html)
		if err == nil {
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", `attachment; filename="constellation-executive.pdf"`)
			_, _ = w.Write(pdf)
			return
		}
		if !errors.Is(err, report.ErrPDFToolMissing) {
			http.Error(w, err.Error(), 500)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(html)
}
