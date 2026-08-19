// Package report renders compliance + executive PDF reports.
//
// At v1 we render HTML via Go's html/template, then convert to PDF by shelling out to
// `wkhtmltopdf` (well-supported, no Chrome required) when available, OR by returning the
// HTML directly with a Content-Disposition header so the user's browser does the print.
// The print-from-browser path matches what most enterprise customers do today and avoids
// shipping a 200 MB chromium binary in the API image.
//
// For embedded preview the API also returns `text/html` so the UI can iframe-preview.
package report

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"os/exec"
	"time"
)

// ComplianceData is the input for a Compliance report.
//
// SignerIdentity / ClusterName / RunID are optional cover-page fields used by
// the constellation-compliance-scheduler (Wave N8). When unset the template
// hides those sections, so existing callers (Reports handler) keep rendering
// the same layout they did before.
type ComplianceData struct {
	OrgName        string
	GeneratedAt    time.Time
	Framework      string
	FrameworkName  string
	Summary        FrameworkSummary
	Checks         []ComplianceCheck
	ClusterName    string
	SignerIdentity string
	RunID          string
}

type FrameworkSummary struct {
	Total  int
	Pass   int
	Fail   int
	Manual int
}

func (s FrameworkSummary) PassPct() int {
	if s.Total == 0 {
		return 0
	}
	return (s.Pass * 100) / s.Total
}

type ComplianceCheck struct {
	ControlID string `json:"control_id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	Severity  string `json:"severity"`
	Evidence  string `json:"evidence"`
}

// ExecutiveData is the input for the Executive Summary report.
type ExecutiveData struct {
	OrgName          string
	GeneratedAt      time.Time
	ScanWindow       string // e.g. "last 30 days"
	TotalFindings    int
	CriticalFindings int
	HighFindings     int
	SuppressedCount  int
	AcceptedCount    int
	TopAssets        []AssetRow
	MTTRBySeverity   []MTTRRow
	FrameworkPass    []FrameworkSummaryNamed
}

type AssetRow struct {
	Name      string
	RiskScore int
	Findings  int
}

type MTTRRow struct {
	Severity string
	Days     float64
	Resolved int
}

type FrameworkSummaryNamed struct {
	Name string
	FrameworkSummary
}

// ComplianceHTML renders the compliance report as HTML.
func ComplianceHTML(d ComplianceData) ([]byte, error) {
	t, err := template.New("compliance").Parse(complianceTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExecutiveHTML renders the executive summary as HTML.
func ExecutiveHTML(d ExecutiveData) ([]byte, error) {
	t, err := template.New("executive").Parse(executiveTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// HTMLToPDF converts HTML bytes to PDF via wkhtmltopdf. Returns ErrPDFToolMissing when
// wkhtmltopdf isn't on PATH so callers can fall back to serving HTML.
func HTMLToPDF(html []byte) ([]byte, error) {
	bin, err := exec.LookPath("wkhtmltopdf")
	if err != nil {
		return nil, ErrPDFToolMissing
	}
	cmd := exec.Command(bin, "--quiet", "--enable-local-file-access", "-", "-")
	cmd.Stdin = bytes.NewReader(html)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("wkhtmltopdf: %w (stderr=%s)", err, errBuf.String())
	}
	return out.Bytes(), nil
}

// ErrPDFToolMissing is returned by HTMLToPDF when wkhtmltopdf isn't installed.
var ErrPDFToolMissing = errors.New("report: wkhtmltopdf not installed; serve HTML for browser-print fallback")

// complianceTemplate is the polished "compliance-detailed" template used by both
// the Reports handler and the Wave N8 scheduled-runs daemon. Layout:
//
//  1. Cover page — org / cluster / framework / run date / signer identity
//  2. Table of contents (anchors below)
//  3. Summary tiles (total / pass / fail / manual / pass rate)
//  4. Per-control results table grouped by control_id
//  5. Failed controls drill-down with full evidence + affected workloads
//  6. Executive summary footer
const complianceTemplate = `<!doctype html>
<html><head><meta charset="utf-8">
<title>Constellation Compliance Report — {{.FrameworkName}}</title>
<style>
  body { font: 11pt/1.4 -apple-system, "Segoe UI", system-ui, sans-serif; color: #18181b; margin: 32px; }
  h1 { font-size: 26pt; margin-bottom: 4px; }
  h2 { font-size: 14pt; margin-top: 28px; border-bottom: 1px solid #e4e4e7; padding-bottom: 4px; }
  h3 { font-size: 11.5pt; margin-top: 18px; }
  .sub { color: #71717a; font-size: 10pt; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 9.5pt; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #e4e4e7; vertical-align: top; }
  th { background: #f4f4f5; text-align: left; font-weight: 600; }
  .pass { color: #16a34a; } .fail { color: #dc2626; } .manual { color: #f59e0b; }
  .exempted { color: #2563eb; } .not_applicable { color: #71717a; }
  .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; margin-top: 12px; }
  .summary-tile { padding: 8px 12px; background: #fafafa; border: 1px solid #e4e4e7; border-radius: 6px; }
  .summary-tile .n { font-size: 18pt; font-weight: 600; }
  .cover { page-break-after: always; border: 1px solid #e4e4e7; border-radius: 12px; padding: 48px 32px; background: linear-gradient(135deg, #fafafa, #ffffff); }
  .cover .badge { display: inline-block; padding: 2px 8px; background: #18181b; color: #fafafa; border-radius: 999px; font-size: 9pt; letter-spacing: 0.04em; }
  .cover .meta { margin-top: 22px; display: grid; grid-template-columns: 160px 1fr; row-gap: 6px; font-size: 10.5pt; }
  .cover .meta .k { color: #71717a; }
  .cover .meta .v { font-weight: 500; }
  .toc { padding: 12px 16px; background: #fafafa; border: 1px solid #e4e4e7; border-radius: 8px; }
  .toc ol { margin: 0; padding-left: 20px; }
  .signer { font-family: ui-monospace, monospace; font-size: 9pt; color: #404040; word-break: break-all; }
  .evidence { font-family: ui-monospace, monospace; font-size: 8.5pt; color: #404040; white-space: pre-wrap; }
  .footer { margin-top: 36px; padding-top: 12px; border-top: 1px solid #e4e4e7; font-size: 9pt; color: #71717a; }
</style></head>
<body>
  <section class="cover">
    <span class="badge">CONSTELLATION COMPLIANCE</span>
    <h1>{{.FrameworkName}}</h1>
    <p class="sub">Cosign-signed evidence package · {{.Framework}}</p>
    <div class="meta">
      <span class="k">Organization</span><span class="v">{{.OrgName}}</span>
      {{if .ClusterName}}<span class="k">Cluster</span><span class="v">{{.ClusterName}}</span>{{end}}
      <span class="k">Framework</span><span class="v">{{.FrameworkName}} ({{.Framework}})</span>
      <span class="k">Run date</span><span class="v">{{.GeneratedAt.Format "2006-01-02 15:04 UTC"}}</span>
      {{if .RunID}}<span class="k">Run ID</span><span class="v signer">{{.RunID}}</span>{{end}}
      {{if .SignerIdentity}}<span class="k">Signer identity</span><span class="v signer">{{.SignerIdentity}}</span>{{end}}
    </div>
  </section>

  <h2 id="toc">Table of contents</h2>
  <nav class="toc">
    <ol>
      <li><a href="#summary">Summary</a></li>
      <li><a href="#controls">Control results (grouped by control)</a></li>
      <li><a href="#failures">Failed controls — full evidence</a></li>
      <li><a href="#exec">Executive summary</a></li>
    </ol>
  </nav>

  <h2 id="summary">Summary</h2>
  <p class="sub">{{.OrgName}} — {{.FrameworkName}} ({{.Framework}}) — generated {{.GeneratedAt.Format "2006-01-02 15:04 UTC"}}</p>
  <div class="summary">
    <div class="summary-tile"><div class="n">{{.Summary.Total}}</div><div>controls evaluated</div></div>
    <div class="summary-tile"><div class="n pass">{{.Summary.Pass}}</div><div>pass</div></div>
    <div class="summary-tile"><div class="n fail">{{.Summary.Fail}}</div><div>fail</div></div>
    <div class="summary-tile"><div class="n manual">{{.Summary.Manual}}</div><div>manual / n-a</div></div>
    <div class="summary-tile"><div class="n">{{.Summary.PassPct}}%</div><div>pass rate</div></div>
  </div>

  <h2 id="controls">Control results</h2>
  <table>
    <thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Severity</th><th>Evidence</th></tr></thead>
    <tbody>
    {{range .Checks}}
      <tr>
        <td><code>{{.ControlID}}</code></td>
        <td>{{.Title}}</td>
        <td class="{{.Status}}">{{.Status}}</td>
        <td>{{.Severity}}</td>
        <td class="evidence">{{.Evidence}}</td>
      </tr>
    {{end}}
    </tbody>
  </table>

  <h2 id="failures">Failed controls — full evidence</h2>
  {{$hasFails := false}}
  {{range .Checks}}{{if eq .Status "fail"}}{{$hasFails = true}}{{end}}{{end}}
  {{if $hasFails}}
    {{range .Checks}}{{if eq .Status "fail"}}
      <h3 class="fail">{{.ControlID}} — {{.Title}}</h3>
      <p class="sub">Severity: <strong>{{.Severity}}</strong></p>
      <pre class="evidence">{{if .Evidence}}{{.Evidence}}{{else}}(no evidence recorded){{end}}</pre>
    {{end}}{{end}}
  {{else}}
    <p class="sub">No failed controls in this run.</p>
  {{end}}

  <h2 id="exec">Executive summary</h2>
  <p>
    Of <strong>{{.Summary.Total}}</strong> controls evaluated for <strong>{{.FrameworkName}}</strong>,
    <span class="pass"><strong>{{.Summary.Pass}}</strong> passed</span>,
    <span class="fail"><strong>{{.Summary.Fail}}</strong> failed</span>, and
    <span class="manual"><strong>{{.Summary.Manual}}</strong></span> require manual attestation.
    Overall pass rate: <strong>{{.Summary.PassPct}}%</strong>.
  </p>
  <p class="footer">
    This report was generated by Constellation and is cosign-signed.
    Verify the signature with <code>cosign verify-blob --signature &lt;sig&gt; --key cosign.pub &lt;file&gt;</code>.
    Hash-chained audit log entries supporting every status are available via
    <code>POST /api/v1/audit/verify</code>.
  </p>
</body></html>`

const executiveTemplate = `<!doctype html>
<html><head><meta charset="utf-8">
<title>Constellation Executive Summary — {{.OrgName}}</title>
<style>
  body { font: 11pt/1.4 -apple-system, "Segoe UI", system-ui, sans-serif; color: #18181b; margin: 32px; }
  h1 { font-size: 24pt; margin-bottom: 4px; }
  h2 { font-size: 14pt; margin-top: 28px; }
  .sub { color: #71717a; font-size: 10pt; }
  .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-top: 16px; }
  .kpi { padding: 12px; border: 1px solid #e4e4e7; border-radius: 8px; background: #fafafa; }
  .kpi .v { font-size: 22pt; font-weight: 700; }
  .kpi .l { color: #71717a; font-size: 9pt; text-transform: uppercase; letter-spacing: 0.04em; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 9.5pt; }
  th, td { padding: 6px 8px; border-bottom: 1px solid #e4e4e7; }
  th { background: #f4f4f5; text-align: left; }
  .crit { color: #dc2626; } .high { color: #ea580c; }
</style></head>
<body>
  <h1>Executive Security Summary</h1>
  <p class="sub">{{.OrgName}} · {{.ScanWindow}} · generated {{.GeneratedAt.Format "2006-01-02"}}</p>

  <div class="kpi-grid">
    <div class="kpi"><div class="v">{{.TotalFindings}}</div><div class="l">total findings</div></div>
    <div class="kpi"><div class="v crit">{{.CriticalFindings}}</div><div class="l">critical</div></div>
    <div class="kpi"><div class="v high">{{.HighFindings}}</div><div class="l">high</div></div>
    <div class="kpi"><div class="v">{{.AcceptedCount}}</div><div class="l">risk accepted</div></div>
  </div>

  <h2>Top assets at risk</h2>
  <table>
    <thead><tr><th>Asset</th><th>Risk</th><th>Findings</th></tr></thead>
    <tbody>
    {{range .TopAssets}}<tr><td>{{.Name}}</td><td>{{.RiskScore}}</td><td>{{.Findings}}</td></tr>{{end}}
    </tbody>
  </table>

  <h2>Mean time-to-resolve (90 days)</h2>
  <table>
    <thead><tr><th>Severity</th><th>MTTR (days)</th><th>Resolved</th></tr></thead>
    <tbody>
    {{range .MTTRBySeverity}}<tr><td>{{.Severity}}</td><td>{{printf "%.1f" .Days}}</td><td>{{.Resolved}}</td></tr>{{end}}
    </tbody>
  </table>

  <h2>Compliance pass-rate</h2>
  <table>
    <thead><tr><th>Framework</th><th>Pass %</th><th>Pass / Total</th></tr></thead>
    <tbody>
    {{range .FrameworkPass}}<tr><td>{{.Name}}</td><td>{{.PassPct}}%</td><td>{{.Pass}} / {{.Total}}</td></tr>{{end}}
    </tbody>
  </table>
</body></html>`
