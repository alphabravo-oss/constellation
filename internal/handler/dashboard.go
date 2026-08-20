package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

// Dashboard aggregates a one-shot summary the home page renders: severity counts,
// risk-score totals, the most recent activity, and queue depth. All queries scope to
// the calling org and run against the user-facing read replica path.
type Dashboard struct {
	db *db.DB
}

// NewDashboard constructs a Dashboard handler.
func NewDashboard(d *db.DB) *Dashboard { return &Dashboard{db: d} }

type dashboardSummaryDTO struct {
	GeneratedAt     string             `json:"generated_at"`
	FindingsByLevel map[string]int     `json:"findings_by_severity"`
	FindingsTotal   int                `json:"findings_total"`
	OpenFindings    int                `json:"open_findings"`
	AcceptedRisks   int                `json:"accepted_risks"`
	HighestRisk     float64            `json:"highest_risk"`
	AssetsTotal     int                `json:"assets_total"`
	ScanQueueDepth  int                `json:"scan_queue_depth"`
	RecentActivity  []dashboardEventDT `json:"recent_activity"`
	Posture         dashboardPostureDTO `json:"posture"`
}

// eventsTimelineDT is one day's bucket of alerting security events (severity high/critical),
// powering NV's dashboard Security-Events timeline chart.
type eventsTimelineDT struct {
	Date     string `json:"date"`     // YYYY-MM-DD
	Total    int    `json:"total"`    // high + critical alerts that day
	Critical int    `json:"critical"`
}

// dashboardPostureDTO carries the NeuVector-style posture rollups: a decomposed
// Security Risk Score plus the raw factors behind it (vuln location/signals + workload
// hardening + exposure). Lets the dashboard answer "how secure is this cluster" beyond
// a raw finding count.
type dashboardPostureDTO struct {
	SecurityScore   int            `json:"security_score"`   // 0-100, higher = safer
	ScoreBreakdown  map[string]int `json:"score_breakdown"`  // per-factor deductions from 100
	VulnsByLocation map[string]int `json:"vulns_by_location"`// image / host / platform finding counts
	VulnSignals     map[string]int `json:"vuln_signals"`     // kev / fixable / high_epss / corroborated
	Hardening       map[string]int `json:"hardening"`        // workloads + privileged / host_network / run_as_root / exposed
	Enforcement     map[string]int `json:"enforcement"`      // groups + discover / monitor / protect (NV service-mode coverage)
	CvesByMode      map[string]int `json:"cves_by_mode"`     // NV RESTRiskScoreMetricsCVE: distinct CVEs on workloads by group mode + platform/host
	ExposedByMode   map[string]int `json:"exposed_by_mode"`  // NV exposed-endpoint policy_mode: net-exposed workloads by group mode
	NewServicePolicyMode  string   `json:"new_service_policy_mode"`  // NV NewServiceMode: default network mode for new groups
	NewServiceProfileMode string   `json:"new_service_profile_mode"` // NV NewServiceProfileMode
	TopVulnerable   []topVulnerableWorkloadDTO `json:"top_vulnerable"` // NV "Top Vulnerable Assets"
}

type topVulnerableWorkloadDTO struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Critical  int    `json:"critical"`
	High      int    `json:"high"`
}

type dashboardEventDT struct {
	At         string `json:"at"`
	Action     string `json:"action"`
	TargetKind string `json:"target_kind"`
	TargetID   string `json:"target_id"`
	ActorID    string `json:"actor_id,omitempty"`
}

// Summary returns the home-page aggregate. Subject must be present.
func (h *Dashboard) Summary(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.aggregate(r.Context(), subj.OrgID, clusterArg)
	if err != nil {
		slog.ErrorContext(r.Context(), "dashboard summary", slog.String("err", err.Error()))
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("summary: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// EventsTimeline returns daily counts of ALERTING security events (severity critical/high)
// over 14 days — NV's dashboard Security-Events timeline. Kept OUT of /dashboard/summary
// because it scans the large events partition (~6s cold); the summary must stay fast, so this
// secondary widget loads on its own with its own spinner. GET /dashboard/events-timeline
func (h *Dashboard) EventsTimeline(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	out := []eventsTimelineDT{}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT date_trunc('day', at)::date AS d,
       COUNT(*)::int AS total,
       COUNT(*) FILTER (WHERE severity = 'critical')::int AS critical
  FROM events
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND severity IN ('critical','high')
   AND at > now() - interval '14 days'
 GROUP BY 1 ORDER BY 1`, subj.OrgID, clusterArg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("events timeline: %v", err))
		return
	}
	defer rows.Close()
	for rows.Next() {
		var d time.Time
		var t eventsTimelineDT
		if err := rows.Scan(&d, &t.Total, &t.Critical); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		t.Date = d.Format("2006-01-02")
		out = append(out, t)
	}
	writeJSON(w, http.StatusOK, map[string]any{"events_timeline": out})
}

func (h *Dashboard) aggregate(ctx context.Context, orgID uuid.UUID, clusterArg any) (dashboardSummaryDTO, error) {
	out := dashboardSummaryDTO{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		FindingsByLevel: map[string]int{},
		RecentActivity:  []dashboardEventDT{},
	}

	// Severity rollup — OPEN findings only. The severity tiles/donut are the "what
	// needs attention now" posture and link to the open findings view; counting
	// accepted/suppressed/resolved here made the critical/high tiles overcount vs
	// their own drill-down (and vs the open-findings tile) the moment anything was
	// triaged. Accepted risk is surfaced separately via AcceptedRisks below.
	rows, err := h.db.Pool().Query(ctx, `
SELECT severity, COUNT(*)::int FROM findings
 WHERE org_id = $1
   AND lifecycle = 'open'
   AND ($2::uuid IS NULL OR cluster_id = $2)
   -- Canonical vuln count: exclude the runtime-agent 'workload' pod-scan duplicate of
   -- the 'image-workload' image scan (see findings.go) so vulns aren't double-counted.
   AND NOT (kind = 'vulnerability' AND target_type = 'workload')
 GROUP BY severity`, orgID, clusterArg)
	if err != nil {
		return out, fmt.Errorf("severity rollup: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return out, err
		}
		out.FindingsByLevel[sev] = n
		out.FindingsTotal += n
	}

	// Lifecycle + max risk.
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE lifecycle = 'open')::int,
       COUNT(*) FILTER (WHERE lifecycle = 'accepted')::int,
       COALESCE(MAX(risk_score), 0)
  FROM findings
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND NOT (kind = 'vulnerability' AND target_type = 'workload')`, orgID, clusterArg).
		Scan(&out.OpenFindings, &out.AcceptedRisks, &out.HighestRisk); err != nil {
		return out, fmt.Errorf("lifecycle: %w", err)
	}

	// Assets total.
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*)::int FROM assets
          WHERE org_id = $1
            AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg).Scan(&out.AssetsTotal); err != nil {
		return out, fmt.Errorf("assets: %w", err)
	}

	// Scan queue depth. Note: scan_jobs are org-scoped (no cluster_id column),
	// so this stays unfiltered — the queue depth is a control-plane signal,
	// not a per-cluster posture metric.
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*)::int FROM scan_jobs WHERE org_id = $1 AND status = 'pending'`, orgID).
		Scan(&out.ScanQueueDepth); err != nil {
		return out, fmt.Errorf("queue: %w", err)
	}

	// Recent audit-log activity (most recent 20 for the org), ordered by `at`
	// so the (org_id, at DESC) index serves it in ~1ms.
	//
	// Previously this filtered to the cluster via `target_id IN (SELECT id FROM
	// findings/assets/deployments/compliance_checks WHERE cluster_id=$2)` and
	// ordered by `id DESC`. audit_events has no cluster_id column, so that
	// correlated filter matched only a handful of 1.3M+ rows and forced a full
	// table scan (~23s) on every dashboard load. Showing recent org activity is
	// a fast, acceptable proxy for this widget. To restore precise per-cluster
	// scoping without the scan, denormalize cluster_id onto audit_events at
	// write time and index (org_id, cluster_id, at DESC).
	evRows, err := h.db.Pool().Query(ctx, `
SELECT at, action, target_kind, target_id, COALESCE(actor_id::text, '')
  FROM audit_events
 WHERE org_id = $1
 ORDER BY at DESC LIMIT 20`, orgID)
	if err != nil {
		return out, fmt.Errorf("audit: %w", err)
	}
	defer evRows.Close()
	for evRows.Next() {
		var ev dashboardEventDT
		var at time.Time
		if err := evRows.Scan(&at, &ev.Action, &ev.TargetKind, &ev.TargetID, &ev.ActorID); err != nil {
			return out, err
		}
		ev.At = at.UTC().Format(time.RFC3339)
		out.RecentActivity = append(out.RecentActivity, ev)
	}

	if err := h.computePosture(ctx, orgID, clusterArg, &out); err != nil {
		return out, fmt.Errorf("posture: %w", err)
	}
	return out, nil
}

// computePosture fills the NeuVector-style posture block: vuln location/signals, workload
// hardening, and a decomposed 0-100 Security Risk Score (100 = safest). The canonical
// 'workload' exclusion (see findings.go) keeps vuln counts from double-counting.
func (h *Dashboard) computePosture(ctx context.Context, orgID uuid.UUID, clusterArg any, out *dashboardSummaryDTO) error {
	p := dashboardPostureDTO{
		ScoreBreakdown:  map[string]int{},
		TopVulnerable:   []topVulnerableWorkloadDTO{},
		VulnsByLocation: map[string]int{"image": 0, "host": 0, "platform": 0},
		VulnSignals:     map[string]int{"kev": 0, "fixable": 0, "high_epss": 0, "corroborated": 0},
		Hardening:       map[string]int{"workloads": 0, "privileged": 0, "host_network": 0, "run_as_root": 0, "exposed": 0},
		Enforcement:     map[string]int{"groups": 0, "discover": 0, "monitor": 0, "protect": 0},
		CvesByMode:      map[string]int{"discover": 0, "monitor": 0, "protect": 0, "platform": 0, "host": 0},
		ExposedByMode:   map[string]int{"discover": 0, "monitor": 0, "protect": 0},
	}

	// Vuln location + signals in one pass over OPEN vulnerability findings (canonical set).
	var vImage, vHost, vPlatform, sKev, sFix, sEpss, sCorr, critical, high int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT
  COUNT(*) FILTER (WHERE target_type = 'image-workload')::int,
  COUNT(*) FILTER (WHERE target_type = 'host')::int,
  COUNT(*) FILTER (WHERE target_type = 'platform')::int,
  COUNT(*) FILTER (WHERE (detail_json->>'kev')::bool IS TRUE)::int,
  COUNT(*) FILTER (WHERE COALESCE(detail_json->>'fixed','') NOT IN ('', 'false'))::int,
  COUNT(*) FILTER (WHERE COALESCE((detail_json->>'epss')::float8, 0) > 0.5)::int,
  COUNT(*) FILTER (WHERE canonical_engine = 'aggregate')::int,
  COUNT(*) FILTER (WHERE severity = 'critical')::int,
  COUNT(*) FILTER (WHERE severity = 'high')::int
  FROM findings
 WHERE org_id = $1
   AND kind = 'vulnerability'
   AND lifecycle = 'open'
   AND target_type <> 'workload'
   AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg).
		Scan(&vImage, &vHost, &vPlatform, &sKev, &sFix, &sEpss, &sCorr, &critical, &high); err != nil {
		return fmt.Errorf("vuln rollup: %w", err)
	}
	p.VulnsByLocation["image"], p.VulnsByLocation["host"], p.VulnsByLocation["platform"] = vImage, vHost, vPlatform
	p.VulnSignals["kev"], p.VulnSignals["fixable"], p.VulnSignals["high_epss"], p.VulnSignals["corroborated"] = sKev, sFix, sEpss, sCorr

	// Workload hardening from deployments.risk_factors (structural facts the discoverer
	// captured from the pod spec).
	var wl, priv, hostNet, root, exposed int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE risk_factors ? 'privileged')::int,
       COUNT(*) FILTER (WHERE risk_factors ? 'host_network')::int,
       COUNT(*) FILTER (WHERE risk_factors ? 'run_as_root')::int,
       COUNT(*) FILTER (WHERE risk_factors ? 'net_exposure')::int
  FROM deployments
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg).
		Scan(&wl, &priv, &hostNet, &root, &exposed); err != nil {
		return fmt.Errorf("hardening rollup: %w", err)
	}
	p.Hardening["workloads"], p.Hardening["privileged"], p.Hardening["host_network"], p.Hardening["run_as_root"], p.Hardening["exposed"] = wl, priv, hostNet, root, exposed

	// Enforcement coverage from group policy_mode (NV service-mode): discover = learning
	// only (no protection), monitor = alert, protect = block. A cluster left in discover is
	// unenforced — that is structural risk NV's service-mode score captures.
	var grps, gDiscover, gMonitor, gProtect int
	var pDiscover, pMonitor, pProtect int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE policy_mode = 'discover')::int,
       COUNT(*) FILTER (WHERE policy_mode = 'monitor')::int,
       COUNT(*) FILTER (WHERE policy_mode = 'protect')::int,
       COUNT(*) FILTER (WHERE profile_mode = 'discover')::int,
       COUNT(*) FILTER (WHERE profile_mode = 'monitor')::int,
       COUNT(*) FILTER (WHERE profile_mode = 'protect')::int
  FROM groups
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg).
		Scan(&grps, &gDiscover, &gMonitor, &gProtect, &pDiscover, &pMonitor, &pProtect); err != nil {
		return fmt.Errorf("enforcement rollup: %w", err)
	}
	p.Enforcement["groups"], p.Enforcement["discover"], p.Enforcement["monitor"], p.Enforcement["protect"] = grps, gDiscover, gMonitor, gProtect
	// Process/file profile-mode maturity (NV shows network AND profile mode distributions).
	p.Enforcement["profile_discover"], p.Enforcement["profile_monitor"], p.Enforcement["profile_protect"] = pDiscover, pMonitor, pProtect

	// CVEs by mode (NV RESTRiskScoreMetricsCVE): distinct workload CVEs bucketed by the
	// strongest policy_mode of any group the workload belongs to, resolved via
	// image_workload_links (finding image digest → workload id → group.members). Plus
	// platform/host CVEs straight from finding target_type. Answers "how many CVEs still
	// sit on workloads we aren't protecting".
	var cDiscover, cMonitor, cProtect, cPlatform, cHost int
	if err := h.db.Pool().QueryRow(ctx, `
WITH wl_mode AS (
  SELECT jsonb_array_elements_text(g.members) AS wl,
         MAX(CASE g.policy_mode WHEN 'protect' THEN 3 WHEN 'monitor' THEN 2 ELSE 1 END) AS r
    FROM groups g
   WHERE g.org_id = $1 AND ($2::uuid IS NULL OR g.cluster_id = $2)
   GROUP BY 1)
SELECT
  COUNT(DISTINCT f.external_id) FILTER (WHERE m.r = 1)::int,
  COUNT(DISTINCT f.external_id) FILTER (WHERE m.r = 2)::int,
  COUNT(DISTINCT f.external_id) FILTER (WHERE m.r = 3)::int
  FROM findings f
  JOIN image_workload_links l
    ON l.image_digest = f.target_ref AND l.org_id = f.org_id AND l.cluster_id = f.cluster_id
  LEFT JOIN wl_mode m ON m.wl = l.workload_id
 WHERE f.org_id = $1 AND f.kind = 'vulnerability' AND f.lifecycle = 'open'
   AND f.target_type = 'image-workload' AND ($2::uuid IS NULL OR f.cluster_id = $2)`,
		orgID, clusterArg).Scan(&cDiscover, &cMonitor, &cProtect); err != nil {
		return fmt.Errorf("cve-by-mode rollup: %w", err)
	}
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(DISTINCT external_id) FILTER (WHERE target_type = 'platform')::int,
       COUNT(DISTINCT external_id) FILTER (WHERE target_type = 'host')::int
  FROM findings
 WHERE org_id = $1 AND kind = 'vulnerability' AND lifecycle = 'open'
   AND target_type IN ('platform','host') AND ($2::uuid IS NULL OR cluster_id = $2)`,
		orgID, clusterArg).Scan(&cPlatform, &cHost); err != nil {
		return fmt.Errorf("cve platform/host rollup: %w", err)
	}
	p.CvesByMode["discover"], p.CvesByMode["monitor"], p.CvesByMode["protect"] = cDiscover, cMonitor, cProtect
	p.CvesByMode["platform"], p.CvesByMode["host"] = cPlatform, cHost

	// Exposed workloads by mode (NV exposed-endpoint policy_mode): net-exposed deployments
	// bucketed by the strongest group mode covering them. An exposed workload still in
	// discover is unprotected attack surface.
	var eDiscover, eMonitor, eProtect int
	if err := h.db.Pool().QueryRow(ctx, `
WITH wl_mode AS (
  SELECT jsonb_array_elements_text(g.members) AS wl,
         MAX(CASE g.policy_mode WHEN 'protect' THEN 3 WHEN 'monitor' THEN 2 ELSE 1 END) AS r
    FROM groups g
   WHERE g.org_id = $1 AND ($2::uuid IS NULL OR g.cluster_id = $2)
   GROUP BY 1)
SELECT
  COUNT(*) FILTER (WHERE m.r = 1)::int,
  COUNT(*) FILTER (WHERE m.r = 2)::int,
  COUNT(*) FILTER (WHERE m.r = 3)::int
  FROM deployments d
  LEFT JOIN wl_mode m ON m.wl = d.namespace || '/' || d.name
 WHERE d.org_id = $1 AND d.risk_factors ? 'net_exposure'
   AND ($2::uuid IS NULL OR d.cluster_id = $2)`,
		orgID, clusterArg).Scan(&eDiscover, &eMonitor, &eProtect); err != nil {
		return fmt.Errorf("exposed-by-mode rollup: %w", err)
	}
	p.ExposedByMode["discover"], p.ExposedByMode["monitor"], p.ExposedByMode["protect"] = eDiscover, eMonitor, eProtect

	// New-service default modes (NV NewServiceMode / NewServiceProfileMode). Default monitor.
	p.NewServicePolicyMode, p.NewServiceProfileMode = "monitor", "monitor"
	if cid, ok := clusterArg.(uuid.UUID); ok {
		_ = h.db.Pool().QueryRow(ctx,
			`SELECT policy_mode, profile_mode FROM service_mode_defaults WHERE org_id = $1 AND cluster_id = $2`,
			orgID, cid).Scan(&p.NewServicePolicyMode, &p.NewServiceProfileMode)
	}

	// Admission control coverage (NV: adm_mode + deny_adm_ctrl_rules). Constellation drives
	// admission via `policies` with engine='constellation-admission'; an enabled policy in
	// enforce mode with deny actions is a live deny rule.
	var admPolicies, admEnforce int
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE enabled AND engine = 'constellation-admission')::int,
       COUNT(*) FILTER (WHERE enabled AND engine = 'constellation-admission'
                          AND (mode IN ('enforce','protect','block')
                               OR enforcement_actions::text ~* 'deny|block'))::int
  FROM policies
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)`, orgID, clusterArg).
		Scan(&admPolicies, &admEnforce); err != nil {
		return fmt.Errorf("admission rollup: %w", err)
	}
	p.Enforcement["admission_policies"], p.Enforcement["admission_enforcing"] = admPolicies, admEnforce

	// Security RISK Score (0-100, HIGHER = worse), matching NeuVector's documented model
	// and factor caps: Protection Mode 30 · Ingress/Egress Exposure 42 · Privileged 4 ·
	// Root 4 · Admission 4 · Vulnerabilities 16. Ranges: 0-20 Good · 21-50 Fair · 51-100
	// Poor. Exposure dominates because network attack surface is the top container risk.
	frac := func(n, d int) float64 {
		if d <= 0 {
			return 0
		}
		return float64(n) / float64(d)
	}
	clampF := func(v, cap float64) int {
		if v > cap {
			v = cap
		}
		if v < 0 {
			v = 0
		}
		return int(v + 0.5)
	}
	// Protection mode: unenforced groups carry risk — discover full weight, monitor half.
	protection := clampF(30*frac(gDiscover*2+gMonitor, grps*2), 30)
	exposureF := clampF(42*frac(exposed, wl), 42)
	privilegedF := clampF(float64(priv)*4, 4)
	rootF := clampF(float64(root)*2, 4)
	// Admission: NV scores absence of enforcing deny rules. Full risk when no admission
	// policy enforces; half when a policy exists only in monitor; none when a deny rule
	// is live.
	admissionF := 4
	if admEnforce > 0 {
		admissionF = 0
	} else if admPolicies > 0 {
		admissionF = 2
	}
	vulnF := clampF(float64(critical)/8.0+float64(high)/100.0+float64(sKev)*2, 16)

	p.ScoreBreakdown["protection_mode"] = protection
	p.ScoreBreakdown["exposure"] = exposureF
	p.ScoreBreakdown["privileged"] = privilegedF
	p.ScoreBreakdown["root"] = rootF
	p.ScoreBreakdown["admission"] = admissionF
	p.ScoreBreakdown["vulnerabilities"] = vulnF
	risk := protection + exposureF + privilegedF + rootF + admissionF + vulnF
	if risk > 100 {
		risk = 100
	}
	p.SecurityScore = risk // NOTE: now a RISK score (higher = worse), NV convention

	// Top vulnerable workloads (NV "Top Vulnerable Assets"): highest critical+high CVE
	// workloads in the cluster.
	twRows, err := h.db.Pool().Query(ctx, `
SELECT namespace, name, COALESCE(critical_count,0)::int, COALESCE(high_count,0)::int
  FROM deployments
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND (COALESCE(critical_count,0) > 0 OR COALESCE(high_count,0) > 0)
 ORDER BY critical_count DESC, high_count DESC
 LIMIT 6`, orgID, clusterArg)
	if err != nil {
		return fmt.Errorf("top vulnerable workloads: %w", err)
	}
	defer twRows.Close()
	for twRows.Next() {
		var t topVulnerableWorkloadDTO
		if err := twRows.Scan(&t.Namespace, &t.Name, &t.Critical, &t.High); err != nil {
			return err
		}
		p.TopVulnerable = append(p.TopVulnerable, t)
	}

	out.Posture = p
	return nil
}
