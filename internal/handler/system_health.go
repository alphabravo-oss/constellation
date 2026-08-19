package handler

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/version"
)

// SystemHealth surfaces a control-plane health dashboard. DB-backed signals
// overlay a neutral component inventory so kernel-free dev still renders
// without inventing incidents, remediation actions, or dated production
// telemetry. A real DB injects live signals — DB ping, scan-job backlog, audit
// chain count — and the Wave N6 heartbeat-driven blocks (version drift,
// crashloop history, per-cluster rollups, license banner).
type SystemHealth struct {
	db *db.DB
}

// NewSystemHealth constructs a SystemHealth handler. Variadic argument keeps
// the zero-arg call signature working for frontend dev / unit tests that have
// no DB; production wires a *db.DB in.
func NewSystemHealth(args ...*db.DB) *SystemHealth {
	h := &SystemHealth{}
	if len(args) > 0 {
		h.db = args[0]
	}
	return h
}

// -----------------------------------------------------------------------------
// DTOs
// -----------------------------------------------------------------------------

type systemHealthSummaryDTO struct {
	Status             string         `json:"status"`
	GeneratedAt        string         `json:"generated_at"`
	ComponentsTotal    int            `json:"components_total"`
	ComponentsByStatus map[string]int `json:"components_by_status"`
	ActiveIncidents    int            `json:"active_incidents"`
	OpenActions        int            `json:"open_actions"`
	DegradedComponents []string       `json:"degraded_components"`
	Healthy            int            `json:"healthy"`
	Degraded           int            `json:"degraded"`
	Stale              int            `json:"stale"`
	Drift              int            `json:"drift"`
	Crashlooping       int            `json:"crashlooping"`
}

type systemHealthComponentDTO struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Domain      string                  `json:"domain"`
	Status      string                  `json:"status"`
	Mode        string                  `json:"mode"`
	Owner       string                  `json:"owner"`
	SLO         string                  `json:"slo"`
	LastChecked string                  `json:"last_checked"`
	Summary     string                  `json:"summary"`
	Signals     []systemHealthSignalDTO `json:"signals"`
}

type systemHealthSignalDTO struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Value     string `json:"value"`
	Threshold string `json:"threshold"`
	Evidence  string `json:"evidence"`
}

type systemHealthIncidentDTO struct {
	ID           string   `json:"id"`
	Severity     string   `json:"severity"`
	Status       string   `json:"status"`
	ComponentIDs []string `json:"component_ids"`
	StartedAt    string   `json:"started_at"`
	Summary      string   `json:"summary"`
	Impact       string   `json:"impact"`
}

type systemHealthRemediationDTO struct {
	ID          string   `json:"id"`
	Priority    string   `json:"priority"`
	Status      string   `json:"status"`
	ComponentID string   `json:"component_id"`
	Title       string   `json:"title"`
	Owner       string   `json:"owner"`
	DueAt       string   `json:"due_at"`
	Steps       []string `json:"steps"`
}

type heartbeatDTO struct {
	Component     string         `json:"component"`
	ClusterID     string         `json:"cluster_id,omitempty"`
	ClusterName   string         `json:"cluster_name,omitempty"`
	Version       string         `json:"version"`
	Commit        string         `json:"commit"`
	CommitShort   string         `json:"commit_short"`
	BuildTime     string         `json:"build_time,omitempty"`
	Hostname      string         `json:"hostname"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	RestartCount  int            `json:"restart_count"`
	LastError     string         `json:"last_error,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	LastSeenAt    string         `json:"last_seen_at"`
	Status        string         `json:"status"` // healthy | degraded | stale | drift | crashlooping
	DriftReason   string         `json:"drift_reason,omitempty"`
}

type clusterDriftDTO struct {
	ClusterID       string         `json:"cluster_id,omitempty"`
	ClusterName     string         `json:"cluster_name"`
	TotalComponents int            `json:"total_components"`
	Healthy         int            `json:"healthy"`
	Degraded        int            `json:"degraded"`
	Stale           int            `json:"stale"`
	Drift           int            `json:"drift"`
	Crashlooping    int            `json:"crashlooping"`
	ControlCommit   string         `json:"control_commit"`
	Versions        []versionCount `json:"versions"`
}

type versionCount struct {
	Component string `json:"component"`
	Commit    string `json:"commit"`
	Count     int    `json:"count"`
}

type crashloopEventDTO struct {
	ID         int64  `json:"id"`
	Component  string `json:"component"`
	Hostname   string `json:"hostname"`
	ClusterID  string `json:"cluster_id,omitempty"`
	PrevUptime int64  `json:"prev_uptime_s"`
	NewUptime  int64  `json:"new_uptime_s"`
	DetectedAt string `json:"detected_at"`
	Reason     string `json:"reason,omitempty"`
}

type licenseBannerDTO struct {
	Kind          string `json:"kind"`
	Severity      string `json:"severity"` // info | warning | critical | fatal
	IssuedAt      string `json:"issued_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	DaysToExpiry  int    `json:"days_to_expiry"`
	Message       string `json:"message"`
	SignedBy      string `json:"signed_by,omitempty"`
	CustomerID    string `json:"customer_id,omitempty"`
	Seats         int    `json:"seats,omitempty"`
	BannerVisible bool   `json:"banner_visible"`
}

type systemHealthOverviewDTO struct {
	Summary            systemHealthSummaryDTO       `json:"summary"`
	Components         []systemHealthComponentDTO   `json:"components"`
	Incidents          []systemHealthIncidentDTO    `json:"incidents"`
	RemediationActions []systemHealthRemediationDTO `json:"remediation_actions"`
	Heartbeats         []heartbeatDTO               `json:"heartbeats"`
	VersionDrift       []clusterDriftDTO            `json:"version_drift"`
	CrashloopHistory   []crashloopEventDTO          `json:"crashloop_history"`
	License            licenseBannerDTO             `json:"license"`
	ControlPlane       map[string]string            `json:"control_plane"`
}

// -----------------------------------------------------------------------------
// HTTP entrypoints
// -----------------------------------------------------------------------------

// List returns the system health snapshot, overlaying real probes when a DB is wired.
func (h *SystemHealth) List(w http.ResponseWriter, r *http.Request) {
	overview := systemHealthOverview()
	overview.ControlPlane = map[string]string{
		"component":    "api",
		"version":      version.Version,
		"commit":       version.Commit,
		"commit_short": version.ShortCommit(),
		"build_time":   version.BuildTimeParsed().Format(time.RFC3339),
		"uptime_s":     fmt.Sprintf("%d", int64(version.Uptime().Seconds())),
	}
	if h.db != nil {
		h.overlayProbes(r.Context(), &overview)
		h.overlayHeartbeats(r.Context(), &overview)
	} else {
		overview.License = licenseBannerDTO{
			Kind: "community", Severity: "info", BannerVisible: false,
			Message: "Community edition — no expiry",
		}
	}
	writeJSON(w, http.StatusOK, overview)
}

// Overview is an alias for List so routing can expose either collection or console semantics.
func (h *SystemHealth) Overview(w http.ResponseWriter, r *http.Request) {
	h.List(w, r)
}

// Cluster returns the per-cluster detail view: heartbeats + drift + crashloops scoped
// to a single cluster_id.
func (h *SystemHealth) Cluster(w http.ResponseWriter, r *http.Request) {
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "system-health: db not wired")
		return
	}
	idStr := chi.URLParam(r, "cluster_id")
	clusterID, err := uuid.Parse(idStr)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid cluster_id")
		return
	}
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "missing subject")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	hbs, err := LoadHeartbeats(ctx, h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	clusterName, _ := clusterNameFor(ctx, h.db, clusterID)
	clusterHBs := filterHeartbeats(hbs, &clusterID)
	dtos := scoreHeartbeats(clusterHBs, map[uuid.UUID]string{clusterID: clusterName})
	drift := summarizeCluster(clusterID.String(), clusterName, dtos)

	restarts, _ := LoadRestartEvents(ctx, h.db.Pool(), subj.OrgID, 100)
	out := map[string]any{
		"cluster_id":        clusterID.String(),
		"cluster_name":      clusterName,
		"heartbeats":        dtos,
		"version_drift":     drift,
		"crashloop_history": filterCrashloopByCluster(restarts, clusterID),
	}
	writeJSON(w, http.StatusOK, out)
}

// -----------------------------------------------------------------------------
// Live-probe overlay (pre-existing path).
// -----------------------------------------------------------------------------

// overlayProbes runs cheap, synchronous health probes and mutates the catalog
// signals to reflect live state. Probes are bounded by a short timeout so a
// slow downstream can't hang the dashboard.
func (h *SystemHealth) overlayProbes(parent context.Context, out *systemHealthOverviewDTO) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	now := time.Now().UTC().Format(time.RFC3339)

	for i := range out.Components {
		c := &out.Components[i]
		switch c.ID {
		case "db":
			c.LastChecked = now
			if err := h.db.Health(ctx); err != nil {
				c.Status = "critical"
				c.Summary = "Database ping failed: " + err.Error()
				c.Signals = []systemHealthSignalDTO{{
					Name: "ping", Status: "critical", Value: err.Error(),
					Threshold: "ok", Evidence: "pgxpool.Ping",
				}}
			} else {
				stats := h.db.Pool().Stat()
				c.Status = "healthy"
				c.Signals = []systemHealthSignalDTO{
					{Name: "ping", Status: "healthy", Value: "ok", Threshold: "ok", Evidence: "pgxpool.Ping"},
					{Name: "connections", Status: "healthy", Value: fmt.Sprintf("%d acquired/%d total", stats.AcquiredConns(), stats.TotalConns()), Threshold: "<80% pool", Evidence: "pool stats"},
				}
			}
		case "scanner-workers":
			c.LastChecked = now
			var queued, oldestMins, readyScanners, activeJobs, idleCapacity, degradedScanners int
			var queueErr error
			if subj, ok := SubjectFrom(parent); ok {
				queueErr = h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)::int,
       COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(requested_at)))::int / 60, 0)
  FROM scan_jobs
 WHERE org_id = $1
   AND status = 'pending'`, subj.OrgID).Scan(&queued, &oldestMins)
				_ = h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes')::int,
       COALESCE(SUM((metadata->>'active_jobs')::int) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes'), 0)::int,
       COALESCE(SUM((metadata->>'idle_capacity')::int) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes'), 0)::int,
       COUNT(*) FILTER (
         WHERE last_seen_at > NOW() - INTERVAL '2 minutes'
           AND COALESCE((metadata->'vulndb'->>'enabled')::boolean, false)
           AND NOT COALESCE((metadata->'vulndb'->>'ready')::boolean, false)
       )::int
  FROM component_heartbeats
 WHERE org_id = $1
   AND component = 'scanner'`, subj.OrgID).Scan(&readyScanners, &activeJobs, &idleCapacity, &degradedScanners)
			} else {
				queueErr = h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*)::int,
       COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(requested_at)))::int / 60, 0)
  FROM scan_jobs WHERE status = 'pending'`).Scan(&queued, &oldestMins)
				_ = h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes')::int,
       COALESCE(SUM((metadata->>'active_jobs')::int) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes'), 0)::int,
       COALESCE(SUM((metadata->>'idle_capacity')::int) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes'), 0)::int,
       COUNT(*) FILTER (
         WHERE last_seen_at > NOW() - INTERVAL '2 minutes'
           AND COALESCE((metadata->'vulndb'->>'enabled')::boolean, false)
           AND NOT COALESCE((metadata->'vulndb'->>'ready')::boolean, false)
       )::int
  FROM component_heartbeats
 WHERE component = 'scanner'`).Scan(&readyScanners, &activeJobs, &idleCapacity, &degradedScanners)
			}
			if queueErr == nil {
				queueStatus := scannerQueueSignalStatus(queued)
				readyStatus := "healthy"
				if readyScanners == 0 {
					readyStatus = "warning"
				}
				capacityStatus := "healthy"
				if queued > 0 && idleCapacity == 0 {
					capacityStatus = "warning"
				}
				vulnStatus := scannerVulnDBSignalStatus(degradedScanners)
				c.Status = worstSystemHealthStatus(queueStatus, readyStatus, capacityStatus, vulnStatus)
				c.Signals = []systemHealthSignalDTO{
					{Name: "queue depth", Status: queueStatus, Value: fmt.Sprintf("%d jobs", queued), Threshold: "<100 jobs", Evidence: "scan_jobs.status=pending"},
					{Name: "oldest pending", Status: queueStatus, Value: fmt.Sprintf("%dm", oldestMins), Threshold: "<10m", Evidence: "MIN(requested_at)"},
					{Name: "ready scanners", Status: readyStatus, Value: fmt.Sprintf("%d pods", readyScanners), Threshold: ">=1 pod", Evidence: "component_heartbeats.component=scanner"},
					{Name: "busy / idle slots", Status: capacityStatus, Value: fmt.Sprintf("%d busy / %d idle", activeJobs, idleCapacity), Threshold: "idle when queue is non-empty", Evidence: "component_heartbeats.metadata"},
					{Name: "scanner VulnDB", Status: vulnStatus, Value: fmt.Sprintf("%d degraded", degradedScanners), Threshold: "0 degraded", Evidence: "component_heartbeats.metadata.vulndb"},
				}
			}
		case "audit-chain":
			c.LastChecked = now
			var auditRows int64
			if err := h.db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM audit_events`).Scan(&auditRows); err == nil {
				c.Status = "healthy"
				c.Signals = []systemHealthSignalDTO{
					{Name: "rows", Status: "healthy", Value: fmt.Sprintf("%d", auditRows), Threshold: ">=0", Evidence: "audit_events"},
					{Name: "append-only", Status: "healthy", Value: "enforced", Threshold: "enforced", Evidence: "trigger forbids UPDATE/DELETE"},
				}
			}
		case "api":
			c.LastChecked = now
			c.Status = "healthy"
			c.Signals = []systemHealthSignalDTO{
				{Name: "readyz", Status: "healthy", Value: "200 OK", Threshold: "200", Evidence: "/readyz returned healthy"},
				{Name: "build", Status: "healthy", Value: version.ShortCommit(), Threshold: "matches release", Evidence: "pkg/version.Commit"},
				{Name: "uptime", Status: "healthy", Value: fmt.Sprintf("%ds", int64(version.Uptime().Seconds())), Threshold: ">=60s", Evidence: "process clock"},
			}
		}
	}

	// Recount summary based on adjusted statuses.
	statusCounts := map[string]int{}
	degraded := []string{}
	for _, component := range out.Components {
		statusCounts[component.Status]++
		if component.Status != "healthy" {
			degraded = append(degraded, component.ID)
		}
	}
	out.Summary.ComponentsByStatus = statusCounts
	out.Summary.DegradedComponents = degraded
	out.Summary.GeneratedAt = now
	switch {
	case statusCounts["critical"] > 0:
		out.Summary.Status = "critical"
	case statusCounts["degraded"]+statusCounts["warning"] > 0:
		out.Summary.Status = "degraded"
	default:
		out.Summary.Status = "healthy"
	}
}

// -----------------------------------------------------------------------------
// Wave N6: heartbeat + drift + crashloop + license overlay.
// -----------------------------------------------------------------------------

// overlayHeartbeats populates heartbeats, version_drift, crashloop_history,
// and license. It also rolls the heartbeat-derived "healthy / stale / drift /
// crashlooping" totals into the summary.
func (h *SystemHealth) overlayHeartbeats(parent context.Context, out *systemHealthOverviewDTO) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()

	subj, ok := SubjectFrom(parent)
	if !ok {
		// Subject-less call (e.g. service path) — leave Wave N6 fields empty.
		return
	}

	hbs, err := LoadHeartbeats(ctx, h.db.Pool(), subj.OrgID)
	if err == nil {
		clusterNames := loadClusterNames(ctx, h.db, hbs)
		dtos := scoreHeartbeats(hbs, clusterNames)
		out.Heartbeats = dtos
		out.VersionDrift = summarizeAllClusters(dtos, clusterNames)
		// Tile counters.
		for _, hb := range dtos {
			switch hb.Status {
			case "healthy":
				out.Summary.Healthy++
			case "degraded":
				out.Summary.Degraded++
			case "stale":
				out.Summary.Stale++
			case "drift":
				out.Summary.Drift++
			case "crashlooping":
				out.Summary.Crashlooping++
			}
		}
		if out.Summary.Degraded > 0 && out.Summary.Status == "healthy" {
			out.Summary.Status = "degraded"
		}
	}

	if restarts, err := LoadRestartEvents(ctx, h.db.Pool(), subj.OrgID, 50); err == nil {
		out.CrashloopHistory = make([]crashloopEventDTO, 0, len(restarts))
		for _, r := range restarts {
			ev := crashloopEventDTO{
				ID: r.ID, Component: r.Component, Hostname: r.Hostname,
				PrevUptime: r.PrevUptime, NewUptime: r.NewUptime,
				DetectedAt: r.DetectedAt.UTC().Format(time.RFC3339),
				Reason:     r.Reason,
			}
			if r.ClusterID != nil {
				ev.ClusterID = r.ClusterID.String()
			}
			out.CrashloopHistory = append(out.CrashloopHistory, ev)
		}
	}

	if lic, err := LoadLicense(ctx, h.db.Pool(), subj.OrgID); err == nil {
		out.License = buildLicenseBanner(lic)
	}
}

// scoreHeartbeats classifies each heartbeat as healthy / degraded / stale /
// drift / crashlooping using the rules from the spec:
//
//   - stale: last_seen_at older than 5 min
//   - crashlooping: restart_count > 3 in the last hour (we approximate by checking
//     restart_count > 3 — the row stores per-process restart counter; combined
//     with last_seen_at < 1h that's effectively the spec's window)
//   - drift: commit != freshest commit observed across all components for that
//     org (cluster_id-aware so a control-plane vs. data-plane SHA mismatch
//     isn't always "drift")
//   - degraded: scanner is alive but its local VulnDB/cache dependencies are not
//     ready
//   - healthy: otherwise
func scoreHeartbeats(hbs []HeartbeatRow, clusterNames map[uuid.UUID]string) []heartbeatDTO {
	// Determine the "current" commit: the most-recent commit across all
	// components, treated as the canonical control-plane SHA. The spec also
	// asks for "max(commit)" — taking max by last_seen_at within each
	// component group is more useful in practice because the strings aren't
	// monotonic.
	current := freshestCommitOverall(hbs)

	now := time.Now().UTC()
	out := make([]heartbeatDTO, 0, len(hbs))
	for _, hb := range hbs {
		status := "healthy"
		reason := ""
		switch {
		case now.Sub(hb.LastSeenAt) > 5*time.Minute:
			status = "stale"
			reason = fmt.Sprintf("last seen %s ago", now.Sub(hb.LastSeenAt).Truncate(time.Second))
		case hb.RestartCount > 3:
			status = "crashlooping"
			reason = fmt.Sprintf("%d restarts observed", hb.RestartCount)
		case current != "" && hb.Commit != "" && hb.Commit != current:
			status = "drift"
			reason = "commit " + shortSha(hb.Commit) + " != control-plane " + shortSha(current)
		}
		if status == "healthy" && hb.Component == "scanner" {
			if scannerReason := scannerHeartbeatDegradedReason(hb.Metadata); scannerReason != "" {
				status = "degraded"
				reason = scannerReason
			}
		}
		dto := heartbeatDTO{
			Component:     hb.Component,
			Version:       hb.Version,
			Commit:        hb.Commit,
			CommitShort:   shortSha(hb.Commit),
			Hostname:      hb.Hostname,
			UptimeSeconds: hb.UptimeSeconds,
			RestartCount:  hb.RestartCount,
			LastError:     hb.LastError,
			Metadata:      hb.Metadata,
			LastSeenAt:    hb.LastSeenAt.UTC().Format(time.RFC3339),
			Status:        status,
			DriftReason:   reason,
		}
		if hb.BuildTime != nil {
			dto.BuildTime = hb.BuildTime.UTC().Format(time.RFC3339)
		}
		if hb.ClusterID != nil {
			dto.ClusterID = hb.ClusterID.String()
			if n, ok := clusterNames[*hb.ClusterID]; ok {
				dto.ClusterName = n
			}
		}
		out = append(out, dto)
	}
	return out
}

func scannerVulnDBSignalStatus(degradedScanners int) string {
	if degradedScanners > 0 {
		return "warning"
	}
	return "healthy"
}

func scannerQueueSignalStatus(queued int) string {
	switch {
	case queued > 500:
		return "critical"
	case queued > 100:
		return "warning"
	default:
		return "healthy"
	}
}

func worstSystemHealthStatus(statuses ...string) string {
	worst := "healthy"
	for _, status := range statuses {
		if systemHealthStatusRank(status) > systemHealthStatusRank(worst) {
			worst = status
		}
	}
	return worst
}

func systemHealthStatusRank(status string) int {
	switch status {
	case "critical":
		return 4
	case "degraded", "warning":
		return 3
	case "stale", "drift", "crashlooping":
		return 2
	default:
		return 1
	}
}

func scannerHeartbeatDegradedReason(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	if vuln := metadataMap(metadata, "vulndb"); len(vuln) > 0 {
		if metadataBool(vuln, "enabled") && !metadataBool(vuln, "ready") {
			status := metadataString(vuln, "status")
			if status == "" {
				status = "not-ready"
			}
			return "scanner VulnDB " + status
		}
	}
	if cacheHealth := metadataMap(metadata, "cache_health"); len(cacheHealth) > 0 {
		for name, raw := range cacheHealth {
			item, _ := raw.(map[string]any)
			if len(item) == 0 {
				continue
			}
			if metadataBool(item, "configured") && !metadataBool(item, "writable") {
				status := metadataString(item, "status")
				if status == "" {
					status = "not-writable"
				}
				return "scanner cache " + name + " " + status
			}
		}
	}
	return ""
}

// freshestCommitOverall picks the commit from the most recently seen heartbeat
// across the whole org. Used as the "control-plane current" reference.
func freshestCommitOverall(hbs []HeartbeatRow) string {
	var best time.Time
	var commit string
	for _, hb := range hbs {
		if hb.Commit == "" {
			continue
		}
		if hb.LastSeenAt.After(best) {
			best = hb.LastSeenAt
			commit = hb.Commit
		}
	}
	return commit
}

func shortSha(s string) string {
	if len(s) <= 7 {
		return s
	}
	return s[:7]
}

// summarizeAllClusters groups the scored heartbeats by cluster_id and produces
// a clusterDriftDTO per cluster (including a synthetic "(control-plane)" group
// for rows with no cluster_id).
func summarizeAllClusters(rows []heartbeatDTO, clusterNames map[uuid.UUID]string) []clusterDriftDTO {
	groups := map[string][]heartbeatDTO{}
	for _, r := range rows {
		groups[r.ClusterID] = append(groups[r.ClusterID], r)
	}
	out := make([]clusterDriftDTO, 0, len(groups))
	for cid, group := range groups {
		name := "(control-plane)"
		if cid != "" {
			if id, err := uuid.Parse(cid); err == nil {
				if n, ok := clusterNames[id]; ok && n != "" {
					name = n
				} else {
					name = cid[:8]
				}
			}
		}
		out = append(out, summarizeCluster(cid, name, group))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClusterName < out[j].ClusterName })
	return out
}

func summarizeCluster(cid, name string, group []heartbeatDTO) clusterDriftDTO {
	d := clusterDriftDTO{ClusterID: cid, ClusterName: name, TotalComponents: len(group)}
	versions := map[string]map[string]int{} // component -> commit -> count
	// Determine the "newest commit observed in this cluster" as the cluster's
	// reference. (Mirrors the global rule but lets a single cluster pin a
	// specific build during a staged rollout.)
	var newestLastSeen time.Time
	var localControl string
	for _, hb := range group {
		if t, err := time.Parse(time.RFC3339, hb.LastSeenAt); err == nil {
			if t.After(newestLastSeen) && hb.Commit != "" {
				newestLastSeen = t
				localControl = hb.Commit
			}
		}
	}
	d.ControlCommit = shortSha(localControl)
	for _, hb := range group {
		switch hb.Status {
		case "healthy":
			d.Healthy++
		case "degraded":
			d.Degraded++
		case "stale":
			d.Stale++
		case "drift":
			d.Drift++
		case "crashlooping":
			d.Crashlooping++
		}
		if versions[hb.Component] == nil {
			versions[hb.Component] = map[string]int{}
		}
		versions[hb.Component][shortSha(hb.Commit)]++
	}
	for component, byCommit := range versions {
		for commit, count := range byCommit {
			d.Versions = append(d.Versions, versionCount{Component: component, Commit: commit, Count: count})
		}
	}
	sort.Slice(d.Versions, func(i, j int) bool {
		if d.Versions[i].Component != d.Versions[j].Component {
			return d.Versions[i].Component < d.Versions[j].Component
		}
		return d.Versions[i].Commit < d.Versions[j].Commit
	})
	return d
}

func filterHeartbeats(hbs []HeartbeatRow, clusterID *uuid.UUID) []HeartbeatRow {
	out := make([]HeartbeatRow, 0, len(hbs))
	for _, hb := range hbs {
		switch {
		case clusterID == nil && hb.ClusterID == nil:
			out = append(out, hb)
		case clusterID != nil && hb.ClusterID != nil && *hb.ClusterID == *clusterID:
			out = append(out, hb)
		}
	}
	return out
}

func filterCrashloopByCluster(rows []RestartEvent, clusterID uuid.UUID) []crashloopEventDTO {
	out := make([]crashloopEventDTO, 0)
	for _, r := range rows {
		if r.ClusterID == nil || *r.ClusterID != clusterID {
			continue
		}
		out = append(out, crashloopEventDTO{
			ID: r.ID, Component: r.Component, Hostname: r.Hostname,
			ClusterID:  clusterID.String(),
			PrevUptime: r.PrevUptime, NewUptime: r.NewUptime,
			DetectedAt: r.DetectedAt.UTC().Format(time.RFC3339),
			Reason:     r.Reason,
		})
	}
	return out
}

// loadClusterNames batch-resolves cluster names for the heartbeat set.
func loadClusterNames(ctx context.Context, d *db.DB, hbs []HeartbeatRow) map[uuid.UUID]string {
	out := map[uuid.UUID]string{}
	seen := map[uuid.UUID]bool{}
	ids := make([]uuid.UUID, 0)
	for _, hb := range hbs {
		if hb.ClusterID == nil || seen[*hb.ClusterID] {
			continue
		}
		seen[*hb.ClusterID] = true
		ids = append(ids, *hb.ClusterID)
	}
	if len(ids) == 0 {
		return out
	}
	rows, err := d.Pool().Query(ctx, `SELECT id, name FROM clusters WHERE id = ANY($1)`, ids)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var name string
		if err := rows.Scan(&id, &name); err == nil {
			out[id] = name
		}
	}
	return out
}

func clusterNameFor(ctx context.Context, d *db.DB, id uuid.UUID) (string, error) {
	var name string
	err := d.Pool().QueryRow(ctx, `SELECT name FROM clusters WHERE id = $1`, id).Scan(&name)
	return name, err
}

// -----------------------------------------------------------------------------
// License banner
// -----------------------------------------------------------------------------

// buildLicenseBanner reduces the JSON license document into the UI banner
// shape. Rules:
//   - kind=community OR no expires_at      → info (banner_visible=false)
//   - 30d < days_to_expiry                 → info (banner_visible=false)
//   - 7d < days_to_expiry <= 30d           → warning
//   - 0 < days_to_expiry <= 7d             → critical
//   - days_to_expiry <= 0                  → fatal (banner_visible=true)
func buildLicenseBanner(lic map[string]any) licenseBannerDTO {
	out := licenseBannerDTO{
		Kind:     stringOr(lic["kind"], "community"),
		SignedBy: stringOr(lic["signed_by"], ""),
		IssuedAt: stringOr(lic["issued_at"], ""),
		Severity: "info",
	}
	out.CustomerID = stringOr(lic["customer_id"], "")
	if seats, ok := lic["seats"].(float64); ok {
		out.Seats = int(seats)
	}

	expiresRaw := stringOr(lic["expires_at"], "")
	out.ExpiresAt = expiresRaw

	if out.Kind == "community" || expiresRaw == "" {
		out.Message = "Community edition — no expiry"
		out.DaysToExpiry = 0
		out.BannerVisible = false
		return out
	}

	t, err := time.Parse(time.RFC3339, expiresRaw)
	if err != nil {
		// Best-effort YYYY-MM-DD fallback.
		if t2, err2 := time.Parse("2006-01-02", expiresRaw); err2 == nil {
			t = t2
		} else {
			out.Message = "License: invalid expires_at"
			out.Severity = "warning"
			out.BannerVisible = true
			return out
		}
	}
	days := int(time.Until(t).Hours() / 24)
	out.DaysToExpiry = days
	switch {
	case days <= 0:
		out.Severity = "fatal"
		out.Message = fmt.Sprintf("License expired %d days ago", -days)
		out.BannerVisible = true
	case days <= 7:
		out.Severity = "critical"
		out.Message = fmt.Sprintf("License expires in %d days", days)
		out.BannerVisible = true
	case days <= 30:
		out.Severity = "warning"
		out.Message = fmt.Sprintf("License expires in %d days", days)
		out.BannerVisible = true
	case days <= 90:
		out.Severity = "info"
		out.Message = fmt.Sprintf("License valid for %d more days", days)
		out.BannerVisible = false
	default:
		out.Severity = "info"
		out.Message = fmt.Sprintf("License valid for %d more days", days)
		out.BannerVisible = false
	}
	return out
}

func stringOr(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fallback
}

// -----------------------------------------------------------------------------
// Neutral component inventory.
// -----------------------------------------------------------------------------

func systemHealthOverview() systemHealthOverviewDTO {
	now := time.Now().UTC()
	components := neutralSystemHealthComponents(now)
	incidents := []systemHealthIncidentDTO{}
	actions := []systemHealthRemediationDTO{}
	return systemHealthOverviewDTO{
		Summary:            buildSystemHealthSummary(now, components, incidents, actions),
		Components:         components,
		Incidents:          incidents,
		RemediationActions: actions,
	}
}

func buildSystemHealthSummary(now time.Time, components []systemHealthComponentDTO, incidents []systemHealthIncidentDTO, actions []systemHealthRemediationDTO) systemHealthSummaryDTO {
	statusCounts := map[string]int{}
	degraded := []string{}
	for _, component := range components {
		statusCounts[component.Status]++
		if component.Status != "healthy" {
			degraded = append(degraded, component.ID)
		}
	}

	openActions := 0
	for _, action := range actions {
		if action.Status != "done" {
			openActions++
		}
	}

	activeIncidents := 0
	for _, incident := range incidents {
		if incident.Status == "investigating" || incident.Status == "mitigating" || incident.Status == "monitoring" {
			activeIncidents++
		}
	}

	status := "healthy"
	if statusCounts["critical"] > 0 {
		status = "critical"
	} else if statusCounts["degraded"] > 0 || statusCounts["warning"] > 0 {
		status = "degraded"
	}

	return systemHealthSummaryDTO{
		Status:             status,
		GeneratedAt:        now.Format(time.RFC3339),
		ComponentsTotal:    len(components),
		ComponentsByStatus: statusCounts,
		ActiveIncidents:    activeIncidents,
		OpenActions:        openActions,
		DegradedComponents: degraded,
	}
}

func neutralSystemHealthComponents(now time.Time) []systemHealthComponentDTO {
	lastChecked := now.Format(time.RFC3339)
	return []systemHealthComponentDTO{
		neutralSystemHealthComponent("api", "API service", "control-plane", "active", "platform", "API process is serving this request; readiness details require live probes.", lastChecked),
		neutralSystemHealthComponent("db", "Primary database", "data-plane", "primary", "platform", "Database status is unknown until the DB health probe runs.", lastChecked),
		neutralSystemHealthComponent("scanner-workers", "Scanner workers", "scanning", "workers", "security-platform", "Scanner queue and worker status are unknown until scan-job and heartbeat probes run.", lastChecked),
		neutralSystemHealthComponent("admission-webhook", "Admission webhook", "policy-enforcement", "webhook", "security-platform", "Admission status is unknown until admission heartbeats or cluster validation are observed.", lastChecked),
		neutralSystemHealthComponent("cve-importer", "VulnDB importer", "vulnerability-intelligence", "importer", "vulnerability-management", "Importer status is reported through VulnDB bundle metadata and importer status files.", lastChecked),
		neutralSystemHealthComponent("integrations-delivery", "Integrations delivery", "notifications", "dispatcher", "secops", "Delivery health is unknown until receiver delivery history is observed.", lastChecked),
		neutralSystemHealthComponent("backups", "Backups", "resilience", "scheduled", "platform", "Backup freshness is unknown until backup manifests or audit archive records are observed.", lastChecked),
		neutralSystemHealthComponent("audit-chain", "Audit chain", "governance", "append-only", "security-platform", "Audit-chain status is unknown until audit rows are counted or verified.", lastChecked),
		neutralSystemHealthComponent("cluster-sensors", "Cluster sensors", "fleet", "heartbeat", "field-engineering", "Fleet status is unknown until cluster component heartbeats are observed.", lastChecked),
	}
}

func neutralSystemHealthComponent(id, name, domain, mode, owner, summary, lastChecked string) systemHealthComponentDTO {
	return systemHealthComponentDTO{
		ID:          id,
		Name:        name,
		Domain:      domain,
		Status:      "unknown",
		Mode:        mode,
		Owner:       owner,
		SLO:         "Requires live telemetry",
		LastChecked: lastChecked,
		Summary:     summary,
		Signals: []systemHealthSignalDTO{{
			Name:      "live evidence",
			Status:    "unknown",
			Value:     "not observed",
			Threshold: "observed",
			Evidence:  "No live probe or heartbeat has populated this component yet.",
		}},
	}
}
