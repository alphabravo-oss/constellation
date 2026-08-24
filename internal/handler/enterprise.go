package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type Enterprise struct {
	db          *db.DB
	audit       *audit.Logger
	customRoles *CustomRoles
}

func NewEnterprise(database ...*db.DB) *Enterprise {
	var d *db.DB
	if len(database) > 0 {
		d = database[0]
	}
	return &Enterprise{db: d}
}

func (h *Enterprise) WithAudit(a *audit.Logger) *Enterprise {
	h.audit = a
	return h
}

func (h *Enterprise) WithCustomRoles(customRoles *CustomRoles) *Enterprise {
	h.customRoles = customRoles
	return h
}

type runtimeEventEvidenceDTO struct {
	ID               string   `json:"id"`
	At               string   `json:"at"`
	ClusterID        string   `json:"cluster_id"`
	ClusterName      string   `json:"cluster_name,omitempty"`
	WorkloadID       string   `json:"workload_id"`
	RuleID           string   `json:"rule_id,omitempty"`
	RuleName         string   `json:"rule_name,omitempty"`
	Source           string   `json:"source"`
	Kind             string   `json:"kind"`
	Severity         string   `json:"severity"`
	Verdict          string   `json:"verdict"`
	AttackTechniques []string `json:"attack_techniques"`
	Message          string   `json:"message"`
}

type runtimeWorkloadEvidenceDTO struct {
	WorkloadID      string   `json:"workload_id"`
	Events          int      `json:"events"`
	Alerts          int      `json:"alerts"`
	Blocks          int      `json:"blocks"`
	HighestSeverity string   `json:"highest_severity"`
	LastSeenAt      string   `json:"last_seen_at"`
	Sources         []string `json:"sources"`
	Techniques      []string `json:"techniques"`
}

type runtimeEvidenceSummaryDTO struct {
	WindowHours       int `json:"window_hours"`
	Events            int `json:"events"`
	Alerts            int `json:"alerts"`
	Blocks            int `json:"blocks"`
	Quarantines       int `json:"quarantines"`
	AffectedWorkloads int `json:"affected_workloads"`
	Techniques        int `json:"techniques"`
}

type runtimeRuleOverviewDTO struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Source            string   `json:"source"`
	Severity          string   `json:"severity"`
	Techniques        []string `json:"techniques"`
	Mode              string   `json:"mode"`
	EventCount        int      `json:"event_count"`
	AffectedWorkloads int      `json:"affected_workloads"`
	LastTriggeredAt   string   `json:"last_triggered_at,omitempty"`
}

func (h *Enterprise) RuntimeOverview(w http.ResponseWriter, r *http.Request) {
	out := runtimeOverviewCatalog()
	out["summary"] = runtimeEvidenceSummaryDTO{WindowHours: runtimeWindowHours(r)}
	out["recent_events"] = []runtimeEventEvidenceDTO{}
	out["workloads"] = []runtimeWorkloadEvidenceDTO{}
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.db != nil {
		if subj, ok := SubjectFrom(r.Context()); ok {
			if err := h.attachRuntimeEvidence(r, out, subj.OrgID.String(), clusterArg); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func runtimeOverviewCatalog() map[string]any {
	return map[string]any{
		"modes": []map[string]any{
			{"id": "learn", "label": "Learn", "blocks": false, "description": "Observe process, endpoint, and network behavior without alerting."},
			{"id": "monitor", "label": "Monitor", "blocks": false, "description": "Alert on baseline, WAF, DLP, Falco, and network-policy drift without blocking."},
			{"id": "enforce", "label": "Enforce", "blocks": true, "description": "Block promoted WAF/DLP/network/process violations and audit every promotion."},
		},
		"subsystems": []map[string]any{
			{"id": "falco", "name": "Falco rules", "status": "ready", "mode": "monitor", "evidence": "YAML parser and evaluator with ATT&CK mapping."},
			{"id": "mitre", "name": "MITRE ATT&CK mapping", "status": "ready", "mode": "monitor", "evidence": "Runtime events map to technique IDs and tactics."},
			{"id": "baseline", "name": "Process and endpoint baselines", "status": "ready", "mode": "learn", "evidence": "Learn -> Monitor -> Enforce lifecycle implemented."},
			{"id": "netpolicy", "name": "Network policy elevation", "status": "ready", "mode": "learn", "evidence": "Observed flows generate Cilium, Calico, and Kubernetes NetworkPolicy."},
			{"id": "forensics", "name": "Forensics snapshot", "status": "ready-kernel-free", "mode": "monitor", "evidence": "Kubernetes events, logs, pod spec, and recent flows capture envelope."},
			{"id": "waf", "name": "WAF inline enforcement", "status": "linux-agent-gated", "mode": "learn", "evidence": "Requires privileged Linux NFQUEUE datapath for GA."},
			{"id": "dlp", "name": "DLP inline enforcement", "status": "linux-agent-gated", "mode": "learn", "evidence": "Requires privileged Linux NFQUEUE datapath for GA."},
			{"id": "ebpf", "name": "eBPF telemetry", "status": "linux-agent-gated", "mode": "learn", "evidence": "Requires Linux kernel/capabilities; not buildable on macOS."},
		},
		"rules": []runtimeRuleOverviewDTO{
			{ID: "container-process-shell", Name: "Terminal shell in container", Source: "Falco", Severity: "high", Techniques: []string{"T1059.004"}, Mode: "monitor"},
			{ID: "network-unauthorized-egress", Name: "Outbound HTTP to unapproved external service", Source: "Network baseline", Severity: "high", Techniques: []string{"T1105"}, Mode: "monitor"},
			{ID: "endpoint-baseline-new-api", Name: "New API endpoint outside learned baseline", Source: "Endpoint baseline", Severity: "medium", Techniques: []string{"T1190"}, Mode: "monitor"},
			{ID: "dlp-secret-exfiltration", Name: "Sensitive-data exfiltration pattern", Source: "DLP", Severity: "critical", Techniques: []string{"T1041"}, Mode: "learn"},
			{ID: "waf-sql-injection", Name: "SQL injection payload", Source: "WAF", Severity: "critical", Techniques: []string{"T1190"}, Mode: "learn"},
		},
	}
}

func runtimeWindowHours(r *http.Request) int {
	hours := 24
	if raw := r.URL.Query().Get("hours"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 168 {
			hours = parsed
		}
	}
	return hours
}

func (h *Enterprise) attachRuntimeEvidence(r *http.Request, out map[string]any, orgID string, clusterArg any) error {
	hours := runtimeWindowHours(r)
	var summary runtimeEvidenceSummaryDTO
	if err := h.db.Pool().QueryRow(r.Context(), `
WITH scoped AS (
    SELECT *
      FROM events
     WHERE org_id = $1
       AND at >= NOW() - ($2::text || ' hours')::interval
       AND ($3::uuid IS NULL OR cluster_id = $3)
)
SELECT COUNT(*)::int,
       COUNT(*) FILTER (WHERE verdict IN ('alert','block','quarantine'))::int,
       COUNT(*) FILTER (WHERE verdict = 'block')::int,
       COUNT(*) FILTER (WHERE verdict = 'quarantine')::int,
       COUNT(DISTINCT workload_id)::int,
       COALESCE((SELECT COUNT(DISTINCT technique)::int FROM scoped, LATERAL unnest(attack_techniques) AS technique), 0)
  FROM scoped`, orgID, strconv.Itoa(hours), clusterArg).
		Scan(&summary.Events, &summary.Alerts, &summary.Blocks, &summary.Quarantines, &summary.AffectedWorkloads, &summary.Techniques); err != nil {
		return err
	}
	summary.WindowHours = hours
	out["summary"] = summary

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT e.id::text, e.at, e.cluster_id::text, COALESCE(c.name, ''), e.workload_id,
       COALESCE(e.payload->>'rule_id', ''), COALESCE(e.payload->>'rule_name', ''),
       e.source, e.kind,
       e.severity, e.verdict, e.attack_techniques, COALESCE(e.payload->>'message', e.payload->>'summary', '')
  FROM events e
  LEFT JOIN clusters c ON c.id = e.cluster_id
 WHERE e.org_id = $1
   AND e.at >= NOW() - ($2::text || ' hours')::interval
   AND ($3::uuid IS NULL OR e.cluster_id = $3)
 ORDER BY e.at DESC
 LIMIT 20`, orgID, strconv.Itoa(hours), clusterArg)
	if err != nil {
		return err
	}
	defer rows.Close()
	events := []runtimeEventEvidenceDTO{}
	for rows.Next() {
		var item runtimeEventEvidenceDTO
		var at time.Time
		if err := rows.Scan(&item.ID, &at, &item.ClusterID, &item.ClusterName, &item.WorkloadID, &item.RuleID, &item.RuleName, &item.Source, &item.Kind, &item.Severity, &item.Verdict, &item.AttackTechniques, &item.Message); err != nil {
			return err
		}
		item.At = at.UTC().Format(time.RFC3339)
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out["recent_events"] = events

	workloadRows, err := h.db.Pool().Query(r.Context(), `
SELECT workload_id,
       COUNT(DISTINCT id)::int,
       COUNT(DISTINCT id) FILTER (WHERE verdict IN ('alert','block','quarantine'))::int,
       COUNT(DISTINCT id) FILTER (WHERE verdict = 'block')::int,
       CASE MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
            WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' WHEN 1 THEN 'low' ELSE 'info' END,
       MAX(at),
       ARRAY_REMOVE(ARRAY_AGG(DISTINCT source), NULL),
       ARRAY_REMOVE(ARRAY_AGG(DISTINCT technique), NULL)
  FROM events
  LEFT JOIN LATERAL unnest(attack_techniques) AS technique ON TRUE
 WHERE org_id = $1
   AND at >= NOW() - ($2::text || ' hours')::interval
   AND ($3::uuid IS NULL OR cluster_id = $3)
 GROUP BY workload_id
 ORDER BY COUNT(DISTINCT id) FILTER (WHERE verdict IN ('alert','block','quarantine')) DESC, COUNT(DISTINCT id) DESC, workload_id
 LIMIT 10`, orgID, strconv.Itoa(hours), clusterArg)
	if err != nil {
		return err
	}
	defer workloadRows.Close()
	workloads := []runtimeWorkloadEvidenceDTO{}
	for workloadRows.Next() {
		var item runtimeWorkloadEvidenceDTO
		var last time.Time
		if err := workloadRows.Scan(&item.WorkloadID, &item.Events, &item.Alerts, &item.Blocks, &item.HighestSeverity, &last, &item.Sources, &item.Techniques); err != nil {
			return err
		}
		item.LastSeenAt = last.UTC().Format(time.RFC3339)
		workloads = append(workloads, item)
	}
	if err := workloadRows.Err(); err != nil {
		return err
	}
	out["workloads"] = workloads
	if err := h.attachRuntimeRuleEvidence(r, out, orgID, hours, clusterArg); err != nil {
		return err
	}
	return nil
}

func (h *Enterprise) attachRuntimeRuleEvidence(r *http.Request, out map[string]any, orgID string, hours int, clusterArg any) error {
	rules, ok := out["rules"].([]runtimeRuleOverviewDTO)
	if !ok {
		return nil
	}
	byID := map[string]int{}
	for i := range rules {
		byID[rules[i].ID] = i
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT payload->>'rule_id' AS rule_id,
       COUNT(*)::int,
       COUNT(DISTINCT workload_id)::int,
       MAX(at)
  FROM events
 WHERE org_id = $1
   AND at >= NOW() - ($2::text || ' hours')::interval
   AND COALESCE(payload->>'rule_id', '') <> ''
   AND ($3::uuid IS NULL OR cluster_id = $3)
 GROUP BY payload->>'rule_id'`, orgID, strconv.Itoa(hours), clusterArg)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var ruleID string
		var count, workloads int
		var last time.Time
		if err := rows.Scan(&ruleID, &count, &workloads, &last); err != nil {
			return err
		}
		idx, ok := byID[ruleID]
		if !ok {
			continue
		}
		rules[idx].EventCount = count
		rules[idx].AffectedWorkloads = workloads
		rules[idx].LastTriggeredAt = last.UTC().Format(time.RFC3339)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	out["rules"] = rules
	return nil
}

func (h *Enterprise) Integrations(w http.ResponseWriter, r *http.Request) {
	out := emptyIntegrationsOverview()
	if h.db != nil {
		subj, ok := SubjectFrom(r.Context())
		if !ok {
			jsonError(w, http.StatusUnauthorized, "no subject")
			return
		}
		rows, err := h.db.Pool().Query(r.Context(), `
SELECT id::text, name, kind, status FROM receivers WHERE org_id = $1 ORDER BY name`, subj.OrgID)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		defer rows.Close()
		recvs := []map[string]any{}
		for rows.Next() {
			var id, name, kind, status string
			if err := rows.Scan(&id, &name, &kind, &status); err != nil {
				jsonError(w, http.StatusInternalServerError, err.Error())
				return
			}
			recvs = append(recvs, map[string]any{
				"id": id, "name": name, "kind": kind, "status": status, "testable": true,
			})
		}
		if err := rows.Err(); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out["receivers"] = recvs

		var routingYAML string
		var revision int
		var updatedAt time.Time
		if err := h.db.Pool().QueryRow(r.Context(),
			`SELECT yaml, revision, updated_at FROM routing_configs WHERE org_id = $1`, subj.OrgID).Scan(&routingYAML, &revision, &updatedAt); err == nil && strings.TrimSpace(routingYAML) != "" {
			if routing, ok := out["routing"].(map[string]any); ok {
				routing["status"] = "configured"
				routing["yaml_present"] = true
				routing["yaml_bytes"] = len(routingYAML)
				routing["revision"] = revision
				routing["updated_at"] = updatedAt.UTC().Format(time.RFC3339)
			}
		}
		h.overlayOrgSettings(r.Context(), subj.OrgID, "integrations", out)
	}
	writeJSON(w, http.StatusOK, out)
}

func emptyIntegrationsOverview() map[string]any {
	return map[string]any{
		"receivers": []map[string]any{},
		"routing": map[string]any{
			"status":        "not-configured",
			"group_by":      []string{},
			"inhibition":    "",
			"default_route": "",
			"yaml_present":  false,
			"yaml_bytes":    0,
		},
		"report_jobs": []map[string]any{},
	}
}

func (h *Enterprise) MigrationSources(w http.ResponseWriter, r *http.Request) {
	out := defaultMigrationSources()
	if h.db != nil {
		if subj, ok := SubjectFrom(r.Context()); ok {
			h.overlayOrgSettings(r.Context(), subj.OrgID, "migration", out)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func defaultMigrationSources() map[string]any {
	return map[string]any{
		"sources": []map[string]any{
			{"id": "stackrox", "name": "StackRox / RHACS", "status": "converter-ready", "imports": []string{"policies", "exceptions", "runtime rules"}},
			{"id": "neuvector", "name": "NeuVector", "status": "converter-ready", "imports": []string{"admission rules", "response rules", "groups", "network allow rules", "process profiles", "DLP/WAF rules", "DLP/WAF group scopes", "file monitor profiles"}},
			{"id": "aqua", "name": "Aqua Security", "status": "converter-ready", "imports": []string{"image assurance policies", "CI gates"}},
			{"id": "prisma", "name": "Prisma Cloud", "status": "converter-ready", "imports": []string{"config policies", "compliance mappings"}},
		},
		"workflow": []map[string]any{
			{"step": 1, "name": "Upload export", "state": "ui-pending"},
			{"step": 2, "name": "Dry-run conversion", "state": "backend-ready"},
			{"step": 3, "name": "Review diff", "state": "ui-pending"},
			{"step": 4, "name": "Apply with rollback bundle", "state": "planned"},
		},
	}
}

func (h *Enterprise) Onboarding(w http.ResponseWriter, r *http.Request) {
	out := defaultOnboarding()
	if h.db != nil {
		subj, ok := SubjectFrom(r.Context())
		if !ok {
			jsonError(w, http.StatusUnauthorized, "no subject")
			return
		}
		dbReady := h.db.Health(r.Context()) == nil
		if dbReady {
			out["control_plane_db"] = "ready"
		} else {
			out["control_plane_db"] = "degraded"
		}
		gates, err := h.onboardingHealthGates(r, subj.OrgID, dbReady)
		if err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out["health_gates"] = gates
		h.overlayOrgSettings(r.Context(), subj.OrgID, "onboarding", out)
	}
	writeJSON(w, http.StatusOK, out)
}

func defaultOnboarding() map[string]any {
	return map[string]any{
		"install_methods": []map[string]any{
			{"id": "helm", "name": "Helm", "status": "ready", "command": "helm upgrade --install constellation deploy/charts/constellation --namespace constellation-system --create-namespace"},
			{"id": "operator", "name": "Operator-managed cluster registration", "status": "ready", "command": "helm upgrade --install constellation deploy/charts/constellation --namespace constellation-system --create-namespace --set operator.enabled=true --set clusterRegistration.enabled=true"},
			{"id": "astronomer", "name": "Astronomer security route mount", "status": "jwks-ready", "command": "helm upgrade --install constellation deploy/charts/constellation --namespace constellation-system --create-namespace --set astronomer.enabled=true --set astronomer.jwksURL=$JWKS_URL"},
		},
		"health_gates": defaultOnboardingHealthGates(),
	}
}

func defaultOnboardingHealthGates() []map[string]any {
	return []map[string]any{
		{"name": "API readyz", "status": "not-observed", "evidence": "No live control-plane probe available."},
		{"name": "Scanner workers", "status": "not-observed", "evidence": "No scanner heartbeat observed."},
		{"name": "Admission webhook", "status": "not-observed", "evidence": "No admission heartbeat observed."},
		{"name": "Runtime privileged agent", "status": "not-observed", "evidence": "No runtime-agent heartbeat observed."},
		{"name": "VulnDB importer", "status": "not-instrumented", "evidence": "Importer readiness is reported through VulnDB status metadata, not component heartbeats."},
	}
}

type onboardingHeartbeatRollup struct {
	ready    int
	lastSeen *time.Time
}

func (h *Enterprise) onboardingHealthGates(r *http.Request, orgID any, dbReady bool) ([]map[string]any, error) {
	rollups := map[string]onboardingHeartbeatRollup{}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT component,
       COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes')::int,
       MAX(last_seen_at)
  FROM component_heartbeats
 WHERE org_id = $1
   AND component IN ('api', 'scanner', 'admission', 'runtime-agent')
 GROUP BY component`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var component string
		var rollup onboardingHeartbeatRollup
		if err := rows.Scan(&component, &rollup.ready, &rollup.lastSeen); err != nil {
			return nil, err
		}
		rollups[component] = rollup
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	dbStatus := "degraded"
	dbEvidence := "Database health probe failed."
	if dbReady {
		dbStatus = "ready"
		dbEvidence = "Database health probe passed."
	}
	return []map[string]any{
		{"name": "API readyz", "status": dbStatus, "evidence": dbEvidence},
		heartbeatGate("Scanner workers", "scanner", rollups["scanner"]),
		heartbeatGate("Admission webhook", "admission", rollups["admission"]),
		heartbeatGate("Runtime privileged agent", "runtime-agent", rollups["runtime-agent"]),
		{"name": "VulnDB importer", "status": "not-instrumented", "evidence": "Importer readiness is reported through VulnDB status metadata, not component heartbeats."},
	}, nil
}

func heartbeatGate(name string, component string, rollup onboardingHeartbeatRollup) map[string]any {
	if rollup.ready > 0 {
		return map[string]any{"name": name, "status": "ready", "evidence": fmt.Sprintf("%d fresh %s heartbeat(s).", rollup.ready, component)}
	}
	if rollup.lastSeen != nil {
		return map[string]any{"name": name, "status": "stale", "evidence": "Last heartbeat at " + rollup.lastSeen.UTC().Format(time.RFC3339) + "."}
	}
	return map[string]any{"name": name, "status": "not-observed", "evidence": "No " + component + " heartbeat observed."}
}

// overlayOrgSettings reads org_settings.settings->section and merges the resulting
// object over the static catalog so admins can override copy + statuses.
func (h *Enterprise) overlayOrgSettings(ctx context.Context, orgID any, section string, out map[string]any) {
	var raw []byte
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT settings->$2 FROM org_settings WHERE org_id = $1`, orgID, section).Scan(&raw); err != nil {
		return
	}
	if len(raw) == 0 {
		return
	}
	var override map[string]any
	if err := json.Unmarshal(raw, &override); err != nil {
		return
	}
	for k, v := range override {
		out[k] = v
	}
}
