package handler

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

type ComponentsInventory struct {
	db *db.DB
}

func NewComponentsInventory(d *db.DB) *ComponentsInventory {
	return &ComponentsInventory{db: d}
}

type componentInventorySummaryDTO struct {
	GeneratedAt    time.Time `json:"generated_at"`
	Components     int       `json:"components"`
	TotalInstances int       `json:"total_instances"`
	Healthy        int       `json:"healthy"`
	Degraded       int       `json:"degraded"`
	Stale          int       `json:"stale"`
	Drift          int       `json:"drift"`
	Crashlooping   int       `json:"crashlooping"`
	Missing        int       `json:"missing"`
}

type componentInventoryRollupDTO struct {
	Component       string     `json:"component"`
	DisplayName     string     `json:"display_name"`
	Role            string     `json:"role"`
	Scope           string     `json:"scope"`
	Kind            string     `json:"kind"`
	Expected        bool       `json:"expected"`
	Status          string     `json:"status"`
	Instances       int        `json:"instances"`
	Healthy         int        `json:"healthy"`
	Degraded        int        `json:"degraded"`
	Stale           int        `json:"stale"`
	Drift           int        `json:"drift"`
	Crashlooping    int        `json:"crashlooping"`
	Missing         int        `json:"missing"`
	LatestVersion   string     `json:"latest_version,omitempty"`
	LatestCommit    string     `json:"latest_commit,omitempty"`
	LatestSeenAt    *time.Time `json:"latest_seen_at,omitempty"`
	LastStatusCause string     `json:"last_status_cause,omitempty"`
}

type componentInstanceDTO struct {
	ID            uuid.UUID      `json:"id"`
	Component     string         `json:"component"`
	DisplayName   string         `json:"display_name"`
	Role          string         `json:"role"`
	Scope         string         `json:"scope"`
	Kind          string         `json:"kind"`
	Status        string         `json:"status"`
	StatusReason  string         `json:"status_reason,omitempty"`
	ClusterID     *uuid.UUID     `json:"cluster_id,omitempty"`
	ClusterName   string         `json:"cluster_name,omitempty"`
	Version       string         `json:"version,omitempty"`
	Commit        string         `json:"commit,omitempty"`
	CommitShort   string         `json:"commit_short,omitempty"`
	BuildTime     *time.Time     `json:"build_time,omitempty"`
	Hostname      string         `json:"hostname"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	RestartCount  int            `json:"restart_count"`
	LastError     string         `json:"last_error,omitempty"`
	Metadata      map[string]any `json:"metadata,omitempty"`
	FirstSeenAt   time.Time      `json:"first_seen_at"`
	LastSeenAt    time.Time      `json:"last_seen_at"`
}

type componentDiagnosticsDTO struct {
	Component   componentInstanceDTO         `json:"component"`
	GeneratedAt time.Time                    `json:"generated_at"`
	AdminGate   string                       `json:"admin_gate"`
	Status      componentDiagnosticsStatus   `json:"status"`
	Diagnostics []componentDiagnosticCheck   `json:"diagnostics"`
	Counters    []componentDiagnosticCounter `json:"counters"`
	Config      []componentDiagnosticConfig  `json:"config"`
	Debug       componentDiagnosticDebug     `json:"debug"`
}

type componentDiagnosticsStatus struct {
	State         string    `json:"state"`
	Reason        string    `json:"reason,omitempty"`
	Stale         bool      `json:"stale"`
	Drift         bool      `json:"drift"`
	Crashlooping  bool      `json:"crashlooping"`
	Degraded      bool      `json:"degraded"`
	Version       string    `json:"version,omitempty"`
	Commit        string    `json:"commit,omitempty"`
	CommitShort   string    `json:"commit_short,omitempty"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	RestartCount  int       `json:"restart_count"`
	LastError     string    `json:"last_error,omitempty"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type componentDiagnosticCheck struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Status     string `json:"status"`
	Value      any    `json:"value,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Evidence   string `json:"evidence,omitempty"`
	Error      string `json:"error,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
}

type componentDiagnosticCounter struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Value  any    `json:"value"`
	Unit   string `json:"unit,omitempty"`
	Window string `json:"window,omitempty"`
	Tone   string `json:"tone,omitempty"`
}

type componentDiagnosticConfig struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Value    any    `json:"value"`
	Evidence string `json:"evidence,omitempty"`
}

type componentDiagnosticDebug struct {
	ProfilingEnabled     bool     `json:"profiling_enabled"`
	LiveLogsEnabled      bool     `json:"live_logs_enabled"`
	SupportBundleEnabled bool     `json:"support_bundle_enabled"`
	Notes                []string `json:"notes,omitempty"`
}

type componentSpec struct {
	Component   string
	DisplayName string
	Role        string
	Scope       string
	Kind        string
	Expected    bool
	HealthGate  bool
}

var componentInventorySpecs = []componentSpec{
	{Component: "api", DisplayName: "API", Role: "control-plane", Scope: "org", Kind: "deployment", Expected: false},
	{Component: "frontend", DisplayName: "Frontend", Role: "control-plane", Scope: "org", Kind: "deployment", Expected: false},
	{Component: "operator", DisplayName: "Operator", Role: "controller", Scope: "cluster", Kind: "deployment", Expected: true, HealthGate: true},
	{Component: "scanner", DisplayName: "Scanner", Role: "scanner", Scope: "cluster", Kind: "deployment", Expected: true, HealthGate: true},
	{Component: "vulndb-importer", DisplayName: "VulnDB importer", Role: "updater", Scope: "cluster", Kind: "cronjob", Expected: true},
	{Component: "admission", DisplayName: "Admission webhook", Role: "policy-enforcement", Scope: "cluster", Kind: "deployment", Expected: true, HealthGate: true},
	{Component: "runtime-agent", DisplayName: "Runtime agent", Role: "enforcer", Scope: "node", Kind: "daemonset", Expected: true, HealthGate: true},
	{Component: "discoverer", DisplayName: "Discoverer", Role: "discovery", Scope: "cluster", Kind: "deployment", Expected: true, HealthGate: true},
	{Component: "registry-walker", DisplayName: "Registry walker", Role: "registry-scanner", Scope: "org", Kind: "deployment", Expected: false},
	{Component: "network-policy-applier", DisplayName: "Network policy applier", Role: "policy-enforcement", Scope: "cluster", Kind: "deployment", Expected: true},
	{Component: "k8s-compliance-collector", DisplayName: "Kubernetes compliance collector", Role: "compliance", Scope: "cluster", Kind: "cronjob", Expected: true},
	{Component: "compliance-scheduler", DisplayName: "Compliance scheduler", Role: "compliance", Scope: "org", Kind: "deployment", Expected: false},
	{Component: "github-app", DisplayName: "GitHub app", Role: "integration", Scope: "org", Kind: "deployment", Expected: false},
	{Component: "audit-archiver", DisplayName: "Audit archiver", Role: "audit", Scope: "org", Kind: "cronjob", Expected: false},
	{Component: "backup", DisplayName: "Backup", Role: "recovery", Scope: "org", Kind: "job", Expected: false},
}

func (h *ComponentsInventory) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	clusterID, ok := optionalUUIDQuery(w, r, "cluster_id")
	if !ok {
		return
	}
	componentFilter := strings.TrimSpace(r.URL.Query().Get("component"))
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	limit := parseComponentInventoryLimit(r)

	hbs, err := LoadHeartbeats(r.Context(), h.db.Pool(), subj.OrgID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "heartbeats: "+err.Error())
		return
	}
	clusterNames := loadClusterNames(r.Context(), h.db, hbs)
	scored := scoreHeartbeats(hbs, clusterNames)
	filteredInstances := make([]componentInstanceDTO, 0, len(hbs))
	for i, hb := range hbs {
		if clusterID != nil {
			if hb.ClusterID == nil || *hb.ClusterID != *clusterID {
				continue
			}
		}
		if componentFilter != "" && hb.Component != componentFilter {
			continue
		}
		dto := componentInstanceFromHeartbeat(hb, scored[i])
		if statusFilter != "" && dto.Status != statusFilter {
			continue
		}
		filteredInstances = append(filteredInstances, dto)
	}
	sort.Slice(filteredInstances, func(i, j int) bool {
		if filteredInstances[i].Component != filteredInstances[j].Component {
			return filteredInstances[i].Component < filteredInstances[j].Component
		}
		if filteredInstances[i].ClusterName != filteredInstances[j].ClusterName {
			return filteredInstances[i].ClusterName < filteredInstances[j].ClusterName
		}
		return filteredInstances[i].Hostname < filteredInstances[j].Hostname
	})
	rollups := componentInventoryRollups(filteredInstances, clusterID != nil, componentFilter)
	instances := filteredInstances
	if len(instances) > limit {
		instances = instances[:limit]
	}
	summary := componentInventorySummary(rollups)
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":    summary,
		"rollups":    rollups,
		"components": instances,
	})
}

func (h *ComponentsInventory) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid component id")
		return
	}
	hb, scored, found, err := h.componentHeartbeat(r.Context(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "heartbeats: "+err.Error())
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "component instance not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"component": componentInstanceFromHeartbeat(hb, scored),
	})
}

func (h *ComponentsInventory) Diagnostics(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(chi.URLParam(r, "id")))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid component id")
		return
	}
	hb, scored, found, err := h.componentHeartbeat(r.Context(), subj.OrgID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "heartbeats: "+err.Error())
		return
	}
	if !found {
		jsonError(w, http.StatusNotFound, "component instance not found")
		return
	}
	component := componentInstanceFromHeartbeat(hb, scored)
	diagnostics := componentDiagnosticsFor(component, hb.Metadata, hb.LastError, time.Now().UTC())
	if err := h.addRuntimeAgentNodeProbeDiagnostics(r.Context(), subj.OrgID, &diagnostics, component, hb.Metadata); err != nil {
		jsonError(w, http.StatusInternalServerError, "runtime-agent probe diagnostics: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, diagnostics)
}

func (h *ComponentsInventory) componentHeartbeat(ctx context.Context, orgID uuid.UUID, id uuid.UUID) (HeartbeatRow, heartbeatDTO, bool, error) {
	hbs, err := LoadHeartbeats(ctx, h.db.Pool(), orgID)
	if err != nil {
		return HeartbeatRow{}, heartbeatDTO{}, false, err
	}
	clusterNames := loadClusterNames(ctx, h.db, hbs)
	scored := scoreHeartbeats(hbs, clusterNames)
	for i, hb := range hbs {
		if hb.ID == id {
			return hb, scored[i], true, nil
		}
	}
	return HeartbeatRow{}, heartbeatDTO{}, false, nil
}

func (h *ComponentsInventory) addRuntimeAgentNodeProbeDiagnostics(ctx context.Context, orgID uuid.UUID, diagnostics *componentDiagnosticsDTO, component componentInstanceDTO, metadata map[string]any) error {
	if component.Component != "runtime-agent" || component.ClusterID == nil {
		return nil
	}
	node := metadataString(metadata, "node")
	if node == "" {
		node = metadataString(metadataMap(metadata, "enforcer"), "node")
	}
	if node == "" {
		node = component.Hostname
	}
	if node == "" {
		return nil
	}

	var row runtimeAgentNodeProbeRow
	err := h.db.Pool().QueryRow(ctx, `
SELECT COALESCE(hc.container_count, 0), hc.observed_at,
       COALESCE(hpr.process_count, 0), COALESCE(hpr.items_count, 0), hpr.observed_at,
       COALESCE(hp.package_count, 0), hp.observed_at,
       COALESCE(cis.failed, 0), COALESCE(cis.warned, 0), cis.observed_at,
       COALESCE(hf.cni_name, ''), COALESCE(hf.cri_runtime, ''), hf.btf_present, hf.nfqueue_capable, hf.observed_at
  FROM (SELECT 1) seed
  LEFT JOIN LATERAL (
      SELECT container_count, observed_at
        FROM host_containers
       WHERE org_id = $1 AND cluster_id = $2 AND node = $3
       ORDER BY observed_at DESC
       LIMIT 1
  ) hc ON true
  LEFT JOIN LATERAL (
      SELECT process_count, items_count, observed_at
        FROM host_processes
       WHERE org_id = $1 AND cluster_id = $2 AND node = $3
       ORDER BY observed_at DESC
       LIMIT 1
  ) hpr ON true
  LEFT JOIN LATERAL (
      SELECT package_count, observed_at
        FROM host_packages
       WHERE org_id = $1 AND cluster_id = $2 AND node = $3
       ORDER BY observed_at DESC
       LIMIT 1
  ) hp ON true
  LEFT JOIN LATERAL (
      SELECT failed, warned, observed_at
        FROM host_cis
       WHERE org_id = $1 AND cluster_id = $2 AND node = $3
       ORDER BY observed_at DESC
       LIMIT 1
  ) cis ON true
  LEFT JOIN LATERAL (
      SELECT cni_name, cri_runtime, btf_present, nfqueue_capable, observed_at
        FROM host_facts
       WHERE org_id = $1 AND cluster_id = $2 AND node = $3
       ORDER BY observed_at DESC
       LIMIT 1
  ) hf ON true`,
		orgID, *component.ClusterID, node).Scan(
		&row.ContainerCount, &row.ContainersObservedAt,
		&row.ProcessCount, &row.ProcessItemsCount, &row.ProcessesObservedAt,
		&row.PackageCount, &row.PackagesObservedAt,
		&row.CISFailed, &row.CISWarned, &row.CISObservedAt,
		&row.CNIName, &row.CRIRuntime, &row.BTFPresent, &row.NFQueueCapable, &row.HostFactsObservedAt,
	)
	if err != nil {
		return err
	}
	diagnostics.Diagnostics = append(diagnostics.Diagnostics, runtimeAgentNodeProbeChecks(node, row, diagnostics.GeneratedAt)...)
	diagnostics.Counters = append(diagnostics.Counters, runtimeAgentNodeProbeCounters(row)...)
	diagnostics.Config = append(diagnostics.Config, runtimeAgentNodeProbeConfig(row)...)
	return nil
}

type runtimeAgentNodeProbeRow struct {
	ContainerCount       int
	ContainersObservedAt *time.Time
	ProcessCount         int
	ProcessItemsCount    int
	ProcessesObservedAt  *time.Time
	PackageCount         int
	PackagesObservedAt   *time.Time
	CISFailed            int
	CISWarned            int
	CISObservedAt        *time.Time
	CNIName              string
	CRIRuntime           string
	BTFPresent           *bool
	NFQueueCapable       *bool
	HostFactsObservedAt  *time.Time
}

func componentInstanceFromHeartbeat(hb HeartbeatRow, scored heartbeatDTO) componentInstanceDTO {
	spec := componentSpecFor(hb.Component)
	dto := componentInstanceDTO{
		ID:            hb.ID,
		Component:     hb.Component,
		DisplayName:   spec.DisplayName,
		Role:          spec.Role,
		Scope:         spec.Scope,
		Kind:          spec.Kind,
		Status:        scored.Status,
		StatusReason:  scored.DriftReason,
		ClusterID:     hb.ClusterID,
		ClusterName:   scored.ClusterName,
		Version:       hb.Version,
		Commit:        hb.Commit,
		CommitShort:   shortSha(hb.Commit),
		BuildTime:     hb.BuildTime,
		Hostname:      hb.Hostname,
		UptimeSeconds: hb.UptimeSeconds,
		RestartCount:  hb.RestartCount,
		Metadata:      componentPublicMetadata(hb.Metadata),
		FirstSeenAt:   hb.FirstSeenAt,
		LastSeenAt:    hb.LastSeenAt,
	}
	if dto.DisplayName == "" {
		dto.DisplayName = hb.Component
	}
	if dto.Role == "" {
		dto.Role = "component"
	}
	if dto.Scope == "" {
		dto.Scope = "org"
	}
	if dto.Kind == "" {
		dto.Kind = "component"
	}
	return dto
}

func componentDiagnosticsFor(component componentInstanceDTO, rawMetadata map[string]any, rawLastError string, now time.Time) componentDiagnosticsDTO {
	status := componentDiagnosticsStatus{
		State:         component.Status,
		Reason:        component.StatusReason,
		Stale:         component.Status == "stale",
		Drift:         component.Status == "drift",
		Crashlooping:  component.Status == "crashlooping",
		Degraded:      component.Status == "degraded",
		Version:       component.Version,
		Commit:        component.Commit,
		CommitShort:   component.CommitShort,
		UptimeSeconds: component.UptimeSeconds,
		RestartCount:  component.RestartCount,
		LastError:     safeDiagnosticText(rawLastError),
		FirstSeenAt:   component.FirstSeenAt,
		LastSeenAt:    component.LastSeenAt,
	}
	diagnostics := componentBaseDiagnostics(component, rawLastError)
	diagnostics = append(diagnostics, componentRoleDiagnostics(component, rawMetadata)...)
	return componentDiagnosticsDTO{
		Component:   component,
		GeneratedAt: now,
		AdminGate:   "manage-org",
		Status:      status,
		Diagnostics: diagnostics,
		Counters:    componentDiagnosticCounters(component, rawMetadata),
		Config:      componentDiagnosticConfigEntries(rawMetadata),
		Debug: componentDiagnosticDebug{
			Notes: []string{
				"Derived from component heartbeats; live logs, profiling, and support bundles require explicit signed/redacted collection workflows.",
				"Raw heartbeat metadata is intentionally not returned by diagnostics.",
			},
		},
	}
}

func runtimeAgentNodeProbeChecks(node string, row runtimeAgentNodeProbeRow, now time.Time) []componentDiagnosticCheck {
	checks := []componentDiagnosticCheck{
		nodeProbeCheck("node_host_facts", "Node host facts", row.HostFactsObservedAt, 10*time.Minute, "host_facts.observed_at", now),
		nodeProbeCheck("node_container_probe", "Node container map", row.ContainersObservedAt, 5*time.Minute, "host_containers.observed_at", now),
		nodeProbeCheck("node_process_probe", "Node process map", row.ProcessesObservedAt, 5*time.Minute, "host_processes.observed_at", now),
		nodeProbeCheck("node_package_probe", "Node package inventory", row.PackagesObservedAt, 2*time.Hour, "host_packages.observed_at", now),
		nodeProbeCheck("node_cis_probe", "Node CIS benchmark", row.CISObservedAt, 12*time.Hour, "host_cis.observed_at", now),
	}
	for i := range checks {
		checks[i].Value = node
	}
	if row.CISObservedAt != nil && row.CISFailed > 0 {
		checks = append(checks, componentDiagnosticCheck{
			Key:        "node_cis_failures",
			Label:      "Node CIS failures",
			Status:     "degraded",
			Value:      map[string]int{"failed": row.CISFailed, "warned": row.CISWarned},
			Reason:     "host CIS benchmark has failing controls",
			Evidence:   "host_cis.failed",
			ObservedAt: row.CISObservedAt.UTC().Format(time.RFC3339),
		})
	}
	return checks
}

func nodeProbeCheck(key, label string, observedAt *time.Time, maxAge time.Duration, evidence string, now time.Time) componentDiagnosticCheck {
	check := componentDiagnosticCheck{
		Key:      key,
		Label:    label,
		Status:   "missing",
		Reason:   "no node evidence observed",
		Evidence: evidence,
	}
	if observedAt == nil {
		return check
	}
	age := now.Sub(*observedAt)
	check.ObservedAt = observedAt.UTC().Format(time.RFC3339)
	check.Status = "ready"
	check.Reason = ""
	if age > maxAge {
		check.Status = "stale"
		check.Reason = "last observed " + age.Truncate(time.Second).String() + " ago"
	}
	return check
}

func runtimeAgentNodeProbeCounters(row runtimeAgentNodeProbeRow) []componentDiagnosticCounter {
	out := []componentDiagnosticCounter{}
	if row.ContainersObservedAt != nil {
		out = append(out, componentDiagnosticCounter{Key: "node_container_count", Label: "Node containers", Value: row.ContainerCount, Tone: "neutral"})
	}
	if row.ProcessesObservedAt != nil {
		out = append(out,
			componentDiagnosticCounter{Key: "node_process_count", Label: "Node processes", Value: row.ProcessCount, Tone: "neutral"},
			componentDiagnosticCounter{Key: "node_process_sample_count", Label: "Node process sample", Value: row.ProcessItemsCount, Tone: "neutral"},
		)
	}
	if row.PackagesObservedAt != nil {
		out = append(out, componentDiagnosticCounter{Key: "node_package_count", Label: "Node packages", Value: row.PackageCount, Tone: "neutral"})
	}
	if row.CISObservedAt != nil {
		out = append(out,
			componentDiagnosticCounter{Key: "node_cis_failed", Label: "Node CIS failed", Value: row.CISFailed, Tone: diagnosticTone(row.CISFailed > 0, row.CISFailed > 0)},
			componentDiagnosticCounter{Key: "node_cis_warned", Label: "Node CIS warned", Value: row.CISWarned, Tone: diagnosticTone(row.CISWarned > 0, false)},
		)
	}
	return out
}

func runtimeAgentNodeProbeConfig(row runtimeAgentNodeProbeRow) []componentDiagnosticConfig {
	out := []componentDiagnosticConfig{}
	if row.CNIName != "" {
		out = append(out, componentDiagnosticConfig{Key: "node.cni_name", Label: "Node CNI", Value: row.CNIName, Evidence: "host_facts.cni_name"})
	}
	if row.CRIRuntime != "" {
		out = append(out, componentDiagnosticConfig{Key: "node.cri_runtime", Label: "Node CRI runtime", Value: row.CRIRuntime, Evidence: "host_facts.cri_runtime"})
	}
	if row.BTFPresent != nil {
		out = append(out, componentDiagnosticConfig{Key: "node.btf_present", Label: "Node BTF present", Value: *row.BTFPresent, Evidence: "host_facts.btf_present"})
	}
	if row.NFQueueCapable != nil {
		out = append(out, componentDiagnosticConfig{Key: "node.nfqueue_capable", Label: "Node NFQUEUE capable", Value: *row.NFQueueCapable, Evidence: "host_facts.nfqueue_capable"})
	}
	return out
}

func componentBaseDiagnostics(component componentInstanceDTO, rawLastError string) []componentDiagnosticCheck {
	heartbeatStatus := "ready"
	if component.Status == "stale" {
		heartbeatStatus = "stale"
	}
	checks := []componentDiagnosticCheck{
		{
			Key:        "heartbeat",
			Label:      "Heartbeat freshness",
			Status:     heartbeatStatus,
			Value:      component.LastSeenAt.UTC().Format(time.RFC3339),
			Reason:     component.StatusReason,
			Evidence:   "component_heartbeats.last_seen_at",
			ObservedAt: component.LastSeenAt.UTC().Format(time.RFC3339),
		},
		{
			Key:      "build",
			Label:    "Build drift",
			Status:   diagnosticReadyUnless(component.Status == "drift", "drift"),
			Value:    component.CommitShort,
			Reason:   componentStatusReasonWhen(component, "drift"),
			Evidence: "component_heartbeats.commit",
		},
		{
			Key:      "restart",
			Label:    "Restart pressure",
			Status:   diagnosticReadyUnless(component.Status == "crashlooping", "crashlooping"),
			Value:    component.RestartCount,
			Reason:   componentStatusReasonWhen(component, "crashlooping"),
			Evidence: "component_heartbeats.restart_count",
		},
	}
	if safeErr := safeDiagnosticText(rawLastError); safeErr != "" {
		checks = append(checks, componentDiagnosticCheck{
			Key:      "last_error",
			Label:    "Last component error",
			Status:   "error",
			Reason:   safeErr,
			Evidence: "component_heartbeats.last_error",
		})
	}
	return checks
}

func componentRoleDiagnostics(component componentInstanceDTO, metadata map[string]any) []componentDiagnosticCheck {
	switch component.Component {
	case "scanner":
		return scannerComponentDiagnostics(metadata)
	case "admission":
		return admissionComponentDiagnostics(metadata)
	case "operator":
		return operatorComponentDiagnostics(metadata)
	case "network-policy-applier":
		return networkPolicyApplierDiagnostics(metadata)
	default:
		if component.Role == "enforcer" {
			return enforcerComponentDiagnostics(metadata)
		}
		return nil
	}
}

func scannerComponentDiagnostics(metadata map[string]any) []componentDiagnosticCheck {
	checks := []componentDiagnosticCheck{}
	active := metadataInt(metadata, "active_jobs")
	idle := metadataInt(metadata, "idle_capacity")
	maxConcurrent := metadataInt(metadata, "max_concurrent")
	if maxConcurrent > 0 || active > 0 || idle > 0 {
		status := "ready"
		reason := ""
		if idle == 0 && active >= maxConcurrent && maxConcurrent > 0 {
			status = "saturated"
			reason = "scanner has no idle worker capacity"
		}
		checks = append(checks, componentDiagnosticCheck{
			Key:      "scanner_capacity",
			Label:    "Scanner capacity",
			Status:   status,
			Value:    map[string]int{"active": active, "idle": idle, "max": maxConcurrent},
			Reason:   reason,
			Evidence: "component_heartbeats.metadata.active_jobs",
		})
	}
	if vuln := metadataMap(metadata, "vulndb"); len(vuln) > 0 {
		status := metadataString(vuln, "status")
		if status == "" {
			status = "ready"
		}
		if !metadataBool(vuln, "enabled") {
			status = "disabled"
		} else if !metadataBool(vuln, "ready") {
			status = "degraded"
		}
		checks = append(checks, componentDiagnosticCheck{
			Key:      "scanner_vulndb",
			Label:    "VulnDB readiness",
			Status:   status,
			Value:    safeMetadataSubset(vuln, []string{"enabled", "ready", "status", "bundle_version", "payload_hash", "exported_at", "record_count"}),
			Reason:   safeDiagnosticText(metadataString(vuln, "error")),
			Evidence: "component_heartbeats.metadata.vulndb",
		})
	}
	if cacheHealth := metadataMap(metadata, "cache_health"); len(cacheHealth) > 0 {
		names := sortedMapKeys(cacheHealth)
		for _, name := range names {
			cache, _ := cacheHealth[name].(map[string]any)
			if len(cache) == 0 {
				continue
			}
			status := metadataString(cache, "status")
			if status == "" {
				status = "unknown"
			}
			if metadataBool(cache, "configured") && metadataBool(cache, "writable") {
				status = "ready"
			}
			checks = append(checks, componentDiagnosticCheck{
				Key:      "scanner_cache_" + name,
				Label:    "Scanner cache " + name,
				Status:   status,
				Value:    safeMetadataSubset(cache, []string{"configured", "present", "is_dir", "writable", "status", "free_bytes", "record_count", "record_size_bytes"}),
				Reason:   safeDiagnosticText(metadataString(cache, "error")),
				Evidence: "component_heartbeats.metadata.cache_health." + name,
			})
		}
	}
	return checks
}

func admissionComponentDiagnostics(metadata map[string]any) []componentDiagnosticCheck {
	return []componentDiagnosticCheck{
		{
			Key:      "admission_tls",
			Label:    "Webhook TLS",
			Status:   diagnosticReadyUnless(!metadataBool(metadata, "tls_enabled"), "disabled"),
			Value:    metadataBool(metadata, "tls_enabled"),
			Evidence: "component_heartbeats.metadata.tls_enabled",
		},
		{
			Key:      "admission_audit",
			Label:    "Admission audit",
			Status:   diagnosticReadyUnless(!metadataBool(metadata, "audit_enabled"), "disabled"),
			Value:    metadataBool(metadata, "audit_enabled"),
			Evidence: "component_heartbeats.metadata.audit_enabled",
		},
	}
}

func operatorComponentDiagnostics(metadata map[string]any) []componentDiagnosticCheck {
	return []componentDiagnosticCheck{
		{
			Key:      "operator_leader_election",
			Label:    "Leader election",
			Status:   diagnosticReadyUnless(!metadataBool(metadata, "leader_election"), "disabled"),
			Value:    metadataBool(metadata, "leader_election"),
			Evidence: "component_heartbeats.metadata.leader_election",
		},
	}
}

func networkPolicyApplierDiagnostics(metadata map[string]any) []componentDiagnosticCheck {
	flavor := metadataString(metadata, "flavor")
	if flavor == "" {
		return nil
	}
	return []componentDiagnosticCheck{{
		Key:      "network_policy_flavor",
		Label:    "Network policy backend",
		Status:   "ready",
		Value:    flavor,
		Evidence: "component_heartbeats.metadata.flavor",
	}}
}

func enforcerComponentDiagnostics(metadata map[string]any) []componentDiagnosticCheck {
	enforcer := metadataMap(metadata, "enforcer")
	if len(enforcer) == 0 {
		return nil
	}
	checks := make([]componentDiagnosticCheck, 0, 3)
	for _, key := range []string{"dp_status", "ebpf_status", "probe_status", "policy_mode"} {
		value := metadataString(enforcer, key)
		if value == "" {
			continue
		}
		status := value
		if key == "policy_mode" {
			status = "ready"
		}
		checks = append(checks, componentDiagnosticCheck{
			Key:      "enforcer_" + key,
			Label:    diagnosticLabel(key),
			Status:   status,
			Value:    value,
			Evidence: "component_heartbeats.metadata.enforcer." + key,
		})
	}
	return checks
}

func componentDiagnosticCounters(component componentInstanceDTO, metadata map[string]any) []componentDiagnosticCounter {
	counters := []componentDiagnosticCounter{
		{Key: "uptime_seconds", Label: "Uptime", Value: component.UptimeSeconds, Unit: "s", Tone: "neutral"},
		{Key: "restart_count", Label: "Restarts", Value: component.RestartCount, Tone: diagnosticTone(component.RestartCount > 0, component.RestartCount > 3)},
	}
	for _, key := range []string{
		"max_concurrent", "active_jobs", "idle_capacity", "interval_seconds", "concurrency", "last_row_count",
		"processed_events", "exec_events", "file_events", "uploaded_events", "dropped_events", "bpf_dropped",
		"flows_uploaded", "flows_dropped", "threats_uploaded", "threats_dropped", "container_count", "process_count",
	} {
		if value, ok := diagnosticNumber(metadata[key]); ok {
			counters = append(counters, componentDiagnosticCounter{
				Key:   key,
				Label: diagnosticLabel(key),
				Value: value,
				Unit:  diagnosticUnit(key),
			})
		}
	}
	counters = append(counters, mapCounters("target_capacity", metadataMap(metadata, "target_capacity"))...)
	counters = append(counters, mapCounters("active_jobs_by_target_type", metadataMap(metadata, "active_jobs_by_target_type"))...)
	counters = append(counters, selectedNestedCounters("dp", metadataMap(metadata, "dp"), []string{
		"starts", "exits", "crashes", "rx_total", "rx_dropped", "keepalive_replied", "keepalive_timeout",
		"keepalive_errors", "taps_current", "taps_errors", "enforce_current", "enforce_errors",
		"connection_events", "threat_events", "sessions_size", "sessions_observed",
	})...)
	if vuln := metadataMap(metadata, "vulndb"); len(vuln) > 0 {
		if value, ok := diagnosticNumber(vuln["record_count"]); ok {
			counters = append(counters, componentDiagnosticCounter{Key: "vulndb_record_count", Label: "VulnDB records", Value: value, Tone: "neutral"})
		}
	}
	if cacheHealth := metadataMap(metadata, "cache_health"); len(cacheHealth) > 0 {
		for _, name := range sortedMapKeys(cacheHealth) {
			cache, _ := cacheHealth[name].(map[string]any)
			if len(cache) == 0 {
				continue
			}
			if value, ok := diagnosticNumber(cache["record_count"]); ok {
				counters = append(counters, componentDiagnosticCounter{Key: "cache_" + name + "_records", Label: name + " cache records", Value: value, Tone: "neutral"})
			}
			if value, ok := diagnosticNumber(cache["free_bytes"]); ok {
				counters = append(counters, componentDiagnosticCounter{Key: "cache_" + name + "_free_bytes", Label: name + " cache free", Value: value, Unit: "bytes", Tone: "neutral"})
			}
		}
	}
	return counters
}

func componentDiagnosticConfigEntries(metadata map[string]any) []componentDiagnosticConfig {
	keys := []string{
		"instance_id", "listen_addr", "jwt_keys_configured", "oidc_enabled", "astronomer_enabled",
		"vulndb_ready_required", "vulndb_rescan_interval_s", "managed_namespace", "watch_namespace",
		"node", "upload_enabled", "batch_size", "batch_interval_ms", "leader_election", "tls_enabled", "quarantine_enabled", "policy_source_enabled", "audit_enabled",
		"flavor", "interval_seconds", "one_shot", "signing_enabled", "include_system_namespaces", "engines",
	}
	config := make([]componentDiagnosticConfig, 0, len(keys))
	for _, key := range keys {
		if value, ok := safeMetadataValue(metadata[key]); ok {
			config = append(config, componentDiagnosticConfig{
				Key:      key,
				Label:    diagnosticLabel(key),
				Value:    value,
				Evidence: "component_heartbeats.metadata." + key,
			})
		}
	}
	if vuln := metadataMap(metadata, "vulndb"); len(vuln) > 0 {
		for _, key := range []string{"enabled", "ready", "status", "bundle_version", "payload_hash", "exported_at", "record_count"} {
			if value, ok := safeMetadataValue(vuln[key]); ok {
				config = append(config, componentDiagnosticConfig{
					Key:      "vulndb." + key,
					Label:    "VulnDB " + diagnosticLabel(key),
					Value:    value,
					Evidence: "component_heartbeats.metadata.vulndb." + key,
				})
			}
		}
	}
	return config
}

func componentPublicMetadata(metadata map[string]any) map[string]any {
	out := map[string]any{}
	for _, key := range []string{
		"instance_id", "max_concurrent", "active_jobs", "idle_capacity", "target_capacity", "active_jobs_by_target_type", "engines",
		"processed_events", "uploaded_events", "dropped_events", "bpf_dropped", "flows_uploaded", "flows_dropped", "threats_uploaded", "threats_dropped",
	} {
		if value, ok := safeMetadataValue(metadata[key]); ok {
			out[key] = value
		}
	}
	if vuln := safeMetadataSubset(metadataMap(metadata, "vulndb"), []string{"enabled", "ready", "status", "bundle_version", "payload_hash", "exported_at", "record_count"}); len(vuln) > 0 {
		out["vulndb"] = vuln
	}
	if cacheHealth := safeNamedMetadataSubset(metadataMap(metadata, "cache_health"), []string{"configured", "present", "is_dir", "writable", "status", "free_bytes", "record_count", "record_size_bytes"}); len(cacheHealth) > 0 {
		out["cache_health"] = cacheHealth
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func safeMetadataSubset(source map[string]any, keys []string) map[string]any {
	if len(source) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, key := range keys {
		if value, ok := safeMetadataValue(source[key]); ok {
			out[key] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func safeNamedMetadataSubset(source map[string]any, keys []string) map[string]any {
	if len(source) == 0 {
		return nil
	}
	out := map[string]any{}
	for _, name := range sortedMapKeys(source) {
		child, _ := source[name].(map[string]any)
		if subset := safeMetadataSubset(child, keys); len(subset) > 0 {
			out[name] = subset
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func safeMetadataValue(raw any) (any, bool) {
	switch value := raw.(type) {
	case nil:
		return nil, false
	case string:
		value = strings.TrimSpace(value)
		if value == "" || !safeDiagnosticString(value) {
			return nil, false
		}
		if len(value) > 256 {
			value = value[:256]
		}
		return value, true
	case bool:
		return value, true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return value, true
	case []any:
		out := make([]any, 0, len(value))
		for i, item := range value {
			if i >= 24 {
				break
			}
			if safe, ok := safeMetadataValue(item); ok {
				out = append(out, safe)
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case map[string]any:
		out := map[string]any{}
		for _, key := range sortedMapKeys(value) {
			if len(out) >= 32 {
				break
			}
			if safe, ok := safeMetadataValue(value[key]); ok {
				out[key] = safe
			}
		}
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	default:
		return nil, false
	}
}

func safeDiagnosticText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if !safeDiagnosticString(value) {
		return "redacted by diagnostics policy"
	}
	if len(value) > 512 {
		return value[:512] + "..."
	}
	return value
}

func safeDiagnosticString(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"password", "passwd", "secret", "token", "bearer ", "authorization", "private key", "://", "postgres://", "mongodb://", "redis://"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return true
}

func diagnosticNumber(raw any) (any, bool) {
	switch value := raw.(type) {
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return value, true
	default:
		return nil, false
	}
}

func mapCounters(prefix string, source map[string]any) []componentDiagnosticCounter {
	if len(source) == 0 {
		return nil
	}
	out := make([]componentDiagnosticCounter, 0, len(source))
	for _, key := range sortedMapKeys(source) {
		if value, ok := diagnosticNumber(source[key]); ok {
			out = append(out, componentDiagnosticCounter{
				Key:   prefix + "." + key,
				Label: diagnosticLabel(prefix) + " " + key,
				Value: value,
				Tone:  "neutral",
			})
		}
	}
	return out
}

func selectedNestedCounters(prefix string, source map[string]any, keys []string) []componentDiagnosticCounter {
	if len(source) == 0 {
		return nil
	}
	out := make([]componentDiagnosticCounter, 0, len(keys))
	for _, key := range keys {
		if value, ok := diagnosticNumber(source[key]); ok {
			out = append(out, componentDiagnosticCounter{
				Key:   prefix + "." + key,
				Label: diagnosticLabel(prefix) + " " + diagnosticLabel(key),
				Value: value,
				Unit:  diagnosticUnit(key),
				Tone:  "neutral",
			})
		}
	}
	return out
}

func sortedMapKeys(source map[string]any) []string {
	keys := make([]string, 0, len(source))
	for key := range source {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func diagnosticReadyUnless(condition bool, status string) string {
	if condition {
		return status
	}
	return "ready"
}

func componentStatusReasonWhen(component componentInstanceDTO, status string) string {
	if component.Status == status {
		return component.StatusReason
	}
	return ""
}

func diagnosticTone(warning, critical bool) string {
	switch {
	case critical:
		return "error"
	case warning:
		return "warning"
	default:
		return "neutral"
	}
}

func diagnosticUnit(key string) string {
	switch {
	case strings.HasSuffix(key, "_seconds"):
		return "s"
	case strings.HasSuffix(key, "_bytes"):
		return "bytes"
	default:
		return ""
	}
}

func diagnosticLabel(key string) string {
	words := strings.Fields(strings.ReplaceAll(strings.ReplaceAll(key, "_", " "), ".", " "))
	acronyms := map[string]string{
		"api":    "API",
		"bpf":    "BPF",
		"cni":    "CNI",
		"dp":     "DP",
		"ebpf":   "eBPF",
		"id":     "ID",
		"jwt":    "JWT",
		"oidc":   "OIDC",
		"tls":    "TLS",
		"vulndb": "VulnDB",
	}
	for i := range words {
		if label, ok := acronyms[strings.ToLower(words[i])]; ok {
			words[i] = label
			continue
		}
		if len(words[i]) > 0 {
			words[i] = strings.ToUpper(words[i][:1]) + words[i][1:]
		}
	}
	return strings.Join(words, " ")
}

func componentInventoryRollups(instances []componentInstanceDTO, clusterScoped bool, componentFilter string) []componentInventoryRollupDTO {
	byComponent := map[string]*componentInventoryRollupDTO{}
	for _, spec := range componentInventorySpecs {
		if componentFilter != "" && spec.Component != componentFilter {
			continue
		}
		if clusterScoped && spec.Scope == "org" {
			continue
		}
		rollup := componentInventoryRollupDTO{
			Component:   spec.Component,
			DisplayName: spec.DisplayName,
			Role:        spec.Role,
			Scope:       spec.Scope,
			Kind:        spec.Kind,
			Expected:    spec.Expected,
		}
		byComponent[spec.Component] = &rollup
	}
	for _, inst := range instances {
		rollup := byComponent[inst.Component]
		if rollup == nil {
			rollup = &componentInventoryRollupDTO{
				Component:   inst.Component,
				DisplayName: inst.DisplayName,
				Role:        inst.Role,
				Scope:       inst.Scope,
				Kind:        inst.Kind,
			}
			byComponent[inst.Component] = rollup
		}
		rollup.Instances++
		switch inst.Status {
		case "healthy":
			rollup.Healthy++
		case "degraded":
			rollup.Degraded++
		case "stale":
			rollup.Stale++
		case "drift":
			rollup.Drift++
		case "crashlooping":
			rollup.Crashlooping++
		}
		if rollup.LatestSeenAt == nil || inst.LastSeenAt.After(*rollup.LatestSeenAt) {
			seen := inst.LastSeenAt
			rollup.LatestSeenAt = &seen
			rollup.LatestVersion = inst.Version
			rollup.LatestCommit = inst.Commit
			rollup.LastStatusCause = inst.StatusReason
		}
	}
	out := make([]componentInventoryRollupDTO, 0, len(byComponent))
	for _, rollup := range byComponent {
		if rollup.Expected && rollup.Instances == 0 {
			rollup.Missing = 1
		}
		rollup.Status = componentRollupStatus(*rollup)
		out = append(out, *rollup)
	}
	sort.Slice(out, func(i, j int) bool {
		oi := componentSpecOrder(out[i].Component)
		oj := componentSpecOrder(out[j].Component)
		if oi != oj {
			return oi < oj
		}
		return out[i].Component < out[j].Component
	})
	return out
}

func componentInventorySummary(rollups []componentInventoryRollupDTO) componentInventorySummaryDTO {
	out := componentInventorySummaryDTO{GeneratedAt: time.Now().UTC(), Components: len(rollups)}
	for _, rollup := range rollups {
		out.TotalInstances += rollup.Instances
		out.Healthy += rollup.Healthy
		out.Degraded += rollup.Degraded
		out.Stale += rollup.Stale
		out.Drift += rollup.Drift
		out.Crashlooping += rollup.Crashlooping
		out.Missing += rollup.Missing
	}
	return out
}

func componentRollupStatus(rollup componentInventoryRollupDTO) string {
	switch {
	case rollup.Missing > 0:
		return "missing"
	case rollup.Crashlooping > 0:
		return "crashlooping"
	case rollup.Degraded > 0:
		return "degraded"
	case rollup.Stale > 0:
		return "stale"
	case rollup.Drift > 0:
		return "drift"
	case rollup.Healthy > 0:
		return "healthy"
	default:
		return "not-observed"
	}
}

func componentSpecFor(component string) componentSpec {
	for _, spec := range componentInventorySpecs {
		if spec.Component == component {
			return spec
		}
	}
	return componentSpec{Component: component, DisplayName: component, Role: "component", Scope: "org"}
}

func componentSpecOrder(component string) int {
	for i, spec := range componentInventorySpecs {
		if spec.Component == component {
			return i
		}
	}
	return len(componentInventorySpecs) + 1
}

func knownComponentSet() map[string]struct{} {
	out := make(map[string]struct{}, len(componentInventorySpecs))
	for _, spec := range componentInventorySpecs {
		out[spec.Component] = struct{}{}
	}
	return out
}

func expectedClusterComponentNames() []string {
	out := make([]string, 0, len(componentInventorySpecs))
	for _, spec := range componentInventorySpecs {
		if spec.HealthGate {
			out = append(out, spec.Component)
		}
	}
	return out
}

func optionalUUIDQuery(w http.ResponseWriter, r *http.Request, key string) (*uuid.UUID, bool) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return nil, true
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid "+key)
		return nil, false
	}
	return &parsed, true
}

func parseComponentInventoryLimit(r *http.Request) int {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		return 500
	}
	return limit
}
