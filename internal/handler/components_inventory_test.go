package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestComponentsInventoryListAndGet(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.component_heartbeats')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: component_heartbeats migration not applied (%v)", err)
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Component Inventory Test')`, orgID, "components-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Component Inventory User')`, userID, orgID, "components-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, last_heartbeat_at)
VALUES ($1, $2, 'local', 'k3s', 'connected', $3)`, clusterID, orgID, now); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	apiID := uuid.New()
	scannerID := uuid.New()
	operatorID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (
    id, org_id, cluster_id, component, version, commit, hostname,
    uptime_seconds, restart_count, metadata, last_seen_at, first_seen_at
) VALUES
    ($1, $4, NULL, 'api', 'test', 'abcdef123456', 'api-0', 120, 0, '{}'::jsonb, $7, $7),
    ($2, $4, $5, 'scanner', 'test', 'abcdef123456', 'scanner-0', 90, 0, $6::jsonb, $7, $7),
    ($3, $4, $5, 'operator', 'test', 'abcdef123456', 'operator-0', 30, 0, '{}'::jsonb, $8, $8)`,
		apiID, scannerID, operatorID, orgID, clusterID,
		`{
			"vulndb":{"enabled":true,"ready":false,"status":"missing-store","bundle_version":"fixture","record_count":42,"path":"/var/lib/constellation/vulndb.bbolt","error":"secret token leaked"},
			"active_jobs":1,
			"idle_capacity":0,
			"max_concurrent":1,
			"target_capacity":{"image":1},
			"cache_dirs":{"syft":"/var/cache/constellation/syft"},
			"cache_health":{"syft":{"path":"/var/cache/constellation/syft","configured":true,"present":true,"writable":false,"status":"read-only","error":"secret token leaked","record_count":2}},
			"token":"scanner-secret"
		}`,
		now, now.Add(-10*time.Minute)); err != nil {
		t.Fatalf("heartbeats: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/components?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewComponentsInventory(d).List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status: %d body: %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Summary    componentInventorySummaryDTO  `json:"summary"`
		Rollups    []componentInventoryRollupDTO `json:"rollups"`
		Components []componentInstanceDTO        `json:"components"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list.Components) != 2 {
		t.Fatalf("cluster components = %+v", list.Components)
	}
	rollups := map[string]componentInventoryRollupDTO{}
	for _, item := range list.Rollups {
		rollups[item.Component] = item
	}
	if rollups["scanner"].Status != "degraded" || rollups["scanner"].Instances != 1 {
		t.Fatalf("scanner rollup = %+v", rollups["scanner"])
	}
	if rollups["operator"].Status != "stale" {
		t.Fatalf("operator rollup = %+v", rollups["operator"])
	}
	if rollups["vulndb-importer"].Status != "missing" || list.Summary.Missing == 0 {
		t.Fatalf("missing importer rollup=%+v summary=%+v", rollups["vulndb-importer"], list.Summary)
	}
	if rollups["network-policy-applier"].Status != "missing" || rollups["network-policy-applier"].Kind != "deployment" {
		t.Fatalf("network-policy applier rollup=%+v", rollups["network-policy-applier"])
	}
	if _, ok := rollups["netpolicy-applier"]; ok {
		t.Fatalf("non-canonical netpolicy-applier rollup should not be present")
	}
	for _, item := range list.Components {
		if item.Component == "scanner" && (item.Status != "degraded" || item.ClusterName != "local" || item.Metadata["vulndb"] == nil) {
			t.Fatalf("scanner instance = %+v", item)
		}
		if item.Component == "scanner" {
			if _, ok := item.Metadata["token"]; ok {
				t.Fatalf("public metadata leaked token: %+v", item.Metadata)
			}
			if _, ok := item.Metadata["cache_dirs"]; ok {
				t.Fatalf("public metadata leaked cache dirs: %+v", item.Metadata)
			}
			vuln := item.Metadata["vulndb"].(map[string]any)
			if _, ok := vuln["path"]; ok {
				t.Fatalf("public metadata leaked vulndb path: %+v", vuln)
			}
			if _, ok := vuln["error"]; ok {
				t.Fatalf("public metadata leaked vulndb error: %+v", vuln)
			}
		}
	}

	router := chi.NewRouter()
	router.Get("/api/v1/components/{id}", NewComponentsInventory(d).Get)
	router.Get("/api/v1/components/{id}/diagnostics", NewComponentsInventory(d).Diagnostics)
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/components/"+scannerID.String(), nil)
	getReq = getReq.WithContext(WithSubject(getReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status: %d body: %s", getRec.Code, getRec.Body.String())
	}
	var detail struct {
		Component componentInstanceDTO `json:"component"`
	}
	if err := json.NewDecoder(getRec.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.Component.ID != scannerID || detail.Component.Status != "degraded" || detail.Component.Role != "scanner" || detail.Component.Kind != "deployment" {
		t.Fatalf("detail = %+v", detail.Component)
	}

	diagReq := httptest.NewRequest(http.MethodGet, "/api/v1/components/"+scannerID.String()+"/diagnostics", nil)
	diagReq = diagReq.WithContext(WithSubject(diagReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	diagRec := httptest.NewRecorder()
	router.ServeHTTP(diagRec, diagReq)
	if diagRec.Code != http.StatusOK {
		t.Fatalf("diagnostics status: %d body: %s", diagRec.Code, diagRec.Body.String())
	}
	var diag componentDiagnosticsDTO
	if err := json.NewDecoder(diagRec.Body).Decode(&diag); err != nil {
		t.Fatal(err)
	}
	if diag.AdminGate != "manage-org" || diag.Component.ID != scannerID || diag.Status.State != "degraded" || !diag.Status.Degraded {
		t.Fatalf("diagnostics status = %+v gate=%q component=%+v", diag.Status, diag.AdminGate, diag.Component)
	}
	if _, ok := diag.Component.Metadata["token"]; ok {
		t.Fatalf("diagnostics component leaked token metadata: %+v", diag.Component.Metadata)
	}
	checks := map[string]componentDiagnosticCheck{}
	for _, check := range diag.Diagnostics {
		checks[check.Key] = check
	}
	if checks["scanner_vulndb"].Status != "degraded" {
		t.Fatalf("scanner_vulndb diagnostic = %+v", checks["scanner_vulndb"])
	}
	if checks["scanner_vulndb"].Reason != "redacted by diagnostics policy" {
		t.Fatalf("scanner_vulndb reason = %q", checks["scanner_vulndb"].Reason)
	}
	if checks["scanner_cache_syft"].Status != "read-only" {
		t.Fatalf("scanner cache diagnostic = %+v", checks["scanner_cache_syft"])
	}
	counters := map[string]componentDiagnosticCounter{}
	for _, counter := range diag.Counters {
		counters[counter.Key] = counter
	}
	if counters["active_jobs"].Value == nil || counters["vulndb_record_count"].Value == nil || counters["cache_syft_records"].Value == nil {
		t.Fatalf("diagnostic counters = %+v", diag.Counters)
	}
	config := map[string]componentDiagnosticConfig{}
	for _, item := range diag.Config {
		config[item.Key] = item
	}
	if config["vulndb.bundle_version"].Value != "fixture" {
		t.Fatalf("diagnostic config = %+v", diag.Config)
	}
	if len(diag.Debug.Notes) == 0 || diag.Debug.ProfilingEnabled || diag.Debug.LiveLogsEnabled || diag.Debug.SupportBundleEnabled {
		t.Fatalf("debug gates = %+v", diag.Debug)
	}

	missingReq := httptest.NewRequest(http.MethodGet, "/api/v1/components/"+uuid.NewString()+"/diagnostics", nil)
	missingReq = missingReq.WithContext(WithSubject(missingReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	missingRec := httptest.NewRecorder()
	router.ServeHTTP(missingRec, missingReq)
	if missingRec.Code != http.StatusNotFound {
		t.Fatalf("missing diagnostics status: %d body: %s", missingRec.Code, missingRec.Body.String())
	}
}

func TestComponentDiagnosticsForRuntimeAgentMetadata(t *testing.T) {
	now := time.Now().UTC()
	component := componentInstanceDTO{
		ID:            uuid.New(),
		Component:     "runtime-agent",
		DisplayName:   "Runtime agent",
		Role:          "enforcer",
		Scope:         "node",
		Kind:          "daemonset",
		Status:        "healthy",
		Hostname:      "node-a",
		UptimeSeconds: 120,
		FirstSeenAt:   now.Add(-2 * time.Minute),
		LastSeenAt:    now,
	}
	diag := componentDiagnosticsFor(component, map[string]any{
		"processed_events": float64(18),
		"dropped_events":   float64(2),
		"dp": map[string]any{
			"status":            "ready",
			"starts":            float64(1),
			"keepalive_replied": float64(3),
			"taps_current":      float64(2),
			"connection_events": float64(7),
		},
		"enforcer": map[string]any{
			"node":             "node-a",
			"dp_status":        "ready",
			"ebpf_status":      "ready",
			"probe_status":     "ready",
			"policy_mode":      "monitor",
			"processed_events": float64(18),
			"dropped_events":   float64(2),
		},
	}, "", now)
	checks := map[string]componentDiagnosticCheck{}
	for _, check := range diag.Diagnostics {
		checks[check.Key] = check
	}
	if checks["enforcer_dp_status"].Status != "ready" || checks["enforcer_ebpf_status"].Status != "ready" || checks["enforcer_policy_mode"].Value != "monitor" {
		t.Fatalf("enforcer checks = %+v", checks)
	}
	counters := map[string]componentDiagnosticCounter{}
	for _, counter := range diag.Counters {
		counters[counter.Key] = counter
	}
	if counters["processed_events"].Value == nil || counters["dropped_events"].Value == nil || counters["dp.connection_events"].Value == nil {
		t.Fatalf("enforcer counters = %+v", diag.Counters)
	}
}

func TestComponentsInventoryRuntimeAgentDiagnosticsIncludesNodeProbes(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"component_heartbeats", "host_facts", "host_containers", "host_processes", "host_packages", "host_cis"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	heartbeatID := uuid.New()
	node := "node-probe-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	now := time.Now().UTC()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Runtime Agent Diagnostics Test')`, orgID, "runtime-agent-diagnostics-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Runtime Agent Diagnostics User')`, userID, orgID, "runtime-agent-diagnostics-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, last_heartbeat_at)
VALUES ($1, $2, 'local', 'k3s', 'connected', $3)`, clusterID, orgID, now); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (
    id, org_id, cluster_id, component, version, commit, hostname,
    uptime_seconds, restart_count, metadata, last_seen_at, first_seen_at
) VALUES ($1, $2, $3, 'runtime-agent', 'test', 'abcdef123456', 'runtime-agent-pod-0',
          300, 0, $4::jsonb, $5, $5)`,
		heartbeatID, orgID, clusterID,
		`{"node":"`+node+`","enforcer":{"node":"`+node+`","dp_status":"ready","ebpf_status":"ready","probe_status":"ready","policy_mode":"monitor"}}`,
		now); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_facts (
    org_id, cluster_id, node, os_id, os_version_id, kernel_release, arch,
    btf_present, cgroup_version, nfqueue_capable, cni_name, cri_runtime,
    facts, observed_at
) VALUES ($1, $2, $3, 'ubuntu', '24.04', '6.8.0-test', 'amd64',
          true, 2, true, 'flannel', 'containerd', '{}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-4*time.Minute)); err != nil {
		t.Fatalf("host facts: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_containers (org_id, cluster_id, node, container_count, runtime, socket, payload, observed_at)
VALUES ($1, $2, $3, 3, 'containerd', '/run/containerd/containerd.sock',
        '{"items":[{"name":"api","image":"example/api:dev"}]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-time.Minute)); err != nil {
		t.Fatalf("host containers: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_processes (org_id, cluster_id, node, process_count, items_count, payload, observed_at)
VALUES ($1, $2, $3, 42, 10, '{"items":[{"pid":1,"comm":"systemd"}]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-time.Minute)); err != nil {
		t.Fatalf("host processes: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_packages (org_id, cluster_id, node, package_count, source, distro, payload, observed_at)
VALUES ($1, $2, $3, 111, 'dpkg', 'ubuntu', '{"items":[]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-30*time.Minute)); err != nil {
		t.Fatalf("host packages: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO host_cis (org_id, cluster_id, node, profile, passed, failed, warned, skipped, payload, observed_at)
VALUES ($1, $2, $3, 'linux-node', 12, 1, 2, 3, '{"checks":[]}'::jsonb, $4)`,
		orgID, clusterID, node, now.Add(-time.Hour)); err != nil {
		t.Fatalf("host cis: %v", err)
	}

	router := chi.NewRouter()
	router.Get("/api/v1/components/{id}/diagnostics", NewComponentsInventory(d).Diagnostics)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/components/"+heartbeatID.String()+"/diagnostics", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("diagnostics status: %d body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	var diag componentDiagnosticsDTO
	if err := json.Unmarshal([]byte(body), &diag); err != nil {
		t.Fatal(err)
	}
	checks := map[string]componentDiagnosticCheck{}
	for _, check := range diag.Diagnostics {
		checks[check.Key] = check
	}
	if checks["node_container_probe"].Status != "ready" || checks["node_process_probe"].Status != "ready" || checks["node_host_facts"].Status != "ready" {
		t.Fatalf("node probe checks = %+v", checks)
	}
	if checks["node_cis_failures"].Status != "degraded" {
		t.Fatalf("node CIS failure check = %+v", checks["node_cis_failures"])
	}
	counters := map[string]componentDiagnosticCounter{}
	for _, counter := range diag.Counters {
		counters[counter.Key] = counter
	}
	if counters["node_container_count"].Value == nil || counters["node_process_count"].Value == nil || counters["node_package_count"].Value == nil {
		t.Fatalf("node counters = %+v", diag.Counters)
	}
	config := map[string]componentDiagnosticConfig{}
	for _, item := range diag.Config {
		config[item.Key] = item
	}
	if config["node.cni_name"].Value != "flannel" || config["node.cri_runtime"].Value != "containerd" {
		t.Fatalf("node config = %+v", diag.Config)
	}
	if strings.Contains(body, "containerd.sock") || strings.Contains(body, "systemd") || strings.Contains(body, "example/api:dev") {
		t.Fatalf("diagnostics leaked raw node payload: %s", body)
	}
}
