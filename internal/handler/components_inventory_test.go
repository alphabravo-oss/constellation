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
	if len(diag.Debug.Notes) == 0 || diag.Debug.ProfilingEnabled || diag.Debug.LiveLogsEnabled || !diag.Debug.SupportBundleEnabled {
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

func TestComponentsInventoryRequiredAndOptionalRoleRollups(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)

	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.component_heartbeats')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: component_heartbeats migration not applied (%v)", err)
	}

	orgID, clusterID, emptyClusterID := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "inventory-roles-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID); err != nil {
			t.Errorf("delete inventory roles org: %v", err)
		}
	})
	for _, cluster := range []uuid.UUID{clusterID, emptyClusterID} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, $3)`, cluster, orgID, "inventory-roles-"+cluster.String()); err != nil {
			t.Fatal(err)
		}
	}
	scannerToken := "inventory-roles-scanner-" + uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO scanner_tokens (org_id, name, token_hash) VALUES ($1, $2, $3)`,
		orgID, "inventory-roles-scanner", tokenHashForTest(scannerToken)); err != nil {
		t.Fatal(err)
	}

	roles := []struct {
		component string
		role      string
		scope     string
		kind      string
		required  bool
	}{
		{"api", "control-plane", "org", "deployment", false},
		{"frontend", "control-plane", "org", "deployment", false},
		{"operator", "controller", "cluster", "deployment", true},
		{"scanner", "scanner", "cluster", "deployment", true},
		{"vulndb-importer", "updater", "cluster", "cronjob", true},
		{"admission", "policy-enforcement", "cluster", "deployment", true},
		{"runtime-agent", "enforcer", "node", "daemonset", true},
		{"discoverer", "discovery", "cluster", "deployment", true},
		{"registry-walker", "registry-scanner", "org", "deployment", false},
		{"network-policy-applier", "policy-enforcement", "cluster", "deployment", true},
		{"k8s-compliance-collector", "compliance", "cluster", "cronjob", true},
		{"compliance-scheduler", "compliance", "org", "deployment", false},
		{"github-app", "integration", "org", "deployment", false},
		{"audit-archiver", "audit", "org", "cronjob", false},
		{"backup", "recovery", "org", "job", false},
	}
	subject := Subject{UserID: uuid.New(), OrgID: orgID}
	inventory := NewComponentsInventory(d)
	ingestHandler := AnyServiceTokenMiddleware(pool)(http.HandlerFunc(NewHeartbeats(d, nil).Ingest))
	list := func(t *testing.T, cluster *uuid.UUID) struct {
		Summary    componentInventorySummaryDTO  `json:"summary"`
		Rollups    []componentInventoryRollupDTO `json:"rollups"`
		Components []componentInstanceDTO        `json:"components"`
	} {
		t.Helper()
		path := "/api/v1/components"
		if cluster != nil {
			path += "?cluster_id=" + cluster.String()
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(WithSubject(req.Context(), subject))
		rec := httptest.NewRecorder()
		inventory.List(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("list %s: status %d body %s", path, rec.Code, rec.Body.String())
		}
		var response struct {
			Summary    componentInventorySummaryDTO  `json:"summary"`
			Rollups    []componentInventoryRollupDTO `json:"rollups"`
			Components []componentInstanceDTO        `json:"components"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	assertInventory := func(t *testing.T, cluster *uuid.UUID, observed map[string]bool) {
		t.Helper()
		response := list(t, cluster)
		rollups := make(map[string]componentInventoryRollupDTO, len(response.Rollups))
		for _, rollup := range response.Rollups {
			if _, duplicate := rollups[rollup.Component]; duplicate {
				t.Fatalf("duplicate rollup %q", rollup.Component)
			}
			rollups[rollup.Component] = rollup
		}
		wantRollups, wantHealthy, wantMissing, wantInstances := 0, 0, 0, 0
		for _, role := range roles {
			if cluster != nil && role.scope == "org" {
				if _, found := rollups[role.component]; found {
					t.Errorf("org-scoped %q included in cluster rollups", role.component)
				}
				continue
			}
			wantRollups++
			rollup, found := rollups[role.component]
			if !found {
				t.Errorf("missing rollup for %q", role.component)
				continue
			}
			wantStatus := "not-observed"
			wantMissingCount, wantInstanceCount := 0, 0
			if role.required {
				wantStatus = "missing"
				wantMissing++
				wantMissingCount = 1
			}
			if observed[role.component] {
				wantStatus = "healthy"
				wantHealthy++
				wantInstances++
				wantInstanceCount = 1
				if role.required {
					wantMissing--
				}
				wantMissingCount = 0
			}
			if rollup.Status != wantStatus || rollup.Expected != role.required || rollup.Missing != wantMissingCount ||
				rollup.Instances != wantInstanceCount || rollup.Healthy != wantInstanceCount ||
				rollup.Role != role.role || rollup.Scope != role.scope || rollup.Kind != role.kind {
				t.Errorf("%q rollup = %+v; want status=%q expected=%t role=%q scope=%q kind=%q instances=%d missing=%d",
					role.component, rollup, wantStatus, role.required, role.role, role.scope, role.kind, wantInstanceCount, wantMissingCount)
			}
		}
		if len(rollups) != wantRollups || len(response.Components) != wantInstances || response.Summary.Components != wantRollups ||
			response.Summary.TotalInstances != wantInstances || response.Summary.Healthy != wantHealthy || response.Summary.Missing != wantMissing ||
			response.Summary.Degraded != 0 || response.Summary.Stale != 0 || response.Summary.Drift != 0 || response.Summary.Crashlooping != 0 {
			t.Errorf("inventory rollups=%d instances=%d summary=%+v; want rollups=%d instances=%d healthy=%d missing=%d",
				len(rollups), len(response.Components), response.Summary, wantRollups, wantInstances, wantHealthy, wantMissing)
		}
		for _, component := range response.Components {
			if !observed[component.Component] || component.Status != "healthy" {
				t.Errorf("unexpected component instance: %+v", component)
			}
			if component.Scope == "org" && component.ClusterID != nil || component.Scope != "org" && (component.ClusterID == nil || *component.ClusterID != clusterID) {
				t.Errorf("component instance has incorrect scope: %+v", component)
			}
			if cluster != nil && (component.ClusterID == nil || *component.ClusterID != *cluster) {
				t.Errorf("component outside requested cluster: %+v", component)
			}
		}
	}
	ingest := func(t *testing.T, component string, cluster *uuid.UUID) {
		t.Helper()
		body := heartbeatBody{Component: component, Version: "test", Commit: "abcdef123456", Hostname: component + "-fixture", UptimeSeconds: 60}
		if cluster != nil {
			body.ClusterID = cluster.String()
		}
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/heartbeats", strings.NewReader(string(payload)))
		req.Header.Set("Authorization", "Bearer "+scannerToken)
		rec := httptest.NewRecorder()
		ingestHandler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ingest %q: status %d body %s", component, rec.Code, rec.Body.String())
		}
	}

	t.Run("not observed", func(t *testing.T) {
		assertInventory(t, nil, nil)
		assertInventory(t, &clusterID, nil)
	})
	ingest(t, "api", nil)
	ingest(t, "operator", &clusterID)
	t.Run("partially ingested", func(t *testing.T) {
		assertInventory(t, nil, map[string]bool{"api": true, "operator": true})
		assertInventory(t, &clusterID, map[string]bool{"operator": true})
	})
	for _, role := range roles {
		if role.component == "api" || role.component == "operator" {
			continue
		}
		if role.scope == "org" {
			ingest(t, role.component, nil)
		} else {
			ingest(t, role.component, &clusterID)
		}
	}
	allObserved := make(map[string]bool, len(roles))
	clusterObserved := make(map[string]bool)
	for _, role := range roles {
		allObserved[role.component] = true
		if role.scope != "org" {
			clusterObserved[role.component] = true
		}
	}
	t.Run("all roles healthy", func(t *testing.T) {
		assertInventory(t, nil, allObserved)
		assertInventory(t, &clusterID, clusterObserved)
		assertInventory(t, &emptyClusterID, nil)
	})
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

func TestComponentsInventoryRoleDiagnosticsAPI(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.component_heartbeats')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: component_heartbeats migration not applied (%v)", err)
	}

	orgID, foreignOrgID := uuid.New(), uuid.New()
	clusterID := uuid.New()
	for _, id := range []uuid.UUID{orgID, foreignOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, id, "role-diagnostics-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, orgID, foreignOrgID); err != nil {
			t.Errorf("delete role diagnostics orgs: %v", err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'role-diagnostics')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	operatorID, agentID, scannerID, foreignID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, row := range []struct {
		id, orgID uuid.UUID
		component string
		metadata  string
	}{
		{operatorID, orgID, "operator", `{"leader_election":true}`},
		{agentID, orgID, "runtime-agent", `{"enforcer":{"node":"node-a","dp_status":"ready","ebpf_status":"ready","probe_status":"ready","policy_mode":"monitor"},"token":"agent-secret"}`},
		{scannerID, orgID, "scanner", `{"active_jobs":1,"idle_capacity":0,"max_concurrent":1,"vulndb":{"enabled":true,"ready":false,"status":"missing-store","error":"secret token leaked"},"token":"scanner-secret"}`},
		{foreignID, foreignOrgID, "scanner", `{"vulndb":{"enabled":true,"ready":true}}`},
	} {
		var rowCluster any
		if row.orgID == orgID {
			rowCluster = clusterID
		}
		if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats
    (id, org_id, cluster_id, component, version, commit, hostname, uptime_seconds, metadata, last_seen_at, first_seen_at)
VALUES ($1, $2, $3, $4, 'test', 'current-commit', $5, 60, $6::jsonb, $7, $7)`,
			row.id, row.orgID, rowCluster, row.component, row.component+"-"+row.id.String(), row.metadata, now); err != nil {
			t.Fatalf("insert %s heartbeat: %v", row.component, err)
		}
	}

	subject := Subject{UserID: uuid.New(), OrgID: orgID}
	inventory := NewComponentsInventory(d)
	router := chi.NewRouter()
	router.Get("/api/v1/components", inventory.List)
	router.Get("/api/v1/components/{id}", inventory.Get)
	router.Get("/api/v1/components/{id}/diagnostics", inventory.Diagnostics)
	request := func(path string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if authenticated {
			req = req.WithContext(WithSubject(req.Context(), subject))
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	readDiagnostics := func(t *testing.T, id uuid.UUID) componentDiagnosticsDTO {
		t.Helper()
		rec := request("/api/v1/components/"+id.String()+"/diagnostics", true)
		if rec.Code != http.StatusOK {
			t.Fatalf("diagnostics %s: status %d body %s", id, rec.Code, rec.Body.String())
		}
		var diagnostics componentDiagnosticsDTO
		if err := json.Unmarshal(rec.Body.Bytes(), &diagnostics); err != nil {
			t.Fatal(err)
		}
		if diagnostics.AdminGate != "manage-org" || diagnostics.Component.ID != id || !diagnostics.Debug.SupportBundleEnabled || diagnostics.Debug.LiveLogsEnabled || diagnostics.Debug.ProfilingEnabled {
			t.Fatalf("diagnostics contract for %s: %+v", id, diagnostics)
		}
		if strings.Contains(rec.Body.String(), "agent-secret") || strings.Contains(rec.Body.String(), "scanner-secret") || strings.Contains(rec.Body.String(), "secret token leaked") {
			t.Fatalf("diagnostics leaked secret: %s", rec.Body.String())
		}
		return diagnostics
	}
	checksFor := func(diagnostics componentDiagnosticsDTO) map[string]componentDiagnosticCheck {
		checks := make(map[string]componentDiagnosticCheck, len(diagnostics.Diagnostics))
		for _, check := range diagnostics.Diagnostics {
			checks[check.Key] = check
		}
		return checks
	}

	list := request("/api/v1/components?cluster_id="+clusterID.String(), true)
	if list.Code != http.StatusOK {
		t.Fatalf("list status %d: %s", list.Code, list.Body.String())
	}
	var inventoryResponse struct {
		Components []componentInstanceDTO        `json:"components"`
		Rollups    []componentInventoryRollupDTO `json:"rollups"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &inventoryResponse); err != nil {
		t.Fatal(err)
	}
	if len(inventoryResponse.Components) != 3 {
		t.Fatalf("role instances = %+v", inventoryResponse.Components)
	}
	roles := map[string]string{"operator": "controller", "runtime-agent": "enforcer", "scanner": "scanner"}
	for _, component := range inventoryResponse.Components {
		if component.Role != roles[component.Component] || component.ClusterID == nil || *component.ClusterID != clusterID {
			t.Errorf("role-alias instance = %+v", component)
		}
	}
	for _, rollup := range inventoryResponse.Rollups {
		if role, ok := roles[rollup.Component]; ok && (rollup.Role != role || rollup.Instances != 1) {
			t.Errorf("role-alias rollup = %+v", rollup)
		}
	}

	for _, role := range []struct {
		id                                              uuid.UUID
		component, alias, status, checkKey, checkStatus string
	}{
		{operatorID, "operator", "controller", "healthy", "operator_leader_election", "ready"},
		{agentID, "runtime-agent", "enforcer", "healthy", "enforcer_dp_status", "ready"},
		{scannerID, "scanner", "scanner", "degraded", "scanner_vulndb", "degraded"},
	} {
		t.Run(role.component, func(t *testing.T) {
			diagnostics := readDiagnostics(t, role.id)
			if diagnostics.Component.Component != role.component || diagnostics.Component.Role != role.alias || diagnostics.Status.State != role.status || diagnostics.Status.Degraded != (role.status == "degraded") {
				t.Fatalf("role diagnostics = %+v", diagnostics)
			}
			checks := checksFor(diagnostics)
			if checks[role.checkKey].Status != role.checkStatus {
				t.Fatalf("role check %s = %+v", role.checkKey, checks[role.checkKey])
			}
		})
	}
	if checks := checksFor(readDiagnostics(t, agentID)); checks["enforcer_policy_mode"].Value != "monitor" || checks["node_host_facts"].Status != "missing" {
		t.Fatalf("enforcer checks = %+v", checks)
	}
	if checks := checksFor(readDiagnostics(t, scannerID)); checks["scanner_capacity"].Status != "saturated" || checks["scanner_vulndb"].Reason != "redacted by diagnostics policy" {
		t.Fatalf("scanner failure checks = %+v", checks)
	}

	if _, err := pool.Exec(ctx, `UPDATE component_heartbeats SET commit = 'old-commit', last_seen_at = $2 WHERE id = $1`, operatorID, now.Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE component_heartbeats SET last_seen_at = $2 WHERE id = $1`, agentID, now.Add(-6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	controller := readDiagnostics(t, operatorID)
	if controller.Status.State != "drift" || !controller.Status.Drift || checksFor(controller)["build"].Status != "drift" {
		t.Fatalf("controller drift = %+v", controller)
	}
	enforcer := readDiagnostics(t, agentID)
	if enforcer.Status.State != "stale" || !enforcer.Status.Stale || checksFor(enforcer)["heartbeat"].Status != "stale" {
		t.Fatalf("enforcer stale = %+v", enforcer)
	}

	for _, failure := range []struct {
		name, path    string
		authenticated bool
		wantStatus    int
	}{
		{"unauthenticated", "/api/v1/components/" + operatorID.String() + "/diagnostics", false, http.StatusUnauthorized},
		{"invalid id", "/api/v1/components/not-a-uuid/diagnostics", true, http.StatusBadRequest},
		{"unknown id", "/api/v1/components/" + uuid.NewString() + "/diagnostics", true, http.StatusNotFound},
		{"foreign org diagnostics", "/api/v1/components/" + foreignID.String() + "/diagnostics", true, http.StatusNotFound},
		{"foreign org get", "/api/v1/components/" + foreignID.String(), true, http.StatusNotFound},
	} {
		t.Run(failure.name, func(t *testing.T) {
			rec := request(failure.path, failure.authenticated)
			if rec.Code != failure.wantStatus {
				t.Fatalf("status %d, want %d: %s", rec.Code, failure.wantStatus, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), foreignID.String()) || strings.Contains(rec.Body.String(), "scanner-secret") {
				t.Fatalf("failure response leaked component data: %s", rec.Body.String())
			}
		})
	}
}
