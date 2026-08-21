package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

func TestBaselinesSetModePersistsAcrossHandlers(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"deployments", "events", "pod_workload_links", "process_baseline_states", "process_baseline_transitions"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	deploymentID := uuid.New()
	now := time.Now().UTC()
	workloadID := "default/api"
	podWorkloadID := "default/pod/api-7d9c"

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Process Baseline Test')`, orgID, "process-baseline-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'Test User', 'x')`, userID, orgID, "process-baseline@example.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'baseline-cluster', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (
    id, org_id, cluster_id, namespace, name, kind, labels, first_seen_at, last_seen_at
) VALUES ($1, $2, $3, 'default', 'api', 'Deployment', '{"app":"api"}'::jsonb, $4, $4)`,
		deploymentID, orgID, clusterID, now); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO pod_workload_links (
    org_id, cluster_id, namespace, pod_name, pod_uid, pod_workload_id,
    owner_kind, owner_name, owner_workload_id, deployment_id, last_seen_at
) VALUES (
    $1, $2, 'default', 'api-7d9c', 'pod-uid-api', $3,
    'Deployment', 'api', $4, $5, $6
)`, orgID, clusterID, podWorkloadID, workloadID, deploymentID, now); err != nil {
		t.Fatalf("pod workload link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO events (
    org_id, cluster_id, node_id, kind, source, severity, verdict, workload_id, payload, at
) VALUES (
    $1, $2, 'test-node', 'process_exec', 'runtime-agent', 'medium', 'observed', $3,
    '{"comm":"nginx","filename":"/usr/sbin/nginx","args":["-g","daemon off;"]}'::jsonb, $4
)`, orgID, clusterID, podWorkloadID, now); err != nil {
		t.Fatalf("event: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	body, _ := json.Marshal(map[string]string{"mode": "monitor", "reason": "validated learned process set"})
	rec := httptest.NewRecorder()
	req := baselineRequest(http.MethodPost, "/api/v1/runtime/baselines/default%2Fapi/mode?cluster_id="+clusterID.String(), workloadID, bytes.NewReader(body), orgID, userID)
	NewBaselines(d, nil).SetMode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set mode status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodGet, "/api/v1/runtime/baselines/default%2Fapi?cluster_id="+clusterID.String(), workloadID, nil, orgID, userID)
	NewBaselines(d, nil).Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got baselineDetailDTO
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "monitor" || len(got.Transitions) != 1 || got.Transitions[0].Reason != "validated learned process set" {
		t.Fatalf("baseline detail = %+v", got)
	}
	if len(got.Processes) != 1 || got.Processes[0].Name != "nginx" {
		t.Fatalf("processes = %+v", got.Processes)
	}
}

// TestBaselinesHydrateFromDB is the RT-DRIFT-50 check: a persisted baseline state +
// its learned process observations are rehydrated into the in-memory map on startup,
// so BaselineMode (the drift-classifier hot path) serves the mode + learned set after
// a restart WITHOUT any prior List/Get request. Before the fix, h.state started empty
// for DB-backed workloads and drift classification silently never fired post-restart.
func TestBaselinesHydrateFromDB(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"events", "process_baseline_states"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	clusterID := uuid.New()
	now := time.Now().UTC()
	workloadID := "default/api"

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Hydrate Test')`, orgID, "hydrate-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'hydrate-cluster', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	// Persisted baseline state in monitor mode — no List/Get has run this process.
	if _, err := pool.Exec(ctx, `
INSERT INTO process_baseline_states (org_id, cluster_id, workload_id, namespace, name, mode, learn_started_at, monitor_started_at)
VALUES ($1, $2, $3, 'default', 'api', 'monitor', $4, $4)`, orgID, clusterID, workloadID, now); err != nil {
		t.Fatalf("baseline state: %v", err)
	}
	// A learned process observation attributed directly to the owner workload.
	if _, err := pool.Exec(ctx, `
INSERT INTO events (org_id, cluster_id, node_id, kind, source, severity, verdict, workload_id, payload, at)
VALUES ($1, $2, 'test-node', 'process_exec', 'runtime-agent', 'medium', 'observed', $3,
    '{"comm":"nginx","filename":"/usr/sbin/nginx","exe_path":"/usr/sbin/nginx"}'::jsonb, $4)`,
		orgID, clusterID, workloadID, now); err != nil {
		t.Fatalf("event: %v", err)
	}

	// Fresh handler, explicit hydrate (deterministic, not racing the constructor goroutine).
	b := NewBaselines(d, nil)
	if err := b.Hydrate(ctx); err != nil {
		t.Fatalf("hydrate: %v", err)
	}

	mode, set, ok := b.BaselineMode(orgID, workloadID)
	if !ok {
		t.Fatalf("expected BaselineMode to resolve the hydrated workload after restart")
	}
	if string(mode) != "monitor" {
		t.Fatalf("mode = %q want monitor", mode)
	}
	if _, has := set["nginx"]; !has {
		t.Fatalf("learned set = %v, expected to contain nginx", set)
	}
}

// TestBaselineModeDriftWiring is the WS-F2 end-to-end check: the Baselines handler's
// in-memory state feeds the events-ingest drift classifier. No DB required — we seed
// the in-memory state map directly and drive EventsIngest.classify through it.
func TestBaselineModeDriftWiring(t *testing.T) {
	orgID := uuid.New()
	b := NewBaselines(nil, nil)

	// Enforce-mode workload whose learned set contains nginx (by Name) and /bin/curl
	// (so curl is reachable by basename-of-path). sh is NOT in the set.
	b.state["cluster-a::default/api"] = &baselineState{
		WorkloadID: "default/api",
		Mode:       baseline.ModeEnforce,
		Processes: []processObservation{
			{Name: "nginx", Path: "/usr/sbin/nginx", ObservedCount: 5},
			{Name: "curl", Path: "/bin/curl", ObservedCount: 2},
		},
	}
	// A learn-mode workload — drift must never promote here.
	b.state["cluster-a::default/web"] = &baselineState{
		WorkloadID: "default/web",
		Mode:       baseline.ModeLearn,
		Processes:  []processObservation{{Name: "nginx", Path: "/usr/sbin/nginx"}},
	}

	h := NewEventsIngest(nil, nil, b.BaselineMode)

	// (a) shell exec NOT in an enforce-mode set -> high / block (Protect blocks).
	sev, verdict := h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/api"})
	if sev != "high" || verdict != "block" {
		t.Fatalf("(a) drift: expected high/block, got %s/%s", sev, verdict)
	}

	// (b) a binary that IS in the set (by basename) -> not high. curl is a shellBinary?
	// curl is not in shellBinaries, so use a process that is both a shell binary and
	// baselined: seed an enforce workload whose set contains "sh".
	b.state["cluster-a::default/shell"] = &baselineState{
		WorkloadID: "default/shell",
		Mode:       baseline.ModeEnforce,
		Processes:  []processObservation{{Name: "sh", Path: "/bin/sh"}},
	}
	sev, verdict = h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/shell"})
	if sev == "high" {
		t.Fatalf("(b) baselined shell: expected not-high (got %s/%s)", sev, verdict)
	}

	// (b') path-basename matching: bash baselined only via Path "/bin/bash".
	b.state["cluster-a::default/pathonly"] = &baselineState{
		WorkloadID: "default/pathonly",
		Mode:       baseline.ModeEnforce,
		Processes:  []processObservation{{Name: "", Path: "/bin/bash"}},
	}
	sev, _ = h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "bash", WorkloadID: "default/pathonly"})
	if sev == "high" {
		t.Fatalf("(b') path-basename baselined bash: expected not-high, got %s", sev)
	}

	// (c) learn mode -> never high (stays medium/observed).
	sev, verdict = h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/web"})
	if sev != "medium" || verdict != "observed" {
		t.Fatalf("(c) learn mode: expected medium/observed, got %s/%s", sev, verdict)
	}

	// (d) unknown workload -> BaselineMode returns ok=false -> unchanged (medium).
	mode, set, ok := b.BaselineMode(orgID, "default/nonexistent")
	if ok || set != nil || mode != "" {
		t.Fatalf("(d) unknown workload: expected ('', nil, false), got (%q, %v, %v)", mode, set, ok)
	}
	sev, verdict = h.classify(orgID, &IngestEvent{Kind: "process_exec", Comm: "sh", WorkloadID: "default/nonexistent"})
	if sev != "medium" || verdict != "observed" {
		t.Fatalf("(d) unknown workload classify: expected medium/observed, got %s/%s", sev, verdict)
	}
}

func baselineRequest(method, target, workloadID string, body *bytes.Reader, orgID, userID uuid.UUID) *http.Request {
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, body)
	}
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("workload_id", workloadID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	return req
}
