package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestSystemHealth_ListReturnsNeutralOperationsInventory(t *testing.T) {
	w := httptest.NewRecorder()
	NewSystemHealth().List(w, httptest.NewRequest("GET", "/api/v1/system-health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var got systemHealthOverviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	requiredComponents := []string{
		"api",
		"db",
		"scanner-workers",
		"admission-webhook",
		"cve-importer",
		"integrations-delivery",
		"backups",
		"audit-chain",
		"cluster-sensors",
	}
	if got.Summary.ComponentsTotal != len(got.Components) {
		t.Fatalf("summary total mismatch: %+v components=%d", got.Summary, len(got.Components))
	}
	if got.Summary.Status == "" || got.Summary.GeneratedAt == "" {
		t.Fatalf("incomplete summary: %+v", got.Summary)
	}
	if got.Summary.ActiveIncidents != len(got.Incidents) {
		t.Fatalf("active incident summary mismatch: %+v incidents=%d", got.Summary, len(got.Incidents))
	}
	if got.Summary.OpenActions != len(got.RemediationActions) {
		t.Fatalf("open action summary mismatch: %+v actions=%d", got.Summary, len(got.RemediationActions))
	}
	if len(got.Incidents) != 0 || len(got.RemediationActions) != 0 {
		t.Fatalf("no-storage system health must not invent incidents/actions: incidents=%+v actions=%+v", got.Incidents, got.RemediationActions)
	}

	byID := map[string]systemHealthComponentDTO{}
	for _, component := range got.Components {
		byID[component.ID] = component
		if component.Name == "" || component.Domain == "" || component.Status == "" || component.Owner == "" || component.SLO == "" || component.LastChecked == "" || component.Summary == "" {
			t.Fatalf("incomplete component: %+v", component)
		}
		if len(component.Signals) == 0 {
			t.Fatalf("missing signals for %s", component.ID)
		}
		for _, signal := range component.Signals {
			if signal.Name == "" || signal.Status == "" || signal.Value == "" || signal.Threshold == "" || signal.Evidence == "" {
				t.Fatalf("incomplete signal for %s: %+v", component.ID, signal)
			}
		}
	}
	for _, id := range requiredComponents {
		if _, ok := byID[id]; !ok {
			t.Fatalf("missing required component %q", id)
		}
	}
}

func TestSystemHealth_OverviewMatchesListShape(t *testing.T) {
	w := httptest.NewRecorder()
	NewSystemHealth().Overview(w, httptest.NewRequest("GET", "/api/v1/system-health/overview", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}

	var got struct {
		Summary            systemHealthSummaryDTO       `json:"summary"`
		Components         []systemHealthComponentDTO   `json:"components"`
		Incidents          []systemHealthIncidentDTO    `json:"incidents"`
		RemediationActions []systemHealthRemediationDTO `json:"remediation_actions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.ComponentsTotal == 0 || len(got.Components) == 0 {
		t.Fatalf("unexpected empty overview: %+v", got)
	}
	if len(got.Incidents) != 0 || len(got.RemediationActions) != 0 {
		t.Fatalf("overview should not include invented incidents/actions: %+v", got)
	}
}

func TestSystemHealth_ScannerMetadataSignals(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	pool := d.Pool()
	ctx := context.Background()

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'System Health Scanner Test')`,
		orgID, "system-health-scanner-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Scanner Admin')`,
		userID, orgID, "scanner-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'scanner-health-test')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats (
    org_id, cluster_id, component, version, commit, hostname, uptime_seconds, restart_count, metadata, last_seen_at
) VALUES ($1,$2,'scanner','test-version','abc123','scanner-0',120,0,$3::jsonb,$4)`,
		orgID, clusterID,
		`{
		  "max_concurrent": 4,
		  "active_jobs": 1,
		  "idle_capacity": 3,
		  "engine_db": {
		    "trivy": {"download_revision": "trivy-download", "applied_revision": "trivy-applied", "status": "ready"},
		    "grype": {"download_revision": "grype-download", "applied_revision": "grype-applied", "status": "ready"}
		  },
		  "target_capacity": {"image": 2, "host": 4},
		  "active_jobs_by_target_type": {"image": 1},
		  "vulndb": {"enabled": true, "ready": false, "status": "unavailable", "error": "missing bundle"},
		  "cache_health": {"syft": {"configured": true, "present": true, "writable": true, "status": "ready"}}
		}`,
		time.Now().UTC()); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/system-health", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewSystemHealth(d).List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got systemHealthOverviewDTO
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Summary.Status != "degraded" || got.Summary.Degraded != 1 {
		t.Fatalf("summary = %+v", got.Summary)
	}
	if len(got.Heartbeats) != 1 || got.Heartbeats[0].Status != "degraded" {
		t.Fatalf("heartbeats = %+v", got.Heartbeats)
	}
	if got.Heartbeats[0].Metadata == nil || got.Heartbeats[0].Metadata["vulndb"] == nil {
		t.Fatalf("heartbeat metadata missing: %+v", got.Heartbeats[0])
	}
	assertScannerDBRevisionMetadata(t, got.Heartbeats[0].Metadata)
	if len(got.VersionDrift) != 1 || got.VersionDrift[0].Degraded != 1 {
		t.Fatalf("cluster drift = %+v", got.VersionDrift)
	}
	var scanners *systemHealthComponentDTO
	for i := range got.Components {
		if got.Components[i].ID == "scanner-workers" {
			scanners = &got.Components[i]
			break
		}
	}
	if scanners == nil || scanners.Status != "warning" {
		t.Fatalf("scanner component = %+v", scanners)
	}
	foundVulnSignal := false
	for _, signal := range scanners.Signals {
		if signal.Name == "scanner VulnDB" {
			foundVulnSignal = true
			if signal.Status != "warning" || signal.Value != "1 degraded" {
				t.Fatalf("vulndb signal = %+v", signal)
			}
		}
	}
	if !foundVulnSignal {
		t.Fatalf("missing scanner VulnDB signal: %+v", scanners.Signals)
	}

	router := chi.NewRouter()
	router.Get("/api/v1/system-health/clusters/{cluster_id}", NewSystemHealth(d).Cluster)
	clusterReq := httptest.NewRequest(http.MethodGet, "/api/v1/system-health/clusters/"+clusterID.String(), nil)
	clusterReq = clusterReq.WithContext(WithSubject(clusterReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	clusterResponse := httptest.NewRecorder()
	router.ServeHTTP(clusterResponse, clusterReq)
	if clusterResponse.Code != http.StatusOK {
		t.Fatalf("cluster status=%d body=%s", clusterResponse.Code, clusterResponse.Body.String())
	}
	var clusterHealth struct {
		Heartbeats []heartbeatDTO `json:"heartbeats"`
	}
	if err := json.NewDecoder(clusterResponse.Body).Decode(&clusterHealth); err != nil {
		t.Fatal(err)
	}
	if len(clusterHealth.Heartbeats) != 1 {
		t.Fatalf("cluster heartbeats = %+v", clusterHealth.Heartbeats)
	}
	assertScannerDBRevisionMetadata(t, clusterHealth.Heartbeats[0].Metadata)
}

func assertScannerDBRevisionMetadata(t *testing.T, metadata map[string]any) {
	t.Helper()
	engineDB := metadataMap(metadata, "engine_db")
	for engine, revisions := range map[string][2]string{
		"trivy": {"trivy-download", "trivy-applied"},
		"grype": {"grype-download", "grype-applied"},
	} {
		values := metadataMap(engineDB, engine)
		if values["download_revision"] != revisions[0] || values["applied_revision"] != revisions[1] {
			t.Fatalf("%s engine revisions = %+v", engine, values)
		}
	}
}
