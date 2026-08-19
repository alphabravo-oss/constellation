package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestClusters_HealthValidatesClusterIDAndSubject(t *testing.T) {
	r := chi.NewRouter()
	r.Get("/api/v1/clusters/{id}/health", NewClusters(nil).Health)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/clusters/not-a-uuid/health", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid id status: %d", w.Code)
	}

	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/api/v1/clusters/"+uuid.NewString()+"/health", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("missing subject status: %d", w.Code)
	}
}

func TestClusters_HealthUsesRegisteredClusterState(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	bundleID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Cluster Health Test')`,
		orgID, "cluster-health-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, agent_version, last_heartbeat_at)
VALUES ($1, $2, 'prod-east', 'k3s', 'connected', 'v1.2.3', NOW() - INTERVAL '30 seconds')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats
  (org_id, cluster_id, component, version, commit, hostname, uptime_seconds, restart_count, last_seen_at, last_error)
VALUES
  ($1, $2, 'operator', 'v1.2.3', 'abc', 'operator-0', 120, 0, NOW() - INTERVAL '20 seconds', ''),
  ($1, $2, 'scanner', 'v1.2.3', 'abc', 'scanner-0', 90, 1, NOW() - INTERVAL '30 seconds', ''),
  ($1, $2, 'runtime-agent', 'v1.2.3', 'abc', 'node-a', 10, 2, NOW() - INTERVAL '10 minutes', 'last probe failed')`,
		orgID, clusterID); err != nil {
		t.Fatalf("heartbeats: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO cluster_init_bundles
  (id, org_id, cluster_id, name, distro, expires_at, kek_fingerprint, contents_encrypted)
VALUES ($1, $2, $3, 'prod-east', 'k3s', NOW() + INTERVAL '7 days', 'test-fingerprint', $4)`,
		bundleID, orgID, clusterID, []byte("sealed")); err != nil {
		t.Fatalf("bundle: %v", err)
	}

	r := chi.NewRouter()
	r.Get("/api/v1/clusters/{id}/health", NewClusters(d).Health)

	req := httptest.NewRequest("GET", "/api/v1/clusters/"+clusterID.String()+"/health", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}

	var got struct {
		ClusterID string `json:"cluster_id"`
		Summary   struct {
			Status            string `json:"status"`
			ConnectedSensors  int    `json:"connected_sensors"`
			ExpectedSensors   int    `json:"expected_sensors"`
			LastCheckIn       string `json:"last_check_in"`
			RegistrationState string `json:"registration_state"`
		} `json:"summary"`
		Components []struct {
			Name         string `json:"name"`
			Status       string `json:"status"`
			Version      string `json:"version"`
			Desired      int    `json:"desired"`
			Ready        int    `json:"ready"`
			LastSeenAt   string `json:"last_seen_at"`
			RestartCount int    `json:"restart_count"`
			LastError    string `json:"last_error"`
		} `json:"components"`
		Gates []struct {
			Name     string `json:"name"`
			Status   string `json:"status"`
			Evidence string `json:"evidence"`
		} `json:"gates"`
		Registration struct {
			BundleID      string `json:"bundle_id"`
			ExpiresAt     string `json:"expires_at"`
			RotateCommand string `json:"rotate_command"`
			HelmCommand   string `json:"helm_command"`
		} `json:"registration"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ClusterID != clusterID.String() {
		t.Fatalf("cluster id: %s", got.ClusterID)
	}
	if got.Summary.Status != "degraded" || got.Summary.ConnectedSensors != 2 ||
		got.Summary.ExpectedSensors != len(expectedClusterComponents) ||
		got.Summary.RegistrationState != "bundle-active" {
		t.Fatalf("summary: %+v", got.Summary)
	}
	if got.Summary.LastCheckIn == "" {
		t.Fatalf("missing last check-in: %+v", got.Summary)
	}
	if len(got.Components) < len(expectedClusterComponents) || len(got.Gates) != 3 {
		t.Fatalf("expected components and gates, got components=%d gates=%d", len(got.Components), len(got.Gates))
	}

	byName := map[string]struct {
		Status       string
		Ready        int
		RestartCount int
		LastError    string
	}{}
	for _, component := range got.Components {
		byName[component.Name] = struct {
			Status       string
			Ready        int
			RestartCount int
			LastError    string
		}{
			Status:       component.Status,
			Ready:        component.Ready,
			RestartCount: component.RestartCount,
			LastError:    component.LastError,
		}
	}
	if byName["scanner"].Status != "ready" || byName["scanner"].Ready != 1 || byName["scanner"].RestartCount != 1 {
		t.Fatalf("scanner component: %+v", byName["scanner"])
	}
	if byName["runtime-agent"].Status != "stale" || byName["runtime-agent"].LastError == "" {
		t.Fatalf("runtime component: %+v", byName["runtime-agent"])
	}
	if byName["admission"].Status != "missing" {
		t.Fatalf("admission component: %+v", byName["admission"])
	}
	if got.Registration.BundleID != bundleID.String() || got.Registration.ExpiresAt == "" ||
		got.Registration.RotateCommand == "" || got.Registration.HelmCommand == "" {
		t.Fatalf("registration: %+v", got.Registration)
	}
	if got.Gates[2].Status != "warn" {
		t.Fatalf("component gate: %+v", got.Gates[2])
	}

	listReq := httptest.NewRequest("GET", "/api/v1/clusters", nil)
	listReq = listReq.WithContext(WithSubject(listReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	listW := httptest.NewRecorder()
	NewClusters(d).List(listW, listReq)
	if listW.Code != http.StatusOK {
		t.Fatalf("list status: %d body=%s", listW.Code, listW.Body.String())
	}
	var listed struct {
		Clusters []struct {
			ID           string `json:"id"`
			SensorHealth struct {
				Status string `json:"status"`
				Ready  int    `json:"ready"`
				Total  int    `json:"total"`
			} `json:"sensor_health"`
			Upgrade struct {
				Available     bool   `json:"available"`
				TargetVersion string `json:"target_version"`
				RolloutStatus string `json:"rollout_status"`
			} `json:"upgrade"`
		} `json:"clusters"`
	}
	if err := json.NewDecoder(listW.Body).Decode(&listed); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listed.Clusters) != 1 || listed.Clusters[0].ID != clusterID.String() {
		t.Fatalf("listed clusters: %+v", listed.Clusters)
	}
	if listed.Clusters[0].SensorHealth.Status != "degraded" ||
		listed.Clusters[0].SensorHealth.Ready != 2 ||
		listed.Clusters[0].SensorHealth.Total != len(expectedClusterComponents) {
		t.Fatalf("list sensor health: %+v", listed.Clusters[0].SensorHealth)
	}
	if listed.Clusters[0].Upgrade.Available || listed.Clusters[0].Upgrade.TargetVersion != "v1.2.3" || listed.Clusters[0].Upgrade.RolloutStatus != "current" {
		t.Fatalf("list upgrade: %+v", listed.Clusters[0].Upgrade)
	}
}

func TestClusters_HealthIgnoresStaleReplacedInstancesForReadiness(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Cluster Health Rollout Test')`,
		orgID, "cluster-health-rollout-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, agent_version, last_heartbeat_at)
VALUES ($1, $2, 'rollout-local', 'k3s', 'connected', 'v1.2.3', NOW() - INTERVAL '15 seconds')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	for _, component := range expectedClusterComponents {
		if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats
  (org_id, cluster_id, component, version, commit, hostname, uptime_seconds, restart_count, last_seen_at, last_error)
VALUES ($1, $2, $3, 'v1.2.3', 'abc', $4, 120, 0, NOW() - INTERVAL '15 seconds', '')`,
			orgID, clusterID, component, component+"-current"); err != nil {
			t.Fatalf("fresh heartbeat %s: %v", component, err)
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO component_heartbeats
  (org_id, cluster_id, component, version, commit, hostname, uptime_seconds, restart_count, last_seen_at, last_error)
VALUES
  ($1, $2, 'operator', 'v1.2.2', 'old', 'operator-old', 30, 0, NOW() - INTERVAL '10 minutes', ''),
  ($1, $2, 'discoverer', 'v1.2.2', 'old', 'discoverer-old', 30, 0, NOW() - INTERVAL '10 minutes', '')`,
		orgID, clusterID); err != nil {
		t.Fatalf("stale heartbeats: %v", err)
	}

	r := chi.NewRouter()
	r.Get("/api/v1/clusters/{id}/health", NewClusters(d).Health)
	req := httptest.NewRequest("GET", "/api/v1/clusters/"+clusterID.String()+"/health", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body=%s", w.Code, w.Body.String())
	}

	var got struct {
		Summary struct {
			Status           string `json:"status"`
			ConnectedSensors int    `json:"connected_sensors"`
			ExpectedSensors  int    `json:"expected_sensors"`
		} `json:"summary"`
		Components []struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Desired int    `json:"desired"`
			Ready   int    `json:"ready"`
		} `json:"components"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Summary.Status != "healthy" ||
		got.Summary.ConnectedSensors != len(expectedClusterComponents) ||
		got.Summary.ExpectedSensors != len(expectedClusterComponents) {
		t.Fatalf("summary: %+v", got.Summary)
	}
	for _, component := range got.Components {
		switch component.Name {
		case "operator", "discoverer":
			if component.Status != "ready" || component.Ready != 1 || component.Desired != 1 {
				t.Fatalf("%s component should ignore stale replaced instance: %+v", component.Name, component)
			}
		}
	}
}
