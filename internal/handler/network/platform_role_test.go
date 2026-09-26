package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestNetworkMapPlatformRole(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	orgID, clusterID := uuid.New(), uuid.New()
	pool := database.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Platform Role Test')`, orgID, "network-platform-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'network-platform-cluster')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES
		($1, $2, 'operations', 'houston', 'Deployment', '{"app.kubernetes.io/part-of":"astronomer"}'::jsonb),
		($1, $2, 'payments', 'api', 'Deployment', '{}'::jsonb)`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/network/map?cluster_id="+clusterID.String(), nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
	response := httptest.NewRecorder()
	NewNetwork(database).Map(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("map status %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Workloads []map[string]any `json:"workloads"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Workloads) != 2 {
		t.Fatalf("workloads: %#v", body.Workloads)
	}
	for _, workload := range body.Workloads {
		switch workload["namespace"] {
		case "operations":
			if workload["platform_role"] != "core" {
				t.Fatalf("custom install not classified: %#v", workload)
			}
		case "payments":
			if _, ok := workload["platform_role"]; ok {
				t.Fatalf("customer workload classified: %#v", workload)
			}
		default:
			t.Fatalf("unexpected workload: %#v", workload)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, src_addr, dst_addr, protocol, dst_port, sessions) VALUES
		($1, $2, 'external', 'operations/houston', '8.8.8.8', '10.0.0.10', 'tcp', 443, 1)`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/network/exposure?cluster_id="+clusterID.String(), nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
	response = httptest.NewRecorder()
	NewNetwork(database).Exposure(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("exposure status %d: %s", response.Code, response.Body.String())
	}
	var exposure struct {
		Ingress []map[string]any `json:"ingress"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &exposure); err != nil {
		t.Fatal(err)
	}
	if len(exposure.Ingress) != 1 || exposure.Ingress[0]["platform_role"] != "core" {
		t.Fatalf("exposure role: %#v", exposure.Ingress)
	}
}
