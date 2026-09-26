package netpolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestNetworkPolicyLifecyclePlatformRole(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ctx := context.Background()
	ensureNetworkPolicyLifecycleTables(t, pool)
	orgID, clusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Lifecycle Platform Role Test')`, orgID, "lifecycle-platform-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'lifecycle-platform-cluster')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES
		($1, $2, 'security', 'agent', 'Deployment', '{"app.kubernetes.io/part-of":"constellation"}'::jsonb),
		($1, $2, 'payments', 'api', 'Deployment', '{}'::jsonb)`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO network_flows (org_id, cluster_id, src_workload, dst_workload, protocol, dst_port, verdict) VALUES
		($1, $2, 'security/agent', 'payments/api', 'tcp', 443, 'allow')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/network/policies/lifecycle?cluster_id="+clusterID.String(), nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: uuid.New()}))
	response := httptest.NewRecorder()
	NewNetworkPolicies(database).List(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("lifecycle status %d: %s", response.Code, response.Body.String())
	}
	var body struct {
		Items []networkPolicyLifecycleDTO `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("items: %#v", body.Items)
	}
	for _, item := range body.Items {
		switch item.Workload {
		case "security/agent":
			if item.PlatformRole != "core" {
				t.Fatalf("platform policy role: %#v", item)
			}
		case "payments/api":
			if item.PlatformRole != "" {
				t.Fatalf("customer policy role: %#v", item)
			}
		default:
			t.Fatalf("unexpected policy: %#v", item)
		}
	}
}
