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

func TestPlatformRole(t *testing.T) {
	cases := []struct {
		name      string
		namespace string
		labels    map[string]string
		want      string
	}{
		{"kubernetes", "KUBE-SYSTEM", nil, "core"},
		{"constellation", "constellation-system", nil, "core"},
		{"astronomer", "astronomer-monitoring", nil, "core"},
		{"custom constellation", "security", map[string]string{"app.kubernetes.io/part-of": "constellation"}, "core"},
		{"custom astronomer", "operations", map[string]string{"app.kubernetes.io/part-of": "astronomer"}, "core"},
		{"custom chart", "security", map[string]string{"helm.sh/chart": "constellation-1.0.0"}, "core"},
		{"custom installation", "security", map[string]string{"app.kubernetes.io/instance": "constellation", "app.kubernetes.io/managed-by": "Helm"}, "core"},
		{"same instance without identity", "security", map[string]string{"app.kubernetes.io/instance": "constellation"}, ""},
		{"customer prefix", "astronomer-screenshot-demo", nil, ""},
		{"customer workload", "payments", map[string]string{"app": "api"}, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := PlatformRole(testCase.namespace, testCase.labels); got != testCase.want {
				t.Fatalf("PlatformRole() = %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestPlatformRoleInventoryAPIs(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	orgID, clusterID, userID, coreID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	pool := database.Pool()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Platform Role Test')`, orgID, "platform-role-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'platform-role-cluster')`, clusterID, orgID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (id, org_id, cluster_id, namespace, name, kind, labels) VALUES
		($1, $2, $3, 'security', 'agent', 'Deployment', '{"app.kubernetes.io/part-of":"constellation"}'::jsonb),
		($4, $2, $3, 'payments', 'api', 'Deployment', '{}'::jsonb)`, coreID, orgID, clusterID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO host_containers (org_id, cluster_id, node, container_count, payload, observed_at) VALUES
		($1, $2, 'node-1', 2, '{"items":[{"id":"core","name":"agent","pod_namespace":"security","pod_name":"agent-abc","state":"running"},{"id":"user","name":"api","pod_namespace":"payments","pod_name":"api-abc","state":"running"}]}'::jsonb, $3)`, orgID, clusterID, time.Now()); err != nil {
		t.Fatal(err)
	}
	subject := Subject{OrgID: orgID, UserID: userID}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/deployments", nil)
	request = request.WithContext(WithSubject(request.Context(), subject))
	response := httptest.NewRecorder()
	NewDeployments(database, nil).List(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("deployments list status %d: %s", response.Code, response.Body.String())
	}
	var listed struct {
		Deployments []map[string]any `json:"deployments"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	assertPlatformRoles(t, listed.Deployments)
	request = httptest.NewRequest(http.MethodGet, "/api/v1/deployments/"+coreID.String(), nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", coreID.String())
	request = request.WithContext(WithSubject(context.WithValue(request.Context(), chi.RouteCtxKey, route), subject))
	response = httptest.NewRecorder()
	NewDeployments(database, nil).Get(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("deployment detail status %d: %s", response.Code, response.Body.String())
	}
	var detail map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
		t.Fatal(err)
	}
	if detail["platform_role"] != "core" {
		t.Fatalf("deployment detail role: %#v", detail["platform_role"])
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/clusters/"+clusterID.String()+"/containers", nil)
	route = chi.NewRouteContext()
	route.URLParams.Add("id", clusterID.String())
	request = request.WithContext(WithSubject(context.WithValue(request.Context(), chi.RouteCtxKey, route), subject))
	response = httptest.NewRecorder()
	NewNodes(database).Containers(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("containers status %d: %s", response.Code, response.Body.String())
	}
	var containers struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &containers); err != nil {
		t.Fatal(err)
	}
	assertPlatformRoles(t, containers.Items)
}

func assertPlatformRoles(t *testing.T, items []map[string]any) {
	t.Helper()
	if len(items) != 2 {
		t.Fatalf("items = %#v", items)
	}
	for _, item := range items {
		switch item["namespace"] {
		case "security":
			if item["platform_role"] != "core" {
				t.Fatalf("core role missing: %#v", item)
			}
		case "payments":
			if _, ok := item["platform_role"]; ok {
				t.Fatalf("customer role should be omitted: %#v", item)
			}
		default:
			t.Fatalf("unexpected item: %#v", item)
		}
	}
}
