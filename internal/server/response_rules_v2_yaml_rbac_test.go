package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestResponseRulesV2YAMLRoutesRBACAndScope(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	clusterID, siblingID, scopedUserID := uuid.New(), uuid.New(), uuid.New()
	for _, cluster := range []uuid.UUID{clusterID, siblingID} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, cluster, orgID, "response-yaml-"+cluster.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Scoped YAML')`, scopedUserID, orgID, scopedUserID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (user_id, role, scope_org_id, scope_cluster_id) VALUES ($1,'ClusterAdmin',$2,$3)`, scopedUserID, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id=$1`, scopedUserID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, scopedUserID)
	})
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	scoped := issueFor(t, signer, scopedUserID, orgID, 0)
	yamlBody := "api_version: constellation.io/v1\nkind: ResponseRules\nscope: cluster\nrules:\n  - name: yaml-rbac-rule\n    enabled: true\n    priority: 10\n    event_type: runtime\n    conditions: []\n    actions: []\n    workload_match: {}\n"
	request := func(method, path, token, body string) (int, string) {
		t.Helper()
		httpRequest, err := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			httpRequest.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			httpRequest.Header.Set("Content-Type", "application/yaml")
		}
		response, err := server.Client().Do(httpRequest)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, string(data)
	}
	exportPath := "/api/v1/response-rules-v2:export?cluster_id=" + clusterID.String()
	importPath := "/api/v1/response-rules-v2:import?cluster_id=" + clusterID.String()
	for _, test := range []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"export anonymous", http.MethodGet, exportPath, "", "", http.StatusUnauthorized},
		{"export auditor", http.MethodGet, exportPath, auditor, "", http.StatusForbidden},
		{"export scoped org-wide", http.MethodGet, "/api/v1/response-rules-v2:export", scoped, "", http.StatusForbidden},
		{"export scoped sibling", http.MethodGet, "/api/v1/response-rules-v2:export?cluster_id=" + siblingID.String(), scoped, "", http.StatusForbidden},
		{"export scoped own", http.MethodGet, exportPath, scoped, "", http.StatusForbidden},
		{"export admin own", http.MethodGet, exportPath, admin, "", http.StatusOK},
		{"import auditor", http.MethodPost, importPath, auditor, yamlBody, http.StatusForbidden},
		{"import scoped sibling", http.MethodPost, "/api/v1/response-rules-v2:import?cluster_id=" + siblingID.String(), scoped, yamlBody, http.StatusForbidden},
		{"import scoped own", http.MethodPost, importPath, scoped, yamlBody, http.StatusForbidden},
		{"import admin own", http.MethodPost, importPath, admin, yamlBody, http.StatusOK},
		{"import admin foreign", http.MethodPost, "/api/v1/response-rules-v2:import?cluster_id=" + uuid.NewString(), admin, yamlBody, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, body := request(test.method, test.path, test.token, test.body)
			if status != test.want {
				t.Fatalf("status=%d want=%d body=%s", status, test.want, body)
			}
		})
	}
	var storedClusterID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT cluster_id FROM response_rules_v2 WHERE org_id=$1 AND name='yaml-rbac-rule'`, orgID).Scan(&storedClusterID); err != nil || storedClusterID != clusterID {
		t.Fatalf("rule stored in cluster=%s err=%v", storedClusterID, err)
	}
}
