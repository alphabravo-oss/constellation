package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestGroupEdgesHTTPRoutesRBACScopeAndAudit(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	clusterID, otherClusterID, siblingClusterID := uuid.New(), uuid.New(), uuid.New()
	otherOrgID := uuid.New()
	ctx := context.Background()
	for _, org := range []uuid.UUID{otherOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Other')`, org, "edge-http-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, otherOrgID) })
	for _, item := range []struct{ id, org uuid.UUID }{{clusterID, orgID}, {otherClusterID, otherOrgID}, {siblingClusterID, orgID}} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, item.id, item.org, "edge-http-"+item.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	groupName := "edge-http-group-" + clusterID.String()
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,$3,'ground','["default/frontend"]'::jsonb)`, orgID, clusterID, groupName); err != nil {
		t.Fatal(err)
	}
	destinationGroup := "edge-http-dest-" + clusterID.String()
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind, members) VALUES ($1,$2,$3,'ground','["default/backend"]'::jsonb)`, orgID, clusterID, destinationGroup); err != nil {
		t.Fatal(err)
	}
	siblingGroup := "edge-http-sibling-" + siblingClusterID.String()
	if _, err := pool.Exec(ctx, `INSERT INTO groups (org_id, cluster_id, name, kind) VALUES ($1,$2,$3,'ground')`, orgID, siblingClusterID, siblingGroup); err != nil {
		t.Fatal(err)
	}
	var foreignEdgeID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group) VALUES ($1,$2,'external','nodes') RETURNING id`, otherOrgID, otherClusterID).Scan(&foreignEdgeID); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token string, body any) (int, []byte) {
		t.Helper()
		var payload io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			payload = bytes.NewReader(encoded)
		}
		request, err := http.NewRequest(method, server.URL+path, payload)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := server.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	base := "/api/v1/runtime-policies/group-edges"
	valid := map[string]any{"cluster_id": clusterID, "from_group": groupName, "to_group": "external"}
	for _, test := range []struct {
		name, method, path, token string
		body                      any
		want                      int
	}{
		{"anonymous", http.MethodPost, base, "", valid, http.StatusUnauthorized},
		{"auditor create", http.MethodPost, base, auditor, valid, http.StatusForbidden},
		{"missing group", http.MethodPost, base, admin, map[string]any{"cluster_id": clusterID, "from_group": "missing", "to_group": "external"}, http.StatusBadRequest},
		{"other cluster group", http.MethodPost, base, admin, map[string]any{"cluster_id": clusterID, "from_group": siblingGroup, "to_group": "external"}, http.StatusBadRequest},
		{"foreign cluster", http.MethodPost, base, admin, map[string]any{"cluster_id": otherClusterID, "from_group": groupName, "to_group": "external"}, http.StatusNotFound},
		{"foreign cluster list", http.MethodGet, base + "?cluster_id=" + otherClusterID.String(), admin, nil, http.StatusNotFound},
		{"foreign edge expand", http.MethodPost, base + "/" + foreignEdgeID.String() + "/expand", admin, nil, http.StatusNotFound},
		{"foreign edge delete", http.MethodDelete, base + "/" + foreignEdgeID.String(), admin, nil, http.StatusNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, body := call(test.method, test.path, test.token, test.body)
			if status != test.want {
				t.Fatalf("status=%d want=%d body=%s", status, test.want, body)
			}
		})
	}
	status, body := call(http.MethodPost, base, admin, valid)
	if status != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", status, body)
	}
	var created struct {
		Edge struct {
			ID uuid.UUID `json:"id"`
		} `json:"edge"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Edge.ID == uuid.Nil {
		t.Fatalf("create edge=%+v err=%v", created, err)
	}
	protect := map[string]any{"cluster_id": clusterID, "from_group": groupName, "to_group": destinationGroup, "mode": "protect", "expand": true}
	status, body = call(http.MethodPost, base, admin, protect)
	if status != http.StatusCreated {
		t.Fatalf("protect create status=%d body=%s", status, body)
	}
	var protectedPolicies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_policies WHERE org_id=$1 AND cluster_id=$2 AND name=$3 AND mode='enforce' AND def_action=$4`, orgID, clusterID, "edge-"+groupName+"-to-"+destinationGroup, int16(dp.PolicyActionDeny)).Scan(&protectedPolicies); err != nil || protectedPolicies != 2 {
		t.Fatalf("protect policies=%d err=%v", protectedPolicies, err)
	}
	var protectedEdge struct {
		Edge struct {
			ID uuid.UUID `json:"id"`
		} `json:"edge"`
	}
	if err := json.Unmarshal(body, &protectedEdge); err != nil || protectedEdge.Edge.ID == uuid.Nil {
		t.Fatalf("protect edge=%+v err=%v", protectedEdge, err)
	}
	var expansionAttempts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND action='group_rule_edge.expand_attempt' AND target_id=$3`, orgID, adminID, clusterID.String()+"/"+groupName+"/"+destinationGroup).Scan(&expansionAttempts); err != nil || expansionAttempts != 1 {
		t.Fatalf("protect expansion attempts=%d err=%v", expansionAttempts, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM groups WHERE org_id=$1 AND name=$2`, orgID, destinationGroup); err != nil {
		t.Fatal(err)
	}
	status, body = call(http.MethodPost, base+"/"+protectedEdge.Edge.ID.String()+"/expand", admin, nil)
	if status != http.StatusConflict {
		t.Fatalf("dangling expand status=%d body=%s", status, body)
	}
	idPath := base + "/" + created.Edge.ID.String()
	for _, test := range []struct {
		method, path, token string
		want                int
	}{
		{http.MethodGet, base + "?cluster_id=" + clusterID.String(), auditor, http.StatusOK},
		{http.MethodPost, idPath + "/expand", auditor, http.StatusForbidden},
		{http.MethodDelete, idPath, auditor, http.StatusForbidden},
		{http.MethodPost, idPath + "/expand", admin, http.StatusOK},
		{http.MethodDelete, idPath, admin, http.StatusNoContent},
		{http.MethodDelete, idPath, admin, http.StatusNotFound},
	} {
		status, body := call(test.method, test.path, test.token, nil)
		if status != test.want {
			t.Fatalf("%s %s status=%d want=%d body=%s", test.method, test.path, status, test.want, body)
		}
	}
	var actions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND target_kind='group_rule_edge' AND target_id=$3 AND action IN ('group_rule_edge.upsert','group_rule_edge.expand','group_rule_edge.delete')`, orgID, adminID, created.Edge.ID.String()).Scan(&actions); err != nil || actions != 3 {
		t.Fatalf("audit events=%d err=%v", actions, err)
	}
}
