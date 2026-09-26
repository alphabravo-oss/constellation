package server

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestPolicyPrecedenceRegisteredRoutesRBACAndAudit(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	clusterID, siblingID, scopedUserID := uuid.New(), uuid.New(), uuid.New()
	for _, cluster := range []uuid.UUID{clusterID, siblingID} {
		if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, cluster, orgID, "precedence-"+cluster.String()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Scoped Precedence')`, scopedUserID, orgID, scopedUserID.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO role_assignments (user_id, role, scope_org_id, scope_cluster_id) VALUES ($1,'ClusterAdmin',$2,$3)`, scopedUserID, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM role_assignments WHERE user_id=$1`, scopedUserID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, scopedUserID)
	})
	for _, cluster := range []uuid.UUID{clusterID, siblingID} {
		if _, err := pool.Exec(ctx, `INSERT INTO network_rule_overrides (org_id, cluster_id, from_ep, to_ep, priority) VALUES ($1,$2,'default/api','default/db',1000),($1,$2,'default/worker','default/db',1010)`, orgID, cluster); err != nil {
			t.Fatal(err)
		}
	}
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	scoped := issueFor(t, signer, scopedUserID, orgID, 0)
	networkBody := map[string]any{"from": "default/worker", "to": "default/db"}
	networkPath := func(cluster uuid.UUID) string {
		return server.URL + "/api/v1/clusters/" + cluster.String() + "/network-rules:move-top"
	}
	for _, test := range []struct {
		name, token string
		cluster     uuid.UUID
		want        int
	}{
		{"anonymous", "", clusterID, http.StatusUnauthorized},
		{"auditor", auditor, clusterID, http.StatusForbidden},
		{"sibling grant", scoped, siblingID, http.StatusForbidden},
		{"own grant", scoped, clusterID, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, body := doJSON(t, http.MethodPost, networkPath(test.cluster), test.token, networkBody)
			if status != test.want {
				t.Fatalf("network move status=%d want=%d body=%v", status, test.want, body)
			}
			if status == http.StatusOK && (body["audit_attempt_id"] == nil || body["completion_audit_id"] == nil) {
				t.Fatalf("network move missing audit receipts: %v", body)
			}
		})
	}
	var ownPriority, siblingPriority, networkReceipts int
	if err := pool.QueryRow(ctx, `SELECT priority FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2 AND from_ep='default/worker'`, orgID, clusterID).Scan(&ownPriority); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT priority FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2 AND from_ep='default/worker'`, orgID, siblingID).Scan(&siblingPriority); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND action IN ('network_rule.move_top_attempt','network_rule.move_top')`, orgID, scopedUserID).Scan(&networkReceipts); err != nil {
		t.Fatal(err)
	}
	if ownPriority != 990 || siblingPriority != 1010 || networkReceipts != 2 {
		t.Fatalf("network scope priority=%d sibling=%d receipts=%d", ownPriority, siblingPriority, networkReceipts)
	}
	firstID, secondID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO response_rules_v2 (id,org_id,cluster_id,name,event_type,priority) VALUES ($1,$2,$3,'precedence-first','runtime',10),($4,$2,$3,'precedence-second','runtime',20)`, firstID, orgID, clusterID, secondID); err != nil {
		t.Fatal(err)
	}
	responsePath := server.URL + "/api/v1/response-rules-v2:reorder?cluster_id=" + clusterID.String()
	responseBody := map[string]any{"ordered_ids": []string{secondID.String(), firstID.String()}}
	foreignOrgID, foreignClusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,'Foreign Precedence')`, foreignOrgID, "foreign-precedence-"+foreignOrgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, foreignOrgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id,org_id,name) VALUES ($1,$2,$3)`, foreignClusterID, foreignOrgID, "foreign-precedence-"+foreignClusterID.String()); err != nil {
		t.Fatal(err)
	}
	if status, body := doJSON(t, http.MethodPatch, server.URL+"/api/v1/response-rules-v2:reorder?cluster_id="+foreignClusterID.String(), admin, responseBody); status != http.StatusNotFound {
		t.Fatalf("foreign response scope status=%d body=%v", status, body)
	}
	for _, test := range []struct {
		name, token string
		want        int
	}{
		{"auditor", auditor, http.StatusForbidden},
		{"cluster grant cannot reorder org-wide route", scoped, http.StatusForbidden},
		{"org admin", admin, http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, body := doJSON(t, http.MethodPatch, responsePath, test.token, responseBody)
			if status != test.want {
				t.Fatalf("response reorder status=%d want=%d body=%v", status, test.want, body)
			}
			if status == http.StatusOK && (body["audit_attempt_id"] == nil || body["completion_audit_id"] == nil) {
				t.Fatalf("response reorder missing audit receipts: %v", body)
			}
		})
	}
	var firstPriority, secondPriority, responseReceipts int
	if err := pool.QueryRow(ctx, `SELECT priority FROM response_rules_v2 WHERE id=$1`, firstID).Scan(&firstPriority); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT priority FROM response_rules_v2 WHERE id=$1`, secondID).Scan(&secondPriority); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND action IN ('response_rule_v2.reorder_attempt','response_rule_v2.reorder')`, orgID, adminID).Scan(&responseReceipts); err != nil {
		t.Fatal(err)
	}
	if firstPriority != 20 || secondPriority != 10 || responseReceipts != 2 {
		t.Fatalf("response reorder priorities=%d/%d receipts=%d", firstPriority, secondPriority, responseReceipts)
	}
}
