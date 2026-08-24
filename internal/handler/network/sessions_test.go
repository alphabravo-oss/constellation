package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestNetwork_KillSessionQueuesRequestAndAuditsTarget(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	node := "node-a"
	sessionID := int64(777)

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Session Test')`, orgID, "network-session-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Network Operator')`, userID, orgID, "network-session-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'prod-east', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_sessions
  (org_id, cluster_id, node, id, workload_id, ip_proto, application,
   client_ip, client_port, server_ip, server_port,
   client_bytes, server_bytes, client_pkts, server_pkts,
   client_state, server_state, age, idle, severity, threat_id, updated_at)
VALUES
  ($1, $2, $3, $4, 'payments/frontend', 6, 0,
   '10.42.0.10', 44120, '3.18.12.8', 443,
   1200, 800, 12, 8,
   1, 1, 30, 2, 7, 4242, NOW())`,
		orgID, clusterID, node, sessionID); err != nil {
		t.Fatalf("session: %v", err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/network/sessions/777?cluster_id="+clusterID.String()+"&node="+node, nil)
	req.RemoteAddr = "127.0.0.1:34812"
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "777")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rec := httptest.NewRecorder()

	NewNetwork(d).WithAudit(audit.New(pool)).KillSession(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var got struct {
		OK          bool   `json:"ok"`
		Queued      bool   `json:"queued"`
		SessionID   int64  `json:"session_id"`
		Node        string `json:"node"`
		ClusterID   string `json:"cluster_id"`
		AuditID     int64  `json:"audit_id"`
		RequestedAt string `json:"requested_at"`
		Target      struct {
			WorkloadID  string `json:"workload_id"`
			Application string `json:"application"`
			IPProto     string `json:"ip_proto"`
			ClientIP    string `json:"client_ip"`
			ClientPort  int    `json:"client_port"`
			ServerIP    string `json:"server_ip"`
			ServerPort  int    `json:"server_port"`
			Severity    int    `json:"severity"`
			ThreatID    int64  `json:"threat_id"`
		} `json:"target"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !got.OK || !got.Queued || got.SessionID != sessionID || got.Node != node || got.ClusterID != clusterID.String() || got.AuditID == 0 || got.RequestedAt == "" {
		t.Fatalf("unexpected response: %+v", got)
	}
	if got.Target.WorkloadID != "payments/frontend" || got.Target.Application != "HTTPS" || got.Target.IPProto != "TCP" ||
		got.Target.ClientIP != "10.42.0.10" || got.Target.ClientPort != 44120 || got.Target.ServerIP != "3.18.12.8" || got.Target.ServerPort != 443 ||
		got.Target.Severity != 7 || got.Target.ThreatID != 4242 {
		t.Fatalf("unexpected target: %+v", got.Target)
	}

	var queuedBy uuid.UUID
	if err := pool.QueryRow(ctx, `
SELECT requested_by
  FROM network_session_kills
 WHERE org_id = $1 AND cluster_id = $2 AND node = $3 AND session_id = $4`,
		orgID, clusterID, node, sessionID).Scan(&queuedBy); err != nil {
		t.Fatalf("queued row: %v", err)
	}
	if queuedBy != userID {
		t.Fatalf("requested_by=%s want %s", queuedBy, userID)
	}

	var auditRows int
	targetID := clusterID.String() + "/" + node + "/777"
	if err := pool.QueryRow(ctx, `
SELECT count(*)::int
  FROM audit_events
 WHERE org_id = $1 AND actor_id = $2
   AND action = 'network.session.kill.queued'
   AND target_kind = 'network_session'
   AND target_id = $3`,
		orgID, userID, targetID).Scan(&auditRows); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if auditRows != 1 {
		t.Fatalf("audit rows=%d want 1", auditRows)
	}
}

func TestNetwork_SessionsReturnsTruncationMetadata(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Session Metadata Test')`, orgID, "network-session-meta-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'prod-east', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	for i := int64(1); i <= 3; i++ {
		clientPort := 44000 + int(i)
		clientBytes := 1000 + i
		age := int(i)
		if _, err := pool.Exec(ctx, `
INSERT INTO network_sessions
  (org_id, cluster_id, node, id, workload_id, ip_proto,
   client_ip, client_port, server_ip, server_port,
   client_bytes, server_bytes, client_pkts, server_pkts, age, idle, updated_at)
VALUES
  ($1, $2, 'node-a', $3, 'payments/frontend', 6,
   '10.42.0.10', $4, '3.18.12.8', 443,
   $5, 500, 10, 5, $6, 1, NOW())`,
			orgID, clusterID, i, clientPort, clientBytes, age); err != nil {
			t.Fatalf("session %d: %v", i, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/network/sessions?cluster_id="+clusterID.String()+"&limit=2", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewNetwork(d).Sessions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var got struct {
		Sessions  []sessionDTO `json:"sessions"`
		Total     int          `json:"total"`
		Limit     int          `json:"limit"`
		HasMore   bool         `json:"has_more"`
		ClusterID string       `json:"cluster_id"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Sessions) != 2 || got.Total != 3 || got.Limit != 2 || !got.HasMore || got.ClusterID != clusterID.String() {
		t.Fatalf("unexpected sessions metadata: %+v", got)
	}
}

func TestNetwork_SessionsAppliesServerSideFilters(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Session Filter Test')`, orgID, "network-session-filter-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'prod-east', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, 'payments-tier', 'ground', '[]'::jsonb, '["payments/frontend"]'::jsonb, 'monitor', 'monitor')`,
		orgID, clusterID); err != nil {
		t.Fatalf("group: %v", err)
	}
	seed := func(id int64, node, workload string, proto int, clientIP string, clientPort int, serverIP string, serverPort int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
INSERT INTO network_sessions
  (org_id, cluster_id, node, id, workload_id, ip_proto,
   client_ip, client_port, server_ip, server_port,
   client_bytes, server_bytes, client_pkts, server_pkts, age, idle, updated_at)
VALUES
  ($1, $2, $3, $4, $5, $6,
   $7, $8, $9, $10,
   1000, 500, 10, 5, 10, 1, NOW())`,
			orgID, clusterID, node, id, workload, proto, clientIP, clientPort, serverIP, serverPort); err != nil {
			t.Fatalf("session %d: %v", id, err)
		}
	}
	seed(1, "node-a", "payments/frontend", 6, "10.42.0.10", 44120, "3.18.12.8", 443)
	seed(2, "node-a", "payments/frontend", 17, "10.42.0.10", 53000, "10.96.0.10", 53)
	seed(3, "node-b", "inventory/api", 6, "10.42.1.20", 43120, "10.42.2.30", 8080)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/network/sessions?cluster_id="+clusterID.String()+"&protocol=tcp&application=https&port=443&peer=3.18&workload=payments&node=node-a", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewNetwork(d).Sessions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Sessions []sessionDTO `json:"sessions"`
		Total    int          `json:"total"`
		HasMore  bool         `json:"has_more"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Total != 1 || got.HasMore || len(got.Sessions) != 1 || got.Sessions[0].ID != 1 || got.Sessions[0].Application != "HTTPS" {
		t.Fatalf("unexpected filtered sessions: %+v", got)
	}

	groupReq := httptest.NewRequest(http.MethodGet, "/api/v1/network/sessions?cluster_id="+clusterID.String()+"&group=payments-tier", nil)
	groupReq = groupReq.WithContext(authctx.WithSubject(groupReq.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	groupRec := httptest.NewRecorder()
	NewNetwork(d).Sessions(groupRec, groupReq)
	if groupRec.Code != http.StatusOK {
		t.Fatalf("group status=%d body=%s", groupRec.Code, groupRec.Body.String())
	}
	var grouped struct {
		Sessions             []sessionDTO `json:"sessions"`
		Total                int          `json:"total"`
		SelectedGroup        string       `json:"selected_group"`
		SelectedGroupMembers int          `json:"selected_group_members"`
	}
	if err := json.NewDecoder(groupRec.Body).Decode(&grouped); err != nil {
		t.Fatalf("decode grouped: %v", err)
	}
	if grouped.Total != 2 || len(grouped.Sessions) != 2 || grouped.SelectedGroup != "payments-tier" || grouped.SelectedGroupMembers != 1 {
		t.Fatalf("unexpected group-filtered sessions: %+v", grouped)
	}

	bad := httptest.NewRequest(http.MethodGet, "/api/v1/network/sessions?cluster_id="+clusterID.String()+"&protocol=bad", nil)
	bad = bad.WithContext(authctx.WithSubject(bad.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	badRec := httptest.NewRecorder()
	NewNetwork(d).Sessions(badRec, bad)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("bad protocol status=%d body=%s", badRec.Code, badRec.Body.String())
	}
}
