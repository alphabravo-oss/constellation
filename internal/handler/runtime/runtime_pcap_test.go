package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestPcapNormalizeStartCaptureRequest(t *testing.T) {
	clusterID := uuid.New()
	got, err := normalizeStartCaptureRequest(StartCaptureRequest{
		ClusterID:  clusterID,
		Workload:   " payments/api ",
		DurationS:  999,
		SrcIP:      " ::ffff:10.0.0.8 ",
		DstIP:      " 8.8.8.8 ",
		DstPort:    443,
		Protocol:   "TCP",
		BPFFilter:  " tcp[13] & 2 != 0 ",
		Interface:  " eth0 ",
		FileCount:  4,
		FileSizeMB: 25,
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got.Workload != "payments/api" || got.DurationS != maxPcapDuration || got.SrcIP != "10.0.0.8" ||
		got.Protocol != "tcp" || got.BPFFilter != "tcp[13] & 2 != 0" || got.Interface != "eth0" ||
		got.FileCount != 4 || got.FileSizeMB != 25 {
		t.Fatalf("normalized request = %+v", got)
	}

	cases := []StartCaptureRequest{
		{ClusterID: clusterID, Workload: "ns/api", SrcIP: "not-an-ip"},
		{ClusterID: clusterID, Workload: "ns/api", DstPort: 70000},
		{ClusterID: clusterID, Workload: "ns/api", Protocol: "sctp"},
		{ClusterID: clusterID, Workload: "ns/api", BPFFilter: "tcp; rm -rf /"},
		{ClusterID: clusterID, Workload: "ns/api", Interface: "bad/name"},
	}
	for _, tc := range cases {
		if _, err := normalizeStartCaptureRequest(tc); err == nil {
			t.Fatalf("expected validation error for %+v", tc)
		}
	}
}

func TestPcapHTTP_RichCaptureStartListAndClaim(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	var tableExists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.runtime_pcap_captures') IS NOT NULL`).Scan(&tableExists); err != nil || !tableExists {
		t.Skipf("runtime_pcap_captures not migrated: %v", err)
	}
	for _, col := range []string{"bpf_filter", "capture_interface", "file_count", "file_size_mb"} {
		var ok bool
		if err := pool.QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1 FROM information_schema.columns
  WHERE table_schema='public' AND table_name='runtime_pcap_captures' AND column_name=$1
)`, col).Scan(&ok); err != nil || !ok {
			t.Skipf("runtime_pcap_captures.%s not migrated: %v", col, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	h := NewPcapHTTP(d)
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'PCAP Group Test')`, orgID, "pcap-group-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'PCAP Operator')`, userID, orgID, "pcap-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'pcap-cluster', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_pcap_captures WHERE org_id=$1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})

	body, _ := json.Marshal(StartCaptureRequest{
		ClusterID:  clusterID,
		Workload:   "payments/api",
		DurationS:  240,
		SrcIP:      "10.0.0.5",
		DstIP:      "10.0.0.9",
		DstPort:    443,
		Protocol:   "TCP",
		BPFFilter:  "tcp[13] & 2 != 0",
		Interface:  "eth0",
		FileCount:  4,
		FileSizeMB: 25,
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runtime-pcap/start", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	h.Start(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Start status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created PcapCapture
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode Start: %v", err)
	}
	if created.ID == uuid.Nil || created.DurationS != 240 || created.Protocol != "tcp" ||
		created.BPFFilter != "tcp[13] & 2 != 0" || created.Interface != "eth0" ||
		created.FileCount != 4 || created.FileSizeMB != 25 {
		t.Fatalf("created capture = %+v", created)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/api/v1/runtime-pcap?cluster_id="+clusterID.String()+"&status=pending&protocol=tcp&src_ip=10.0.0.5&dst_port=443",
		nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List status=%d body=%s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Captures []PcapCapture `json:"captures"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode List: %v", err)
	}
	if len(listed.Captures) != 1 || listed.Captures[0].ID != created.ID {
		t.Fatalf("filtered list = %+v, want only %s", listed.Captures, created.ID)
	}

	groupID := uuid.New()
	groupName := "pcap-group-" + uuid.New().String()
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, $3, $4, 'ground', '[]'::jsonb, '["payments/api"]'::jsonb, 'monitor', 'monitor')`,
		groupID, orgID, clusterID, groupName); err != nil {
		t.Fatalf("group: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_pcap_captures (org_id, cluster_id, workload, namespace, requested_by, duration_s, status)
VALUES ($1, $2, 'inventory/api', 'inventory', $3, 30, 'completed')`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("other capture: %v", err)
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet,
		"/api/v1/runtime-pcap?cluster_id="+clusterID.String()+"&group="+groupID.String(),
		nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("group List status=%d body=%s", rec.Code, rec.Body.String())
	}
	var grouped struct {
		Captures             []PcapCapture `json:"captures"`
		SelectedGroup        string        `json:"selected_group"`
		SelectedGroupMembers int           `json:"selected_group_members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &grouped); err != nil {
		t.Fatalf("decode group List: %v", err)
	}
	if grouped.SelectedGroup != groupName || grouped.SelectedGroupMembers != 1 {
		t.Fatalf("selected group metadata = %+v", grouped)
	}
	if len(grouped.Captures) != 1 || grouped.Captures[0].ID != created.ID {
		t.Fatalf("group captures = %+v, want only %s", grouped.Captures, created.ID)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/runtime-pcap/claim?cluster_id="+clusterID.String()+"&node=node-a", nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{ID: uuid.New(), OrgID: orgID, Name: "agent"}))
	h.Claim(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Claim status=%d body=%s", rec.Code, rec.Body.String())
	}
	var claimed PcapCapture
	if err := json.Unmarshal(rec.Body.Bytes(), &claimed); err != nil {
		t.Fatalf("decode Claim: %v", err)
	}
	if claimed.ID != created.ID || claimed.Status != PcapStatusRunning || claimed.ClaimedByNode != "node-a" ||
		claimed.BPFFilter != created.BPFFilter || claimed.Interface != created.Interface ||
		claimed.FileCount != created.FileCount || claimed.FileSizeMB != created.FileSizeMB {
		t.Fatalf("claimed capture = %+v", claimed)
	}
}
