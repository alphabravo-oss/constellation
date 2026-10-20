//go:build integration

package netpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
)

// TestNetworkFlowsIngest_DPFields exercises Wave 4: a row from the NeuVector
// dp data-plane carries real client_bytes/server_bytes/sessions/application/
// policy_action/policy_id/threat_id/severity/ep_mac, plus source="dp". The
// handler must accept all of these, derive `bytes` from client+server when
// the legacy field is omitted, and store every column.
func TestNetworkFlowsIngest_DPFields(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	// A deployment so the handler's cluster-resolver finds a cluster_id.
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx,
		`SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	tokenName := "wave4-test-" + uuid.New().String()
	raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgID, clusterID, "flow-test-"+uuid.NewString(), tokenID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM network_flows WHERE org_id=$1 AND ep_mac=$2`,
			orgID, "76:0d:1e:a2:58:a1")
	})

	now := time.Now().UTC()
	body, _ := json.Marshal([]handler.FlowIngestRow{{
		SrcWorkload:  "external/1.2.3.4",
		DstWorkload:  "cluster/10.42.0.5", // server-side resolver will leave this alone if not in pod_ips
		SrcAddr:      "1.2.3.4",
		DstAddr:      "10.42.0.5",
		DstPort:      443,
		Protocol:     "tcp",
		L7Protocol:   "http",
		ClientBytes:  4096,
		ServerBytes:  8192,
		Sessions:     7,
		Application:  1001, // HTTP
		PolicyAction: "alert",
		PolicyID:     42,
		ThreatID:     2022, // SQL_INJECTION
		Severity:     5,
		EPMAC:        "76:0d:1e:a2:58:a1",
		Source:       "dp",
		At:           now,
	}})

	h := NewNetworkFlowsIngest(d)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/network-flows:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	// An acknowledged replay must not insert data or increment rule hits again.
	producer := uuid.NewString()
	// The original legacy upload remains a separate observation. Replay a new
	// identified batch twice and count only its distinct EP MAC.
	identity := uuid.MustParse(producer)
	replayMAC := net.HardwareAddr(append([]byte{0x7a}, identity[:5]...)).String()
	replayBody := bytes.ReplaceAll(body, []byte("76:0d:1e:a2:58:a1"), []byte(replayMAC))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_flows WHERE org_id=$1 AND ep_mac=$2`, orgID, replayMAC)
		_, _ = pool.Exec(context.Background(), `DELETE FROM telemetry_producers WHERE producer_id=$1`, producer)
	})
	for range 2 {
		request := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/network-flows:bulk", bytes.NewReader(replayBody))
		request.Header.Set("Authorization", "Bearer "+raw)
		request.Header.Set("X-Constellation-Producer", producer)
		request.Header.Set("X-Constellation-Sequence", "1")
		recorder := httptest.NewRecorder()
		handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusOK || recorder.Header().Get("X-Constellation-Ack") != "1" {
			t.Fatalf("replay: %d %s", recorder.Code, recorder.Body.String())
		}
	}
	var copies int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_flows WHERE org_id=$1 AND ep_mac=$2`, orgID, replayMAC).Scan(&copies); err != nil || copies != 1 {
		t.Fatalf("replay copies=%d err=%v", copies, err)
	}

	// Verify the row landed with every dp field populated and `bytes` was
	// derived from client+server (the request set bytes to 0).
	var (
		gotBytes, gotClientBytes, gotServerBytes, gotPolicyID int64
		gotSessions                                           int64
		gotApplication, gotThreatID                           int32
		gotSeverity                                           int16
		gotPolicyAction, gotEPMAC, gotSource                  string
	)
	err = pool.QueryRow(ctx, `
SELECT bytes, client_bytes, server_bytes, sessions,
       application, policy_action, policy_id, threat_id, severity,
       ep_mac, source
  FROM network_flows
 WHERE org_id=$1 AND ep_mac=$2
 ORDER BY at DESC LIMIT 1`, orgID, "76:0d:1e:a2:58:a1").
		Scan(&gotBytes, &gotClientBytes, &gotServerBytes, &gotSessions,
			&gotApplication, &gotPolicyAction, &gotPolicyID, &gotThreatID, &gotSeverity,
			&gotEPMAC, &gotSource)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if gotBytes != 4096+8192 {
		t.Errorf("bytes derived=%d want %d (= 4096+8192)", gotBytes, 4096+8192)
	}
	if gotClientBytes != 4096 || gotServerBytes != 8192 {
		t.Errorf("client/server bytes = (%d,%d) want (4096,8192)", gotClientBytes, gotServerBytes)
	}
	if gotSessions != 7 {
		t.Errorf("sessions = %d want 7", gotSessions)
	}
	if gotApplication != 1001 {
		t.Errorf("application = %d want 1001", gotApplication)
	}
	if gotPolicyAction != "alert" {
		t.Errorf("policy_action = %q want alert", gotPolicyAction)
	}
	if gotPolicyID != 42 {
		t.Errorf("policy_id = %d want 42", gotPolicyID)
	}
	if gotThreatID != 2022 {
		t.Errorf("threat_id = %d want 2022", gotThreatID)
	}
	if gotSeverity != 5 {
		t.Errorf("severity = %d want 5", gotSeverity)
	}
	if gotSource != "dp" {
		t.Errorf("source = %q want dp", gotSource)
	}
	if gotEPMAC != "76:0d:1e:a2:58:a1" {
		t.Errorf("ep_mac = %q want 76:0d:1e:a2:58:a1", gotEPMAC)
	}
}

func TestNetworkFlowsIngestLateObservationReachesRollup(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id,name,display_name) VALUES ($1,$2,$2)`, org, "late-flow-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM network_flows WHERE org_id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM network_flow_rollups WHERE org_id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id,org_id,name) VALUES ($1,$2,'late')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, org, "late", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted) VALUES ($1,$2,'late',now()+interval '1 hour',$3,'test','\x00'::bytea)`, org, cluster, tokenID); err != nil {
		t.Fatal(err)
	}
	// Use the existing watermark instead of mutating shared aggregate state.
	var watermark time.Time
	if err := pool.QueryRow(ctx, `SELECT watermark FROM network_flow_rollup_state WHERE id=true`).Scan(&watermark); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal([]handler.FlowIngestRow{{SrcWorkload: "late/source", DstWorkload: "late/destination", Protocol: "tcp", At: watermark.Add(-time.Hour), Bytes: 42, Packets: 3}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/network-flows:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	h := NewNetworkFlowsIngest(d)
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("late ingest: %d %s", w.Code, w.Body.String())
	}
	var count, bytes, packets int64
	if err := pool.QueryRow(ctx, `SELECT flow_count,sum_bytes,sum_packets FROM network_flow_rollups WHERE org_id=$1 AND cluster_id=$2`, org, cluster).Scan(&count, &bytes, &packets); err != nil || count != 1 || bytes != 42 || packets != 3 {
		t.Fatalf("late rollup count=%d bytes=%d packets=%d err=%v", count, bytes, packets, err)
	}
}

// TestNetworkFlowsIngest_HubbleSource covers NET-3: a row tagged
// source="hubble" (Cilium-eBPF clusters where the dp/iptables datapath is
// blind) must be accepted and stored with source="hubble"; an unknown source
// string must be coerced to "bpf" rather than poisoning the table.
func TestNetworkFlowsIngest_HubbleSource(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx,
		`SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	tokenName := "net3-hubble-" + uuid.New().String()
	raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgID, clusterID, "flow-test-"+uuid.NewString(), tokenID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM network_flows WHERE org_id=$1 AND src_workload IN ('net3-hubble-row','net3-unknown-row')`, orgID)
	})

	now := time.Now().UTC()
	body, _ := json.Marshal([]handler.FlowIngestRow{
		{
			SrcWorkload: "net3-hubble-row",
			DstWorkload: "external",
			Protocol:    "tcp",
			DstPort:     443,
			Bytes:       2048,
			Verdict:     "deny",
			Source:      "hubble",
			At:          now,
		},
		{
			SrcWorkload: "net3-unknown-row",
			DstWorkload: "external",
			Protocol:    "tcp",
			DstPort:     80,
			Bytes:       512,
			Source:      "bogus-source", // must be coerced to bpf
			At:          now,
		},
	})

	h := NewNetworkFlowsIngest(d)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/network-flows:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var hubbleSource string
	if err := pool.QueryRow(ctx, `
SELECT source FROM network_flows
 WHERE org_id=$1 AND src_workload='net3-hubble-row'
 ORDER BY at DESC LIMIT 1`, orgID).Scan(&hubbleSource); err != nil {
		t.Fatalf("read hubble row: %v", err)
	}
	if hubbleSource != "hubble" {
		t.Errorf("source = %q want hubble", hubbleSource)
	}

	var unknownSource string
	if err := pool.QueryRow(ctx, `
SELECT source FROM network_flows
 WHERE org_id=$1 AND src_workload='net3-unknown-row'
 ORDER BY at DESC LIMIT 1`, orgID).Scan(&unknownSource); err != nil {
		t.Fatalf("read unknown-source row: %v", err)
	}
	if unknownSource != "bpf" {
		t.Errorf("unknown source = %q want bpf (coerced)", unknownSource)
	}
}

// TestNetworkFlowsIngest_LegacyBPFStillWorks ensures a row without any Wave 4
// fields still lands cleanly with source defaulted to "bpf" and the new
// columns left NULL — so legacy agents that haven't been redeployed don't
// break when the migration runs.
func TestNetworkFlowsIngest_LegacyBPFStillWorks(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx,
		`SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	tokenName := "wave4-legacy-" + uuid.New().String()
	raw, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgID, clusterID, "flow-test-"+uuid.NewString(), tokenID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM network_flows WHERE org_id=$1 AND src_workload='legacy-bpf-test'`, orgID)
	})

	body, _ := json.Marshal([]handler.FlowIngestRow{{
		SrcWorkload: "legacy-bpf-test",
		DstWorkload: "external",
		Protocol:    "tcp",
		Bytes:       1024,
		Packets:     8,
		At:          time.Now().UTC(),
		// No Source field → defaults to "bpf". No client_bytes/etc.
	}})
	h := NewNetworkFlowsIngest(d)
	req := httptest.NewRequestWithContext(t.Context(), "POST", "/api/v1/network-flows:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var (
		gotBytes, gotPackets int64
		gotSource            string
		gotClientBytes       *int64
		gotApplication       *int32
	)
	err = pool.QueryRow(ctx, `
SELECT bytes, packets, source, client_bytes, application
  FROM network_flows
 WHERE org_id=$1 AND src_workload='legacy-bpf-test'
 ORDER BY at DESC LIMIT 1`, orgID).
		Scan(&gotBytes, &gotPackets, &gotSource, &gotClientBytes, &gotApplication)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	if gotBytes != 1024 || gotPackets != 8 {
		t.Errorf("bytes=%d packets=%d want 1024/8", gotBytes, gotPackets)
	}
	if gotSource != "bpf" {
		t.Errorf("source = %q want bpf (default)", gotSource)
	}
	if gotClientBytes != nil {
		t.Errorf("client_bytes = %v want NULL", *gotClientBytes)
	}
	if gotApplication != nil {
		t.Errorf("application = %v want NULL", *gotApplication)
	}
}
