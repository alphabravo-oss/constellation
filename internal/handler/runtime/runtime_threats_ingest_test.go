package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/response"
	"github.com/google/uuid"
)

// TestRuntimeThreats_BulkRoundTrip covers Wave 5: agent POSTs a DPI threat
// (the SQL_INJECTION signature, ID 2022) with the captured packet bytes,
// and the handler:
//   - Persists every field including the bytea packet
//   - Defaults reported_at to `at` when omitted
//   - Truncates oversized packets to maxThreatPacketBytes
//   - Rejects rows with threat_id = 0
func TestRuntimeThreats_BulkRoundTrip(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	tokenName := "wave5-test-" + uuid.New().String()
	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM runtime_agent_tokens WHERE name = $1`, tokenName)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM runtime_threats WHERE org_id=$1 AND node='wave5-node'`, orgID)
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM pod_ips WHERE org_id=$1 AND namespace='payments' AND pod_name='api-7d9c'`, orgID)
	})

	if _, err := pool.Exec(ctx, `
INSERT INTO pod_ips (org_id, cluster_id, namespace, pod_name, deployment, kind, ip)
VALUES ($1, $2, 'payments', 'api-7d9c', 'api', 'Deployment', '10.42.0.6'::inet)
ON CONFLICT (org_id, cluster_id, pod_uid, ip)
DO UPDATE SET namespace = EXCLUDED.namespace,
              pod_name = EXCLUDED.pod_name,
              deployment = EXCLUDED.deployment,
              kind = EXCLUDED.kind,
              last_seen_at = NOW()`, orgID, clusterID); err != nil {
		t.Fatalf("pod ip: %v", err)
	}

	// Real-looking SQL_INJECTION threat with a small captured packet.
	packet := []byte("GET /products?id=1' OR '1'='1 HTTP/1.1\r\nHost: app\r\n\r\n")
	// Plus one row with an oversized fake packet to exercise the truncate.
	oversize := bytes.Repeat([]byte("A"), maxThreatPacketBytes+128)
	// Plus a row that must be rejected (threat_id = 0).
	bogus := ThreatIngestRow{ThreatID: 0, At: time.Now()}

	body, _ := json.Marshal([]ThreatIngestRow{
		{
			At:          time.Now().UTC(),
			Node:        "wave5-node",
			EPMAC:       "76:0d:1e:a2:58:a1",
			ThreatID:    2022, // SQL_INJECTION
			Severity:    7,
			Action:      0,
			Application: 1001, // HTTP
			Msg:         "SQL injection pattern matched",
			IPProto:     6,
			SrcIP:       "10.42.0.5",
			SrcPort:     49000,
			DstIP:       "10.42.0.6",
			DstPort:     8080,
			Packet:      packet,
			PktLen:      len(packet),
			CapLen:      len(packet),
			PktIngress:  true,
			SessIngress: true,
			TapMode:     true,
		},
		{
			At:       time.Now().UTC(),
			Node:     "wave5-node",
			ThreatID: 2009, // SSL_HEARTBLEED
			Severity: 9,
			Packet:   oversize,
			PktLen:   len(oversize),
			CapLen:   len(oversize),
		},
		bogus,
	})

	h := NewRuntimeThreats(d)
	req := httptest.NewRequest("POST", "/api/v1/runtime-threats:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res ThreatIngestResponse
	_ = json.NewDecoder(w.Body).Decode(&res)
	if res.Accepted != 2 {
		t.Fatalf("accepted=%d want 2", res.Accepted)
	}
	if res.Rejected != 1 {
		t.Fatalf("rejected=%d want 1 (threat_id=0)", res.Rejected)
	}

	// Verify the SQL_INJECTION row.
	var (
		gotThreatID, gotApp                int32
		gotSeverity                        int16
		gotMsg, gotSrcIP, gotDstIP, gotMAC string
		gotWorkload, gotNamespace, gotPod  string
		gotPkt                             []byte
		gotPktLen                          int
		gotPktIngress                      bool
	)
	err = pool.QueryRow(ctx, `
SELECT threat_id, severity, application, msg, src_ip, dst_ip, ep_mac,
       COALESCE(workload_id,''), COALESCE(namespace,''), COALESCE(pod_name,''),
       packet, pkt_len, pkt_ingress
  FROM runtime_threats
 WHERE org_id=$1 AND threat_id=2022
 ORDER BY at DESC LIMIT 1`, orgID).
		Scan(&gotThreatID, &gotSeverity, &gotApp, &gotMsg, &gotSrcIP, &gotDstIP, &gotMAC,
			&gotWorkload, &gotNamespace, &gotPod,
			&gotPkt, &gotPktLen, &gotPktIngress)
	if err != nil {
		t.Fatalf("read SQL_INJECTION row: %v", err)
	}
	if gotThreatID != 2022 || gotSeverity != 7 || gotApp != 1001 {
		t.Errorf("threat fields = (id=%d, sev=%d, app=%d) want (2022,7,1001)",
			gotThreatID, gotSeverity, gotApp)
	}
	if gotMAC != "76:0d:1e:a2:58:a1" {
		t.Errorf("ep_mac = %q want 76:0d:1e:a2:58:a1", gotMAC)
	}
	if gotSrcIP != "10.42.0.5" || gotDstIP != "10.42.0.6" {
		t.Errorf("ips = (%s,%s) want (10.42.0.5,10.42.0.6)", gotSrcIP, gotDstIP)
	}
	if gotWorkload != "payments/api" || gotNamespace != "payments" || gotPod != "" {
		t.Errorf("attribution = (%q,%q,%q) want (payments/api,payments,'')", gotWorkload, gotNamespace, gotPod)
	}
	if !bytes.Equal(gotPkt, packet) {
		t.Errorf("packet bytes round-trip mismatch (got %d bytes, want %d)", len(gotPkt), len(packet))
	}
	if !gotPktIngress {
		t.Error("pkt_ingress = false want true")
	}

	// Verify the oversize packet got truncated to maxThreatPacketBytes.
	var bigPktLen int
	err = pool.QueryRow(ctx, `
SELECT pkt_len FROM runtime_threats
 WHERE org_id=$1 AND threat_id=2009 ORDER BY at DESC LIMIT 1`, orgID).
		Scan(&bigPktLen)
	if err != nil {
		t.Fatalf("read SSL_HEARTBLEED row: %v", err)
	}
	if bigPktLen != maxThreatPacketBytes {
		t.Errorf("oversize packet stored pkt_len=%d want %d (truncated)",
			bigPktLen, maxThreatPacketBytes)
	}
}

func TestRuntimeThreats_V2SuppressLogSkipsThreatRow(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	tokenName := "threat-v2-suppress-" + uuid.New().String()
	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	workloadID := "payments/api-" + uuid.New().String()
	ruleName := "threat-v2-suppress-" + uuid.New().String()
	conds, _ := json.Marshal([]response.Condition{{Type: response.CondLevel, Value: "high"}})
	acts, _ := json.Marshal([]response.Action{{Kind: response.ActionSuppressLog}})
	sel, _ := json.Marshal(response.WorkloadSelector{})
	var ruleID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO response_rules_v2 (org_id, name, description, enabled, event_type, conditions, actions, workload_match)
VALUES ($1, $2, '', true, 'threat', $3, $4, $5) RETURNING id`,
		orgID, ruleName, conds, acts, sel).Scan(&ruleID); err != nil {
		t.Fatalf("insert response rule: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
		_, _ = pool.Exec(context.Background(), `DELETE FROM response_rules_v2 WHERE id=$1`, ruleID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_threats WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, workloadID)
	})

	body, _ := json.Marshal([]ThreatIngestRow{{
		At:         time.Now().UTC(),
		Node:       "threat-v2-suppress-node",
		WorkloadID: workloadID,
		Namespace:  "payments",
		PodName:    "api",
		ThreatID:   2022,
		Severity:   4,
		Msg:        "SQL injection pattern matched",
		IPProto:    6,
		SrcIP:      "10.42.0.5",
		SrcPort:    49000,
		DstIP:      "10.42.0.6",
		DstPort:    8080,
	}})

	h := NewRuntimeThreats(d).
		WithAudit(audit.New(pool)).
		WithResponseEngine(NewResponseDispatch(d, nil)).
		WithResponseDecision(NewResponseDecision(d))
	req := httptest.NewRequest("POST", "/api/v1/runtime-threats:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var res ThreatIngestResponse
	_ = json.NewDecoder(w.Body).Decode(&res)
	if res.Accepted != 0 || res.Alerts != 0 {
		t.Fatalf("response accepted=%d alerts=%d, want 0/0 for suppressed threat", res.Accepted, res.Alerts)
	}

	var threatRows, alertRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM runtime_threats WHERE org_id=$1 AND workload_id=$2`, orgID, workloadID).Scan(&threatRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='runtime.alert.dpi'`, orgID, workloadID).Scan(&alertRows); err != nil {
		t.Fatal(err)
	}
	if threatRows != 0 || alertRows != 0 {
		t.Fatalf("suppressed threat wrote runtime_threats=%d runtime_alert_audits=%d, want 0/0", threatRows, alertRows)
	}
	var enforced string
	if err := pool.QueryRow(ctx, `
SELECT COALESCE(after->>'enforced','')
  FROM audit_events
 WHERE org_id=$1 AND target_id=$2 AND action='response_rule_v2.action.suppress_log'`,
		orgID, workloadID).Scan(&enforced); err != nil {
		t.Fatalf("expected v2 suppress-log audit row: %v", err)
	}
	if enforced != "suppressed_log" {
		t.Fatalf("v2 suppress-log enforced=%q want suppressed_log", enforced)
	}
}

// TestThreatCategory pins the NeuVector-parity threat_id->category mapping that the
// ?category= filter relies on: built-in IPS/IDS DPI signatures (incl. SQL_INJECTION 2022
// and the flood detectors 1001-1003) are "ips" — NOT "waf"; DLP rules occupy [20000,40000)
// and custom WAF-sensor rules [40000,50000). The previous dlp_name_hash heuristic mislabeled
// every built-in signature as 'waf' and real WAF hits as 'dlp'.
func TestThreatCategory(t *testing.T) {
	cases := []struct {
		id   int32
		want string
	}{
		{0, "ips"},
		{1001, "ips"}, // SYN_FLOOD
		{2006, "ips"}, // PING_DEATH
		{2022, "ips"}, // SQL_INJECTION (built-in DPI, not WAF)
		{2027, "ips"},
		{19999, "ips"},
		{20000, "dlp"}, // MinDlpRuleID
		{30000, "dlp"}, // predefined DLP
		{39999, "dlp"},
		{40000, "waf"}, // MinWafRuleID
		{49999, "waf"},
		{50000, "ips"}, // above MaxWafRuleID -> falls back to ips bucket
	}
	for _, c := range cases {
		if got := threatCategory(c.id); got != c.want {
			t.Errorf("threatCategory(%d) = %q want %q", c.id, got, c.want)
		}
	}
}

// TestRuntimeThreats_CategoryFilter is the regression for the mislabel bug: it ingests one
// built-in IPS signature (2022), one DLP rule hit (20001), and one custom WAF rule hit
// (40001), then asserts the ?category= filter buckets each into the correct engine via the
// threat_id range — in particular that ?category=waf returns the WAF hit (and NOT the IPS
// signature) and ?category=ips returns the IPS signature.
func TestRuntimeThreats_CategoryFilter(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	node := "cat-filter-node-" + uuid.New().String()
	tokenName := "cat-filter-" + uuid.New().String()
	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_threats WHERE org_id=$1 AND node=$2`, orgID, node)
	})

	// dlp_name_hash is deliberately set on the IPS row and left 0 on the WAF row to prove the
	// classification no longer keys on the hash (the old bug): if it still did, these two would
	// be swapped.
	body, _ := json.Marshal([]ThreatIngestRow{
		{At: time.Now().UTC(), Node: node, ThreatID: 2022, Severity: 7, DlpNameHash: 999}, // IPS built-in, hash set
		{At: time.Now().UTC(), Node: node, ThreatID: 20001, Severity: 5, DlpNameHash: 0},  // DLP rule
		{At: time.Now().UTC(), Node: node, ThreatID: 40001, Severity: 6, DlpNameHash: 0},  // WAF rule, hash unset
	})
	h := NewRuntimeThreats(d)
	req := httptest.NewRequest("POST", "/api/v1/runtime-threats:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest status=%d body=%s", w.Code, w.Body.String())
	}

	// listCategory issues GET /runtime-threats?category=<cat> as the org's user and returns the
	// threat_ids (restricted to this test's node) so cross-test rows don't interfere.
	listCategory := func(cat string) []int32 {
		t.Helper()
		lreq := httptest.NewRequest("GET", "/api/v1/runtime-threats?category="+cat, nil)
		lreq = lreq.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: orgID}))
		lw := httptest.NewRecorder()
		h.List(lw, lreq)
		if lw.Code != http.StatusOK {
			t.Fatalf("list category=%s status=%d body=%s", cat, lw.Code, lw.Body.String())
		}
		var resp struct {
			Threats []RuntimeThreatRow `json:"threats"`
		}
		if err := json.NewDecoder(lw.Body).Decode(&resp); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		var ids []int32
		for _, tr := range resp.Threats {
			if tr.Node == node {
				ids = append(ids, tr.ThreatID)
				if tr.Category != cat {
					t.Errorf("category=%s returned row threat_id=%d with category=%q", cat, tr.ThreatID, tr.Category)
				}
			}
		}
		return ids
	}

	if got := listCategory("ips"); len(got) != 1 || got[0] != 2022 {
		t.Errorf("category=ips returned %v, want [2022]", got)
	}
	if got := listCategory("dlp"); len(got) != 1 || got[0] != 20001 {
		t.Errorf("category=dlp returned %v, want [20001]", got)
	}
	if got := listCategory("waf"); len(got) != 1 || got[0] != 40001 {
		t.Errorf("category=waf returned %v, want [40001]", got)
	}
}

func TestRuntimeThreats_GroupFilter(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx, `SELECT id FROM clusters WHERE org_id=$1 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}

	groupID := uuid.New()
	groupName := "runtime-threats-" + uuid.New().String()
	node := "group-threat-node-" + uuid.New().String()
	memberWorkload := "payments/api-" + uuid.New().String()
	otherWorkload := "inventory/api-" + uuid.New().String()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_threats WHERE org_id=$1 AND node=$2`, orgID, node)
		_, _ = pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, groupID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, $3, $4, 'ground', '[]'::jsonb, to_jsonb(ARRAY[$5::text]), 'monitor', 'monitor')`,
		groupID, orgID, clusterID, groupName, memberWorkload); err != nil {
		t.Fatalf("group: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_threats
  (org_id, cluster_id, node, workload_id, namespace, threat_id, severity, action, reported_at, at)
VALUES
  ($1, $2, $3, $4, 'payments', 2022, 7, 0, NOW(), NOW()),
  ($1, $2, $3, $5, 'inventory', 2023, 6, 0, NOW(), NOW())`,
		orgID, clusterID, node, memberWorkload, otherWorkload); err != nil {
		t.Fatalf("threats: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/v1/runtime-threats?cluster_id="+clusterID.String()+"&group="+groupID.String(), nil)
	req = req.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: orgID}))
	rec := httptest.NewRecorder()
	NewRuntimeThreats(d).List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got struct {
		Threats              []RuntimeThreatRow `json:"threats"`
		SelectedGroup        string             `json:"selected_group"`
		SelectedGroupMembers int                `json:"selected_group_members"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SelectedGroup != groupName || got.SelectedGroupMembers != 1 {
		t.Fatalf("selected group metadata = %+v", got)
	}
	if len(got.Threats) != 1 || got.Threats[0].WorkloadID != memberWorkload {
		t.Fatalf("group-filtered threats = %+v", got.Threats)
	}
}

func TestNeuVectorThreatName(t *testing.T) {
	cases := []struct {
		id   uint32
		want string
	}{
		{2022, "SQL_INJECTION"},
		{2009, "SSL_HEARTBLEED"},
		{2024, "DNS_TUNNELING"},
		{0, ""},
		{9999, "threat_9999"},
	}
	for _, c := range cases {
		if got := handler.NeuVectorThreatName(c.id); got != c.want {
			t.Errorf("handler.NeuVectorThreatName(%d) = %q want %q", c.id, got, c.want)
		}
	}
}
