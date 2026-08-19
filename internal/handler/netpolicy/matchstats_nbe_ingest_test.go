package netpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// TestNetworkFlowsIngest_MatchCountersAndNBE exercises A7 (per-rule match
// counters written from the flow-ingest path) and B6 (cross-namespace boundary
// enforcement stamping policy_action under protect). DB-gated; skips without a
// reachable test DB + seed org/cluster/migrations.
func TestNetworkFlowsIngest_MatchCountersAndNBE(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	// Resolve the cluster the same way the ingest handler does for
	// unresolvable workloads (its default-cluster fallback), so the NBE toggle
	// and match-stats reads key on the same cluster_id the handler will write.
	var clusterID uuid.UUID
	_ = pool.QueryRow(ctx,
		`SELECT id FROM clusters WHERE org_id = $1
		 ORDER BY CASE WHEN state = 'connected' THEN 0 ELSE 1 END,
		          last_heartbeat_at DESC NULLS LAST, created_at ASC
		 LIMIT 1`, orgID).Scan(&clusterID)
	if clusterID == uuid.Nil {
		t.Skip("no seed cluster")
	}
	// Confirm migration 127/128 tables exist; skip cleanly otherwise.
	if _, err := pool.Exec(ctx, `SELECT 1 FROM network_rule_match_stats LIMIT 0`); err != nil {
		t.Skipf("migration 127 not applied: %v", err)
	}

	const ruleID = 918273
	tokenName := "a7b6-test-" + uuid.New().String()
	raw, _, err := handler.IssueRuntimeAgentToken(ctx, pool, orgID, tokenName, time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM runtime_agent_tokens WHERE name=$1`, tokenName)
		_, _ = pool.Exec(bg, `DELETE FROM network_rule_match_stats WHERE org_id=$1 AND rule_id=$2`, orgID, ruleID)
		_, _ = pool.Exec(bg, `DELETE FROM netpolicy_nbe_settings WHERE org_id=$1 AND namespace='billing'`, orgID)
		_, _ = pool.Exec(bg, `DELETE FROM network_flows WHERE org_id=$1 AND ep_mac='aa:bb:cc:dd:ee:ff'`, orgID)
	})

	// B6: put the destination namespace "billing" into protect so a
	// cross-namespace flow into it is denied.
	nbe := NewNBEStore(d)
	if err := nbe.Put(ctx, orgID, clusterID, "billing", netpolicy.NBEProtect, nil); err != nil {
		t.Fatalf("put nbe: %v", err)
	}

	// Baseline the rule counter so the assertion is a delta (robust against any
	// pre-existing row for this rule id).
	var baseCount int64
	_ = pool.QueryRow(ctx,
		`SELECT match_count FROM network_rule_match_stats
		  WHERE org_id=$1 AND cluster_id=$2 AND rule_id=$3`,
		orgID, clusterID, ruleID).Scan(&baseCount)

	now := time.Now().UTC()
	// Two flows for the same rule (cross-namespace shop -> billing) so the
	// match counter accumulates sessions (3 + 2 = 5).
	body, _ := json.Marshal([]handler.FlowIngestRow{
		{
			SrcWorkload: "shop/frontend", DstWorkload: "billing/api",
			DstPort: 8443, Protocol: "tcp", Sessions: 3,
			PolicyID: ruleID, EPMAC: "aa:bb:cc:dd:ee:ff", Source: "dp", At: now,
		},
		{
			SrcWorkload: "shop/frontend", DstWorkload: "billing/api",
			DstPort: 8443, Protocol: "tcp", Sessions: 2,
			PolicyID: ruleID, EPMAC: "aa:bb:cc:dd:ee:ff", Source: "dp", At: now.Add(time.Second),
		},
	})

	h := NewNetworkFlowsIngest(d)
	req := httptest.NewRequest("POST", "/api/v1/network-flows:bulk", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp FlowIngestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	if resp.Accepted != 2 {
		t.Fatalf("accepted=%d want 2 (body=%s)", resp.Accepted, w.Body.String())
	}
	if resp.RuleMatches != 2 {
		t.Errorf("rule_matches=%d want 2", resp.RuleMatches)
	}
	if resp.NBEDenied != 2 {
		t.Errorf("nbe_denied=%d want 2", resp.NBEDenied)
	}

	// A7: the per-rule counter accumulated both flows' sessions.
	var matchCount int64
	var lastMatched time.Time
	if err := pool.QueryRow(ctx,
		`SELECT match_count, last_matched_at FROM network_rule_match_stats
		  WHERE org_id=$1 AND cluster_id=$2 AND rule_id=$3`,
		orgID, clusterID, ruleID).Scan(&matchCount, &lastMatched); err != nil {
		t.Fatalf("read match stats: %v", err)
	}
	if matchCount-baseCount != 5 {
		t.Errorf("match_count delta=%d want 5 (3+2 sessions)", matchCount-baseCount)
	}

	// B6: protect stamped policy_action=deny on the ingested cross-ns flow.
	var gotAction string
	if err := pool.QueryRow(ctx,
		`SELECT policy_action FROM network_flows
		  WHERE org_id=$1 AND ep_mac='aa:bb:cc:dd:ee:ff' ORDER BY at DESC LIMIT 1`,
		orgID).Scan(&gotAction); err != nil {
		t.Fatalf("read flow: %v", err)
	}
	if gotAction != "deny" {
		t.Errorf("policy_action=%q want deny (NBE protect)", gotAction)
	}

	// A7: dead-rule detection — the just-matched rule is NOT dead over a wide
	// window, but IS dead over a zero-length lookback anchored in the past.
	stats := NewMatchStatsStore(d)
	dead, err := stats.DeadRules(ctx, orgID, clusterID, now.Add(2*time.Second), 24*time.Hour)
	if err != nil {
		t.Fatalf("dead rules: %v", err)
	}
	for _, s := range dead {
		if s.RuleID == ruleID {
			t.Errorf("rule %d flagged dead but it just matched", ruleID)
		}
	}
	deadFuture, err := stats.DeadRules(ctx, orgID, clusterID, now.Add(48*time.Hour), time.Hour)
	if err != nil {
		t.Fatalf("dead rules future: %v", err)
	}
	found := false
	for _, s := range deadFuture {
		if s.RuleID == ruleID {
			found = true
		}
	}
	if !found {
		t.Errorf("rule %d should be dead when window ends 48h after its last match", ruleID)
	}
}
