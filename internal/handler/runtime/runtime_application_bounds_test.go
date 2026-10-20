//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/response"
)

func TestRuntimeApplicationBoundsPreserveNativeRowsAndRejectBeforeAlerting(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, cluster := uuid.New(), uuid.New()
	t.Cleanup(func() {
		cleanup := context.WithoutCancel(ctx)
		_, _ = pool.Exec(cleanup, `DELETE FROM runtime_threats WHERE org_id=$1`, org)
		_, _ = pool.Exec(cleanup, `DELETE FROM cluster_init_bundles WHERE org_id=$1`, org)
		_, _ = pool.Exec(cleanup, `DELETE FROM runtime_agent_tokens WHERE org_id=$1`, org)
		_, _ = pool.Exec(cleanup, `DELETE FROM clusters WHERE org_id=$1`, org)
		_, _ = pool.Exec(cleanup, `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "application-"+org.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'application-bounds')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	raw, token, err := handler.IssueRuntimeAgentToken(ctx, pool, org, "application-bounds-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted) VALUES($1,$2,'application-bounds',NOW()+INTERVAL '1 hour',$3,'test','\x00')`, org, cluster, token); err != nil {
		t.Fatal(err)
	}
	// Legacy invalid data is retained; new validation must not rewrite history.
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,node,threat_id,severity,application,reported_at) VALUES($1,$2,'retained-application',2022,7,-1,NOW())`, org, cluster); err != nil {
		t.Fatal(err)
	}
	values := []uint32{0, 1001, math.MaxUint16, math.MaxUint16 + 1, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32}
	rows := make([]ThreatIngestRow, len(values))
	for i, application := range values {
		rows[i] = ThreatIngestRow{Node: "new-application", ThreatID: 2022, Application: application, Severity: 7, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 30000 + i, DstPort: 44000 + i}
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	alerts := 0
	h := NewRuntimeThreats(d).WithResponseEngine(func(context.Context, uuid.UUID, uuid.UUID, response.Event) { alerts++ })
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/runtime-threats:bulk", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, r)
	var receipt ThreatIngestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || w.Code != 200 || receipt.Accepted != 3 || receipt.Rejected != 4 || receipt.Alerts != 3 || alerts != 3 {
		t.Fatalf("unexpected bounded ingest receipt status=%d receipt=%+v alerts=%d error=%v", w.Code, receipt, alerts, err)
	}
	var applications []int32
	if err := pool.QueryRow(ctx, `SELECT array_agg(COALESCE(application,0) ORDER BY COALESCE(application,0)) FROM runtime_threats WHERE org_id=$1 AND node='new-application'`, org).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if len(applications) != 3 || applications[0] != 0 || applications[1] != 1001 || applications[2] != math.MaxUint16 {
		t.Fatalf("native applications changed: %v", applications)
	}
	var retained int32
	if err := pool.QueryRow(ctx, `SELECT application FROM runtime_threats WHERE org_id=$1 AND node='retained-application'`, org).Scan(&retained); err != nil || retained != -1 {
		t.Fatalf("retained application changed: %d %v", retained, err)
	}
}

func TestEvaluateApplicationIDsDoNotAliasNegativeRetainedValues(t *testing.T) {
	cases := []struct {
		rule uint32
		flow int32
		want bool
	}{
		{1001, 1001, true}, {math.MaxUint16, math.MaxUint16, true},
		{math.MaxInt32, math.MaxInt32, true}, {math.MaxUint32, -1, false},
		{math.MaxInt32 + 1, math.MinInt32, false}, {1001, -1, false},
		{0, -1, true}, // Wildcard retains its established match-any behavior.
	}
	for _, test := range cases {
		t.Run(strconv.FormatUint(uint64(test.rule), 10)+"/"+strconv.FormatInt(int64(test.flow), 10), func(t *testing.T) {
			rule := &dp.PolicyRule{Action: dp.PolicyActionAllow, Apps: []dp.PolicyApp{{App: test.rule}}}
			action, fallback := EvaluateFlow([]*dp.PolicyRule{rule}, dp.PolicyActionDeny, false, EvaluatedFlow{Application: test.flow})
			if (action == EvalActionAllow) != test.want || fallback == test.want {
				t.Fatalf("application match=%s fallback=%v wantMatch=%v", action, fallback, test.want)
			}
		})
	}
}

func TestThreatCategoryFullWireRange(t *testing.T) {
	for _, id := range []int64{-1, math.MinInt32, 0, 1001, 49999, 50000, math.MaxInt32, math.MaxUint32} {
		want := "ips"
		if id == 49999 {
			want = "waf"
		}
		if got := threatCategory(id); got != want {
			t.Errorf("threat ID %d category %s want %s", id, got, want)
		}
	}
}
