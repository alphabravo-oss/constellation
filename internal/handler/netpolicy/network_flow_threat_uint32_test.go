//go:build integration

package netpolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestNetworkFlowThreatUint32PreservesEntireWireRange(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, cluster := uuid.New(), uuid.New()
	t.Cleanup(func() {
		cleanup := context.WithoutCancel(ctx)
		_, _ = pool.Exec(cleanup, `DELETE FROM network_flows WHERE org_id=$1`, org)
		_, _ = pool.Exec(cleanup, `DELETE FROM network_flow_rollups WHERE org_id=$1`, org)
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
	values := []uint32{0, 1, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32}
	rows := make(handler.FlowIngestRequest, len(values))
	for i, threat := range values {
		rows[i] = handler.FlowIngestRow{SrcWorkload: "application/source", DstWorkload: "application/destination", Protocol: "tcp", DstPort: 40000 + i, Application: 1001, ThreatID: threat, Source: "dp", At: time.Now().UTC()}
	}
	body, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	h := NewNetworkFlowsIngest(d)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/v1/network-flows:bulk", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(h.Bulk)).ServeHTTP(w, r)
	var receipt FlowIngestResponse
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || w.Code != 200 || receipt.Accepted != 5 || receipt.Rejected != 0 {
		t.Fatalf("unexpected bounded ingest receipt status=%d receipt=%+v error=%v body=%s", w.Code, receipt, err, w.Body.String())
	}
	var applications []int64
	if err := pool.QueryRow(ctx, `SELECT array_agg(COALESCE(threat_id,0) ORDER BY COALESCE(threat_id,0)) FROM network_flows WHERE org_id=$1`, org).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if len(applications) != 5 || applications[0] != 0 || applications[1] != 1 || applications[2] != math.MaxInt32 || applications[3] != math.MaxInt32+1 || applications[4] != math.MaxUint32 {
		t.Fatalf("native applications changed or unsupported rows persisted: %v", applications)
	}
}
