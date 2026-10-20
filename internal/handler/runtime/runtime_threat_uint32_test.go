//go:build integration

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
	"github.com/alphabravocompany/constellation/pkg/response"
)

func TestRuntimeThreatUint32PreservesHighIDsAndRejectsZero(t *testing.T) {
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
	values := []uint32{0, 1, math.MaxInt32, math.MaxInt32 + 1, math.MaxUint32}
	rows := make([]ThreatIngestRow, len(values))
	for i, threat := range values {
		rows[i] = ThreatIngestRow{Node: "new-application", ThreatID: threat, Application: 1001, Severity: 7, SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: 30000 + i, DstPort: 44000 + i}
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
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || w.Code != 200 || receipt.Accepted != 4 || receipt.Rejected != 1 || receipt.Alerts != 4 || alerts != 4 {
		t.Fatalf("unexpected bounded ingest receipt status=%d receipt=%+v alerts=%d error=%v", w.Code, receipt, alerts, err)
	}
	var applications []int64
	if err := pool.QueryRow(ctx, `SELECT array_agg(threat_id ORDER BY threat_id) FROM runtime_threats WHERE org_id=$1 AND node='new-application'`, org).Scan(&applications); err != nil {
		t.Fatal(err)
	}
	if len(applications) != 4 || applications[0] != 1 || applications[1] != math.MaxInt32 || applications[2] != math.MaxInt32+1 || applications[3] != math.MaxUint32 {
		t.Fatalf("native applications changed: %v", applications)
	}
}

func TestStoredThreatNameFullUnsignedRange(t *testing.T) {
	for _, id := range []int64{2147483648, 4294967295} {
		if name := storedThreatName(id); name == "" || !strings.Contains(name, fmt.Sprint(id)) {
			t.Fatalf("ID %d name %q", id, name)
		}
	}
}

func TestThreatUint32GenerationExcludesAllNonzeroIncludingLegacy(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	p := pgfixture.Schema(t, d.Pool())
	ctx := t.Context()
	org, cluster := uuid.New(), uuid.New()
	if _, err := p.Exec(ctx, `CREATE TABLE network_flows(org_id uuid,cluster_id uuid,src_workload text,dst_workload text,src_addr text,dst_addr text,dst_port integer,protocol text,l7_protocol text,threat_id bigint,at timestamptz,fqdn text)`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO network_flows SELECT $1,$2,'prod/api','prod/db','','',443,'tcp','',n,now(),'' FROM unnest(ARRAY[0,1,2147483647,2147483648,4294967295,-1]::bigint[])n`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewRuntimePoliciesHTTP(db.NewFromPool(p), nil)
	rows, seen, excluded, err := h.fetchFlowsForGeneration(ctx, org, cluster, "prod/api", 24)
	if err != nil || seen != 6 || excluded != 5 || len(rows) != 1 {
		t.Fatalf("rows=%d seen=%d excluded=%d err=%v", len(rows), seen, excluded, err)
	}
}

func TestThreatUint32InventoryDetailAndCSVDoNotNarrow(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	org, cluster, foreign := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM runtime_threats WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'threat uint32')`, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'threat uint32')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := d.Pool().QueryRow(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,workload_id,threat_id,severity,reported_at)VALUES($1,$2,'prod/api',4294967295,7,now())RETURNING id`, org, cluster).Scan(&id); err != nil {
		t.Fatal(err)
	}
	h := NewRuntimeThreats(d)
	request := func(path string, owner uuid.UUID) *http.Request {
		return httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: owner}), "GET", path, nil)
	}
	base := "/?cluster_id=" + cluster.String() + "&q=4294967295&sort=signature&order=desc"
	for _, call := range []func(http.ResponseWriter, *http.Request){h.List, h.ListCSV} {
		w := httptest.NewRecorder()
		call(w, request(base, org))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "4294967295") {
			t.Fatalf("read %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	h.Get(w, request("/runtime-threats/"+id.String(), org))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"threat_id":4294967295`) {
		t.Fatalf("detail %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.Get(w, request("/runtime-threats/"+id.String(), foreign))
	if w.Code != 404 {
		t.Fatalf("foreign detail %d", w.Code)
	}
}
