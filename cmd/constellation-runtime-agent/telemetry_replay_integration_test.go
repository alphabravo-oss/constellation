package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/netpolicy"
	"github.com/alphabravocompany/constellation/internal/telemetryspool"
)

// A real ingest transaction commits but the client misses its acknowledgement.
// Restart the disk queue and replay through HTTP; raw rows, late aggregates and
// policy counters must still represent precisely one observation.
func TestTelemetryReplayAfterLostAcknowledgement(t *testing.T) {
	databaseURL := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("requires migrated integration database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	d, err := db.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pool := d.Pool()
	org, cluster := uuid.New(), uuid.New()
	if _, err = pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES ($1,$2,$2)`, org, "replay-"+org.String()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_flows WHERE org_id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM network_flow_rollups WHERE org_id=$1`, org)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	}()
	if _, err = pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES ($1,$2,'replay')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	token, tokenID, err := handler.IssueRuntimeAgentToken(ctx, pool, org, "replay", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted) VALUES ($1,$2,'replay',now()+interval '1 hour',$3,'test','\x00'::bytea)`, org, cluster, tokenID); err != nil {
		t.Fatal(err)
	}
	var watermark time.Time
	if err = pool.QueryRow(ctx, `SELECT watermark FROM network_flow_rollup_state WHERE id=true`).Scan(&watermark); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal([]handler.FlowIngestRow{{SrcWorkload: "test/source", DstWorkload: "test/dest", Protocol: "tcp", Source: "dp", At: watermark.Add(-time.Hour), Bytes: 42, Packets: 3, PolicyID: 77, Sessions: 2}})
	if err != nil {
		t.Fatal(err)
	}
	ingest := handler.RuntimeAgentTokenMiddleware(pool)(http.HandlerFunc(netpolicy.NewNetworkFlowsIngest(d).Bulk))
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := httptest.NewRecorder()
		ingest.ServeHTTP(recorder, r)
		calls++
		for key, values := range recorder.Header() {
			if calls == 1 && key == ackHeader {
				continue
			}
			w.Header()[key] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	}))
	defer server.Close()
	dir := t.TempDir()
	q, err := telemetryspool.Open(dir, server.URL, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue(body, 1); err != nil {
		t.Fatal(err)
	}
	batch, err := q.Peek()
	if err != nil {
		t.Fatal(err)
	}
	// http.Header canonicalizes the acknowledgement's spelling.
	// The first response is deliberately stripped of its durable acknowledgement.
	if err = postTelemetry(ctx, server.Client(), server.URL, token, batch.Body, q.Producer(), batch.Sequence); err == nil {
		t.Fatal("lost acknowledgement was accepted")
	}
	if err = q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = telemetryspool.Open(dir, server.URL, 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	batch, err = q.Peek()
	if err != nil || batch == nil {
		t.Fatalf("pending batch lost: %v", err)
	}
	if err = postTelemetry(ctx, server.Client(), server.URL, token, batch.Body, q.Producer(), batch.Sequence); err != nil {
		t.Fatal(err)
	}
	if err = q.Ack(batch.Sequence); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`SELECT count(*) FROM network_flows WHERE org_id=$1`,
		`SELECT sum(flow_count) FROM network_flow_rollups WHERE org_id=$1`,
	} {
		var n int64
		if err = pool.QueryRow(ctx, query, org).Scan(&n); err != nil || n != 1 {
			t.Fatalf("replay count=%d err=%v", n, err)
		}
	}
	var hits int64
	if err = pool.QueryRow(ctx, `SELECT match_count FROM network_rule_match_stats WHERE org_id=$1 AND rule_id=77`, org).Scan(&hits); err != nil || hits != 2 {
		t.Fatalf("replay hits=%d err=%v", hits, err)
	}
	if pending, _ := q.Stats(); pending != 0 {
		t.Fatal("acknowledged queue did not drain")
	}
}
