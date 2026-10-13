package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestEventsExportPreservesRowsAndEnrichesExactThreatRoles(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	org, foreignOrg := uuid.New(), uuid.New()
	cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New()
	asset := uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "events-export-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM runtime_threats WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'a'),($3,$2,'b'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,kind,name) VALUES($1,$2,'image','export-fixture')`, asset, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'operations','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),($1,$3,'operations','api','Deployment','{}'),($4,$5,'operations','api','Deployment','{"helm.sh/chart":"constellation-1"}')`, org, cluster, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,cluster_id,kind,title,severity,detail_json,first_seen_at) SELECT $1,$2,$3,'runtime','finding-'||n,'high',jsonb_build_object('message','quoted "source" evidence'),NOW() FROM generate_series(1,505)n`, org, asset, cluster); err != nil {
		t.Fatal(err)
	}
	// 505 equal-time rows cross two keyset boundaries; no source cap or duplicate
	// row may appear. The raw threat packet/message fields must remain unchanged.
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,workload_id,namespace,threat_id,severity,msg,packet,reported_at,at) SELECT $1,$2,'operations/api','operations',2022,8,'quoted "source" evidence','\x0102'::bytea,NOW(),NOW() FROM generate_series(1,505)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,workload_id,namespace,threat_id,severity,reported_at,at) VALUES($1,$2,'operations/api','operations',2022,8,NOW(),NOW()),($1,$3,'unknown/api','unknown',2022,8,NOW(),NOW()),($4,$5,'operations/api','operations',2022,8,NOW(),NOW()),($1,$3,'operations/api','operations',2022,8,NOW()-INTERVAL '100 days',NOW()-INTERVAL '100 days')`, org, sibling, cluster, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	config := pool.Config().Copy()
	config.MaxConns = 1
	single, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(single.Close)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events:export?hours=24", nil)
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org}))
	w := httptest.NewRecorder()
	NewEventsExport(single).Export(w, r)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("status/type %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	counts := map[string]int{}
	ids := map[string]bool{}
	roles := map[string]int{}
	decoder := json.NewDecoder(strings.NewReader(w.Body.String()))
	for decoder.More() {
		var frame struct {
			Event string         `json:"event"`
			Data  map[string]any `json:"data"`
		}
		if err := decoder.Decode(&frame); err != nil {
			t.Fatal(err)
		}
		id, _ := frame.Data["id"].(string)
		key := frame.Event + ":" + id
		if ids[key] {
			t.Fatalf("duplicate streamed record %s", key)
		}
		ids[key] = true
		counts[frame.Event]++
		if frame.Data["org_id"] != org.String() {
			t.Fatal("foreign record exported")
		}
		if frame.Event == "finding" {
			if role, ok := frame.Data["platform_role"].(string); !ok || role != "" {
				t.Fatalf("finding unknown role omitted or borrowed %#v", frame.Data)
			}
		}
		if frame.Event == "threat" {
			role, ok := frame.Data["platform_role"].(string)
			if !ok {
				t.Fatalf("evaluated role omitted: %#v", frame.Data)
			}
			roles[role]++
			if frame.Data["cluster_id"] == cluster.String() && frame.Data["workload_id"] == "operations/api" {
				if role != "core" || frame.Data["msg"] != `quoted "source" evidence` || frame.Data["packet"] != `\x0102` {
					t.Fatalf("raw evidence or role changed: %#v", frame.Data)
				}
			} else if role != "" {
				t.Fatalf("borrowed role: %#v", frame.Data)
			}
		}
	}
	if counts["finding"] != 505 || counts["threat"] != 507 || roles["core"] != 505 || roles[""] != 2 {
		t.Fatalf("counts=%v roles=%v", counts, roles)
	}
}

func TestEventsExportInitialAndPartialFailuresStayValidJSON(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	org, cluster, asset := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "export-error-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM runtime_threats WHERE org_id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'errors')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,kind,name) VALUES($1,$2,'image','error-fixture')`, asset, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(org_id,cluster_id,workload_id,threat_id,severity,reported_at) VALUES($1,$2,'prod/api',2022,8,NOW())`, org, cluster); err != nil {
		t.Fatal(err)
	}
	schema := "export_error_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE") })
	if _, err := pool.Exec(ctx, "CREATE FUNCTION "+quoted+`.fail() RETURNS boolean LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'test "quoted" failure'; END$$`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "CREATE VIEW "+quoted+".runtime_threats AS SELECT * FROM public.runtime_threats WHERE "+quoted+".fail()"); err != nil {
		t.Fatal(err)
	}
	config := pool.Config().Copy()
	config.MaxConns = 1
	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+quoted+",public")
		return err
	}
	failing, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(failing.Close)
	invoke := func(export *EventsExport) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/events:export", nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		export.Export(w, r)
		return w
	}
	// With no finding record, a failed threat query must still set HTTP 500.
	w := invoke(NewEventsExport(failing))
	if w.Code != 500 || w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("initial source failure %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	var errorFrame struct{ Event, Data string }
	if err := json.Unmarshal(w.Body.Bytes(), &errorFrame); err != nil {
		t.Fatal(err)
	}
	if errorFrame.Event != "error" || !strings.Contains(errorFrame.Data, `"quoted"`) {
		t.Fatalf("wrong JSON failure: %+v", errorFrame)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,asset_id,kind,title,severity) VALUES($1,$2,'runtime','before failure','high')`, org, asset); err != nil {
		t.Fatal(err)
	}
	w = invoke(NewEventsExport(failing))
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("partial failure %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	decoder := json.NewDecoder(strings.NewReader(w.Body.String()))
	var frame struct {
		Event string
		Data  json.RawMessage
	}
	if err := decoder.Decode(&frame); err != nil || frame.Event != "finding" {
		t.Fatalf("finding before failure %v %+v", err, frame)
	}
	if err := decoder.Decode(&errorFrame); err != nil || errorFrame.Event != "error" || !strings.Contains(errorFrame.Data, `"quoted"`) {
		t.Fatalf("partial JSON failure %v %+v", err, errorFrame)
	}
	// Force the initial time-bound query (before NDJSON setup) to fail.
	if _, err := pool.Exec(ctx, "CREATE FUNCTION "+quoted+`.now() RETURNS timestamptz LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'bound query failure'; END$$`); err != nil {
		t.Fatal(err)
	}
	initialConfig := pool.Config().Copy()
	initialConfig.MaxConns = 1
	initialConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET search_path TO "+quoted+",pg_catalog,public")
		return err
	}
	initial, err := pgxpool.NewWithConfig(ctx, initialConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(initial.Close)
	w = invoke(NewEventsExport(initial))
	if w.Code != 500 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("bound query failure %d %s", w.Code, w.Header().Get("Content-Type"))
	}
	initial.Close()
	w = invoke(NewEventsExport(initial))
	if w.Code != 500 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("transaction failure %d %s", w.Code, w.Header().Get("Content-Type"))
	}
}
