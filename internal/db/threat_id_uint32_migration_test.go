//go:build integration

package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func threatMigration(t *testing.T, up bool) string {
	t.Helper()
	body, err := os.ReadFile("../../db/migrations/180_runtime_threat_uint32.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(string(body), "-- +goose Down")
	sql := parts[1]
	if up {
		sql = strings.Split(parts[0], "-- +goose Up")[1]
	}
	return sql
}
func threatMigrationFixture(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	base, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(base.Close)
	p := pgfixture.Schema(t, base)
	_, err = p.Exec(t.Context(), `CREATE TABLE runtime_threats(threat_id integer NOT NULL);
 CREATE TABLE network_flows(org_id uuid,cluster_id uuid,src_workload text,dst_workload text,protocol text,l7_protocol text,dst_port integer,verdict text,at timestamptz,threat_id integer) PARTITION BY RANGE(at);
 CREATE TABLE network_flows_default PARTITION OF network_flows DEFAULT;
 CREATE TABLE network_flow_rollup_state(id boolean PRIMARY KEY,watermark timestamptz,raw_pruned_before timestamptz);
 INSERT INTO network_flow_rollup_state VALUES(true,'2026-10-17 12:30Z','2026-10-17 10:00Z');
 CREATE TABLE network_flow_rollups(org_id uuid,cluster_id uuid,src_workload text,dst_workload text,protocol text,l7_protocol text,dst_port integer,verdict text,bucket timestamptz,flow_count bigint,max_threat_id integer,sum_bytes bigint DEFAULT 99,sum_packets bigint DEFAULT 88,
 PRIMARY KEY(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket));`)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestThreatUint32MigrationRepairsOnlyProvenHistory(t *testing.T) {
	p := threatMigrationFixture(t)
	ctx := t.Context()
	_, err := p.Exec(ctx, `INSERT INTO runtime_threats VALUES(-1),(-2147483648),(0),(2147483647);
 INSERT INTO network_flow_rollups(org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket,flow_count,max_threat_id)
 SELECT '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',name,'dst','tcp','',443,'allow',at,2,maximum FROM (VALUES
 ('complete','2026-10-17 10:00Z'::timestamptz,2022),('gone','2026-10-17 10:00Z',2022),('zero','2026-10-17 10:00Z',0),('negative','2026-10-17 10:00Z',-1),('null','2026-10-17 10:00Z',NULL),('partial','2026-10-17 10:00Z',2022),('pruned','2026-10-17 09:00Z',2022),('future','2026-10-17 12:00Z',2022),('watermark','2026-10-17 12:00Z',2022),('foreign','2026-10-17 10:00Z',2022),('sibling','2026-10-17 10:00Z',2022))v(name,at,maximum);
 INSERT INTO network_flows SELECT org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket+interval '1 minute',2022 FROM network_flow_rollups WHERE src_workload IN('complete','partial','pruned','future','watermark');
 INSERT INTO network_flows SELECT org_id,cluster_id,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket+CASE WHEN src_workload='future' THEN interval '45 minutes' WHEN src_workload='watermark' THEN interval '30 minutes' ELSE interval '2 minutes' END,-1 FROM network_flow_rollups WHERE src_workload IN('complete','pruned','future','watermark');
 INSERT INTO network_flows SELECT CASE WHEN src_workload='foreign' THEN '00000000-0000-0000-0000-000000000003'::uuid ELSE org_id END,CASE WHEN src_workload='sibling' THEN '00000000-0000-0000-0000-000000000004'::uuid ELSE cluster_id END,src_workload,dst_workload,protocol,l7_protocol,dst_port,verdict,bucket+interval '1 minute',id FROM network_flow_rollups CROSS JOIN unnest(ARRAY[2022,-1])id WHERE src_workload IN('foreign','sibling');`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, threatMigration(t, true)); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"complete": true, "gone": false, "zero": false, "negative": true, "null": true, "partial": false, "pruned": false, "future": false, "watermark": true, "foreign": false, "sibling": false} {
		var complete bool
		var max *int64
		var bytes, packets int64
		if err = p.QueryRow(ctx, `SELECT max_threat_id,threat_id_complete,sum_bytes,sum_packets FROM network_flow_rollups WHERE src_workload=$1`, name).Scan(&max, &complete, &bytes, &packets); err != nil {
			t.Fatal(err)
		}
		if complete != want || bytes != 99 || packets != 88 {
			t.Fatalf("%s complete=%v counters=%d/%d", name, complete, bytes, packets)
		}
		if (name == "complete" || name == "negative" || name == "watermark") && (max == nil || *max != 4294967295) {
			t.Fatalf("%s unsigned max=%v", name, max)
		}
		if name == "zero" && (max == nil || *max != 0) {
			t.Fatal("unknown zero evidence changed")
		}
	}
	var ids []int64
	if err = p.QueryRow(ctx, `SELECT array_agg(threat_id ORDER BY threat_id) FROM runtime_threats`).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 || ids[0] != 0 || ids[1] != 2147483647 || ids[2] != 2147483648 || ids[3] != 4294967295 {
		t.Fatalf("IDs=%v", ids)
	}
	for _, value := range []int64{-1, 4294967296} {
		if _, err = p.Exec(ctx, `INSERT INTO runtime_threats VALUES($1)`, value); err == nil {
			t.Fatalf("accepted %d", value)
		}
	}
	if _, err = p.Exec(ctx, threatMigration(t, false)); err == nil {
		t.Fatal("unsafe downgrade accepted")
	}
	var complete bool
	if err = p.QueryRow(ctx, `SELECT threat_id_complete FROM network_flow_rollups WHERE src_workload='zero'`).Scan(&complete); err != nil || complete {
		t.Fatalf("failed down mutated schema: %v", err)
	}
}
func TestThreatUint32MigrationLocksBeforeSchemaAndGuardedDown(t *testing.T) {
	p := threatMigrationFixture(t)
	ctx := t.Context()
	lock, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Rollback(context.WithoutCancel(ctx)) })
	if _, err = lock.Exec(ctx, `SELECT 1 FROM network_flow_rollup_state FOR SHARE`); err != nil {
		t.Fatal(err)
	}
	blocked, cancel := context.WithTimeout(ctx, 80*time.Millisecond)
	defer cancel()
	if _, err = p.Exec(blocked, threatMigration(t, true)); err == nil {
		t.Fatal("migration bypassed state lock")
	}
	if err = lock.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, threatMigration(t, true)); err != nil {
		t.Fatal(err)
	}
	// Even low known IDs cannot discard an uncertain historical maximum.
	if _, err = p.Exec(ctx, `INSERT INTO network_flow_rollups VALUES('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','zero','dst','tcp','',443,'allow',now(),1,0,99,88,false)`); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, threatMigration(t, false)); err == nil {
		t.Fatal("unknown low maximum downgrade accepted")
	}
	if _, err = p.Exec(ctx, `DELETE FROM network_flow_rollups`); err != nil {
		t.Fatal(err)
	}
	if _, err = p.Exec(ctx, threatMigration(t, false)); err != nil {
		t.Fatal(err)
	}
}
