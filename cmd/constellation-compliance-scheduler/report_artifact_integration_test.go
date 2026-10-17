package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestReportSchedulerPersistsActualArtifactAndFullSource(t *testing.T) {
	raw := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("fresh test database required")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	org, cluster, schedule := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Real report org')`, org, "scheduler-report-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO compliance_schedules(id,org_id,cluster_id,name,framework,cron_expression,report_format) VALUES($1,$2,$3,'source fixture','scheduler-fixture','0 0 * * *','pdf')`, schedule, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO compliance_checks(org_id,cluster_id,framework,control_id,title,status,severity,evidence) SELECT $1,$2,'scheduler-fixture','c-'||i,'quoted "control" '||i,CASE WHEN i=1 THEN 'fail' ELSE 'pass' END,'high','{"pod":"api"}' FROM generate_series(1,5005)i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO compliance_exemptions(org_id,cluster_id,framework,control_id,reason,expires_at) VALUES($1,$2,'scheduler-fixture','c-1','reviewed',NOW()+INTERVAL '1 day')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	d := daemon{pool: pool, outDir: t.TempDir(), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	s := dueSchedule{ID: schedule, OrgID: org, ClusterID: &cluster, Framework: "scheduler-fixture", Name: "source fixture", ReportFormat: "pdf"}
	checks, summary, err := d.loadChecks(ctx, s)
	if err != nil || len(checks) != 5005 || summary["total"] != 5005 || summary["pass"] != 5004 || summary["exempted"] != 1 || summary["fail"] != 0 {
		t.Fatalf("full source rows%d summary%+v %v", len(checks), summary, err)
	}
	// No renderer, signer, email/webhook/S3 delivery, or live database is involved.
	t.Setenv("PATH", t.TempDir())
	if err := d.run(ctx, s); err != nil {
		t.Fatal(err)
	}
	var format, media, name, uri, status string
	var encoded []byte
	if err := pool.QueryRow(ctx, `SELECT artifact_format,artifact_media_type,artifact_filename,artifact_uri,status,summary FROM compliance_runs WHERE org_id=$1 AND schedule_id=$2`, org, schedule).Scan(&format, &media, &name, &uri, &status, &encoded); err != nil {
		t.Fatal(err)
	}
	if format != "html" || media != "text/html; charset=utf-8" || filepath.Ext(name) != ".html" || status != "succeeded" {
		t.Fatalf("actual metadata %s %s %s %s", format, media, name, status)
	}
	var stored map[string]int
	if err := json.Unmarshal(encoded, &stored); err != nil {
		t.Fatal(err)
	}
	if stored["total"] != 5005 || stored["exempted"] != 1 {
		t.Fatalf("persisted source %+v", stored)
	}
	data, err := os.ReadFile(strings.TrimPrefix(uri, "file://"))
	if err != nil || !strings.Contains(string(data), "5005 returned of 5005") || !strings.Contains(string(data), "Real report org") {
		t.Fatalf("actual HTML evidence %v", err)
	}
	s.ReportFormat = "csv"
	if err := d.run(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT artifact_uri FROM compliance_runs WHERE org_id=$1 AND artifact_format='csv'`, org).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(strings.TrimPrefix(uri, "file://"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil || len(rows) != 5006 {
		t.Fatalf("actual CSV artifact rows%d %v", len(rows), err)
	}
}
