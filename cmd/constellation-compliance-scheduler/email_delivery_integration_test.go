//go:build integration

package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

func TestEmailDeliveryFailurePersistsFailedRunAndRetainsArtifact(t *testing.T) {
	ctx := context.Background()
	pool, org, cluster := newEmailDeliveryFixture(t)
	for _, tc := range []struct{ name, host, recipient, want string }{
		{"missing host", "", "reader@example.test", "SMTP_HOST is required"},
		{"blank host", " \t", "reader@example.test", "SMTP_HOST is required"},
		{"empty recipient", "smtp.example.test", "", "target email required"},
		{"blank recipient", "smtp.example.test", " \t", "target email required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SMTP_HOST", tc.host)
			schedule := uuid.New()
			if _, err := pool.Exec(ctx, `INSERT INTO compliance_schedules(id,org_id,cluster_id,name,framework,cron_expression,report_format) VALUES($1,$2,$3,$4,'scheduler-fixture','0 0 * * *','csv')`, schedule, org, cluster, tc.name); err != nil {
				t.Fatal(err)
			}
			outDir := t.TempDir()
			destination := filepath.Join(outDir, "delivered")
			d := daemon{pool: pool, outDir: outDir, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			s := dueSchedule{ID: schedule, OrgID: org, ClusterID: &cluster, Framework: "scheduler-fixture", Name: "email fixture", ReportFormat: "csv", Delivery: []compliancehandler.DeliveryTarget{{Kind: "email", Target: tc.recipient}, {Kind: "file", Target: "file://" + destination}}}
			if err := d.run(ctx, s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("missing delivery failure: %v", err)
			}
			assertFailedEmailRun(t, ctx, pool, schedule, tc.want, outDir, destination)
		})
	}
}

func newEmailDeliveryFixture(t *testing.T) (*pgxpool.Pool, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Email delivery fixture')`, org, "email-delivery-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	return pool, org, cluster
}

func assertFailedEmailRun(t *testing.T, ctx context.Context, pool *pgxpool.Pool, schedule uuid.UUID, want, outDir, destination string) {
	t.Helper()
	var status, runError, uri, scheduleStatus, scheduleError, format string
	var size int64
	if err := pool.QueryRow(ctx, `SELECT r.status,r.error_message,r.artifact_uri,r.artifact_format,r.artifact_size_bytes,s.last_status,s.last_error FROM compliance_runs r JOIN compliance_schedules s ON s.id=r.schedule_id WHERE r.schedule_id=$1`, schedule).Scan(&status, &runError, &uri, &format, &size, &scheduleStatus, &scheduleError); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || scheduleStatus != "failed" || !strings.Contains(runError, want) || !strings.Contains(scheduleError, want) {
		t.Fatalf("false delivery success: run=%s schedule=%s errors=%q/%q", status, scheduleStatus, runError, scheduleError)
	}
	// A failed email must not discard the rendered report or prevent subsequent
	// configured targets from receiving it.
	if format != "csv" || size <= 0 || !strings.HasPrefix(uri, "file://"+destination+"/") {
		t.Fatalf("lost available artifact metadata: %s %d %s", format, size, uri)
	}
	artifact, err := readSecurityFixture(t, strings.TrimPrefix(uri, "file://"))
	if err != nil || len(artifact) == 0 {
		t.Fatalf("remaining target not delivered: %v", err)
	}
	local, err := readSecurityFixture(t, filepath.Join(outDir, filepath.Base(uri)))
	if err != nil || string(local) != string(artifact) {
		t.Fatalf("rendered local report was discarded: %v", err)
	}
}
