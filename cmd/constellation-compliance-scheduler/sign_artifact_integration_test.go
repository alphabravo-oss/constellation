//go:build integration

package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

func TestConfiguredSigningFailureFailsRunBeforeEveryDelivery(t *testing.T) {
	pool, org, cluster := newEmailDeliveryFixture(t)
	for _, tc := range []struct{ name, script, want string }{
		{"signer error", "#!/bin/sh\nexit 1\n", "sign compliance artifact"},
		{"empty signature", "#!/bin/sh\nexit 0\n", "empty signature"},
		{"blank signature", "#!/bin/sh\nprintf '  \\n'\n", "empty signature"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := newSigningDeliveryProbe(t)
			t.Setenv("SMTP_HOST", probe.smtpAddress)
			t.Setenv("SMTP_FROM", "sender@example.test")
			t.Setenv("SMTP_USER", "")
			schedule := uuid.New()
			if _, err := pool.Exec(t.Context(), `INSERT INTO compliance_schedules(id,org_id,cluster_id,name,framework,cron_expression,report_format) VALUES($1,$2,$3,$4,'scheduler-fixture','0 0 * * *','csv')`, schedule, org, cluster, tc.name); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(t.TempDir(), "cosign")
			if err := writeSecurityFixture(bin, []byte(tc.script), 0o700); err != nil {
				t.Fatal(err)
			}
			outDir := t.TempDir()
			destination := filepath.Join(outDir, "delivered")
			d := daemon{pool: pool, outDir: outDir, signer: &cosignSigner{bin: bin}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			s := dueSchedule{ID: schedule, OrgID: org, ClusterID: &cluster, Name: tc.name, Framework: "scheduler-fixture", ReportFormat: "csv", Delivery: []compliancehandler.DeliveryTarget{
				{Kind: "file", Target: "file://" + destination},
				{Kind: "webhook", URL: probe.webhook.URL},
				{Kind: "email", Target: "reader@example.test"},
			}}
			if err := d.run(t.Context(), s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("signing failure ignored: %v", err)
			}
			assertSigningFailureReceipt(t, pool, schedule, tc.want, outDir)
			probe.assertNoDelivery(t, destination)
		})
	}
}

type signingDeliveryProbe struct {
	smtpAddress string
	smtpHits    atomic.Int64
	webhook     *httptest.Server
	webhookHits atomic.Int64
}

func newSigningDeliveryProbe(t *testing.T) *signingDeliveryProbe {
	t.Helper()
	p := new(signingDeliveryProbe)
	p.webhook = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.webhookHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(p.webhook.Close)
	var config net.ListenConfig
	listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.smtpAddress = listener.Addr().String()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			p.smtpHits.Add(1)
			if err := conn.Close(); err != nil {
				t.Errorf("close unexpected SMTP connection: %v", err)
			}
		}
	}()
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
		<-stopped
	})
	return p
}

func (p *signingDeliveryProbe) assertNoDelivery(t *testing.T, destination string) {
	t.Helper()
	if p.webhookHits.Load() != 0 || p.smtpHits.Load() != 0 {
		t.Fatalf("unsigned artifact dispatched: webhook=%d SMTP=%d", p.webhookHits.Load(), p.smtpHits.Load())
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatalf("unsigned file delivery created destination: %v", err)
	}
}

func assertSigningFailureReceipt(t *testing.T, pool *pgxpool.Pool, schedule uuid.UUID, want, outDir string) {
	t.Helper()
	var status, runError, uri, format, name, scheduleStatus, scheduleError string
	var sig *string
	var size int64
	if err := pool.QueryRow(t.Context(), `SELECT r.status,r.error_message,r.artifact_uri,r.artifact_format,r.artifact_filename,r.artifact_size_bytes,r.artifact_signature,s.last_status,s.last_error FROM compliance_runs r JOIN compliance_schedules s ON s.id=r.schedule_id WHERE r.schedule_id=$1`, schedule).Scan(&status, &runError, &uri, &format, &name, &size, &sig, &scheduleStatus, &scheduleError); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || scheduleStatus != "failed" || !strings.Contains(runError, want) || !strings.Contains(scheduleError, want) {
		t.Fatalf("signing failure not persisted: run=%s schedule=%s errors=%q/%q", status, scheduleStatus, runError, scheduleError)
	}
	if sig != nil {
		t.Fatal("failed signer retained a valid signature claim")
	}
	if format != "csv" || size <= 0 || uri != "file://"+filepath.Join(outDir, name) {
		t.Fatalf("local artifact metadata discarded: %s %d %s", format, size, uri)
	}
	body, err := readSecurityFixture(t, filepath.Join(outDir, name))
	if err != nil || int64(len(body)) != size {
		t.Fatalf("local failed-run artifact unavailable: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, name+".sig")); !os.IsNotExist(err) {
		t.Fatalf("failed signing published a sidecar signature: %v", err)
	}
}
