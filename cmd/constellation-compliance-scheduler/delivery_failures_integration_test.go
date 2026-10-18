package main

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

func TestMalformedWebhookFailsRunAndSchedulerContinuesOtherTenant(t *testing.T) {
	pool, orgA, clusterA := newEmailDeliveryFixture(t)
	_, orgB, clusterB := newEmailDeliveryFixture(t)
	outDir := t.TempDir()
	destinationA := filepath.Join(outDir, "tenant-a-delivered")
	destinationB := filepath.Join(outDir, "tenant-b-delivered")
	scheduleA, scheduleB := uuid.New(), uuid.New()
	var received atomic.Int64
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ScheduleID string `json:"schedule_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.ScheduleID != scheduleB.String() {
			t.Error("valid tenant webhook received another schedule or malformed payload")
		}
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(webhook.Close)
	for _, fixture := range []struct {
		id       uuid.UUID
		org      uuid.UUID
		cluster  uuid.UUID
		name     string
		due      string
		delivery []compliancehandler.DeliveryTarget
	}{
		{id: scheduleA, org: orgA, cluster: clusterA, name: "malformed webhook", due: "2000-01-01", delivery: []compliancehandler.DeliveryTarget{
			{Kind: "webhook", URL: "http://" + schedulerDeliveryCanary + "@%zz/hook"},
			{Kind: "file", Target: "file://" + destinationA},
		}},
		{id: scheduleB, org: orgB, cluster: clusterB, name: "other tenant", due: "2000-01-02", delivery: []compliancehandler.DeliveryTarget{
			{Kind: "webhook", URL: webhook.URL},
			{Kind: "file", Target: "file://" + destinationB},
		}},
	} {
		raw, err := json.Marshal(fixture.delivery)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(t.Context(), `INSERT INTO compliance_schedules(id,org_id,cluster_id,name,framework,cron_expression,report_format,delivery,next_run_at) VALUES($1,$2,$3,$4,'scheduler-fixture','0 0 * * *','csv',$5::jsonb,$6::timestamptz)`, fixture.id, fixture.org, fixture.cluster, fixture.name, raw, fixture.due); err != nil {
			t.Fatal(err)
		}
	}
	var logs bytes.Buffer
	d := daemon{pool: pool, outDir: outDir, http: webhook.Client(), logger: slog.New(slog.NewTextHandler(&logs, nil))}
	d.tick(t.Context())
	assertFailedEmailRun(t, t.Context(), pool, scheduleA, "webhook request construction failed", outDir, destinationA)
	if received.Load() != 1 {
		t.Fatalf("bad webhook prevented or duplicated the other tenant: requests=%d", received.Load())
	}
	var runStatus, scheduleStatus, uri string
	var nextRunAdvanced bool
	if err := pool.QueryRow(t.Context(), `SELECT r.status,s.last_status,r.artifact_uri,s.next_run_at>NOW() FROM compliance_runs r JOIN compliance_schedules s ON s.id=r.schedule_id WHERE r.org_id=$1 AND r.schedule_id=$2`, orgB, scheduleB).Scan(&runStatus, &scheduleStatus, &uri, &nextRunAdvanced); err != nil {
		t.Fatal(err)
	}
	if runStatus != "succeeded" || scheduleStatus != "succeeded" || !nextRunAdvanced || !strings.HasPrefix(uri, "file://"+destinationB+"/") {
		t.Fatal("other tenant did not retain its own successful terminal receipt and artifact")
	}
	var storedError string
	if err := pool.QueryRow(t.Context(), `SELECT error_message FROM compliance_runs WHERE org_id=$1 AND schedule_id=$2`, orgA, scheduleA).Scan(&storedError); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedError+logs.String(), schedulerDeliveryCanary) {
		t.Fatal("malformed endpoint escaped through persisted status or logs")
	}
}

func TestS3SignatureFailurePersistsFailedRunAndRetainsLocalDelivery(t *testing.T) {
	pool, org, cluster := newEmailDeliveryFixture(t)
	configureSchedulerS3Fixture(t)
	probe := newSchedulerS3Probe(t, "signature")
	schedule := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO compliance_schedules(id,org_id,cluster_id,name,framework,cron_expression,report_format) VALUES($1,$2,$3,'signature delivery fixture','scheduler-fixture','0 0 * * *','csv')`, schedule, org, cluster); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nprintf 'fixture-signature'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	destination := filepath.Join(outDir, "retained-delivery")
	var logs bytes.Buffer
	d := daemon{pool: pool, outDir: outDir, signer: &cosignSigner{bin: bin}, logger: slog.New(slog.NewTextHandler(&logs, nil))}
	s := dueSchedule{ID: schedule, OrgID: org, ClusterID: &cluster, Name: "signature delivery fixture", Framework: "scheduler-fixture", ReportFormat: "csv", Delivery: []compliancehandler.DeliveryTarget{
		{Kind: "s3", Bucket: "reports", Prefix: "operator-prefix", Endpoint: probe.server.URL},
		{Kind: "file", Target: "file://" + destination},
	}}
	err := d.run(t.Context(), s)
	if err == nil || !strings.Contains(err.Error(), "s3 signature upload failed") {
		t.Fatalf("sidecar failure did not fail the run: %v", err)
	}
	assertFailedEmailRun(t, t.Context(), pool, schedule, "s3 signature upload failed", outDir, destination)
	var signature, filename, storedError string
	if err := pool.QueryRow(t.Context(), `SELECT artifact_signature,artifact_filename,error_message FROM compliance_runs WHERE org_id=$1 AND schedule_id=$2`, org, schedule).Scan(&signature, &filename, &storedError); err != nil {
		t.Fatal(err)
	}
	if signature != "fixture-signature" || strings.Contains(storedError+logs.String()+err.Error(), schedulerDeliveryCanary) {
		t.Fatal("sidecar failure lost retained signing metadata or disclosed provider diagnostics")
	}
	for _, dir := range []string{outDir, destination} {
		data, err := readSecurityFixture(t, filepath.Join(dir, filename+".sig"))
		if err != nil || string(data) != signature {
			t.Fatalf("local or subsequent signature delivery was discarded: %v", err)
		}
	}
	calls := probe.recorded()
	if len(calls) != 2 || calls[0].signature != signature || calls[1].body != signature || !strings.HasSuffix(calls[1].path, ".sig") {
		t.Fatal("artifact metadata or sidecar request changed")
	}
}
