package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSupportBundleJobs_QueuedDownloadRBACAndAudit(t *testing.T) {
	server, httpServer, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	baseURL := httpServer.URL + "/api/v1/support/bundle/jobs"

	if status, _ := doJSON(t, http.MethodPost, baseURL, auditor, nil); status != http.StatusForbidden {
		t.Fatalf("auditor create status = %d, want 403", status)
	}
	if status, _ := doJSON(t, http.MethodGet, baseURL, auditor, nil); status != http.StatusForbidden {
		t.Fatalf("auditor list status = %d, want 403", status)
	}
	if status, _ := doJSON(t, http.MethodPatch, httpServer.URL+"/api/v1/system/config", admin, map[string]any{
		"nvd_api_key": "async-bundle-secret",
	}); status != http.StatusOK {
		t.Fatalf("configure redaction fixture status = %d", status)
	}

	status, created := doJSON(t, http.MethodPost, baseURL, admin, nil)
	if status != http.StatusAccepted || created["status"] != "queued" {
		t.Fatalf("create status = %d, job = %+v", status, created)
	}
	jobID, ok := created["id"].(string)
	if !ok || jobID == "" {
		t.Fatalf("created job has no id: %+v", created)
	}
	jobURL := baseURL + "/" + jobID
	if status, _ := doJSON(t, http.MethodGet, jobURL+"/download", admin, nil); status != http.StatusConflict {
		t.Fatalf("queued download status = %d, want 409", status)
	}

	workerContext, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go server.supportBundleJobs.RunWorker(workerContext)

	deadline := time.Now().Add(20 * time.Second)
	var job map[string]any
	for time.Now().Before(deadline) {
		status, job = doJSON(t, http.MethodGet, jobURL, admin, nil)
		if status != http.StatusOK {
			t.Fatalf("get job status = %d, job = %+v", status, job)
		}
		if job["status"] == "ready" || job["status"] == "failed" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if job["status"] != "ready" || job["bundle_id"] == "" {
		t.Fatalf("job did not become ready: %+v", job)
	}

	status, history := doJSON(t, http.MethodGet, baseURL+"?limit=10", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("history status = %d, body = %+v", status, history)
	}
	items, ok := history["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("history is empty: %+v", history)
	}
	status, downloaded := doJSON(t, http.MethodGet, jobURL+"/download", admin, nil)
	if status != http.StatusOK || downloaded["bundle_id"] != job["bundle_id"] {
		t.Fatalf("download status = %d, bundle = %+v", status, downloaded)
	}
	encoded, err := json.Marshal(downloaded)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "async-bundle-secret") || !strings.Contains(string(encoded), "***REDACTED***") {
		t.Fatal("persisted bundle did not redact the configured secret")
	}
	status, job = doJSON(t, http.MethodGet, jobURL, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("job after download status = %d", status)
	}
	auditID, ok := job["audit_event_id"].(float64)
	if !ok || auditID <= 0 {
		t.Fatalf("job has no download audit link: %+v", job)
	}
	auditURL := httpServer.URL + "/api/v1/audit/events?event_id=" + strconv.FormatInt(int64(auditID), 10)
	status, auditResult := doJSON(t, http.MethodGet, auditURL, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("audit drill-down status = %d, result = %+v", status, auditResult)
	}
	auditEvents, ok := auditResult["events"].([]any)
	if !ok || len(auditEvents) != 1 || auditEvents[0].(map[string]any)["target_id"] != jobID {
		t.Fatalf("audit drill-down missed job: %+v", auditResult)
	}
	status, auditHistory := doJSON(t, http.MethodGet, httpServer.URL+"/api/v1/audit/events?support_bundle_job_id="+jobID, admin, nil)
	if status != http.StatusOK {
		t.Fatalf("audit history status = %d, result = %+v", status, auditHistory)
	}
	historyEvents, ok := auditHistory["events"].([]any)
	if !ok || len(historyEvents) != 3 {
		t.Fatalf("audit history missed create/ready/download: %+v", auditHistory)
	}
	if status, _ := doJSON(t, http.MethodGet, httpServer.URL+"/api/v1/audit/events?event_id=invalid", admin, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid audit event id status = %d, want 400", status)
	}
	if status, _ := doJSON(t, http.MethodGet, httpServer.URL+"/api/v1/audit/events?support_bundle_job_id=invalid", admin, nil); status != http.StatusBadRequest {
		t.Fatalf("invalid support bundle job id status = %d, want 400", status)
	}

	for _, action := range []string{"support.bundle.job.create", "support.bundle.job.download"} {
		var count int
		if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND action=$3 AND target_id=$4`,
			orgID, adminID, action, jobID).Scan(&count); err != nil || count != 1 {
			t.Fatalf("audit action %s count = %d, err = %v", action, count, err)
		}
	}
}
