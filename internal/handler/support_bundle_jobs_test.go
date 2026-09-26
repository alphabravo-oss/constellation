package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type supportBundleJobsFixture struct {
	db      *db.DB
	handler *SupportBundleJobs
	orgs    [2]uuid.UUID
	users   [2]uuid.UUID
}

func newSupportBundleJobsFixture(t *testing.T) *supportBundleJobsFixture {
	t.Helper()
	database := openTestDB(t)
	ctx := context.Background()
	var exists bool
	if err := database.Pool().QueryRow(ctx, `SELECT to_regclass('public.support_bundle_jobs') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		database.Close()
		t.Skip("support bundle jobs migration not applied")
	}
	fixture := &supportBundleJobsFixture{db: database, handler: NewSupportBundleJobs(database, audit.New(database.Pool()))}
	for index := range fixture.orgs {
		fixture.orgs[index] = uuid.New()
		fixture.users[index] = uuid.New()
		_, err := database.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Support Bundle Jobs Test')`,
			fixture.orgs[index], "support-bundle-jobs-"+fixture.orgs[index].String())
		if err != nil {
			t.Fatal(err)
		}
		_, err = database.Pool().Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Support Bundle Jobs User')`,
			fixture.users[index], fixture.orgs[index], fixture.users[index].String()+"@example.test")
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, orgID := range fixture.orgs {
			_, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
		}
		database.Close()
	})
	return fixture
}

func (fixture *supportBundleJobsFixture) request(method, path string, tenant int, call func(http.ResponseWriter, *http.Request)) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: fixture.orgs[tenant], UserID: fixture.users[tenant]}))
	if strings.Contains(path, "/jobs/") {
		parts := strings.Split(path, "/")
		for index, part := range parts {
			if part == "jobs" && index+1 < len(parts) {
				routeContext := chi.NewRouteContext()
				routeContext.URLParams.Add("id", parts[index+1])
				request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, routeContext))
				break
			}
		}
	}
	response := httptest.NewRecorder()
	call(response, request)
	return response
}

func (fixture *supportBundleJobsFixture) create(t *testing.T, tenant int) supportBundleJobDTO {
	t.Helper()
	response := fixture.request(http.MethodPost, "/api/v1/support/bundle/jobs", tenant, fixture.handler.CreateJob)
	if response.Code != http.StatusAccepted {
		t.Fatalf("create: %d %s", response.Code, response.Body.String())
	}
	var job supportBundleJobDTO
	if err := json.Unmarshal(response.Body.Bytes(), &job); err != nil {
		t.Fatal(err)
	}
	if job.ID == uuid.Nil || job.Status != "queued" || job.AuditEventID == nil {
		t.Fatalf("invalid create receipt: %+v", job)
	}
	return job
}

func TestSupportBundleJobsLifecycleTenantAuditAndRedaction(t *testing.T) {
	fixture := newSupportBundleJobsFixture(t)
	job := fixture.create(t, 0)
	foreign := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String(), 1, fixture.handler.GetJob)
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign get: %d", foreign.Code)
	}
	foreign = fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String()+"/download", 1, fixture.handler.DownloadJob)
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign download: %d", foreign.Code)
	}
	foreign = fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs", 1, fixture.handler.ListJobs)
	if !strings.Contains(foreign.Body.String(), `"items":[]`) || strings.Contains(foreign.Body.String(), job.ID.String()) {
		t.Fatalf("foreign list: %s", foreign.Body.String())
	}

	fixture.handler.build = func(_ context.Context, subject Subject) (supportBundleDTO, error) {
		return newSupportBundle(subject.OrgID.String(), time.Now().UTC(), map[string]any{
			"safe": "healthy", "api_token": "do-not-persist-raw-token",
		})
	}
	processed, err := fixture.handler.runOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("worker: processed=%v err=%v", processed, err)
	}
	get := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String(), 0, fixture.handler.GetJob)
	var ready supportBundleJobDTO
	if get.Code != http.StatusOK || json.Unmarshal(get.Body.Bytes(), &ready) != nil || ready.Status != "ready" || ready.StartedAt == nil || ready.FinishedAt == nil || ready.ExpiresAt == nil || ready.BundleID == nil {
		t.Fatalf("ready receipt: %d %s", get.Code, get.Body.String())
	}
	var payload []byte
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT payload FROM support_bundle_jobs WHERE id = $1`, job.ID).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "do-not-persist-raw-token") || !strings.Contains(string(payload), supportBundleRedacted) {
		t.Fatalf("persisted payload not redacted: %s", payload)
	}
	download := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String()+"/download", 0, fixture.handler.DownloadJob)
	if download.Code != http.StatusOK || !strings.Contains(download.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatalf("download: %d %s", download.Code, download.Body.String())
	}
	var eventCount int
	if err := fixture.db.Pool().QueryRow(context.Background(), `
SELECT count(*) FROM audit_events WHERE org_id = $1 AND target_kind = 'support_bundle_job' AND target_id = $2
AND action IN ('support.bundle.job.create', 'support.bundle.job.ready', 'support.bundle.job.download')`, fixture.orgs[0], job.ID.String()).Scan(&eventCount); err != nil || eventCount != 3 {
		t.Fatalf("audit count=%d err=%v", eventCount, err)
	}
}

func TestSupportBundleJobsFailureExpiryAndRestart(t *testing.T) {
	fixture := newSupportBundleJobsFixture(t)
	job := fixture.create(t, 0)
	fixture.handler.build = func(context.Context, Subject) (supportBundleDTO, error) {
		return supportBundleDTO{}, errors.New("database password=supersecret")
	}
	processed, err := fixture.handler.runOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("failed worker: processed=%v err=%v", processed, err)
	}
	get := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String(), 0, fixture.handler.GetJob)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"failed"`) || !strings.Contains(get.Body.String(), supportBundleJobFailure) || strings.Contains(get.Body.String(), "supersecret") {
		t.Fatalf("failed receipt: %d %s", get.Code, get.Body.String())
	}
	var failedCount int
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE target_id = $1 AND action = 'support.bundle.job.failed'`, job.ID.String()).Scan(&failedCount); err != nil || failedCount != 1 {
		t.Fatalf("failed audit count=%d err=%v", failedCount, err)
	}
	if _, err := fixture.db.Pool().Exec(context.Background(), `UPDATE support_bundle_jobs SET expires_at = now() - interval '1 second' WHERE id = $1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := fixture.handler.expireJobs(context.Background()); err != nil {
		t.Fatal(err)
	}
	get = fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String(), 0, fixture.handler.GetJob)
	if !strings.Contains(get.Body.String(), `"status":"expired"`) || strings.Contains(get.Body.String(), supportBundleJobFailure) {
		t.Fatalf("expired receipt: %s", get.Body.String())
	}
	if response := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String()+"/download", 0, fixture.handler.DownloadJob); response.Code != http.StatusGone {
		t.Fatalf("expired download: %d", response.Code)
	}

	stale := fixture.create(t, 0)
	if _, err := fixture.db.Pool().Exec(context.Background(), `UPDATE support_bundle_jobs SET status = 'running', started_at = now() - interval '2 minutes', lease_expires_at = now() - interval '1 second', attempts = 1 WHERE id = $1`, stale.ID); err != nil {
		t.Fatal(err)
	}
	restarted := NewSupportBundleJobs(fixture.db, audit.New(fixture.db.Pool()))
	restarted.build = func(_ context.Context, subject Subject) (supportBundleDTO, error) {
		return newSupportBundle(subject.OrgID.String(), time.Now().UTC(), map[string]any{"status": "recovered"})
	}
	processed, err = restarted.runOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("restart worker: processed=%v err=%v", processed, err)
	}
	var status string
	var attempts int
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT status, attempts FROM support_bundle_jobs WHERE id = $1`, stale.ID).Scan(&status, &attempts); err != nil || status != "ready" || attempts != 2 {
		t.Fatalf("restart result: status=%s attempts=%d err=%v", status, attempts, err)
	}
	if _, err := fixture.db.Pool().Exec(context.Background(), `UPDATE support_bundle_jobs SET expires_at = now() - interval '1 second' WHERE id = $1`, stale.ID); err != nil {
		t.Fatal(err)
	}
	if err := restarted.expireJobs(context.Background()); err != nil {
		t.Fatal(err)
	}
	var payload []byte
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT payload FROM support_bundle_jobs WHERE id = $1`, stale.ID).Scan(&payload); err != nil || payload != nil {
		t.Fatalf("expired payload retained: %s err=%v", payload, err)
	}
}

func TestSupportBundleJobsPaginationAndClaimConcurrency(t *testing.T) {
	fixture := newSupportBundleJobsFixture(t)
	created := make(map[uuid.UUID]bool)
	for index := 0; index < 5; index++ {
		job := fixture.create(t, 0)
		created[job.ID] = true
	}
	cursor := ""
	seen := make(map[uuid.UUID]bool)
	for {
		path := "/api/v1/support/bundle/jobs?limit=2"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		response := fixture.request(http.MethodGet, path, 0, fixture.handler.ListJobs)
		if response.Code != http.StatusOK {
			t.Fatalf("list: %d %s", response.Code, response.Body.String())
		}
		var page struct {
			Items      []supportBundleJobDTO `json:"items"`
			NextCursor string                `json:"next_cursor"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		if len(page.Items) > 2 {
			t.Fatalf("unbounded page: %+v", page)
		}
		for _, item := range page.Items {
			if seen[item.ID] || !created[item.ID] {
				t.Fatalf("duplicate/unexpected job: %s", item.ID)
			}
			seen[item.ID] = true
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}
	if len(seen) != len(created) {
		t.Fatalf("pagination lost jobs: got %d want %d", len(seen), len(created))
	}
	if response := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs?cursor=bad", 0, fixture.handler.ListJobs); response.Code != http.StatusBadRequest {
		t.Fatalf("bad cursor: %d", response.Code)
	}
	if response := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs?limit=101", 0, fixture.handler.ListJobs); response.Code != http.StatusOK {
		t.Fatalf("bounded limit: %d", response.Code)
	}

	first := NewSupportBundleJobs(fixture.db, audit.New(fixture.db.Pool()))
	second := NewSupportBundleJobs(fixture.db, audit.New(fixture.db.Pool()))
	barrier := make(chan struct{})
	var wait sync.WaitGroup
	results := make(chan bool, 2)
	for _, worker := range []*SupportBundleJobs{first, second} {
		worker.build = func(_ context.Context, subject Subject) (supportBundleDTO, error) {
			<-barrier
			return newSupportBundle(subject.OrgID.String(), time.Now().UTC(), map[string]any{"status": "ok"})
		}
		wait.Add(1)
		go func(worker *SupportBundleJobs) {
			defer wait.Done()
			processed, err := worker.runOne(context.Background())
			if err != nil {
				t.Errorf("concurrent claim: %v", err)
			}
			results <- processed
		}(worker)
	}
	time.Sleep(100 * time.Millisecond)
	close(barrier)
	wait.Wait()
	close(results)
	processed := 0
	for result := range results {
		if result {
			processed++
		}
	}
	if processed != 2 {
		t.Fatalf("workers did not claim separate queued jobs: %d", processed)
	}
}

func TestSupportBundleJobsAuditFailureFailsClosedAndRecovers(t *testing.T) {
	fixture := newSupportBundleJobsFixture(t)
	appendAudit := fixture.handler.appendAudit
	fixture.handler.appendAudit = func(context.Context, audit.Event) (int64, string, error) {
		return 0, "", errors.New("audit store unavailable: password=not-for-clients")
	}
	response := fixture.request(http.MethodPost, "/api/v1/support/bundle/jobs", 0, fixture.handler.CreateJob)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "not-for-clients") {
		t.Fatalf("create audit failure: %d %s", response.Code, response.Body.String())
	}
	var count int
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM support_bundle_jobs WHERE org_id = $1`, fixture.orgs[0]).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unaudited job queued: count=%d err=%v", count, err)
	}
	fixture.handler.appendAudit = appendAudit
	job := fixture.create(t, 0)
	fixture.handler.build = func(_ context.Context, subject Subject) (supportBundleDTO, error) {
		return newSupportBundle(subject.OrgID.String(), time.Now().UTC(), map[string]any{"status": "ready"})
	}
	fixture.handler.appendAudit = func(context.Context, audit.Event) (int64, string, error) {
		return 0, "", errors.New("audit store unavailable: password=not-for-clients")
	}
	processed, err := fixture.handler.runOne(context.Background())
	if !processed || err == nil {
		t.Fatalf("worker audit failure: processed=%v err=%v", processed, err)
	}
	var status, pending string
	var eventID *int64
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT status, audit_pending, audit_event_id FROM support_bundle_jobs WHERE id = $1`, job.ID).Scan(&status, &pending, &eventID); err != nil || status != "ready" || pending != "ready" || eventID != nil {
		t.Fatalf("pending audit link: status=%s pending=%s event=%v err=%v", status, pending, eventID, err)
	}
	get := fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String(), 0, fixture.handler.GetJob)
	if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), `"status":"running"`) {
		t.Fatalf("audit-pending job exposed as downloadable: %d %s", get.Code, get.Body.String())
	}
	response = fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String()+"/download", 0, fixture.handler.DownloadJob)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "schema_version") {
		t.Fatalf("pending audit released payload: %d %s", response.Code, response.Body.String())
	}
	fixture.handler.appendAudit = appendAudit
	if err := fixture.handler.reconcileAudit(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	fixture.handler.appendAudit = func(context.Context, audit.Event) (int64, string, error) {
		return 0, "", errors.New("audit store unavailable: password=not-for-clients")
	}
	response = fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String()+"/download", 0, fixture.handler.DownloadJob)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "schema_version") || strings.Contains(response.Body.String(), "not-for-clients") {
		t.Fatalf("download audit failure: %d %s", response.Code, response.Body.String())
	}
	fixture.handler.appendAudit = appendAudit
	response = fixture.request(http.MethodGet, "/api/v1/support/bundle/jobs/"+job.ID.String()+"/download", 0, fixture.handler.DownloadJob)
	if response.Code != http.StatusOK {
		t.Fatalf("recovered download: %d %s", response.Code, response.Body.String())
	}
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE target_id = $1 AND action = 'support.bundle.job.download'`, job.ID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("download audit count=%d err=%v", count, err)
	}
}

func TestSupportBundleJobsListLimitAndUnredactedPayloadRejected(t *testing.T) {
	fixture := newSupportBundleJobsFixture(t)
	_, err := fixture.db.Pool().Exec(context.Background(), `
INSERT INTO support_bundle_jobs (org_id, requested_by)
SELECT $1, $2 FROM generate_series(1, 105)`, fixture.orgs[0], fixture.users[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		path string
		want int
	}{
		{path: "/api/v1/support/bundle/jobs", want: 50},
		{path: "/api/v1/support/bundle/jobs?limit=101", want: 100},
	} {
		response := fixture.request(http.MethodGet, testCase.path, 0, fixture.handler.ListJobs)
		var page struct {
			Items      []supportBundleJobDTO `json:"items"`
			NextCursor string                `json:"next_cursor"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != testCase.want || page.NextCursor == "" {
			t.Fatalf("bounded list %s: %d %s", testCase.path, response.Code, response.Body.String())
		}
	}
	if _, err := fixture.db.Pool().Exec(context.Background(), `UPDATE support_bundle_jobs SET status = 'expired' WHERE org_id = $1`, fixture.orgs[0]); err != nil {
		t.Fatal(err)
	}
	job := fixture.create(t, 1)
	fixture.handler.build = func(_ context.Context, subject Subject) (supportBundleDTO, error) {
		bundle, err := newSupportBundle(subject.OrgID.String(), time.Now().UTC(), map[string]any{"safe": "value"})
		if err != nil {
			return supportBundleDTO{}, err
		}
		bundle.Sections["api_token"] = "raw-credential"
		bundle.Integrity.SHA256, err = supportBundleHash(bundle.Sections)
		return bundle, err
	}
	processed, err := fixture.handler.runOne(context.Background())
	if err != nil || !processed {
		t.Fatalf("unredacted worker: processed=%v err=%v", processed, err)
	}
	var status string
	var payload []byte
	if err := fixture.db.Pool().QueryRow(context.Background(), `SELECT status, payload FROM support_bundle_jobs WHERE id = $1`, job.ID).Scan(&status, &payload); err != nil || status != "failed" || payload != nil {
		t.Fatalf("unredacted payload persisted: status=%s payload=%s err=%v", status, payload, err)
	}
}
