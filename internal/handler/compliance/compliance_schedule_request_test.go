//go:build integration

package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type complianceScheduleRequestFixture struct {
	pool            *pgxpool.Pool
	org             uuid.UUID
	foreign         uuid.UUID
	ownedSchedule   uuid.UUID
	foreignSchedule uuid.UUID
	router          http.Handler
}

func newComplianceScheduleRequestFixture(t *testing.T) *complianceScheduleRequestFixture {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	f := &complianceScheduleRequestFixture{pool: database.Pool(), org: uuid.New(), foreign: uuid.New(), ownedSchedule: uuid.New(), foreignSchedule: uuid.New()}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM orgs WHERE id IN($1,$2)`, f.org, f.foreign)
	})
	for _, org := range []uuid.UUID{f.org, f.foreign} {
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "schedule-request-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range [][2]uuid.UUID{{f.ownedSchedule, f.org}, {f.foreignSchedule, f.foreign}} {
		if _, err := f.pool.Exec(t.Context(), `INSERT INTO compliance_schedules(id,org_id,name,framework,cron_expression,enabled,next_run_at) VALUES($1,$2,$3,'fixture','0 2 * * *',FALSE,NOW()+INTERVAL '1 day')`, row[0], row[1], "disabled-"+row[0].String()); err != nil {
			t.Fatal(err)
		}
	}
	router := chi.NewRouter()
	handler := NewComplianceSchedulesDB(database, audit.New(f.pool))
	router.Post("/compliance/schedules/{id}/run-now", handler.RunNow)
	f.router = router
	return f
}

func (f *complianceScheduleRequestFixture) request(t *testing.T, schedule uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/compliance/schedules/"+schedule.String()+"/run-now", nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: f.org, UserID: uuid.New()}))
	response := httptest.NewRecorder()
	f.router.ServeHTTP(response, request)
	return response
}

func (f *complianceScheduleRequestFixture) assertState(t *testing.T, schedule uuid.UUID, wantEnabled, wantDue bool) {
	t.Helper()
	var enabled, due, noLastRun, noLastStatus bool
	if err := f.pool.QueryRow(t.Context(), `SELECT enabled,next_run_at<=NOW(),last_run_at IS NULL,last_status IS NULL FROM compliance_schedules WHERE id=$1`, schedule).Scan(&enabled, &due, &noLastRun, &noLastStatus); err != nil {
		t.Fatal(err)
	}
	if enabled != wantEnabled || due != wantDue || !noLastRun || !noLastStatus {
		t.Fatalf("request state enabled=%t due=%t noLastRun=%t noLastStatus=%t", enabled, due, noLastRun, noLastStatus)
	}
	var runs int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM compliance_runs WHERE org_id IN($1,$2)`, f.org, f.foreign).Scan(&runs); err != nil {
		t.Fatal(err)
	}
	if runs != 0 {
		t.Fatalf("request inserted %d execution rows without a scheduler", runs)
	}
}

func TestComplianceScheduleRunRequestMarksDueWithoutExecuting(t *testing.T) {
	fixture := newComplianceScheduleRequestFixture(t)
	response := fixture.request(t, fixture.ownedSchedule)
	if response.Code != http.StatusAccepted {
		t.Fatalf("request status=%d body=%q", response.Code, response.Body.String())
	}
	var envelope struct {
		Schedule complianceScheduleRow `json:"schedule"`
		Queued   bool                  `json:"queued"`
		Message  string                `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.Queued || envelope.Schedule.ID != fixture.ownedSchedule || !envelope.Schedule.Enabled || envelope.Schedule.NextRunAt == nil {
		t.Fatalf("request compatibility envelope changed: %+v", envelope)
	}
	want := "Run requested; processing is pending. A running report scheduler is required. Review History for execution and delivery."
	if envelope.Message != want || strings.Contains(envelope.Message, "30s") {
		t.Fatalf("request message claims unsupported execution: %q", envelope.Message)
	}
	fixture.assertState(t, fixture.ownedSchedule, true, true)
	fixture.assertState(t, fixture.foreignSchedule, false, false)
}

func TestComplianceScheduleRunRequestRejectsForeignSchedule(t *testing.T) {
	fixture := newComplianceScheduleRequestFixture(t)
	response := fixture.request(t, fixture.foreignSchedule)
	if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), fixture.foreignSchedule.String()) {
		t.Fatalf("foreign request status=%d body=%q", response.Code, response.Body.String())
	}
	fixture.assertState(t, fixture.foreignSchedule, false, false)
	fixture.assertState(t, fixture.ownedSchedule, false, false)
}
