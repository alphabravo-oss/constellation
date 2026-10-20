//go:build integration

package compliance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestComplianceSchedulePatchRejectsStaleVersion(t *testing.T) {
	f := newComplianceScheduleRequestFixture(t)
	database := openTestDB(t)
	defer database.Close()
	h := NewComplianceSchedulesDB(database, audit.New(f.pool))
	router := chi.NewRouter()
	router.Patch("/schedules/{id}", h.Patch)
	var version time.Time
	if err := f.pool.QueryRow(t.Context(), `SELECT updated_at FROM compliance_schedules WHERE id=$1`, f.ownedSchedule).Scan(&version); err != nil {
		t.Fatal(err)
	}
	patch := func(id uuid.UUID, name string, expected time.Time) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]any{"name": name, "expected_updated_at": expected})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPatch, "/schedules/"+id.String(), strings.NewReader(string(body)))
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: f.org, UserID: uuid.New()}))
		res := httptest.NewRecorder()
		router.ServeHTTP(res, req)
		return res
	}
	if res := patch(f.ownedSchedule, "newer saved name", version); res.Code != http.StatusOK {
		t.Fatalf("first patch: %d %s", res.Code, res.Body.String())
	}
	if res := patch(f.ownedSchedule, "stale overwrite", version); res.Code != http.StatusConflict {
		t.Fatalf("stale patch: %d %s", res.Code, res.Body.String())
	}
	if res := patch(f.foreignSchedule, "foreign overwrite", version); res.Code != http.StatusNotFound {
		t.Fatalf("foreign patch: %d", res.Code)
	}
	var name string
	if err := f.pool.QueryRow(t.Context(), `SELECT name FROM compliance_schedules WHERE id=$1`, f.ownedSchedule).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if name != "newer saved name" {
		t.Fatalf("stale edit overwrote name: %q", name)
	}
	var updates int
	if err := f.pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='compliance.schedule.update'`, f.org).Scan(&updates); err != nil {
		t.Fatal(err)
	}
	if updates != 1 {
		t.Fatalf("successful update audits=%d, want 1", updates)
	}
}

// A legacy client without a version must still not overwrite a change committed
// after the handler read its snapshot but before its UPDATE acquired the row.
func TestComplianceSchedulePatchRejectsConcurrentWrite(t *testing.T) {
	f := newComplianceScheduleRequestFixture(t)
	database := openTestDB(t)
	defer database.Close()
	h := NewComplianceSchedulesDB(database, audit.New(f.pool))
	router := chi.NewRouter()
	router.Patch("/schedules/{id}", h.Patch)
	tx, err := f.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.WithoutCancel(t.Context()))
	var blocker int
	if err := tx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(t.Context(), `UPDATE compliance_schedules SET name='concurrent winner',updated_at=clock_timestamp() WHERE id=$1`, f.ownedSchedule); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodPatch, "/schedules/"+f.ownedSchedule.String(), strings.NewReader(`{"description":"stale snapshot"}`))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: f.org, UserID: uuid.New()}))
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { res := httptest.NewRecorder(); router.ServeHTTP(res, req); done <- res }()
	for {
		var waiting bool
		if err := f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, blocker).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case res := <-done:
			t.Fatalf("patch ended before conflicting commit: %d", res.Code)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-done:
		if res.Code != http.StatusConflict {
			t.Fatalf("concurrent patch: %d %s", res.Code, res.Body.String())
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var name, description string
	if err := f.pool.QueryRow(ctx, `SELECT name,description FROM compliance_schedules WHERE id=$1`, f.ownedSchedule).Scan(&name, &description); err != nil {
		t.Fatal(err)
	}
	if name != "concurrent winner" || description == "stale snapshot" {
		t.Fatalf("concurrent update lost: name=%q description=%q", name, description)
	}
}
