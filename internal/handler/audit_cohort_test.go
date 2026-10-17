package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestAuditSelectedCohortValidation(t *testing.T) {
	for _, query := range []string{"event_ids=-1", "event_ids=0", "event_ids=01", "event_ids=1,,2", "event_ids=9223372036854775808", "event_ids=1&event_ids=2", "event_ids=1&cluster_id=" + uuid.NewString(), "event_ids=1&event_id=1", "event_ids=1&action=test", "event_ids=" + strings.Repeat("1,", 20) + "1", "event_ids=1;bad"} {
		if _, _, err := auditEventCohort(httptest.NewRequest("GET", "/?"+query, nil)); err == nil {
			t.Errorf("accepted %q", query)
		}
	}
	ids, set, err := auditEventCohort(httptest.NewRequest("GET", "/?event_ids=42,42,43", nil))
	if err != nil || !set || len(ids) != 2 {
		t.Fatalf("deduplicated cohort: %v %v %v", ids, set, err)
	}
	ids, set, err = auditEventCohort(httptest.NewRequest("GET", "/?event_ids=", nil))
	if err != nil || !set || ids == nil || len(ids) != 0 {
		t.Fatalf("empty cohort widened: %v %v %v", ids, set, err)
	}
}

func TestDashboardAuditSelectedCohortStaysExact(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	org, other := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, other} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "audit-cohort-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, other) })
	logger := audit.New(d.Pool())
	at := time.Now().UTC().Truncate(time.Second)
	insert := func(owner uuid.UUID, action string) string {
		t.Helper()
		id, _, err := logger.Log(ctx, audit.Event{OrgID: &owner, Action: action, At: at})
		if err != nil {
			t.Fatal(err)
		}
		return strconv.FormatInt(id, 10)
	}
	ids := []string{}
	for i := 0; i < 25; i++ {
		ids = append(ids, insert(org, "activity."+strconv.Itoa(i)))
	}
	foreign := insert(other, "foreign")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/v1/dashboard/summary", nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org}))
	NewDashboard(d).Summary(rec, req)
	if rec.Code != 200 {
		t.Fatalf("summary %d: %s", rec.Code, rec.Body.String())
	}
	var summary dashboardSummaryDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if len(summary.RecentActivity) != 20 {
		t.Fatalf("summary len=%d", len(summary.RecentActivity))
	}
	selected := []string{}
	for i, row := range summary.RecentActivity {
		if row.ID != ids[24-i] {
			t.Fatalf("tie order %d=%s", i, row.ID)
		}
		selected = append(selected, row.ID)
	}
	newer := insert(org, "newer.after.dashboard")
	read := func(query string) []auditDTO {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/audit/events?"+query, nil)
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org}))
		rec := httptest.NewRecorder()
		NewAudit(d).List(rec, req)
		if rec.Code != 200 {
			t.Fatalf("list %d: %s", rec.Code, rec.Body.String())
		}
		var out struct {
			Events  []auditDTO `json:"events"`
			HasMore bool       `json:"has_more"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.HasMore {
			t.Fatal("bounded cohort unexpectedly has more")
		}
		return out.Events
	}
	rows := read("event_ids=" + url.QueryEscape(strings.Join(selected, ",")) + "&limit=20")
	if len(rows) != 20 {
		t.Fatalf("rows=%d", len(rows))
	}
	for i, row := range rows {
		if row.EventID != selected[i] || row.EventID == newer {
			t.Fatalf("cohort shifted %d=%s", i, row.EventID)
		}
	}
	rows = read("event_ids=" + selected[0] + "," + foreign)
	if len(rows) != 1 || rows[0].EventID != selected[0] {
		t.Fatalf("foreign cohort leak: %+v", rows)
	}
	if rows = read("event_ids="); len(rows) != 0 {
		t.Fatal("empty selection widened")
	}
	// Explicit record lookup stays tenant-scoped through the same audit endpoint.
	rows = read("event_id=" + foreign)
	if len(rows) != 0 {
		t.Fatal("foreign event lookup leaked")
	}
}
