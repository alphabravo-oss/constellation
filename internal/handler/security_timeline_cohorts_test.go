package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestTimelineDashboardCohortsExactCountsAndScope(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := context.Background()
	org, foreignOrg := uuid.New(), uuid.New()
	cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "timeline-cohort-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'a'),($3,$2,'b'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		severity, verdict string
		hours             int
	}{{"critical", "alert", 2}, {"high", "block", 25}, {"low", "quarantine", 1}, {"critical", "allow", 1}, {"critical", "ALERT", 1}, {"HIGH", "alert", 1}, {"high", "alert", 384}, {"critical", "alert", 48}, {"critical", "alert", -48}}
	for i, row := range rows {
		if _, err := pool.Exec(ctx, `INSERT INTO events(org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict,at,payload) VALUES($1,$2,'node','prod/api','prod','agent',$3,$4,$5,NOW()-make_interval(hours=>$6),'{}')`, org, cluster, "event-"+string(rune('a'+i)), row.severity, row.verdict, row.hours); err != nil {
			t.Fatal(err)
		}
	}
	for _, identity := range []struct{ org, cluster uuid.UUID }{{org, sibling}, {foreignOrg, foreign}} {
		if _, err := pool.Exec(ctx, `INSERT INTO events(org_id,cluster_id,node_id,workload_id,source,kind,severity,verdict,at,payload) VALUES($1,$2,'node','other/api','agent','excluded','critical','alert',NOW(),'{}')`, identity.org, identity.cluster); err != nil {
			t.Fatal(err)
		}
	}
	request := func(path string, fn http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		fn(w, req)
		return w
	}
	timeline := NewSecurityTimeline(d)
	var runtime struct {
		Summary runtimeEvidenceSummaryDTO `json:"summary"`
	}
	response := request("/api/v1/runtime/overview?hours=24&cluster_id="+cluster.String(), NewEnterprise(d).RuntimeOverview)
	if response.Code != 200 {
		t.Fatalf("runtime=%d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &runtime); err != nil {
		t.Fatal(err)
	}
	if runtime.Summary.Alerts != 4 || runtime.Summary.WindowStart == "" {
		t.Fatalf("runtime source: %+v", runtime.Summary)
	}
	var daily struct {
		WindowStart string             `json:"window_start"`
		Events      []eventsTimelineDT `json:"events_timeline"`
	}
	response = request("/api/v1/dashboard/events-timeline?cluster_id="+cluster.String(), NewDashboard(d).EventsTimeline)
	if response.Code != 200 {
		t.Fatalf("daily=%d %s", response.Code, response.Body.String())
	}
	if err := json.Unmarshal(response.Body.Bytes(), &daily); err != nil {
		t.Fatal(err)
	}
	dailyTotal := 0
	for _, day := range daily.Events {
		dailyTotal += day.Total
	}
	if dailyTotal != 6 || daily.WindowStart == "" {
		t.Fatalf("daily source: %+v", daily)
	}
	for _, cohort := range []struct {
		name, bound, filters string
		expected             int
	}{{"runtime", runtime.Summary.WindowStart, "verdict=alert,block,quarantine", runtime.Summary.Alerts}, {"daily", daily.WindowStart, "severity=high,critical&after_exclusive=true", dailyTotal}} {
		t.Run(cohort.name, func(t *testing.T) {
			path := "/api/v1/security/timeline?type=runtime_event&cluster_id=" + cluster.String() + "&after=" + url.QueryEscape(cohort.bound) + "&" + cohort.filters
			seen := map[string]bool{}
			for offset := 0; offset < cohort.expected; offset += 2 {
				response := request(path+"&limit=2&offset="+strconv.Itoa(offset), timeline.List)
				if response.Code != 200 {
					t.Fatalf("timeline=%d %s", response.Code, response.Body.String())
				}
				var body struct {
					Items     []timelineItem `json:"items"`
					Total     int            `json:"total"`
					HasMore   bool           `json:"has_more"`
					From      string         `json:"from"`
					LowerOnly bool           `json:"lower_only"`
				}
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body.Total != cohort.expected || body.From != cohort.bound || !body.LowerOnly {
					t.Fatalf("scope/count: %+v", body)
				}
				for _, item := range body.Items {
					if seen[item.ID] {
						t.Fatalf("duplicate across pages: %s", item.ID)
					}
					seen[item.ID] = true
					if item.ClusterID != cluster.String() {
						t.Fatalf("wrong cluster: %+v", item)
					}
				}
				if body.HasMore != (offset+len(body.Items) < body.Total) {
					t.Fatalf("has_more: %+v", body)
				}
			}
			if len(seen) != cohort.expected {
				t.Fatalf("got %d IDs", len(seen))
			}
			response := request(strings.Replace(path, "/timeline?", "/timeline.csv?", 1)+"&limit=1&offset=100", timeline.ExportCSV)
			if response.Code != 200 {
				t.Fatalf("csv=%d %s", response.Code, response.Body.String())
			}
			csvRows, err := csv.NewReader(strings.NewReader(response.Body.String())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(csvRows) != cohort.expected+1 || response.Header().Get("X-Export-Total") != strconv.Itoa(cohort.expected) || response.Header().Get("X-Export-Truncated") != "false" {
				t.Fatalf("CSV scope: %v rows=%d", response.Header(), len(csvRows))
			}
			for _, row := range csvRows[1:] {
				if !seen[row[0]] {
					t.Fatalf("CSV diverged: %v", row)
				}
			}
		})
	}
	for _, fn := range []http.HandlerFunc{timeline.List, timeline.ExportCSV} {
		response = request("/api/v1/security/timeline?type=runtime_event&cluster_id="+foreign.String()+"&hours=24", fn)
		if response.Code != 404 {
			t.Fatalf("foreign cluster %d", response.Code)
		}
		for _, filters := range []string{"after=bad", "hours=0", "hours=2161", "hours=24&from=2026-10-01T00:00:00Z", "after_exclusive=true", "offset=1000001", "verdict=alert&type=dpi_threat", "verdict=unknown"} {
			response = request("/api/v1/security/timeline?cluster_id="+cluster.String()+"&"+filters, fn)
			if response.Code != 400 {
				t.Fatalf("%s status=%d %s", filters, response.Code, response.Body.String())
			}
		}
	}
	// Exact lower-bound inclusivity is preserved at PostgreSQL microsecond precision.
	bound := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	if _, err := pool.Exec(ctx, `INSERT INTO events(org_id,cluster_id,node_id,workload_id,source,kind,severity,verdict,at,payload) VALUES($1,$2,'node','boundary','agent','boundary','high','alert',$3,'{}')`, org, cluster, bound); err != nil {
		t.Fatal(err)
	}
	for _, exclusive := range []bool{false, true} {
		response = request("/api/v1/security/timeline?type=runtime_event&cluster_id="+cluster.String()+"&q=boundary&after="+url.QueryEscape(bound.Format(time.RFC3339Nano))+"&after_exclusive="+strconv.FormatBool(exclusive), timeline.List)
		var body struct {
			Total int `json:"total"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		want := 1
		if exclusive {
			want = 0
		}
		if response.Code != 200 || body.Total != want {
			t.Fatalf("boundary exclusive=%t body=%s", exclusive, response.Body.String())
		}
	}
}

func TestTimelineEventExportCapAndStablePages(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "timeline-large-"+org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE org_id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'large')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO events(org_id,cluster_id,node_id,workload_id,source,kind,severity,verdict,at,payload) SELECT $1,$2,'node','prod/api','agent','large-alert','high','alert',NOW(),'{}'::jsonb FROM generate_series(1,10005)`, org, cluster); err != nil {
		t.Fatal(err)
	}
	h := NewSecurityTimeline(d)
	request := func(path string, fn http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: org}))
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	base := "/api/v1/security/timeline?cluster_id=" + cluster.String() + "&type=runtime_event&hours=24&verdict=alert&limit=100&offset=200"
	w := request(base, h.List)
	if w.Code != 200 {
		t.Fatalf("list %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Items   []timelineItem `json:"items"`
		Total   int            `json:"total"`
		HasMore bool           `json:"has_more"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Total != 10005 || len(body.Items) != 100 || !body.HasMore {
		t.Fatalf("large page: %+v", body)
	}
	again := request(base, h.List)
	if again.Body.String() != w.Body.String() {
		var repeated struct {
			Items []timelineItem `json:"items"`
		}
		if err := json.Unmarshal(again.Body.Bytes(), &repeated); err != nil {
			t.Fatal(err)
		}
		for i, item := range body.Items {
			if repeated.Items[i].ID != item.ID {
				t.Fatal("unstable equal-timestamp ordering")
			}
		}
	}
	w = request(strings.Replace(base, "timeline?", "timeline.csv?", 1), h.ExportCSV)
	if w.Code != 200 {
		t.Fatalf("export %d: %s", w.Code, w.Body.String())
	}
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 10001 || w.Header().Get("X-Export-Total") != "10005" || w.Header().Get("X-Export-Limit") != "10000" || w.Header().Get("X-Export-Truncated") != "true" {
		t.Fatalf("cap rows=%d headers=%v", len(rows), w.Header())
	}
}

func TestTimelineReadFailuresDoNotReportEmptySuccess(t *testing.T) {
	d := openTestDB(t)
	h := NewSecurityTimeline(d)
	for _, fn := range []http.HandlerFunc{h.List, h.ExportCSV} {
		w := httptest.NewRecorder()
		fn(w, httptest.NewRequest(http.MethodGet, "/api/v1/security/timeline?type=runtime_event", nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("missing subject=%d", w.Code)
		}
	}
	d.Close()
	for _, fn := range []http.HandlerFunc{h.List, h.ExportCSV} {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/security/timeline?type=runtime_event&hours=24", nil)
		r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: uuid.New()}))
		w := httptest.NewRecorder()
		fn(w, r)
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), `"items":[]`) || strings.Contains(w.Header().Get("Content-Type"), "text/csv") {
			t.Fatalf("failed DB falsely successful: %d %s", w.Code, w.Body.String())
		}
	}
}
