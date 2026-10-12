package compliance

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/google/uuid"
)

func TestComplianceChecksInventory(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := context.Background()
	org, foreignOrg, cluster, otherCluster, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "compliance-inventory-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'selected'),($3,$2,'other'),($4,$5,'foreign')`, cluster, org, otherCluster, foreignCluster, foreignOrg); err != nil {
		t.Fatal(err)
	}
	insert := func(o uuid.UUID, c any, framework, control, status, title string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO compliance_checks(id,org_id,cluster_id,framework,control_id,title,status,severity,evidence,tags_v2,evaluated_at) VALUES($1,$2,$3,$4,$5,$6,$7,'high','literal %_\ evidence','{"profile-a":{}}'::jsonb,'2026-10-12T00:00:00Z')`, id, o, c, framework, control, title, status); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// Duplicate framework/control evidence is intentionally counted independently.
	insert(org, cluster, "alpha", "same", "pass", "alpha pass 1")
	insert(org, cluster, "alpha", "same", "pass", "alpha pass 2")
	insert(org, cluster, "zulu", "same", "fail", "zulu fail")
	for _, status := range []string{"manual", "not_applicable", "unknown"} {
		insert(org, cluster, "alpha", status, status, status)
	}
	insert(org, cluster, "alpha", "accepted", "fail", "active exemption")
	insert(org, cluster, "alpha", "expired", "fail", "expired exemption")
	insert(org, cluster, "alpha", "revoked", "fail", "revoked exemption")
	insert(org, cluster, "alpha", "foreign-exemption", "fail", "foreign exemption")
	insert(org, otherCluster, "alpha", "other", "fail", "other cluster")
	insert(org, nil, "alpha", "org", "pass", "organization evidence")
	insert(org, foreignCluster, "alpha", "bad", "pass", "misattributed cluster")
	insert(foreignOrg, foreignCluster, "alpha", "foreign", "pass", "foreign org")
	for _, e := range []struct {
		control string
		owner   uuid.UUID
		scope   any
		expiry  string
		revoked bool
	}{
		{"accepted", org, nil, "1 day", false}, {"accepted", org, cluster, "2 days", false}, {"expired", org, cluster, "-1 day", false}, {"revoked", org, cluster, "1 day", true}, {"foreign-exemption", foreignOrg, cluster, "1 day", false},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO compliance_exemptions(org_id,cluster_id,framework,control_id,reason,expires_at,revoked_at) VALUES($1,$2,'alpha',$3,'Approved fixture',$4::interval+NOW(),CASE WHEN $5 THEN NOW() ELSE NULL END)`, e.owner, e.scope, e.control, e.expiry, e.revoked); err != nil {
			t.Fatal(err)
		}
	}
	h := NewCompliance(d, nil)
	request := func(serve func(http.ResponseWriter, *http.Request), owner uuid.UUID, params string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/compliance/checks?"+params, nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: owner}))
		w := httptest.NewRecorder()
		serve(w, r)
		return w
	}
	type result struct {
		Checks  []complianceInventoryCheck `json:"checks"`
		Total   int                        `json:"total"`
		HasMore bool                       `json:"has_more"`
		Limit   int                        `json:"limit"`
		Offset  int                        `json:"offset"`
		Summary map[string]int             `json:"summary"`
	}
	read := func(params string) result {
		t.Helper()
		w := request(h.Checks, org, params)
		if w.Code != 200 {
			t.Fatalf("status %d: %s", w.Code, w.Body.String())
		}
		var body result
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	scope := "cluster_id=" + cluster.String()
	t.Run("graded matches dashboard summary across duplicate frameworks", func(t *testing.T) {
		body := read(scope + "&framework=all&status=graded&limit=100")
		if body.Total != 6 || body.Summary["pass"] != 2 || body.Summary["fail"] != 4 || body.Summary["ungraded"] != 0 {
			t.Fatalf("graded cohort %+v", body)
		}
		w := request(h.Summary, org, scope)
		if w.Code != 200 {
			t.Fatalf("summary %d %s", w.Code, w.Body.String())
		}
		var summary struct{ Frameworks []struct{ Pass, Fail int } }
		if err := json.Unmarshal(w.Body.Bytes(), &summary); err != nil {
			t.Fatal(err)
		}
		pass, fail := 0, 0
		for _, f := range summary.Frameworks {
			pass += f.Pass
			fail += f.Fail
		}
		if pass != body.Summary["pass"] || fail != body.Summary["fail"] {
			t.Fatalf("source=%d/%d destination=%v", pass, fail, body.Summary)
		}
		all := read(scope + "&limit=100")
		if all.Total != 10 || all.Summary["exempted"] != 1 || all.Summary["manual"] != 1 || all.Summary["not_applicable"] != 1 || all.Summary["ungraded"] != 4 {
			t.Fatalf("all cohort %+v", all)
		}
		for _, row := range all.Checks {
			if row.ControlID == "accepted" && (row.Exemption == nil || row.Exemption.ExpiresAt.Before(row.EvaluatedAt)) {
				t.Fatalf("missing active exemption %+v", row)
			}
		}
	})
	t.Run("tenant cluster and filters", func(t *testing.T) {
		all := read("limit=100")
		if all.Total != 12 {
			t.Fatalf("org total=%d", all.Total)
		}
		for _, params := range []string{"cluster_id=" + foreignCluster.String(), "cluster_id=" + uuid.NewString()} {
			w := request(h.Checks, org, params)
			if w.Code != 404 {
				t.Fatalf("scope %s: %d", params, w.Code)
			}
		}
		w := request(h.Checks, foreignOrg, "cluster_id="+foreignCluster.String())
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		var foreign result
		_ = json.Unmarshal(w.Body.Bytes(), &foreign)
		if foreign.Total != 1 {
			t.Fatalf("foreign %+v", foreign)
		}
		if body := read(scope + "&framework=alpha&control_id=same&profile=profile-a&status=pass"); body.Total != 2 {
			t.Fatalf("exact filter %+v", body)
		}
		if body := read(scope + "&q=" + url.QueryEscape("%_\\")); body.Total != 10 {
			t.Fatalf("literal matching %+v", body)
		}
		if body := read(scope + "&q=" + url.QueryEscape("%_\\does-not-exist")); body.Total != 0 {
			t.Fatalf("wildcards broadened %+v", body)
		}
	})
	t.Run("primary descending sort and matching CSV", func(t *testing.T) {
		body := read(scope + "&status=graded&sort=framework&order=desc&limit=1")
		if len(body.Checks) != 1 || body.Checks[0].Framework != "zulu" || !body.HasMore {
			t.Fatalf("descending framework %+v", body)
		}
		control := read(scope + "&status=graded&sort=control&order=desc&limit=1")
		if control.Checks[0].ControlID != "same" {
			t.Fatalf("descending control %+v", control)
		}
		w := request(h.ChecksCSV, org, scope+"&status=graded&sort=framework&order=desc&limit=1&offset=5")
		if w.Code != 200 {
			t.Fatalf("csv %d %s", w.Code, w.Body.String())
		}
		rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 7 || rows[1][3] != "zulu" || w.Header().Get("X-Export-Total") != "6" || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "false" {
			t.Fatalf("csv %v headers=%v", rows, w.Header())
		}
	})
	t.Run("stable continuation and exact control beyond legacy bound", func(t *testing.T) {
		for i := 0; i < 205; i++ {
			insert(org, cluster, "paging", fmt.Sprintf("%04d", i), "pass", fmt.Sprintf("Paged %d", i))
		}
		seen := map[uuid.UUID]bool{}
		for offset := 0; offset < 205; offset += 100 {
			body := read(scope + fmt.Sprintf("&framework=paging&limit=100&offset=%d&sort=evaluated&order=desc", offset))
			if body.Total != 205 || body.HasMore != (offset < 200) {
				t.Fatalf("page %+v", body)
			}
			for _, row := range body.Checks {
				if seen[row.ID] {
					t.Fatalf("duplicate page id %s", row.ID)
				}
				seen[row.ID] = true
			}
		}
		if len(seen) != 205 {
			t.Fatalf("loaded %d", len(seen))
		}
		for i := 0; i < 501; i++ {
			insert(org, cluster, "legacy", fmt.Sprintf("%04d", i), "pass", "Legacy row")
		}
		insert(org, cluster, "legacy", "zz-final", "fail", "Exact selected control")
		legacy := read(scope + "&framework=legacy")
		if legacy.Limit != 500 || len(legacy.Checks) != 500 || legacy.Total != 502 {
			t.Fatalf("legacy %+v", legacy)
		}
		exact := read(scope + "&framework=legacy&control_id=zz-final")
		if exact.Total != 1 || exact.Checks[0].Title != "Exact selected control" {
			t.Fatalf("exact %+v", exact)
		}
	})
	t.Run("reject invalid query contracts", func(t *testing.T) {
		for _, params := range []string{"sort=DROP", "sort=framework;DROP", "order=invalid", "status=unknown", "cluster_id=bad"} {
			for _, serve := range []func(http.ResponseWriter, *http.Request){h.Checks, h.ChecksCSV} {
				w := request(serve, org, params)
				if w.Code != 400 {
					t.Fatalf("query %s status %d: %s", params, w.Code, w.Body.String())
				}
			}
		}
	})
}
