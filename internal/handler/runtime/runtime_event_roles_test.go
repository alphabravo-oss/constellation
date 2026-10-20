//go:build integration

package runtime

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestRuntimeAndTimelineRolesKeepExactEvidenceScope(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := context.Background()
	org, foreignOrg := uuid.New(), uuid.New()
	cluster, sibling, foreign := uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreignOrg} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "runtime-role-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM events WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM runtime_threats WHERE org_id IN($1,$2)`, org, foreignOrg)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreignOrg)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'a'),($3,$2,'b'),($4,$5,'foreign')`, cluster, org, sibling, foreign, foreignOrg); err != nil {
		t.Fatal(err)
	}
	deployment := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES
 ($1,$2,$3,'operations','api','Deployment','{"app.kubernetes.io/part-of":"astronomer"}'),
 (gen_random_uuid(),$2,$4,'operations','api','Deployment','{}'),
 (gen_random_uuid(),$5,$6,'operations','api','Deployment','{"helm.sh/chart":"constellation-1"}')`, deployment, org, cluster, sibling, foreignOrg, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id) VALUES($1,$2,'operations','api-pod','role-pod','operations/pod/api-pod','Deployment','api','operations/api',$3)`, org, cluster, deployment); err != nil {
		t.Fatal(err)
	}
	type evidence struct {
		org, cluster, id          uuid.UUID
		workload, namespace, role string
	}
	records := []evidence{{org, cluster, uuid.New(), "operations/api", "operations", "core"}, {org, sibling, uuid.New(), "operations/api", "operations", ""}, {org, cluster, uuid.New(), "operations/pod/api-pod", "operations", "core"}, {org, cluster, uuid.New(), "unknown/api", "unknown", ""}, {org, cluster, uuid.New(), "host/worker", "kube-system", ""}, {foreignOrg, foreign, uuid.New(), "operations/api", "operations", "core"}}
	for _, record := range records {
		if _, err := pool.Exec(ctx, `INSERT INTO events(id,org_id,cluster_id,node_id,workload_id,namespace,source,kind,severity,verdict,payload) VALUES($1,$2,$3,'node',$4,$5,'agent','event','high','alert','{}')`, record.id, record.org, record.cluster, record.workload, record.namespace); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO runtime_threats(id,org_id,cluster_id,workload_id,namespace,threat_id,severity,reported_at) VALUES($1,$2,$3,$4,$5,2022,8,NOW())`, record.id, record.org, record.cluster, record.workload, record.namespace); err != nil {
			t.Fatal(err)
		}
	}
	request := func(path string, fn http.HandlerFunc) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		fn(w, r)
		return w
	}
	decode := func(w *httptest.ResponseRecorder, result any) {
		t.Helper()
		if w.Code != 200 {
			t.Fatalf("status=%d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), result); err != nil {
			t.Fatal(err)
		}
	}
	var raw struct {
		Events []EventDTO `json:"events"`
	}
	decode(request("/api/v1/events", NewEventsIngest(d, nil, nil).List), &raw)
	if len(raw.Events) != 5 {
		t.Fatalf("raw tenant scope count=%d", len(raw.Events))
	}
	byID := map[uuid.UUID]EventDTO{}
	for _, row := range raw.Events {
		byID[row.ID] = row
	}
	for _, record := range records {
		if record.org == org {
			row, ok := byID[record.id]
			if !ok || row.PlatformRole != record.role || row.ClusterID != record.cluster {
				t.Fatalf("wrong raw role/cluster: %+v wanted %+v", row, record)
			}
		} else if _, ok := byID[record.id]; ok {
			t.Fatal("foreign event exposed")
		}
	}
	for _, scope := range []string{"", "&cluster_id=" + cluster.String()} {
		var overview struct {
			Summary struct {
				Events int `json:"events"`
			} `json:"summary"`
			Recent    []struct{ ID, ClusterID, WorkloadID, PlatformRole string } `json:"recent_events"`
			Workloads []map[string]any                                           `json:"workloads"`
		}
		// Decode snake_case metadata explicitly in a separate map below.
		response := request("/api/v1/runtime/overview?hours=24"+scope, handler.NewEnterprise(d).RuntimeOverview)
		decode(response, &overview)
		var body map[string]json.RawMessage
		decode(response, &body)
		var recent []map[string]any
		if err := json.Unmarshal(body["recent_events"], &recent); err != nil {
			t.Fatal(err)
		}
		want := 5
		if scope != "" {
			want = 4
		}
		if overview.Summary.Events != want || len(recent) != want {
			t.Fatalf("overview source counts changed: %+v", overview.Summary)
		}
		for _, record := range records {
			if record.org != org || scope != "" && record.cluster != cluster {
				continue
			}
			found := false
			for _, row := range recent {
				if row["id"] == record.id.String() {
					found = true
					if row["platform_role"] != record.role {
						t.Fatalf("overview role: %#v wanted %+v", row, record)
					}
				}
			}
			if !found {
				t.Fatalf("missing recent %s", record.id)
			}
		}
		for _, row := range overview.Workloads {
			if row["workload_id"] == "operations/api" {
				role := ""
				events := float64(2)
				if scope != "" {
					role = "core"
					events = 1
				}
				if row["platform_role"] != role || row["events"] != events {
					t.Fatalf("org ambiguity/grouping changed: %#v", row)
				}
				if scope == "" && row["cluster_id"] != nil {
					t.Fatalf("ambiguous aggregate has a fabricated cluster: %#v", row)
				}
			}
		}
	}
	timeline := handler.NewSecurityTimeline(d)
	for _, source := range []string{"runtime_event", "dpi_threat"} {
		response := request("/api/v1/security/timeline?type="+source+"&hours=24", timeline.List)
		var body struct {
			Items []map[string]any `json:"items"`
		}
		decode(response, &body)
		if len(body.Items) != 5 {
			t.Fatalf("timeline %s tenant count %d", source, len(body.Items))
		}
		for _, record := range records {
			if record.org != org {
				continue
			}
			found := false
			for _, row := range body.Items {
				if row["id"] == record.id.String() {
					found = true
					if row["platform_role"] != record.role {
						t.Fatalf("timeline wrong role: %#v wanted %+v", row, record)
					}
				}
			}
			if !found {
				t.Fatalf("missing timeline %s", record.id)
			}
		}
		response = request("/api/v1/security/timeline.csv?type="+source+"&hours=24", timeline.ExportCSV)
		if response.Code != 200 {
			t.Fatalf("CSV status=%d %s", response.Code, response.Body.String())
		}
		rows, err := csv.NewReader(strings.NewReader(response.Body.String())).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		roleIndex := -1
		for i, header := range rows[0] {
			if header == "platform_role" {
				roleIndex = i
			}
		}
		if roleIndex < 0 {
			t.Fatal("role missing from CSV")
		}
		exported := map[string]string{}
		for _, row := range rows[1:] {
			exported[row[0]] = row[roleIndex]
		}
		for _, record := range records {
			if record.org == org {
				role, ok := exported[record.id.String()]
				if !ok || role != record.role {
					t.Fatalf("CSV role for %s=%q", record.id, role)
				}
			}
		}
	}
	// A violation is tied to an exact deployment ID. A same-name different-kind
	// workload must not override that evidence's known installation labels.
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'operations','api','StatefulSet','{}')`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO violations(org_id,deployment_id,severity,kind,message) VALUES($1,$2,'high','runtime','exact deployment')`, org, deployment); err != nil {
		t.Fatal(err)
	}
	response := request("/api/v1/security/timeline?type=network_violation&cluster_id="+cluster.String(), timeline.List)
	var violations struct {
		Items []map[string]any `json:"items"`
	}
	decode(response, &violations)
	if len(violations.Items) != 1 || violations.Items[0]["platform_role"] != "core" {
		t.Fatalf("exact violation identity role lost: %+v", violations.Items)
	}
}
