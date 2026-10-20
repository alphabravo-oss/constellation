//go:build integration

package runtime

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestRuntimeThreatInventoryFullCohortAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, cluster, sibling, foreignCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'inventory'),($2::uuid,$2::text,'foreign')`, org, foreign)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM runtime_threats WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'main'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreign)
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,labels) VALUES(gen_random_uuid(),$1,$2,'operations','core','Deployment','{"app.kubernetes.io/part-of":"constellation"}')`, org, cluster)
	exec(`INSERT INTO runtime_threats(org_id,cluster_id,node,workload_id,namespace,threat_id,severity,action,application,src_ip,dst_ip,dst_port,msg,reported_at,at)
 SELECT $1,$2,'node-a','prod/api','prod',2022,CASE WHEN n<=600 THEN 8 ELSE 4 END,CASE WHEN n<=600 THEN 2 ELSE 0 END,7,'10.0.0.1','10.0.0.2',443,CASE WHEN n=1 THEN 'literal%_needle' ELSE 'message' END,NOW(),NOW() FROM generate_series(1,1205)n`, org, cluster)
	exec(`INSERT INTO runtime_threats(org_id,cluster_id,workload_id,namespace,threat_id,severity,action,reported_at,at)
 SELECT $1,$2,'operations/core','operations',40001,9,4,NOW(),NOW() FROM generate_series(1,15)`, org, cluster)
	exec(`INSERT INTO runtime_threats(org_id,cluster_id,workload_id,namespace,threat_id,severity,reported_at,at) VALUES($1,$2,'prod/api','prod',2022,8,NOW(),NOW()),($1,$3,'prod/api','prod',2022,8,NOW(),NOW()),($4,$5,'prod/api','prod',2022,8,NOW(),NOW()),($1,$2,'prod/old','prod',2022,8,NOW()-INTERVAL '730 hours',NOW()-INTERVAL '730 hours')`, org, cluster, sibling, foreign, foreignCluster)
	h := NewRuntimeThreats(d)
	request := func(query string, csv bool, code int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/runtime-threats?"+query, nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: org, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		if csv {
			h.ListCSV(w, r)
		} else {
			h.List(w, r)
		}
		if w.Code != code {
			t.Fatalf("query %s code %d want%d: %s", query, w.Code, code, w.Body.String())
		}
		return w
	}
	type page struct {
		Threats     []RuntimeThreatRow
		Total       int
		Summary     map[string]int
		HasMore     bool   `json:"has_more"`
		ClusterID   string `json:"cluster_id"`
		Sort, Order string
	}
	read := func(query string) page {
		t.Helper()
		var p page
		if err := json.Unmarshal(request(query, false, 200).Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := "cluster_id=" + cluster.String() + "&hide_platform=true&sort=severity&order=desc"
	first := read(base + "&limit=100")
	if first.Total != 1206 || first.Summary["critical"] != 601 || first.Summary["blocked"] != 600 || len(first.Threats) != 100 || !first.HasMore || first.ClusterID != cluster.String() {
		t.Fatalf("bad full metadata %+v", first)
	}
	allIDs := []string{}
	seen := map[string]bool{}
	previous := int16(10)
	for offset := 0; offset < first.Total; offset += 100 {
		p := read(base + "&limit=100&offset=" + strconv.Itoa(offset))
		if p.Total != first.Total {
			t.Fatal("total changed")
		}
		for _, row := range p.Threats {
			if seen[row.ID] || row.Severity > previous || row.PlatformRole == "core" || row.ClusterID != cluster.String() {
				t.Fatalf("bad row %+v", row)
			}
			previous = row.Severity
			seen[row.ID] = true
			allIDs = append(allIDs, row.ID)
		}
	}
	if len(allIDs) != 1206 {
		t.Fatalf("missing rows %d", len(allIDs))
	}
	empty := read(base + "&offset=2000000")
	if len(empty.Threats) != 0 || empty.Total != 1206 || empty.HasMore {
		t.Fatal("empty page lost metadata")
	}
	response := request(base+"&limit=1&offset=999999", true, 200)
	records, err := csv.NewReader(strings.NewReader(response.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1207 || response.Header().Get("X-Export-Total") != "1206" || response.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("badCSV %d", len(records))
	}
	for i, row := range records[1:] {
		if row[0] != allIDs[i] {
			t.Fatal("CSV order differs")
		}
	}
	filtered := read(base + "&q=literal%25_needle&port=443&peer=10.0.0.2&application=7&namespace=prod&node=node-a")
	if filtered.Total != 1 {
		t.Fatalf("literal filters=%d", filtered.Total)
	}
	if read(base+"&application=https").Total != 1205 {
		t.Fatal("named application filter ignored")
	}
	if read(base+"&application=dns").Total != 0 {
		t.Fatal("named application mismatch")
	}
	withCore := read("cluster_id=" + cluster.String() + "&category=waf")
	if withCore.Total != 15 || withCore.Summary["critical"] != 15 || withCore.Threats[0].PlatformRole != "core" {
		t.Fatal("core evidence missing")
	}
	if read("cluster_id="+sibling.String()).Total != 1 {
		t.Fatal("sibling cohort")
	}
	for _, query := range []string{"limit=0", "limit=2001", "offset=-1", "offset=2147483648", "hours=banana", "severity_min=10", "application=-1", "sort=rawSQL", "order=no", "hide_platform=maybe", "q=%ZZ", "category=other"} {
		request("cluster_id="+cluster.String()+"&"+query, false, 400)
	}
	request("cluster_id="+foreignCluster.String(), false, 404)
	request("cluster_id="+uuid.NewString(), true, 404)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/runtime-threats", nil)
	w := httptest.NewRecorder()
	h.List(w, r)
	if w.Code != 401 {
		t.Fatal("missing auth")
	}
}
