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

	"github.com/google/uuid"
)

func TestNodeVulnerabilitiesInventoryAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := t.Context()
	org, foreign, cluster, sibling, foreignCluster, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name)VALUES($1,$2,$2)`, id, "node-cves-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM findings WHERE org_id IN($1,$2)`, org, foreign); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'selected'),($3,$2,'sibling'),($4,$5,'foreign')`, cluster, org, sibling, foreignCluster, foreign); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name)VALUES($1,$2,$3,'host','node')`, asset, org, cluster); err != nil {
		t.Fatal(err)
	}
	const node = "node%2F-literal"
	if _, err := pool.Exec(ctx, `INSERT INTO host_facts(org_id,cluster_id,node,facts,observed_at)VALUES($1,$2,$3,'{}',NOW()),($1,$2,'facts-only','{}',NOW())`, org, cluster, node); err != nil {
		t.Fatal(err)
	}
	// 2,050 instances share ten IDs and all have the same risk/time: UUID breaks ties.
	if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,cluster_id,target_cluster_id,asset_id,target_type,target_ref,kind,title,severity,lifecycle,external_id,risk_score,last_seen_at,detail_json,source_type)
 SELECT $1,$2,$2,$3,'host',$4,'vulnerability','fixture',CASE WHEN i%2=0 THEN 'critical' ELSE 'high' END,'open','CVE-2026-'||lpad((i%10)::text,4,'0'),80,'2026-10-12T00:00:00Z',jsonb_build_object('package',jsonb_build_object('name','pkg-'||lpad(i::text,4,'0'),'version','1.0'),'fixed',CASE WHEN i%3=0 THEN '2.0' ELSE 'false' END),CASE WHEN i%2=0 THEN 'trivy' ELSE 'grype' END FROM generate_series(0,2049)i`, org, cluster, asset, node); err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		owner, source, target                             uuid.UUID
		ref, kind, lifecycle, targetType, cve, pkg, fixed string
	}
	fixtures := []fixture{
		{org, cluster, sibling, node, "vulnerability", "open", "host", "ADV-source-only", "source-only", "2.0"},
		{org, sibling, cluster, node, "vulnerability", "open", "host", "ADV-effective-only", "effective-only", "false"},
		{org, cluster, cluster, node, "vulnerability", "open", "host", "CVE-literal", "literal%_\\package", "2.0"},
		{org, sibling, sibling, node, "vulnerability", "open", "host", "EXCLUDED-sibling", "excluded", "2.0"},
		{foreign, cluster, cluster, node, "vulnerability", "open", "host", "EXCLUDED-tenant", "excluded", "2.0"},
		{org, cluster, cluster, "other-node", "vulnerability", "open", "host", "EXCLUDED-node", "excluded", "2.0"},
		{org, cluster, cluster, node, "vulnerability", "accepted", "host", "EXCLUDED-accepted", "excluded", "2.0"},
		{org, cluster, cluster, node, "secret", "open", "host", "EXCLUDED-kind", "excluded", "2.0"},
		{org, cluster, cluster, node, "vulnerability", "open", "workload", "EXCLUDED-workload", "excluded", "2.0"},
	}
	for _, f := range fixtures {
		if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,cluster_id,target_cluster_id,asset_id,target_type,target_ref,kind,title,severity,lifecycle,external_id,risk_score,last_seen_at,detail_json,source_type)VALUES($1,$2,$3,$4,$5,$6,$7,'fixture','high',$8,$9,80,'2026-10-12T00:00:00Z',jsonb_build_object('package',jsonb_build_object('name',$10::text,'version','1.0'),'fixed',$11::text),'fixture')`, f.owner, f.source, f.target, asset, f.targetType, f.ref, f.kind, f.lifecycle, f.cve, f.pkg, f.fixed); err != nil {
			t.Fatal(err)
		}
	}
	duplicateID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO findings(id,org_id,cluster_id,target_cluster_id,asset_id,target_type,target_ref,kind,title,severity,lifecycle,external_id,risk_score,last_seen_at,first_seen_at,detail_json,source_type)
 SELECT $1,$2,$3,$3,$4,'host',$5,'vulnerability','duplicate UUID instances',CASE WHEN i=0 THEN 'critical' ELSE 'high' END,'open','CVE-2026-0000',80,'2026-10-12T00:00:00Z','2026-10-01T00:00:00Z'::timestamptz+i*INTERVAL '1 microsecond','{"fixed":"2.0"}'::jsonb,'duplicate' FROM generate_series(0,1)i`, duplicateID, org, cluster, asset, node); err != nil {
		t.Fatal(err)
	}

	h := NewNodes(d)
	request := func(serve http.HandlerFunc, owner, scope uuid.UUID, name, query string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: owner}), http.MethodGet, "/nodes/"+url.PathEscape(name)+"/vulnerabilities?"+query, nil)
		r = withRouteParam(r, "id", scope.String())
		r = withRouteParam(r, "node", name)
		w := httptest.NewRecorder()
		serve(w, r)
		return w
	}
	type response struct {
		Items                []NodeVulnerabilityRow
		Total, Limit, Offset int
		HasMore              bool `json:"has_more"`
		Summary              map[string]int
		Node                 string
		ClusterID            uuid.UUID `json:"cluster_id"`
	}
	read := func(query string) response {
		t.Helper()
		w := request(h.Vulnerabilities, org, cluster, node, query)
		if w.Code != 200 {
			t.Fatalf("list %d %s", w.Code, w.Body.String())
		}
		var out response
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	t.Run("all 2055 instances remain reachable with stable ties and full summaries", func(t *testing.T) {
		seen := map[string]bool{}
		var previous string
		for offset := 0; offset < 2055; offset += 100 {
			page := read("limit=100&offset=" + strconv.Itoa(offset))
			if page.Total != 2055 || page.Summary["total"] != 2055 || page.Summary["unique_cves"] != 13 || page.Summary["critical"] != 1026 || page.Summary["high"] != 1029 || page.Summary["fixable"] != 688 || page.HasMore != (offset < 2000) || page.Node != node || page.ClusterID != cluster {
				t.Fatalf("page metadata %+v", page)
			}
			for _, item := range page.Items {
				if seen[item.RowID] || item.ID == uuid.Nil || item.Node != node || strings.HasPrefix(item.VulnID, "EXCLUDED-") {
					t.Fatalf("bad instance %+v", item)
				}
				if previous != "" && previous >= item.RowID {
					t.Fatal("equal risk/time order unstable")
				}
				previous = item.RowID
				seen[item.RowID] = true
			}
		}
		if len(seen) != 2055 {
			t.Fatalf("instances=%d", len(seen))
		}
		empty := read("offset=9999")
		if empty.Total != 2055 || len(empty.Items) != 0 || empty.HasMore || empty.Summary["unique_cves"] != 13 {
			t.Fatalf("empty %+v", empty)
		}
	})
	t.Run("literal tail search and complete filtered counts", func(t *testing.T) {
		tail := read("q=pkg-2049&severity=high&fixable=true&source=grype")
		if tail.Total != 1 || tail.Items[0].PackageName != "pkg-2049" || tail.Summary["fixable"] != 1 {
			t.Fatalf("tail %+v", tail)
		}
		literal := read("q=" + url.QueryEscape("%_\\"))
		if literal.Total != 1 || literal.Items[0].VulnID != "CVE-literal" {
			t.Fatalf("literal %+v", literal)
		}
		for _, filter := range []struct {
			query string
			total int
		}{{"severity=critical", 1026}, {"severity=high", 1029}, {"fixable=true", 688}, {"fixable=false", 1367}, {"source=grype", 1025}, {"q=missing", 0}} {
			if page := read(filter.query); page.Total != filter.total || page.Summary["total"] != filter.total {
				t.Fatalf("%s %+v", filter.query, page)
			}
		}
	})
	t.Run("source OR effective target attribution stays distinct from global host cohort", func(t *testing.T) {
		source := read("q=ADV-source-only")
		if source.Total != 1 || *source.Items[0].SourceClusterID != cluster || *source.Items[0].ClusterID != sibling {
			t.Fatalf("source-only %+v", source)
		}
		target := read("q=ADV-effective-only")
		if target.Total != 1 || *target.Items[0].SourceClusterID != sibling || *target.Items[0].ClusterID != cluster {
			t.Fatalf("target-only %+v", target)
		}
		legacy := request(h.Get, org, cluster, node, "")
		if legacy.Code != 200 {
			t.Fatalf("detail %d %s", legacy.Code, legacy.Body.String())
		}
		var detail NodeDetail
		if err := json.Unmarshal(legacy.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if len(detail.Vulnerabilities) != 2000 || detail.VulnerabilitiesTotal != 2055 || detail.VulnerabilitiesLimit != 2000 || !detail.VulnerabilitiesHasMore || detail.Node.OpenVulns != 2055 || detail.Vulnerabilities[0].ID == uuid.Nil {
			t.Fatalf("legacy counts %d/%d/%+v", len(detail.Vulnerabilities), detail.VulnerabilitiesTotal, detail.Node)
		}
	})
	t.Run("matching CSV includes the complete filtered cohort in identical order", func(t *testing.T) {
		for _, query := range []string{"sort=package&order=desc", "severity=high&fixable=true&sort=cve&order=asc", "q=" + url.QueryEscape("%_\\"), "q=missing"} {
			all := []NodeVulnerabilityRow{}
			var total int
			for offset := 0; ; offset += 500 {
				page := read(query + "&limit=500&offset=" + strconv.Itoa(offset))
				total = page.Total
				all = append(all, page.Items...)
				if !page.HasMore {
					break
				}
			}
			w := request(h.VulnerabilitiesCSV, org, cluster, node, query+"&limit=1&offset=2000")
			if w.Code != 200 {
				t.Fatalf("CSV %d %s", w.Code, w.Body.String())
			}
			records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
			if err != nil {
				t.Fatal(err)
			}
			if len(records) != total+1 || w.Header().Get("X-Export-Total") != strconv.Itoa(total) || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "false" {
				t.Fatalf("CSV %s records%d headers%v", query, len(records), w.Header())
			}
			for i, item := range all {
				if records[i+1][0] != item.RowID || records[i+1][1] != item.ID.String() || records[i+1][5] != item.VulnID || records[i+1][3] != item.SourceClusterID.String() || records[i+1][4] != item.ClusterID.String() {
					t.Fatalf("CSV instance mismatch %+v %v", item, records[i+1])
				}
			}
		}
	})
	t.Run("duplicate UUID timestamp instances both traverse and export", func(t *testing.T) {
		page := read("q=" + duplicateID.String() + "&limit=1&offset=0")
		next := read("q=" + duplicateID.String() + "&limit=1&offset=1")
		if page.Total != 2 || next.Total != 2 || len(page.Items) != 1 || len(next.Items) != 1 || page.Items[0].ID != duplicateID || next.Items[0].ID != duplicateID || page.Items[0].RowID == next.Items[0].RowID || !page.HasMore || next.HasMore || page.Items[0].FirstSeenAt.Equal(next.Items[0].FirstSeenAt) {
			t.Fatalf("duplicate pages %+v %+v", page, next)
		}
		w := request(h.VulnerabilitiesCSV, org, cluster, node, "q="+duplicateID.String())
		records, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
		if err != nil || w.Code != 200 || len(records) != 3 || records[1][0] == records[2][0] || records[1][1] != duplicateID.String() || records[2][1] != duplicateID.String() {
			t.Fatalf("duplicate export %d %v %v", w.Code, records, err)
		}
	})

	t.Run("rejects missing or foreign nodes and clusters rather than returning an empty success", func(t *testing.T) {
		for _, serve := range []http.HandlerFunc{h.Vulnerabilities, h.VulnerabilitiesCSV} {
			for _, check := range []struct {
				o, c uuid.UUID
				n    string
			}{{org, cluster, "missing"}, {foreign, cluster, node}, {org, foreignCluster, node}, {org, uuid.New(), node}} {
				if w := request(serve, check.o, check.c, check.n, ""); w.Code != 404 {
					t.Fatalf("scope %d %s", w.Code, w.Body.String())
				}
			}
		}
		w := request(h.Vulnerabilities, org, cluster, "facts-only", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"total":0`) {
			t.Fatalf("owned empty node %d %s", w.Code, w.Body.String())
		}
	})
	t.Run("rejects malformed queries and nonallowlisted sorting or paging", func(t *testing.T) {
		for _, query := range []string{"sort=id;DROP", "sort=bad", "order=sideways", "limit=0", "limit=501", "limit=bad", "offset=-1", "offset=bad", "severity=bad", "fixable=yes"} {
			for _, serve := range []http.HandlerFunc{h.Vulnerabilities, h.VulnerabilitiesCSV} {
				if w := request(serve, org, cluster, node, query); w.Code != 400 {
					t.Fatalf("invalid %s %d %s", query, w.Code, w.Body.String())
				}
			}
		}
	})
}
