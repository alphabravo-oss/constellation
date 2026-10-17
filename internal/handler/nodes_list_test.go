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

func TestNodesFilteredInventoryAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	ctx := t.Context()
	org, foreign, cluster, sibling, foreignCluster, asset := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name)VALUES($1,$2,$2)`, id, "nodes-inventory-"+id.String()); err != nil {
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
	if _, err := pool.Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name)VALUES($1,$2,$3,'host','fixture')`, asset, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO host_facts(org_id,cluster_id,node,os_id,os_version_id,kernel_release,arch,cni_name,cri_runtime,facts,observed_at) SELECT $1,$2,'node-'||lpad(i::text,4,'0'),'ubuntu','24.04','kernel-fixture','amd64','cilium','containerd','{}'::jsonb,NOW()-INTERVAL '10 minutes' FROM generate_series(0,649) i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO component_heartbeats(org_id,cluster_id,component,hostname,version,last_seen_at) SELECT $1,$2,'runtime-agent','node-'||lpad(i::text,4,'0'),'v1',NOW() FROM generate_series(0,9) i`, org, cluster); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		o, c uuid.UUID
		name string
	}{{org, cluster, "literal%_\\node"}, {org, cluster, "clean-node"}, {org, sibling, "node-0649"}, {foreign, cluster, "foreign-org"}, {org, foreignCluster, "foreign-cluster"}} {
		if _, err := pool.Exec(ctx, `INSERT INTO host_facts(org_id,cluster_id,node,facts,observed_at)VALUES($1,$2,$3,'{}',NOW()-INTERVAL '10 minutes')`, item.o, item.c, item.name); err != nil {
			t.Fatal(err)
		}
	}
	// Clean means collected packages/facts/CIS AND completed scan, not empty findings.
	target, job := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO host_packages(org_id,cluster_id,node,package_count,source,payload,observed_at)VALUES($1,$2,'clean-node',7,'dpkg','{}',NOW())`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO host_cis(org_id,cluster_id,node,profile,payload,observed_at)VALUES($1,$2,'clean-node','cis','{}',NOW())`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets(id,org_id,cluster_id,type,ref,inventory_hash)VALUES($1,$2,$3,'host','clean-node','hash')`, target, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs(id,org_id,target_id,status,finished_at)VALUES($1,$2,$3,'completed',NOW())`, job, org, target); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		node, severity, lifecycle string
		target                    any
	}{{"node-0649", "critical", "open", nil}, {"node-0649", "high", "open", nil}, {"node-0649", "critical", "accepted", nil}, {"node-0648", "high", "open", sibling}} {
		if _, err := pool.Exec(ctx, `INSERT INTO findings(org_id,cluster_id,asset_id,target_type,target_ref,target_cluster_id,kind,title,severity,lifecycle)VALUES($1,$2,$3,'host',$4,$5,'vulnerability','fixture',$6,$7)`, org, cluster, asset, item.node, item.target, item.severity, item.lifecycle); err != nil {
			t.Fatal(err)
		}
	}
	h := NewNodes(d)
	request := func(serve http.HandlerFunc, owner, scope uuid.UUID, query string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: owner}), http.MethodGet, "/clusters/"+scope.String()+"/nodes?"+query, nil)
		r = withRouteParam(r, "id", scope.String())
		w := httptest.NewRecorder()
		serve(w, r)
		return w
	}
	type result struct {
		Items                []NodeSummary
		Total, Limit, Offset int
		HasMore              bool `json:"has_more"`
		Summary              map[string]int
		HostCVEs             string `json:"host_cves"`
	}
	read := func(query string) result {
		t.Helper()
		w := request(h.List, org, cluster, query)
		if w.Code != 200 {
			t.Fatalf("nodes %d %s", w.Code, w.Body.String())
		}
		var body result
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body
	}
	t.Run("stable all-page matching summary and tail search", func(t *testing.T) {
		seen := map[string]bool{}
		for offset := 0; offset < 652; offset += 100 {
			page := read("sort=node&order=desc&limit=100&offset=" + strconv.Itoa(offset))
			if page.Total != 652 || page.Summary["nodes"] != 652 || page.Summary["runtime_agent_healthy"] != 10 || page.Summary["runtime_agent_stale"] != 642 || page.HasMore != (offset < 600) {
				t.Fatalf("page metadata %+v", page)
			}
			for _, item := range page.Items {
				if seen[item.Node] {
					t.Fatalf("duplicate %s", item.Node)
				}
				seen[item.Node] = true
			}
		}
		if len(seen) != 652 {
			t.Fatalf("rows%d", len(seen))
		}
		tail := read("q=node-0649&agent=stale&risk=high&limit=100")
		if tail.Total != 1 || tail.Items[0].Node != "node-0649" || tail.Summary["critical_vulns"] != 1 || tail.Summary["high_vulns"] != 1 {
			t.Fatalf("tail %+v", tail)
		}
		zero := read("q=nonexistent&limit=100&offset=1000")
		if zero.Total != 0 || len(zero.Items) != 0 || zero.Summary["nodes"] != 0 || zero.HasMore {
			t.Fatalf("empty %+v", zero)
		}
	})
	t.Run("literal search coverage filters and clean evidence", func(t *testing.T) {
		literal := read("q=" + url.QueryEscape("%_\\"))
		if literal.Total != 1 || literal.Items[0].Node != "literal%_\\node" {
			t.Fatalf("literal %+v", literal)
		}
		gap := read("q=host_packages&agent=healthy")
		if gap.Total != 10 {
			t.Fatalf("gap %+v", gap)
		}
		clean := read("risk=clean")
		if clean.Total != 1 || clean.Items[0].Node != "clean-node" || len(clean.Items[0].CoverageGaps) != 0 || clean.Summary["scan_completed"] != 1 {
			t.Fatalf("clean %+v", clean)
		}
		high := read("risk=high")
		if high.Total != 2 {
			t.Fatalf("high %+v", high)
		}
		host := read("risk=host-cves")
		if host.Total != 2 || host.HostCVEs != "open" {
			t.Fatalf("host cohort %+v", host)
		}
		filtered := request(h.List, org, sibling, "host_cves=open")
		var other result
		_ = json.Unmarshal(filtered.Body.Bytes(), &other)
		if filtered.Code != 200 || other.Total != 0 {
			t.Fatalf("attributed findings leak into source cohort %d %s", filtered.Code, filtered.Body.String())
		}
	})
	t.Run("matching CSV export ignores visible page", func(t *testing.T) {
		w := request(h.ExportCSV, org, cluster, "agent=stale&sort=node&order=desc&limit=1&offset=1000")
		if w.Code != 200 {
			t.Fatalf("CSV %d %s", w.Code, w.Body.String())
		}
		records, err := csv.NewReader(w.Body).ReadAll()
		if err != nil {
			t.Fatal(err)
		}
		if len(records) != 643 || records[1][1] != "node-0649" || w.Header().Get("X-Export-Total") != "642" || w.Header().Get("X-Export-Limit") != "100000" || w.Header().Get("X-Export-Truncated") != "false" {
			t.Fatalf("csv rows%d headers%v first%v", len(records), w.Header(), records[1])
		}
	})
	t.Run("tenant cluster and strict input contract", func(t *testing.T) {
		for _, scope := range []uuid.UUID{foreignCluster, uuid.New()} {
			for _, serve := range []http.HandlerFunc{h.List, h.ExportCSV} {
				if w := request(serve, org, scope, ""); w.Code != 404 {
					t.Fatalf("scope status%d", w.Code)
				}
			}
		}
		if w := request(h.List, foreign, cluster, ""); w.Code != 404 {
			t.Fatalf("foreign subject%d", w.Code)
		}
		for _, query := range []string{"agent=invalid", "risk=invalid", "sort=DROP", "sort=node;DROP", "order=invalid", "host_cves=invalid", "limit=0", "limit=501", "offset=-1", "offset=bad"} {
			for _, serve := range []http.HandlerFunc{h.List, h.ExportCSV} {
				if w := request(serve, org, cluster, query); w.Code != 400 {
					t.Fatalf("invalid%s status%d body%s", query, w.Code, w.Body.String())
				}
			}
		}
		legacy := read("")
		if legacy.Limit != 500 || len(legacy.Items) != 500 || legacy.Total != 652 {
			t.Fatalf("legacy bounds %d %d %d", legacy.Limit, len(legacy.Items), legacy.Total)
		}
		desc := read("sort=node&order=desc&limit=1")
		asc := read("sort=node&order=asc&limit=1")
		if strings.Compare(desc.Items[0].Node, asc.Items[0].Node) <= 0 {
			t.Fatal("descending sort direction ignored")
		}
	})
}
