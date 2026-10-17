package runtime

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestPcapInventoryFullScopePagesAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, foreign, cluster, sibling, user := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1::uuid,$1::text,'pcap'),($2::uuid,$2::text,'foreign')`, org, foreign)
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM runtime_pcap_captures WHERE org_id IN($1,$2)`, org, foreign)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'main'),($2,$3,'sibling')`, cluster, sibling, org)
	exec(`INSERT INTO runtime_pcap_captures(org_id,cluster_id,requested_by,workload,namespace,status,protocol,dst_port,bpf_filter,requested_at,packet_count,file_size_bytes,file_path)
 SELECT $1,$2,$3,'prod/api','prod',CASE n%5 WHEN 0 THEN 'pending' WHEN 1 THEN 'running' WHEN 2 THEN 'completed' WHEN 3 THEN 'failed' ELSE 'expired' END,'tcp',443,CASE WHEN n=1005 THEN 'needle%_literal' ELSE 'tcp' END,now()-(n||' seconds')::interval,CASE WHEN n%5=2 THEN n ELSE NULL END,CASE WHEN n%5=2 THEN n*10 ELSE NULL END,'/private/path' FROM generate_series(1,1005)n`, org, cluster, user)
	exec(`INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels) VALUES($1,$2,'custom-install','agent','Deployment','{"helm.sh/chart":"constellation-1.0"}')`, org, cluster)
	exec(`INSERT INTO runtime_pcap_captures(org_id,cluster_id,requested_by,workload,namespace,packet_count,file_size_bytes) VALUES($1,$2,$4,'custom-install/agent','custom-install',0,0),($1,$3,$4,'prod/api','prod',999,999),($5,$2,$4,'prod/api','prod',999,999)`, org, cluster, sibling, user, foreign)
	exec(`INSERT INTO groups(org_id,cluster_id,name,kind,members) VALUES($1,$2,'exact-pcap','ground','["prod/api"]'),($1,$2,'empty-pcap','ground','["prod/api-extra"]')`, org, cluster)
	exec(`UPDATE runtime_pcap_captures SET src_ip='10.0.0.1',dst_ip='10.0.0.2',claimed_by_node='node-a' WHERE org_id=$1 AND cluster_id=$2 AND workload='prod/api'`, org, cluster)
	h := NewPcapHTTP(d)
	base := "cluster_id=" + cluster.String()
	call := func(query string, export bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), "GET", "/runtime-pcap/inventory?"+query, nil)
		r = r.WithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		if export {
			h.InventoryCSV(w, r)
		} else {
			h.Inventory(w, r)
		}
		return w
	}
	type page struct {
		Captures []*pcapInventoryRow `json:"captures"`
		inventorylist.Metadata
		ClusterID uuid.UUID `json:"cluster_id"`
	}
	read := func(query string) page {
		t.Helper()
		w := call(base+query, false)
		if w.Code != 200 {
			t.Fatalf("%d%s", w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read("&hide_platform=false&limit=100")
	if p.Total != 1006 || len(p.Captures) != 100 || p.Summary["pending"] != 202 || p.Summary["completed"] != 201 || p.Summary["file_reports"] != 202 || p.Summary["platform"] != 1 || p.ClusterID != cluster {
		t.Fatalf("summary %+v", p.Metadata)
	}
	if p.Captures[0].PacketCount == nil || *p.Captures[0].PacketCount != 0 || p.Captures[0].PlatformRole != "core" {
		t.Fatal("recorded zero or exact role lost")
	}
	p = read("&hide_platform=true")
	if p.Total != 1005 || p.Summary["platform"] != 0 || p.Captures[0].PacketCount != nil {
		t.Fatal("hidden filter / unknown packet metadata differs")
	}
	seen := map[string]bool{}
	for offset := 0; offset < 1100; offset += 100 {
		if p := read("&group=exact-pcap&namespace=prod&node=node-a&src_ip=10.0.0.1&dst_ip=10.0.0.2"); p.Total != 1005 {
			t.Fatal("exact group/source tuple differs")
		}
		if p := read("&group=empty-pcap"); p.Total != 0 {
			t.Fatal("group guessed workload prefix")
		}
		p = read("&offset=" + strconv.Itoa(offset))
		for _, capture := range p.Captures {
			if seen[capture.RowID] || capture.RowID != capture.ID.String() || capture.ClusterID != cluster || capture.OrgID != org {
				t.Fatal("wrong capture identity/scope")
			}
			seen[capture.RowID] = true
		}
	}
	if len(seen) != 1006 {
		t.Fatal("continuation lost captures")
	}
	p = read("&offset=" + strconv.Itoa(inventorylist.MaxOffset))
	if p.Total != 1006 || len(p.Captures) != 0 || p.HasMore {
		t.Fatal("deep page lost total")
	}
	p = read("&q=needle%25_&workload=prod%2Fapi&namespace=prod&status=pending&protocol=tcp&dst_port=443")
	if p.Total != 1 || p.Captures[0].BPFFilter != "needle%_literal" {
		t.Fatal("tail/literal mixed filter missed capture")
	}
	p = read("&status=completed&sort=packets&order=desc")
	if p.Total != 201 || p.Captures[0].PacketCount == nil || *p.Captures[0].PacketCount != 1002 {
		t.Fatal("full-source sort differs")
	}
	w := call(base+"&offset=2147483647&limit=1", true)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(rows) != 1007 || w.Header().Get("X-Export-Total") != "1006" || strings.Contains(w.Body.String(), "/private/path") {
		t.Fatal("metadata-only full CSV scope/cap incorrect")
	}
	if rows[1][20] != "0" || rows[2][20] != "" {
		t.Fatal("CSV must preserve recorded zero vs unknown")
	}
	for _, query := range []string{"", base + "&limit=501", base + "&limit=", base + "&offset=2147483648", base + "&q=a&q=b", base + "&status=invalid", base + "&src_ip=invalid", base + "&dst_port=65536", base + "&sort=invalid"} {
		for _, export := range []bool{false, true} {
			if w := call(query, export); w.Code != 400 {
				t.Fatalf("bad query%d%s", w.Code, query)
			}
		}
	}
	if w := call(base+"&group=missing", false); w.Code != 400 {
		t.Fatal("missing group not rejected")
	}
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/runtime-pcap/inventory?"+base, nil)
	for _, export := range []bool{false, true} {
		w := httptest.NewRecorder()
		if export {
			h.InventoryCSV(w, r)
		} else {
			h.Inventory(w, r)
		}
		if w.Code != 401 {
			t.Fatal("unauthenticated inventory not rejected")
		}
	}
	if w := call("cluster_id="+uuid.NewString(), false); w.Code != 404 {
		t.Fatal("unknown cluster must reject")
	}
}

func TestPcapInventoryCSVFullCap(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, cluster, user := uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := d.Pool().Exec(t.Context(), query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'cap')`, org)
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM runtime_pcap_captures WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org)
	})
	exec(`INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'cap')`, cluster, org)
	exec(`INSERT INTO runtime_pcap_captures(org_id,cluster_id,requested_by,workload,namespace,packet_count,file_size_bytes)
 SELECT $1,$2,$3,'prod/a','prod',n,n*10 FROM generate_series(1,100001)n`, org, cluster, user)
	h := NewPcapHTTP(d)
	r := httptest.NewRequestWithContext(t.Context(), "GET", "/runtime-pcap/inventory.csv?cluster_id="+cluster.String()+"&offset=2147483647&limit=1&sort=packets&order=asc", nil)
	r = r.WithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: org}))
	w := httptest.NewRecorder()
	h.InventoryCSV(w, r)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(rows) != 100001 || w.Header().Get("X-Export-Total") != "100001" || w.Header().Get("X-Export-Truncated") != "true" || rows[1][20] != "1" || rows[100000][20] != "100000" {
		t.Fatalf("CSV full cap status%d rows%d headers%v err%v", w.Code, len(rows), w.Header(), err)
	}
}
