package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestImageInventoryServerFiltersSummaryContinuationAndCSV(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, foreign, cluster, deployment := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Image inventory contract')`, id, "image-inventory-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=ANY($1::uuid[])`, []uuid.UUID{org, foreign})
	}()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'Inventory cluster')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind) VALUES($1,$2,$3,'default','inventory','Deployment')`, deployment, org, cluster); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 103; i++ {
		id := uuid.New()
		ref := fmt.Sprintf("example.test/image-%03d", i)
		if i == 102 {
			ref = `example.test/literal%_\image`
		}
		if _, err := d.Pool().Exec(ctx, `INSERT INTO image_scan_results(id,org_id,image_ref,image_ref_normalized,image_repository,image_digest,package_count,last_scanned_at,engine_status) VALUES($1,$2,$3,$3,'example.test',$4,10,'2026-10-12', '{"syft":"succeeded","trivy":"succeeded","grype":"succeeded"}')`, id, org, ref, fmt.Sprintf("sha256:inventory-%d", i)); err != nil {
			t.Fatal(err)
		}
		if i < 102 {
			if _, err := d.Pool().Exec(ctx, `INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_digest) VALUES($1,$2,$3,$4,'default','inventory','Deployment',$5,$5,$6)`, org, cluster, deployment, fmt.Sprintf("workload-%d", i), ref, fmt.Sprintf("sha256:inventory-%d", i)); err != nil {
				t.Fatal(err)
			}
		}
		if i >= 100 && i < 102 {
			if _, err := d.Pool().Exec(ctx, `INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,title,severity,risk_score) VALUES($1,$2,'critical','Critical package','critical',80)`, org, id); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO image_scan_results(org_id,image_ref,image_ref_normalized,image_repository,image_digest) VALUES($1,'foreign','foreign','foreign','sha256:foreign')`, foreign); err != nil {
		t.Fatal(err)
	}
	h := NewImageScanResults(d)
	request := func(query string, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/image-scan-results?"+query, nil)
		w := httptest.NewRecorder()
		if export {
			h.ExportCSV(w, r)
		} else {
			h.List(w, r)
		}
		return w
	}
	type page struct {
		Rows []imageScanResultDTO `json:"image_scan_results"`
		inventorylist.Metadata
		Offset int `json:"offset"`
	}
	read := func(query string) page {
		t.Helper()
		w := request(query, false)
		if w.Code != 200 {
			t.Fatalf("query %s: %d %s", query, w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	first := read("limit=100&sort=image&order=asc")
	second := read("limit=100&offset=100&sort=image&order=asc")
	if first.Total != 103 || len(first.Rows) != 100 || !first.HasMore || len(second.Rows) != 3 || second.HasMore || first.Summary["packages"] != 1030 {
		t.Fatalf("continuation/summary: %+v %+v", first.Metadata, second.Metadata)
	}
	seen := map[uuid.UUID]bool{}
	for _, p := range []page{first, second} {
		for _, item := range p.Rows {
			if seen[item.ID] {
				t.Fatal("duplicate paging row")
			}
			seen[item.ID] = true
		}
	}
	filtered := read("severity=critical&cluster_id=" + cluster.String() + "&sort=image&order=asc&limit=1")
	if filtered.Total != 2 || len(filtered.Rows) != 1 || filtered.Summary["critical_high"] != 2 || filtered.Summary["packages"] != 20 || !filtered.HasMore {
		t.Fatalf("filtered totals: %+v", filtered)
	}
	end := read("severity=critical&offset=999")
	if len(end.Rows) != 0 || end.Total != 2 || end.Summary["packages"] != 20 || end.HasMore {
		t.Fatalf("empty page lost totals: %+v", end)
	}
	scoped := read("cluster_id=" + cluster.String())
	if scoped.Total != 102 {
		t.Fatalf("cluster total=%d", scoped.Total)
	}
	for _, literal := range []string{"%", "_", `\`} {
		p := read("q=" + url.QueryEscape(literal))
		if p.Total != 1 || p.Rows[0].ImageRef != `example.test/literal%_\image` {
			t.Fatalf("literal %q total=%d", literal, p.Total)
		}
	}
	w := request("severity=critical&sort=image&order=asc&limit=1&offset=999", true)
	if w.Code != 200 {
		t.Fatalf("CSV: %d %s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(records) != 3 || w.Header().Get("X-Export-Total") != "2" || w.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("matching CSV rows=%d err=%v headers=%v", len(records), err, w.Header())
	}
	if records[1][0] != filtered.Rows[0].ID.String() {
		t.Fatal("CSV order differs from list")
	}
	for _, query := range []string{"severity=bad", "sort=image;DROP", "order=backwards", "cluster_id=invalid"} {
		if w := request(query, false); w.Code != 400 {
			t.Fatalf("invalid %s: %d", query, w.Code)
		}
	}
	repeat := read("limit=100&sort=scan&order=desc")
	again := read("limit=100&sort=scan&order=desc")
	if !reflect.DeepEqual(repeat.Rows, again.Rows) {
		t.Fatal("equal timestamps have unstable order")
	}
}

func TestRepositoryInventoryStatusFilteringTotalsAndMatchingCSV(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, foreign := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Repository inventory contract')`, id, "repository-contract-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=ANY($1::uuid[])`, []uuid.UUID{org, foreign})
	}()
	for i := 0; i < 103; i++ {
		id := uuid.New()
		ref := fmt.Sprintf("repository-%03d", i)
		if i == 102 {
			ref = `repository%_\literal`
		}
		meta, _ := json.Marshal(map[string]any{"package_count": 10, "branch": "main", "workflow": "build"})
		if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,metadata,last_seen_at) VALUES($1,$2,'repository',$3,'repository',$4,'2026-10-12')`, id, org, ref, meta); err != nil {
			t.Fatal(err)
		}
		status := "completed"
		if i >= 100 {
			status = "failed"
		}
		if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_jobs(org_id,target_id,status,requested_at) VALUES($1,$2,$3,'2026-10-12')`, org, id, status); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(org_id,type,ref,source_type) VALUES($1,'repository','foreign','repository')`, foreign); err != nil {
		t.Fatal(err)
	}
	h := NewRepositoryInventory(d)
	request := func(query string, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/repository-scans?"+query, nil)
		w := httptest.NewRecorder()
		if export {
			h.ExportCSV(w, r)
		} else {
			h.List(w, r)
		}
		return w
	}
	type page struct {
		Rows []repositoryScanDTO `json:"repository_scans"`
		inventorylist.Metadata
	}
	read := func(query string) page {
		t.Helper()
		w := request(query, false)
		if w.Code != 200 {
			t.Fatalf("query %s: %d %s", query, w.Code, w.Body.String())
		}
		var p page
		if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := read("status=failed&branch=main&workflow=build&limit=1&sort=repository&order=asc")
	if p.Total != 3 || len(p.Rows) != 1 || !p.HasMore || p.Summary["packages"] != 30 || p.Rows[0].LatestJobStatus != "failed" || p.Rows[0].PackageCount != 10 {
		t.Fatalf("filtered: %+v", p)
	}
	second := read("status=failed&offset=1&limit=1&sort=repository&order=asc")
	if second.Rows[0].ID == p.Rows[0].ID || second.Total != 3 {
		t.Fatal("continuation duplicates or loses total")
	}
	end := read("status=failed&offset=999")
	if end.Total != 3 || len(end.Rows) != 0 || end.Summary["packages"] != 30 {
		t.Fatal("empty page loses filtered summary")
	}
	if got := read("q=" + url.QueryEscape("%_\\")); got.Total != 1 {
		t.Fatalf("literal match total=%d", got.Total)
	}
	w := request("status=failed&branch=main&workflow=build&limit=1&offset=999&sort=repository&order=asc", true)
	if w.Code != 200 {
		t.Fatalf("CSV %d %s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(records) != 4 || records[1][0] != p.Rows[0].ID.String() || w.Header().Get("X-Export-Total") != "3" {
		t.Fatalf("export: rows=%d err=%v", len(records), err)
	}
	for _, query := range []string{"status=bad", "sort=unsafe", "order=unsafe"} {
		if w := request(query, false); w.Code != 400 {
			t.Fatalf("invalid %s: %d", query, w.Code)
		}
	}
}

func TestRepositoryInventoryMetadataFieldIsolation(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org := uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Metadata isolation')`, org, "repository-metadata-"+org.String()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=$1`, org) }()
	for _, fixture := range []struct {
		ref      string
		count    any
		evidence bool
	}{{"string", "10", false}, {"malformed", true, false}, {"zero-evidence", 777, true}} {
		id := uuid.New()
		metadata, _ := json.Marshal(map[string]any{"repository_ref": fixture.ref, "repository_url": "https://example.test/repository", "branch": "main", "workflow": "build", "commit_sha": "commit", "package_count": fixture.count, "path": true})
		if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,metadata) VALUES($1,$2,'repository',$3,'repository',$4)`, id, org, fixture.ref, metadata); err != nil {
			t.Fatal(err)
		}
		if fixture.evidence {
			if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_evidence(org_id,scan_target_id,target_type,target_ref,source_type,evidence_type,inventory_hash,package_count,payload,observed_at) VALUES($1,$2,'repository',$3,'repository','package-inventory','zero',0,'{}',now())`, org, id, fixture.ref); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := NewRepositoryInventory(d)
	r := httptest.NewRequestWithContext(WithSubject(ctx, Subject{OrgID: org}), http.MethodGet, "/repository-scans?branch=main&workflow=build&sort=repository&order=asc", nil)
	w := httptest.NewRecorder()
	h.List(w, r)
	if w.Code != 200 {
		t.Fatalf("list %d %s", w.Code, w.Body.String())
	}
	var page struct {
		Rows []repositoryScanDTO `json:"repository_scans"`
		inventorylist.Metadata
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Summary["packages"] != 10 || page.Summary["branches"] != 1 {
		t.Fatalf("summary %+v", page)
	}
	for _, row := range page.Rows {
		want := 0
		if row.RepositoryRef == "string" {
			want = 10
		}
		if row.PackageCount != want || row.Branch != "main" || row.Workflow != "build" || row.CommitSHA != "commit" || row.Path != "" {
			t.Fatalf("independent fields lost: %+v", row)
		}
	}
	csvW := httptest.NewRecorder()
	h.ExportCSV(csvW, r)
	records, err := csv.NewReader(csvW.Body).ReadAll()
	if err != nil || len(records) != 4 {
		t.Fatalf("CSV rows=%d err=%v", len(records), err)
	}
	for _, record := range records[1:] {
		want := "0"
		if record[1] == "string" {
			want = "10"
		}
		if record[7] != want || record[4] != "main" || record[6] != "build" {
			t.Fatalf("CSV normalization %v", record)
		}
	}
}
