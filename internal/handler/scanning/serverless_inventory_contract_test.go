//go:build integration

package scanning

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestServerlessInventoryPostureTotalsContinuationAndMatchingCSV(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, foreign := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Serverless inventory contract')`, id, "serverless-contract-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=ANY($1::uuid[])`, []uuid.UUID{org, foreign})
	}()
	for i := 0; i < 103; i++ {
		id := uuid.New()
		ref := fmt.Sprintf("function-%03d", i)
		level := "low"
		if i >= 100 {
			level = "high"
		}
		if i == 102 {
			ref = `function%_\literal`
		}
		meta, _ := json.Marshal(map[string]any{"function_name": ref, "package_count": 10, "provider": "aws", "account_id": "account", "region": "region", "permission_analysis": map[string]any{"status": "analyzed", "level": level}})
		if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,metadata,last_seen_at) VALUES($1,$2,'serverless',$3,'manual',$4,'2026-10-12')`, id, org, ref, meta); err != nil {
			t.Fatal(err)
		}
	}
	for _, fixture := range []struct {
		ref      string
		level    any
		packages int
	}{{"function-mixed", "\tHiGh \n", 7}, {"function-near", "high-ish", 8}, {"function-empty", "", 9}, {"function-unrecognized", "admin", 10}, {"function-malformed", true, 11}} {
		metadata, _ := json.Marshal(map[string]any{"function_name": fixture.ref, "provider": "aws", "account_id": "account", "region": "region", "package_count": fixture.packages, "permission_analysis": map[string]any{"level": fixture.level}})
		if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(org_id,type,ref,source_type,metadata) VALUES($1,'serverless',$2,'manual',$3)`, org, fixture.ref, metadata); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(org_id,type,ref,source_type) VALUES($1,'serverless','foreign','manual')`, foreign); err != nil {
		t.Fatal(err)
	}
	h := NewServerlessInventory(d)
	request := func(query string, export bool) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), http.MethodGet, "/serverless-functions?"+query, nil)
		w := httptest.NewRecorder()
		if export {
			h.ExportCSV(w, r)
		} else {
			h.List(w, r)
		}
		return w
	}
	type page struct {
		Rows []serverlessFunctionDTO `json:"serverless_functions"`
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
	p := read("posture=high&provider=aws&account_id=account&region=region&limit=1&sort=function&order=asc")
	if p.Total != 4 || len(p.Rows) != 1 || !p.HasMore || p.Summary["packages"] != 37 || p.Summary["role_risks"] != 4 || p.Rows[0].PermissionLevel != "high" || p.Rows[0].PackageCount != 10 {
		t.Fatalf("filtered %+v", p)
	}
	second := read("posture=high&offset=1&limit=1&sort=function&order=asc")
	if second.Total != 4 || second.Rows[0].ID == p.Rows[0].ID {
		t.Fatal("continuation wrong")
	}
	end := read("posture=high&offset=999")
	if end.Total != 4 || len(end.Rows) != 0 || end.HasMore || end.Summary["packages"] != 37 {
		t.Fatal("out of range lost summary")
	}
	for _, literal := range []string{"%", "_", `\`} {
		if got := read("q=" + url.QueryEscape(literal)); got.Total != 1 {
			t.Fatalf("literal %q total=%d", literal, got.Total)
		}
	}
	w := request("posture=high&provider=aws&account_id=account&region=region&offset=999&limit=1&sort=function&order=asc", true)
	if w.Code != 200 {
		t.Fatalf("CSV %d %s", w.Code, w.Body.String())
	}
	records, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(records) != 5 || records[1][0] != p.Rows[0].ID.String() || w.Header().Get("X-Export-Total") != "4" {
		t.Fatalf("export rows=%d err=%v", len(records), err)
	}
	unknown := read("posture=unknown&sort=function&order=asc")
	if unknown.Total != 4 || unknown.Summary["role_risks"] != 0 {
		t.Fatalf("unknown projection: %+v", unknown)
	}
	for _, row := range unknown.Rows {
		if row.PermissionLevel != "unknown" {
			t.Fatalf("unrecognized posture leaked: %+v", row)
		}
	}
	mixed := read("q=function-mixed&posture=high")
	if mixed.Total != 1 || mixed.Rows[0].PermissionLevel != "high" || mixed.Rows[0].PackageCount != 7 {
		t.Fatalf("mixed case/whitespace mismatch: %+v", mixed)
	}
	for _, query := range []string{"posture=invalid", "sort=invalid", "order=unsafe"} {
		if w := request(query, false); w.Code != 400 {
			t.Fatalf("invalid %s: %d", query, w.Code)
		}
	}
}

func TestServerlessInventoryMetadataFieldIsolation(t *testing.T) {
	t.Parallel()
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org := uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Metadata isolation')`, org, "serverless-metadata-"+org.String()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=$1`, org) }()
	for _, fixture := range []struct {
		ref      string
		count    any
		level    string
		evidence bool
	}{{"string", "10", "high", false}, {"malformed", true, "high", false}, {"zero-evidence", 777, "high", true}, {"malformed-status", 3, "high", false}, {"unicode", 4, "\u00A0HiGh\u2003", false}} {
		id := uuid.New()
		metadata, _ := json.Marshal(map[string]any{"function_name": fixture.ref, "provider": "aws", "account_id": "account", "region": "region", "package_count": fixture.count, "runtime": false, "permission_analysis": map[string]any{"status": true, "level": fixture.level}})
		if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_targets(id,org_id,type,ref,source_type,metadata) VALUES($1,$2,'serverless',$3,'manual',$4)`, id, org, fixture.ref, metadata); err != nil {
			t.Fatal(err)
		}
		if fixture.evidence {
			if _, err := d.Pool().Exec(ctx, `INSERT INTO scan_evidence(org_id,scan_target_id,target_type,target_ref,source_type,evidence_type,inventory_hash,package_count,payload,observed_at) VALUES($1,$2,'serverless',$3,'manual','package-inventory','zero',0,'{}',now())`, org, id, fixture.ref); err != nil {
				t.Fatal(err)
			}
		}
	}
	h := NewServerlessInventory(d)
	r := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), http.MethodGet, "/serverless-functions?provider=aws&posture=high&sort=function&order=asc", nil)
	w := httptest.NewRecorder()
	h.List(w, r)
	if w.Code != 200 {
		t.Fatalf("list %d %s", w.Code, w.Body.String())
	}
	var page struct {
		Rows []serverlessFunctionDTO `json:"serverless_functions"`
		inventorylist.Metadata
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 4 || page.Summary["role_risks"] != 4 || page.Summary["packages"] != 13 || page.Summary["providers"] != 1 {
		t.Fatalf("SQL/DTO summary mismatch %+v", page)
	}
	for _, row := range page.Rows {
		want := 0
		switch row.FunctionRef {
		case "string":
			want = 10
		case "malformed-status":
			want = 3
		case "unicode":
			want = 4
		}
		if row.Provider != "aws" || row.PermissionLevel != "high" || row.PermissionStatus != "" || row.PackageCount != want || row.Runtime != "" {
			t.Fatalf("independent fields lost %+v", row)
		}
	}
	csvW := httptest.NewRecorder()
	h.ExportCSV(csvW, r)
	records, err := csv.NewReader(csvW.Body).ReadAll()
	if err != nil || len(records) != 5 {
		t.Fatalf("CSV rows=%d err=%v", len(records), err)
	}
	for _, record := range records[1:] {
		if record[3] != "aws" || record[11] != "high" || record[12] != "" {
			t.Fatalf("CSV projection mismatch %v", record)
		}
	}
	unicodeRequest := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), http.MethodGet, "/serverless-functions?provider=aws&posture=unknown&q=unicode", nil)
	unicodeResponse := httptest.NewRecorder()
	h.List(unicodeResponse, unicodeRequest)
	if unicodeResponse.Code != 200 {
		t.Fatalf("unicode %d %s", unicodeResponse.Code, unicodeResponse.Body.String())
	}
	if err := json.Unmarshal(unicodeResponse.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 1 || page.Rows[0].PermissionLevel != "unknown" || page.Summary["role_risks"] != 0 || page.Summary["packages"] != 4 {
		t.Fatalf("Unicode whitespace did not match strict SQL normalization %+v", page)
	}
}
