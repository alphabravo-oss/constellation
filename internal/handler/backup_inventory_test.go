package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestBackupInventoryOptions(t *testing.T) {
	o, e := parseBackupInventoryOptions(url.Values{})
	if e != nil || o.Limit != 100 || o.Sort != "when" || o.Order != "desc" {
		t.Fatalf("defaults %+v %v", o, e)
	}
	v, _ := url.ParseQuery("q=%20Needle%25_%20&status=all&mode=pg-dump&signed=false&offset=2147483647&sort=size&order=asc")
	o, e = parseBackupInventoryOptions(v)
	if e != nil || o.Query != "needle%_" || o.Status != "" || o.Mode != "pg-dump" || o.Signed != "false" || o.Offset != inventorylist.MaxOffset {
		t.Fatalf("normalization %+v %v", o, e)
	}
	for _, raw := range []string{"q=a&q=b", "status=weird", "mode=full", "signed=1", "sort=evil", "order=wrong", "limit=", "limit=0", "limit=501", "limit=1.5", "offset=", "offset=-1", "offset=2147483648", "offset=no"} {
		v, _ := url.ParseQuery(raw)
		if _, e = parseBackupInventoryOptions(v); e == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
func TestBackupInventoryFullOwnedSourceLatestAndCSV(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx, pool := t.Context(), d.Pool()
	org, foreign, legacy, oldSuccess, newSuccess := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, e := pool.Exec(ctx, sql, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'backup inventory'),($2::uuid,$2::text,'foreign')`, org, foreign)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM backups WHERE org_id IN($1,$2) OR id=$3`, org, foreign, legacy)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	exec(`INSERT INTO backups(org_id,mode,status,started_at,size_bytes,signed,error,local_path) SELECT $1,'org-backup','failed','2026-10-12'::timestamptz+n*interval '1 second',n,false,CASE WHEN n=240 THEN 'needle%_literal' ELSE 'failed run '||n END,'/secret/artifact' FROM generate_series(1,240)n`, org)
	exec(`INSERT INTO backups(id,org_id,mode,status,started_at,finished_at,size_bytes,signed,signer_identity,s3_uri,tables_included)VALUES($1,$3,'org-backup','succeeded','2020-01-01','2020-01-01T00:00:01.123456Z',8192,true,'signer, complete','s3://owned/archive','{assets,findings}'),($2,$3,'org-backup','succeeded','2021-01-01','2021-01-01T00:00:01.123456Z',4096,false,'','', '{}')`, oldSuccess, newSuccess, org)
	exec(`INSERT INTO backups(org_id,status,started_at,error)VALUES($1,'running','2026-10-12','in-flight'),($2,'succeeded','2030-01-01','foreign successful')`, org, foreign)
	exec(`INSERT INTO backups(id,status,started_at,error)VALUES($1,'succeeded','2040-01-01','legacy unowned successful')`, legacy)
	// Independently filtered bulk cohort proves the export cap without changing the
	// selected organization-backup history or its older successful-run KPI.
	exec(`INSERT INTO backups(org_id,mode,status,started_at,size_bytes,error)SELECT $1,'pg-dump','failed','2019-01-01',1,'cap-proof-'||n FROM generate_series(1,100005)n`, org)
	h := &Backups{db: d}
	request := func(raw string, export, auth bool, canceled bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), "GET", "/backups/inventory?"+raw, nil)
		if auth {
			r = r.WithContext(WithSubject(r.Context(), Subject{OrgID: org}))
		}
		if canceled {
			c, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(c)
		}
		w := httptest.NewRecorder()
		if export {
			h.InventoryCSV(w, r)
		} else {
			h.Inventory(w, r)
		}
		return w
	}
	read := func(raw string) backupInventoryPage {
		t.Helper()
		w := request(raw, false, true, false)
		if w.Code != 200 {
			t.Fatalf("read%d %s", w.Code, w.Body.String())
		}
		var p backupInventoryPage
		if e := json.Unmarshal(w.Body.Bytes(), &p); e != nil {
			t.Fatal(e)
		}
		return p
	}
	p := read("mode=org-backup")
	if p.Total != 243 || len(p.Backups) != 100 || !p.HasMore || p.Summary["failed"] != 240 || p.Summary["running"] != 1 || p.Summary["succeeded"] != 2 || p.Summary["signed"] != 1 || p.Summary["size_bytes"] != 240*241/2+12288 || p.LatestSuccess == nil || p.LatestSuccess.ID != newSuccess.String() {
		t.Fatalf("full metadata %+v", p)
	}
	if p.OrgID != org || !p.SourceComplete || p.SummaryScope != "matching_owned_backup_runs" {
		t.Fatalf("scope %+v", p)
	}
	tail := read("mode=org-backup&offset=200")
	if len(tail.Backups) != 43 || tail.HasMore || tail.Total != 243 || tail.Backups[42].ID != oldSuccess.String() {
		t.Fatalf("tail %+v", tail)
	}
	needle := read("mode=org-backup&q=Needle%25_&status=failed&signed=false")
	if needle.Total != 1 || needle.Backups[0].ErrorMessage != "needle%_literal" || needle.LatestSuccess.ID != newSuccess.String() {
		t.Fatalf("literal/latest %+v", needle)
	}
	empty := read("mode=org-backup&offset=" + strconv.Itoa(inventorylist.MaxOffset))
	if len(empty.Backups) != 0 || empty.Total != 243 || empty.HasMore || empty.LatestSuccess.ID != newSuccess.String() {
		t.Fatalf("deep %+v", empty)
	}
	ascending := read("mode=org-backup&sort=when&order=asc&limit=1")
	if len(ascending.Backups) != 1 || ascending.Backups[0].ID != oldSuccess.String() {
		t.Fatalf("ascending %+v", ascending)
	}
	for _, sort := range []string{"when", "size", "mode", "status", "signer"} {
		first := read("mode=org-backup&sort=" + sort + "&limit=1")
		next := read("mode=org-backup&sort=" + sort + "&limit=1&offset=1")
		if first.Backups[0].ID == next.Backups[0].ID {
			t.Fatal("unstable ordering")
		}
	}
	w := request("mode=org-backup&sort=when&order=asc&limit=1&offset=100", true, true, false)
	csvRows, e := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if e != nil || w.Code != 200 || len(csvRows) != 244 || csvRows[1][0] != oldSuccess.String() || w.Header().Get("X-Export-Total") != "243" || w.Header().Get("X-Export-Truncated") != "false" || w.Header().Get("X-Export-Org-ID") != org.String() {
		t.Fatalf("CSV%d rows%d %v %v", w.Code, len(csvRows), e, w.Header())
	}
	if strings.Contains(w.Body.String(), "/secret/artifact") || strings.Contains(w.Body.String(), legacy.String()) || strings.Contains(w.Body.String(), foreign.String()) {
		t.Fatal("CSV leaked artifact path or foreign/legacy metadata")
	}
	if csvRows[1][5] != "2020-01-01T00:00:01.123456Z" || csvRows[1][12] != `["assets","findings"]` {
		t.Fatalf("CSV precision %+v", csvRows[1])
	}
	w = request("mode=pg-dump&q=cap-proof", true, true, false)
	csvRows, e = csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if e != nil || len(csvRows) != 100001 || w.Header().Get("X-Export-Total") != "100005" || w.Header().Get("X-Export-Truncated") != "true" {
		t.Fatalf("cap rows%d err%v headers%v", len(csvRows), e, w.Header())
	}
	first := read("mode=pg-dump&limit=1")
	next := read("mode=pg-dump&limit=1&offset=1")
	if first.Backups[0].ID >= next.Backups[0].ID {
		t.Fatal("timestamp ties not ordered by exact ID")
	}
	for _, export := range []bool{false, true} {
		w = request("", export, false, false)
		if w.Code != 401 {
			t.Fatal("missing subject accepted")
		}
		w = request("", export, true, true)
		if w.Code != 500 || !strings.Contains(w.Body.String(), "Backup history is unavailable") || strings.Contains(w.Body.String(), "context canceled") {
			t.Fatalf("failure%d %s", w.Code, w.Body.String())
		}
	}
	// Full owned latest success remains null when no success exists, rather than
	// borrowing a more recent legacy/system or foreign-organization backup.
	exec(`UPDATE backups SET status='failed' WHERE org_id=$1 AND status='succeeded'`, org)
	p = read("mode=org-backup&limit=1")
	if p.LatestSuccess != nil {
		t.Fatal("borrowed another owner's successful backup")
	}
}
