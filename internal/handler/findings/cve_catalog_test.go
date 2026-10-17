package findings

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/inventorylist"
)

func TestCVECatalogParserAndAuthorization(t *testing.T) {
	for _, query := range []string{"q=a&q=b", "kev=maybe", "epss_gt=NaN", "epss_gt=1.1", "cvss_gt=11", "cvss_gt=-1", "severity=bad", "sort=sql", "dir=sideways", "offset=-1", "offset=2147483648", "offset=oops", "limit=oops", "q=unknown:foo", "q=%zz"} {
		t.Run(query, func(t *testing.T) {
			for _, export := range []bool{false, true} {
				if export && (strings.HasPrefix(query, "offset=") || strings.HasPrefix(query, "limit=")) {
					continue
				}
				if _, err := parseCVECatalog(httptest.NewRequestWithContext(t.Context(), "GET", "/cve/search?"+query, nil), export); err == nil {
					t.Fatal("malformed query accepted")
				}
			}
		})
	}
	for _, handler := range []func(http.ResponseWriter, *http.Request){(&CVE{}).Search, (&CVE{}).SearchCSV} {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequestWithContext(t.Context(), "GET", "/cve/search", nil))
		if w.Code != 401 {
			t.Fatalf("anonymous=%d", w.Code)
		}
	}
	query, err := parseCVECatalog(httptest.NewRequestWithContext(t.Context(), "GET", "/cve/search?limit=201&offset=2147483647", nil), false)
	if err != nil || query.limit != 50 || query.offset != inventorylist.MaxOffset {
		t.Fatalf("legacy default/deep offset: %+v %v", query, err)
	}
	query, err = parseCVECatalog(httptest.NewRequestWithContext(t.Context(), "GET", "/cve/search.csv?limit=oops&offset=-1", nil), true)
	if err != nil || query.limit != 100001 || query.offset != 0 {
		t.Fatalf("matching CSV used page bounds: %+v %v", query, err)
	}
	if !strings.HasSuffix(query.order, "cve_id ASC") {
		t.Fatalf("default order lacks exact-ID tie: %s", query.order)
	}
}

func TestCVECatalogMatchingExportFiltersOrderingAndCap(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool, ctx := d.Pool(), t.Context()
	prefix := "CVE-CATALOG-" + uuid.NewString()
	must := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	must(`INSERT INTO cve_records(cve_id,title,description,cvss_base,kev_listed,epss_probability,aliases,sources,published_at) SELECT $1||'-'||lpad(n::text,6,'0'),'catalog title','description, with quote " and newline'||chr(10)||'next',9.1,true,0.9000000003,ARRAY['alias-'||n],ARRAY['NVD','KEV'],'2026-10-13T01:02:03.123456Z' FROM generate_series(1,100005)n`, prefix)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM cve_records WHERE cve_id LIKE $1`, prefix+"%")
	})
	// Different failure modes must be excluded by the exact conjunction, not page filtering.
	must(`INSERT INTO cve_records(cve_id,title,cvss_base,kev_listed,epss_probability,sources) VALUES ($1||'-not-kev','negative',9.1,false,0.9,ARRAY['NVD']),($1||'-wrong-source','negative',9.1,true,0.9,ARRAY['OSV']),($1||'-epss-boundary','negative',9.1,true,0.5,ARRAY['NVD']),($1||'-cvss-boundary','negative',7,true,0.9,ARRAY['NVD']),($1||'-null-score','negative',NULL,true,NULL,ARRAY['NVD'])`, prefix)
	h := NewCVE(d, "")
	request := func(query string, export bool, org uuid.UUID) *httptest.ResponseRecorder {
		r := httptest.NewRequestWithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: org}), http.MethodGet, "/cve/search?"+query, nil)
		w := httptest.NewRecorder()
		if export {
			h.SearchCSV(w, r)
		} else {
			h.Search(w, r)
		}
		return w
	}
	filters := url.Values{"q": {prefix}, "kev": {"true"}, "epss_gt": {"0.5"}, "cvss_gt": {"7"}, "severity": {"critical"}, "source": {"NVD"}, "sort": {"cvss"}, "dir": {"desc"}}
	org := uuid.New()
	filters.Set("limit", "51")
	filters.Set("offset", "50")
	w := request(filters.Encode(), false, org)
	var page struct {
		Results       []cveDTO
		Limit, Offset int
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Results) != 51 || page.Results[0].CVEID != prefix+"-000051" || page.Results[50].CVEID != prefix+"-000101" {
		t.Fatalf("deterministic page: %d %s", w.Code, w.Body.String())
	}
	exported := request(filters.Encode(), true, org)
	records, err := csv.NewReader(exported.Body).ReadAll()
	if err != nil || exported.Code != 200 || len(records) != 100001 || exported.Header().Get("X-Export-Rows") != "100000" || exported.Header().Get("X-Export-Limit") != "100000" || exported.Header().Get("X-Export-Truncated") != "true" || exported.Header().Get("X-Export-Total") != "" {
		t.Fatalf("cap/metadata %d rows=%d headers=%v err=%v", exported.Code, len(records), exported.Header(), err)
	}
	if records[1][0] != prefix+"-000001" || records[100000][0] != prefix+"-100000" || records[1][7] != "0.9000000003" || records[1][11] != "2026-10-13T01:02:03.123456Z" || !strings.Contains(records[1][2], "\n") {
		t.Fatalf("exact scalar/order loss first=%v last=%v", records[1], records[100000])
	}
	ids := map[string]bool{}
	for _, row := range records[1:] {
		if ids[row[0]] {
			t.Fatal("duplicate exported catalog ID")
		}
		ids[row[0]] = true
	}
	filters.Set("q", prefix+"-100005")
	filters.Set("offset", "2000")
	w = request(filters.Encode(), false, org)
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Results) != 0 {
		t.Fatal("deep page not empty")
	}
	exported = request(filters.Encode(), true, uuid.New())
	records, err = csv.NewReader(exported.Body).ReadAll()
	if err != nil || len(records) != 2 || records[1][0] != prefix+"-100005" || exported.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("tail/global read/matching export %s %v", exported.Body.String(), err)
	}
	filters.Set("q", `cve:"`+prefix+`-100005" kev:true`)
	filters.Set("offset", "0")
	w = request(filters.Encode(), false, org)
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Results) != 1 || page.Results[0].CVEID != prefix+"-100005" {
		t.Fatalf("DSL lost: %s", w.Body.String())
	}
	filters.Set("q", prefix)
	filters.Set("sort", "cve_id")
	filters.Set("dir", "desc")
	w = request(filters.Encode(), false, org)
	if json.Unmarshal(w.Body.Bytes(), &page) != nil || page.Results[0].CVEID != prefix+"-100005" {
		t.Fatalf("descending exact IDs %s", w.Body.String())
	}
	// Query errors must not leak internals or partially prepare a successful CSV.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	r := httptest.NewRequestWithContext(authctx.WithSubject(cancelled, authctx.Subject{OrgID: org}), "GET", "/cve/search.csv?q="+prefix, nil)
	w = httptest.NewRecorder()
	h.SearchCSV(w, r)
	if w.Code != 500 || w.Header().Get("X-Export-Rows") != "" || strings.Contains(w.Body.String(), "context canceled") {
		t.Fatalf("failed read %d %s", w.Code, w.Body.String())
	}
}
