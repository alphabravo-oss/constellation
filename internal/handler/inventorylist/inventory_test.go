package inventorylist

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseRejectsUntrustedSortAndOrder(t *testing.T) {
	sorts := map[string]string{"scan": "last_scanned_at"}
	for _, raw := range []string{"sort=unknown", "sort=scan%3BDROP+TABLE+orgs", "order=desc%3Bselect+1"} {
		values, _ := url.ParseQuery(raw)
		if _, err := Parse(values, sorts, "scan"); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	o, err := Parse(url.Values{"limit": {"501"}, "offset": {"-1"}}, sorts, "scan")
	if err != nil || o.Limit != 100 || o.Offset != 0 || o.OrderSQL != "last_scanned_at DESC NULLS LAST, id ASC" {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	values, _ := url.ParseQuery("sort=scan&order=asc&limit=1&offset=100")
	o, err = Parse(values, sorts, "scan")
	if err != nil || o.Limit != 1 || o.Offset != 100 || o.OrderSQL != "last_scanned_at ASC NULLS LAST, id ASC" {
		t.Fatalf("paging: %+v %v", o, err)
	}
}
func TestFilterAllAndInvalidValues(t *testing.T) {
	for _, value := range []string{"", "all", "critical"} {
		v, err := Filter(url.Values{"severity": {value}}, "severity", "critical")
		if err != nil || value == "critical" && v != value {
			t.Fatalf("filter %q: %q %v", value, v, err)
		}
	}
	if _, err := Filter(url.Values{"severity": {"anything"}}, "severity", "critical"); err == nil {
		t.Fatal("unknown filter accepted")
	}
}
func TestCSVHeadersIdentifyMatchingScopeAndCap(t *testing.T) {
	for _, total := range []int64{0, 100001} {
		w := httptest.NewRecorder()
		WriteCSV(w, "inventory.csv", []byte("ID\n"), Metadata{Total: total})
		if w.Header().Get("X-Export-Limit") != "100000" || w.Code != 200 {
			t.Fatalf("headers: %v", w.Header())
		}
		want := "false"
		if total > ExportLimit {
			want = "true"
		}
		if w.Header().Get("X-Export-Truncated") != want {
			t.Fatal("wrong cap disclosure")
		}
	}
}
