package server

import (
	"net/http"
	"strings"
	"testing"
)

func TestReportScopeReceiptsExposedToAllowedBrowserOrigin(t *testing.T) {
	_, ts, _, signer, adminID, _, orgID := newSysConfigTestServer(t)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ts.URL+"/api/v1/reports/executive.html", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+issueFor(t, signer, adminID, orgID, 0))
	request.Header.Set("Origin", "http://localhost:5173")
	response, err := ts.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("X-Report-Org-ID") != orgID.String() || response.Header.Get("X-Report-Cluster-ID") != "organization" {
		t.Fatalf("report receipt: status=%d headers=%v", response.StatusCode, response.Header)
	}
	exposed := map[string]bool{}
	for _, header := range strings.Split(response.Header.Get("Access-Control-Expose-Headers"), ",") {
		exposed[strings.ToLower(strings.TrimSpace(header))] = true
	}
	for _, header := range []string{"x-report-org-id", "x-report-cluster-id", "content-disposition", "x-constellation-pdf-fallback"} {
		if !exposed[header] {
			t.Fatalf("browser cannot validate report download %s: %v", header, response.Header)
		}
	}
}
