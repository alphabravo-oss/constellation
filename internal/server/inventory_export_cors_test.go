package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInventoryExportReceiptsExposedOnlyToAllowedBrowserOrigin(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.db.Close)
	for _, origin := range []string{"http://localhost:5173", "https://untrusted.example.test", ""} {
		t.Run(origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/backups/inventory.csv", nil)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			response := httptest.NewRecorder()
			s.router.ServeHTTP(response, req)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("CORS must not bypass inventory authentication: %d", response.Code)
			}
			if origin != "http://localhost:5173" {
				if response.Header().Get("Access-Control-Allow-Origin") != "" || response.Header().Get("Access-Control-Expose-Headers") != "" {
					t.Fatalf("untrusted/same-origin request received cross-origin permission: %v", response.Header())
				}
				return
			}
			if response.Header().Get("Access-Control-Allow-Origin") != origin || response.Header().Get("Access-Control-Allow-Credentials") != "true" {
				t.Fatalf("allowed credentialed origin missing: %v", response.Header())
			}
			exposed := map[string]bool{}
			for _, header := range strings.Split(response.Header().Get("Access-Control-Expose-Headers"), ",") {
				exposed[strings.ToLower(strings.TrimSpace(header))] = true
			}
			for _, header := range []string{"x-export-total", "x-export-limit", "x-export-truncated", "x-export-org-id", "x-export-scope", "x-report-org-id", "x-report-cluster-id", "content-disposition"} {
				if !exposed[header] {
					t.Fatalf("browser cannot verify receipt %s: %v", header, response.Header())
				}
			}
		})
	}
}
