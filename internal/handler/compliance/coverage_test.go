package compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCoverage_ListHasDecisionEvidence(t *testing.T) {
	w := httptest.NewRecorder()
	NewCoverage().List(w, httptest.NewRequest("GET", "/api/v1/coverage", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d", w.Code)
	}
	var got struct {
		Items []coverageItem `json:"items"`
	}
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Items) < 10 {
		t.Fatalf("expected broad coverage matrix, got %d", len(got.Items))
	}
	for _, item := range got.Items {
		if item.Domain == "" || item.Feature == "" || item.Decision == "" || item.Status == "" || item.UXSurface == "" || item.Evidence == "" {
			t.Fatalf("incomplete coverage item: %+v", item)
		}
		if len(item.Reference) == 0 {
			t.Fatalf("missing references for %s", item.ID)
		}
	}
}
