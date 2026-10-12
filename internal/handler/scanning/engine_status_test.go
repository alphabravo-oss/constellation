package scanning

import (
	"encoding/json"
	"testing"
)

func TestScanEngineStatusFailClosed(t *testing.T) {
	for _, engines := range [][]completeScanEngine{
		{{Engine: "Trivy"}, {Engine: "trivy", Error: "private upstream credential fixture"}, {Engine: "grype"}},
		{{Engine: "trivy", Error: "private upstream credential fixture"}, {Engine: " Trivy "}, {Engine: "grype"}},
	} {
		raw := scanEngineStatus(engines)
		var statuses map[string]string
		if err := json.Unmarshal([]byte(raw), &statuses); err != nil {
			t.Fatal(err)
		}
		if len(statuses) != 2 || statuses["trivy"] != "failed" || statuses["grype"] != "succeeded" {
			t.Fatalf("unexpected outcomes: %s", raw)
		}
	}
	if got := scanEngineStatus(nil); got != "{}" {
		t.Fatalf("legacy upload must not imply success: %s", got)
	}
}
