package compliance

import (
	"strings"
	"testing"
)

func TestBenchExecutionReportRequiresActualEvaluations(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{`null`, `{}`, `{"Controls":[]}`, `{"Controls":[{"tests":[{"results":[{"status":"PASS"}]}]}]}`, `{"Controls":[{"tests":[{"results":[{"test_number":"1","test_desc":"test","status":"surprise"}]}]}]}`} {
		if _, err := ValidateBenchExecutionReport([]byte(raw)); err == nil {
			t.Fatalf("non-evaluation qualified as successful execution: %s", raw)
		}
	}
	valid := `{"Controls":[{"tests":[{"results":[{"test_number":"1","test_desc":"bad control","status":"FAIL"},{"test_number":"2","test_desc":"good control","status":"PASS"},{"test_number":"3","test_desc":"review","status":"WARN"},{"test_number":"4","test_desc":"context","status":"INFO"}]}]}]}`
	counts, err := ValidateBenchExecutionReport([]byte(valid))
	if err != nil || counts != (BenchExecutionCounts{Total: 4, Pass: 1, Fail: 1, Manual: 1, NotApplicable: 1}) {
		t.Fatalf("lost actual source control status: %+v %v", counts, err)
	}
}

func TestBenchExecutionCanonicalDigestAndBounds(t *testing.T) {
	t.Parallel()
	a, hashA, err := CanonicalBenchReport([]byte(" { \"x\" : 1 } \n"))
	if err != nil {
		t.Fatal(err)
	}
	b, hashB, err := CanonicalBenchReport([]byte(`{"x":1}`))
	if err != nil || string(a) != string(b) || hashA != hashB || len(hashA) != 64 {
		t.Fatal("transport JSON compaction changed canonical digest")
	}
	for _, raw := range []string{"", "{} {}", `"` + strings.Repeat("x", BenchExecutionMaxReport) + `"`} {
		if _, _, err := CanonicalBenchReport([]byte(raw)); err == nil {
			t.Fatal("invalid or oversized report accepted")
		}
	}
}
