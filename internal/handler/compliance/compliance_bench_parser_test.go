package compliance

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestBenchRunInvalidBodyDoesNotWrite(t *testing.T) {
	f := newComplianceAgentFixture(t)
	cases := []struct {
		name string
		body func() io.Reader
	}{
		{"invalid JSON", func() io.Reader { return strings.NewReader(`{"profile":`) }},
		{"trailing object", func() io.Reader { return strings.NewReader(`{} {}`) }},
		{"trailing garbage", func() io.Reader { return strings.NewReader(`{} private-broken-input`) }},
		{"oversize object", func() io.Reader { return strings.NewReader(`{"ignored":"` + strings.Repeat("x", 4096) + `"}`) }},
		{"oversize whitespace", func() io.Reader { return strings.NewReader(`{}` + strings.Repeat(" ", 4096)) }},
		{"read error", func() io.Reader { return &benchRequestFailure{} }},
		{"read error after object", func() io.Reader { return io.MultiReader(strings.NewReader(`{}`), &benchRequestFailure{}) }},
		{"null", func() io.Reader { return strings.NewReader(`null`) }},
		{"array", func() io.Reader { return strings.NewReader(`[]`) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := callBenchRunBody(t, f, "?profile=kube-bench&benchmark=eks-1.4.0&cluster_id="+f.cluster.String(), tc.body())
			if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("malformed body accepted or leaked: %d %s", w.Code, w.Body.String())
			}
			var requests, audits int
			if err := f.database.Pool().QueryRow(t.Context(), `SELECT (SELECT count(*) FROM compliance_bench_run_requests WHERE org_id=$1),(SELECT count(*) FROM audit_events WHERE org_id=$1)`, f.org).Scan(&requests, &audits); err != nil || requests != 0 || audits != 0 {
				t.Fatalf("rejected request wrote requests=%d audits=%d err=%v", requests, audits, err)
			}
		})
	}
}

func TestBenchRunBodyCompatibilityAndPrecedence(t *testing.T) {
	f := newComplianceAgentFixture(t)
	cases := []struct {
		name, query, body, profile, benchmark string
	}{
		{"empty", "", "", "kube-bench", ""},
		{"whitespace", "", " \n\t", "kube-bench", ""},
		{"body selectors", "", `{"profile":"docker","benchmark":" cis-1.6.0 "}`, "docker-bench", "cis-1.6.0"},
		{"query selectors", "?profile=kubebench&benchmark=eks-1.4.0", `{"profile":"docker","benchmark":"gke-1.6.0"}`, "kube-bench", "eks-1.4.0"},
		{"body fills blank query", "?profile=&benchmark=%20", `{"profile":"docker-bench","benchmark":"cis-1.6.0"}`, "docker-bench", "cis-1.6.0"},
		{"unknown fields compatible", "", `{"ignored":true}`, "kube-bench", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := callBenchRunBody(t, f, tc.query, strings.NewReader(tc.body))
			var result struct {
				Request BenchRunRequest `json:"request"`
				Message string          `json:"message"`
			}
			if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &result) != nil {
				t.Fatalf("valid body rejected: %d %s", w.Code, w.Body.String())
			}
			if result.Request.Profile != tc.profile || result.Request.Benchmark != tc.benchmark || !strings.Contains(result.Message, "/agent/compliance/ingest") {
				t.Fatalf("changed selection or endpoint: %+v", result)
			}
		})
	}
}

type benchRequestFailure struct{}

func (*benchRequestFailure) Read([]byte) (int, error) {
	return 0, errors.New("private transport failure")
}

func callBenchRunBody(t *testing.T, f *complianceAgentFixture, query string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/v1/compliance/bench/run"+query, body)
	r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: f.org, UserID: f.user}))
	w := httptest.NewRecorder()
	f.service.RunBench(w, r)
	return w
}
