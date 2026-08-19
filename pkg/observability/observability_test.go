package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestInit_PrometheusOnly confirms Prometheus is wired even when OTLP is disabled.
func TestInit_PrometheusOnly(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	tel, err := Init(context.Background(), "test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tel.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	tel.MetricsHandler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("metrics status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "go_goroutines") {
		t.Fatalf("expected goroutines metric in Prometheus output")
	}
}

// TestAdmissionDecisionsCounter confirms admission_decisions_total is registered and
// increments on a deny path.
func TestAdmissionDecisionsCounter(t *testing.T) {
	tel, err := Init(context.Background(), "adm-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	tel.RecordAdmissionDecision("deny", "rule-abc")
	tel.RecordAdmissionDecision("deny", "rule-abc")

	mfs, err := tel.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var got float64
	found := false
	for _, mf := range mfs {
		if mf.GetName() != "admission_decisions_total" {
			continue
		}
		found = true
		for _, m := range mf.GetMetric() {
			labels := map[string]string{}
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			if labels["result"] == "deny" && labels["rule"] == "rule-abc" {
				got = m.GetCounter().GetValue()
			}
		}
	}
	if !found {
		t.Fatal("admission_decisions_total not registered")
	}
	if got != 2 {
		t.Fatalf("counter = %v, want 2", got)
	}
}

// TestHTTPMiddleware_RecordsHistogram exercises the middleware and confirms the histogram
// receives observations.
func TestHTTPMiddleware_RecordsHistogram(t *testing.T) {
	tel, err := Init(context.Background(), "mw-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	called := 0
	h := tel.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(204)
	}))

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/things", nil)
		req = SetRoutePattern(req, "/things")
		h.ServeHTTP(rec, req)
		if rec.Code != 204 {
			t.Fatalf("inner status %d", rec.Code)
		}
	}
	if called != 3 {
		t.Fatalf("inner handler called %d times", called)
	}

	// Scrape metrics and assert the bucket appears.
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, "constellation_http_request_duration_seconds") {
		t.Fatalf("expected histogram in metrics output:\n%s", truncate(body, 2000))
	}
	if !strings.Contains(body, `route="/things"`) {
		t.Fatalf("expected route label in histogram, got:\n%s", truncate(body, 2000))
	}
}

// TestInit_OTLPRoundTrip stands up a fake OTLP/HTTP receiver, runs Init pointed at it, emits
// a span, and confirms the receiver gets a POST to /v1/traces.
func TestInit_OTLPRoundTrip(t *testing.T) {
	var (
		mu     sync.Mutex
		hits   = map[string]int{}
		bodies = map[string][]byte{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		mu.Lock()
		hits[r.URL.Path]++
		bodies[r.URL.Path] = body
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://"+u.Host)
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")

	ctx := context.Background()
	tel, err := Init(ctx, "otlp-test")
	if err != nil {
		t.Fatal(err)
	}

	_, span := tel.Tracer.Start(ctx, "test-op")
	span.End()

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := tel.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if hits["/v1/traces"] == 0 {
		t.Fatalf("expected at least one POST to /v1/traces; hits=%v", hits)
	}
	if len(bodies["/v1/traces"]) == 0 {
		t.Fatalf("trace body empty")
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
