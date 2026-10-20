package telemetry

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	collectorlogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
)

func TestInit_PrometheusOnly(t *testing.T) {
	t.Parallel()
	tel, err := Init(context.Background(), Config{ServiceName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"go_goroutines", `service_build_info{`, `service="test"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in /metrics output", want)
		}
	}
}

func TestAdmissionDecisionsCounter(t *testing.T) {
	t.Parallel()
	tel, err := Init(context.Background(), Config{ServiceName: "adm-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()
	tel.RecordAdmissionDecision("deny", "rule-abc")
	tel.RecordAdmissionDecision("deny", "rule-abc")
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `admission_decisions_total{result="deny",rule="rule-abc"} 2`) {
		t.Fatalf("counter missing:\n%s", rec.Body.String())
	}
}

// The route label must be the chi pattern, never the raw path with its UUID.
func TestHTTPMiddleware_UsesChiRoutePattern(t *testing.T) {
	t.Parallel()
	tel, err := Init(context.Background(), Config{ServiceName: "mw-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()

	r := chi.NewRouter()
	r.Use(tel.HTTPMiddleware)
	r.Get("/things/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	r.Get("/boom", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
	for _, p := range []string{"/things/1b6a2f00-0000-4000-8000-000000000001", "/things/2", "/boom"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, p, nil))
	}
	rec := httptest.NewRecorder()
	tel.MetricsHandler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	if !strings.Contains(body, `requests_total{method="GET",route="/things/{id}",status_class="2xx"} 2`) {
		t.Fatalf("expected pattern-labelled counter:\n%s", body)
	}
	if strings.Contains(body, "1b6a2f00") {
		t.Fatalf("raw path leaked into a label:\n%s", body)
	}
	if !strings.Contains(body, `request_errors_total{reason="internal",route="/boom"} 1`) {
		t.Fatalf("expected error counter:\n%s", body)
	}
}

type fakeTraceServer struct {
	collectortrace.UnimplementedTraceServiceServer
	mu    sync.Mutex
	spans int
}

func (f *fakeTraceServer) Export(_ context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			f.spans += len(ss.GetSpans())
		}
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

type fakeMetricsServer struct {
	collectormetrics.UnimplementedMetricsServiceServer
}

func (fakeMetricsServer) Export(context.Context, *collectormetrics.ExportMetricsServiceRequest) (*collectormetrics.ExportMetricsServiceResponse, error) {
	return &collectormetrics.ExportMetricsServiceResponse{}, nil
}

type fakeLogsServer struct {
	collectorlogs.UnimplementedLogsServiceServer
}

func (fakeLogsServer) Export(context.Context, *collectorlogs.ExportLogsServiceRequest) (*collectorlogs.ExportLogsServiceResponse, error) {
	return &collectorlogs.ExportLogsServiceResponse{}, nil
}

// TestInit_OTLPGRPCRoundTrip stands up an OTLP/gRPC trace receiver and confirms a span lands.
func TestInit_OTLPGRPCRoundTrip(t *testing.T) {
	t.Parallel()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	fake := &fakeTraceServer{}
	collectortrace.RegisterTraceServiceServer(srv, fake)
	collectormetrics.RegisterMetricsServiceServer(srv, fakeMetricsServer{})
	collectorlogs.RegisterLogsServiceServer(srv, fakeLogsServer{})
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx := context.Background()
	tel, err := Init(ctx, Config{ServiceName: "otlp-test", Endpoint: lis.Addr().String(), Insecure: true, MetricsOTLP: true, LogsOTLP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, span := tel.Tracer.Start(ctx, "test-op")
	span.End()
	shutdownCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tel.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.spans == 0 {
		t.Fatal("expected at least one exported span")
	}
}

func TestAdminHandler(t *testing.T) {
	t.Parallel()
	tel, err := Init(context.Background(), Config{ServiceName: "admin-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tel.Shutdown(context.Background()) }()
	h := tel.AdminHandler(AdminOptions{Ready: func(context.Context) error { return context.DeadlineExceeded }})
	for path, want := range map[string]int{"/healthz": 200, "/readyz": 503, "/metrics": 200, "/debug/pprof/": 404} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		if rec.Code != want {
			t.Fatalf("%s: status %d, want %d", path, rec.Code, want)
		}
	}
}
