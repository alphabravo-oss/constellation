// Package observability wires OpenTelemetry SDK (traces + metrics + logs over OTLP/HTTP)
// alongside a Prometheus /metrics endpoint. Every service main() calls Init() exactly once.
//
// Environment knobs (read from the OTel SDK defaults, plus our own):
//
//	OTEL_EXPORTER_OTLP_ENDPOINT       - if set, OTLP exporters are wired (HTTP/protobuf)
//	OTEL_EXPORTER_OTLP_INSECURE       - "true" to disable TLS
//	OTEL_SERVICE_NAME                 - overrides the serviceName argument
//	CONSTELLATION_PROMETHEUS_ONLY     - if "true", skip OTLP exporters even if endpoint set
//
// All three signal types (trace/metric/log) share the same endpoint by default; OTel's
// SDK allows per-signal overrides through its standard environment-variable scheme.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/alphabravocompany/constellation/internal/obslog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

// Telemetry is the handle returned by Init. Callers must call Shutdown before process exit.
type Telemetry struct {
	ServiceName string
	Logger      *slog.Logger
	Registry    *prometheus.Registry

	HTTPDuration *prometheus.HistogramVec
	GRPCDuration *prometheus.HistogramVec
	DBDuration   *prometheus.HistogramVec

	// AdmissionDecisions counts admission-control verdicts by result ("allow"/"deny")
	// and the admission rule id that produced them. Callers bump it at the point an
	// admission decision is recorded via RecordAdmissionDecision.
	AdmissionDecisions *prometheus.CounterVec

	Tracer         trace.Tracer
	LoggerOTel     otellog.Logger          // OTel-native logger; slog still emits to stdout
	otelHTTPHist   metric.Float64Histogram // duplicates Prometheus HTTPDuration into OTel
	otelReqCounter metric.Int64Counter     // total HTTP requests for OTel meter
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	loggerProvider *sdklog.LoggerProvider

	shutdowns []func(context.Context) error
}

// Init initializes the OTel SDK + a Prometheus registry. The OTLP exporters are wired only
// when OTEL_EXPORTER_OTLP_ENDPOINT is set (and CONSTELLATION_PROMETHEUS_ONLY is not "true");
// otherwise OTel falls back to no-op providers and only the Prometheus side is live.
func Init(ctx context.Context, serviceName string) (*Telemetry, error) {
	if env := os.Getenv("OTEL_SERVICE_NAME"); env != "" {
		serviceName = env
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: obslog.Level()})).
		With(slog.String("service", serviceName))

	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	httpHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "constellation_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route", "status"})

	grpcHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "constellation_grpc_server_duration_seconds",
		Help:    "gRPC server handler duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"service", "method", "code"})

	dbHist := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "constellation_db_query_duration_seconds",
		Help:    "Postgres query duration in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"query", "status"})

	admissionDecisions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "admission_decisions_total",
		Help: "Admission control decisions by result and rule.",
	}, []string{"result", "rule"})

	reg.MustRegister(httpHist, grpcHist, dbHist, admissionDecisions)

	t := &Telemetry{
		ServiceName:        serviceName,
		Logger:             logger,
		Registry:           reg,
		HTTPDuration:       httpHist,
		GRPCDuration:       grpcHist,
		DBDuration:         dbHist,
		AdmissionDecisions: admissionDecisions,
		Tracer:             otel.Tracer(serviceName),
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	promOnly := os.Getenv("CONSTELLATION_PROMETHEUS_ONLY") == "true"
	if endpoint == "" || promOnly {
		logger.Info("observability: prometheus-only mode (OTLP exporters not wired)",
			slog.String("endpoint", endpoint), slog.Bool("prom_only", promOnly))
		// Register global propagators so even no-op tracer respects W3C headers.
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{},
		))
		return t, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(serviceVersion()),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("observability: resource: %w", err)
	}

	traceExp, err := otlptracehttp.New(ctx, otlpTraceOpts()...)
	if err != nil {
		return nil, fmt.Errorf("observability: trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	t.tracerProvider = tp
	t.Tracer = tp.Tracer(serviceName)
	t.shutdowns = append(t.shutdowns, tp.Shutdown)

	metricExp, err := otlpmetrichttp.New(ctx, otlpMetricOpts()...)
	if err != nil {
		return nil, fmt.Errorf("observability: metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp, sdkmetric.WithInterval(15*time.Second))),
		sdkmetric.WithResource(res),
	)
	otel.SetMeterProvider(mp)
	t.meterProvider = mp
	t.shutdowns = append(t.shutdowns, mp.Shutdown)

	meter := mp.Meter(serviceName)
	if hist, err := meter.Float64Histogram(
		"http.server.duration",
		metric.WithUnit("s"),
		metric.WithDescription("HTTP server request duration in seconds (mirrors Prometheus histogram)"),
	); err == nil {
		t.otelHTTPHist = hist
	}
	if counter, err := meter.Int64Counter(
		"http.server.request_count",
		metric.WithDescription("Total HTTP requests served"),
	); err == nil {
		t.otelReqCounter = counter
	}

	logExp, err := otlploghttp.New(ctx, otlpLogOpts()...)
	if err != nil {
		return nil, fmt.Errorf("observability: log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)
	global.SetLoggerProvider(lp)
	t.loggerProvider = lp
	t.LoggerOTel = lp.Logger(serviceName)
	t.shutdowns = append(t.shutdowns, lp.Shutdown)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	logger.Info("observability: OTLP exporters wired",
		slog.String("endpoint", endpoint))
	return t, nil
}

// RecordAdmissionDecision increments admission_decisions_total for a single admission
// verdict. result is typically "allow" or "deny"; rule is the admission rule id that
// produced it (may be empty). Nil-safe so callers holding a metrics-disabled Telemetry
// need no guard.
func (t *Telemetry) RecordAdmissionDecision(result, rule string) {
	if t == nil || t.AdmissionDecisions == nil {
		return
	}
	t.AdmissionDecisions.WithLabelValues(result, rule).Inc()
}

// Shutdown drains exporters with the provided context's deadline.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var combined error
	for _, fn := range t.shutdowns {
		if err := fn(ctx); err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return combined
}

// MetricsHandler returns the Prometheus /metrics handler bound to this Telemetry's registry.
func (t *Telemetry) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(t.Registry, promhttp.HandlerOpts{Registry: t.Registry})
}

// HTTPMiddleware wraps an http.Handler and records request duration + an OTel span per request.
// The span name comes from the chi route pattern when present (set via the SetRoutePattern
// wrapper) or falls back to the URL path. W3C traceparent / tracestate are read off the request.
//
// Both Prometheus and OTel meters receive the same observation: Prometheus for /metrics
// scraping, OTel for OTLP push to a customer collector. Logs are emitted via the OTel
// log SDK as a one-line summary per request so the OTLP logs pipeline carries real data.
func (t *Telemetry) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		route := routeOf(r)
		ctx, span := t.Tracer.Start(ctx, r.Method+" "+route)
		defer span.End()

		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(ww, r.WithContext(ctx))

		dur := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", ww.status)
		t.HTTPDuration.WithLabelValues(r.Method, route, status).Observe(dur)

		if t.otelHTTPHist != nil {
			t.otelHTTPHist.Record(ctx, dur, metric.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.route", route),
				attribute.Int("http.status_code", ww.status),
			))
		}
		if t.otelReqCounter != nil {
			t.otelReqCounter.Add(ctx, 1, metric.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.Int("http.status_code", ww.status),
			))
		}
		if t.LoggerOTel != nil {
			rec := otellog.Record{}
			rec.SetSeverity(otellog.SeverityInfo)
			rec.SetBody(otellog.StringValue(fmt.Sprintf("%s %s -> %d (%.3fs)", r.Method, route, ww.status, dur)))
			rec.SetTimestamp(time.Now())
			t.LoggerOTel.Emit(ctx, rec)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// routeOf prefers the chi route pattern attached to the context (set by SetRoutePattern); falls
// back to the raw URL path. Bounded-cardinality routes keep Prometheus + OTel happy.
func routeOf(r *http.Request) string {
	if v := r.Context().Value(routePatternKey{}); v != nil {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return r.URL.Path
}

type routePatternKey struct{}

// SetRoutePattern is called by route middleware (e.g. chi's RouteContext) to publish the
// matched pattern into the request context for downstream observability use.
func SetRoutePattern(r *http.Request, pattern string) *http.Request {
	if pattern == "" {
		return r
	}
	ctx := r.Context()
	return r.WithContext(contextWithRoute(ctx, pattern))
}

func contextWithRoute(ctx context.Context, pattern string) context.Context {
	return contextWithValue(ctx, routePatternKey{}, pattern)
}

// contextWithValue is a tiny indirection so callers in tests can plug values without importing
// internal types directly. It's effectively context.WithValue.
func contextWithValue(parent context.Context, key, val any) context.Context {
	return context.WithValue(parent, key, val)
}

func otlpTraceOpts() []otlptracehttp.Option {
	var opts []otlptracehttp.Option
	if os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	return opts
}

func otlpMetricOpts() []otlpmetrichttp.Option {
	var opts []otlpmetrichttp.Option
	if os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}
	return opts
}

func otlpLogOpts() []otlploghttp.Option {
	var opts []otlploghttp.Option
	if os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "true" {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	return opts
}

// serviceVersion is the build-time service version stamp; populated via -ldflags from the
// goreleaser build, falls back to "dev" otherwise.
var serviceVersion = func() string {
	if v := os.Getenv("CONSTELLATION_VERSION"); v != "" {
		return v
	}
	return "dev"
}
