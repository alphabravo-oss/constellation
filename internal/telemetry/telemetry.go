// Package telemetry is the single OpenTelemetry + Prometheus initialisation point for every
// Constellation binary (Technology Selection Guide ch.05). The composition root builds a
// Config (usually via ConfigFromEnv) and calls Init exactly once; nothing in this package reads
// the environment on its own.
//
// Signals:
//   - traces  -> OTLP/gRPC (otlptracegrpc) when Config.Endpoint is set, otherwise a noop tracer
//   - metrics -> always served at /metrics through the OTel Prometheus exporter reader on the
//     Telemetry.Registry (which also carries the client_golang Go/process collectors and the
//     hand-rolled RED histograms); additionally pushed over OTLP/gRPC when Endpoint is set
//   - logs    -> JSON (or text in dev) on stderr via slog; mirrored to OTLP/gRPC when Endpoint is set
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/alphabravocompany/constellation/internal/logging"
	"github.com/alphabravocompany/constellation/pkg/version"
)

// Config is the telemetry configuration. It is populated by the composition root.
type Config struct {
	ServiceName    string
	ServiceVersion string
	// Environment is attached as deployment.environment; defaults to "development".
	Environment string
	// Endpoint is the OTLP/gRPC collector address (host:port, or a URL). Empty disables
	// every OTLP exporter; Prometheus /metrics stays live regardless.
	Endpoint string
	// Insecure disables TLS on the OTLP connection (dev compose stack).
	Insecure bool
	// MetricsOTLP additionally pushes metrics over OTLP (OTEL_METRICS_EXPORTER=otlp). Off by
	// default: Prometheus scrapes /metrics, and a trace-only collector such as Tempo rejects
	// the metrics service.
	MetricsOTLP bool
	// LogsOTLP mirrors log records over OTLP (OTEL_LOGS_EXPORTER=otlp). Off by default: logs
	// go to stderr as JSON for the sidecar/collector path.
	LogsOTLP bool
	// SampleRate in [0,1]; 1 samples everything. Zero means "use the default of 1".
	SampleRate float64
	// LogLevel defaults to Info (Debug when DevMode).
	LogLevel slog.Level
	// LogFormat is "json" (default) or "text".
	LogFormat string
	// DevMode flips the logging defaults (debug level, text format).
	DevMode bool
}

// ConfigFromEnv builds a Config from the conventional environment variables. It is the only
// place in the package that touches the environment and exists for the cmd/ composition roots.
//
//	OTEL_SERVICE_NAME               overrides serviceName
//	OTEL_EXPORTER_OTLP_ENDPOINT     OTLP/gRPC endpoint; empty = no OTLP export
//	OTEL_EXPORTER_OTLP_INSECURE     "true" disables TLS
//	OTEL_TRACES_SAMPLER_ARG         sample ratio
//	OTEL_METRICS_EXPORTER           "otlp" also pushes metrics over OTLP (default: prometheus only)
//	OTEL_LOGS_EXPORTER              "otlp" mirrors logs over OTLP (default: stderr only)
//	CONSTELLATION_PROMETHEUS_ONLY   "true" forces Endpoint empty
//	CONSTELLATION_ENVIRONMENT       deployment environment (default development)
//	CONSTELLATION_LOG_LEVEL         debug|info|warn|error
//	CONSTELLATION_LOG_FORMAT        json|text
//	CONSTELLATION_DEV_MODE          "true" -> debug level + text logs unless overridden
func ConfigFromEnv(serviceName string) Config {
	cfg := Config{
		ServiceName:    serviceName,
		ServiceVersion: version.Version,
		Environment:    envOr("CONSTELLATION_ENVIRONMENT", "development"),
		Endpoint:       strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")),
		Insecure:       isTrue(os.Getenv("OTEL_EXPORTER_OTLP_INSECURE")),
		MetricsOTLP:    strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_METRICS_EXPORTER")), "otlp"),
		LogsOTLP:       strings.EqualFold(strings.TrimSpace(os.Getenv("OTEL_LOGS_EXPORTER")), "otlp"),
		LogFormat:      strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_LOG_FORMAT"))),
		DevMode:        isTrue(os.Getenv("CONSTELLATION_DEV_MODE")),
	}
	if v := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")); v != "" {
		cfg.ServiceName = v
	}
	if isTrue(os.Getenv("CONSTELLATION_PROMETHEUS_ONLY")) {
		cfg.Endpoint = ""
	}
	if v, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")), 64); err == nil {
		cfg.SampleRate = v
	}
	cfg.LogLevel = parseLevel(os.Getenv("CONSTELLATION_LOG_LEVEL"), cfg.DevMode)
	return cfg
}

// AdminAddrFromEnv returns ADMIN_LISTEN_ADDR or the conventional default ":9090". It lives
// next to ConfigFromEnv so every environment lookup stays in one place.
func AdminAddrFromEnv() string { return envOr("ADMIN_LISTEN_ADDR", ":9090") }

// Telemetry is the handle returned by Init. Callers must call Shutdown before process exit.
type Telemetry struct {
	ServiceName string
	// Logger is the slog facade (bridged onto Log) for code that still speaks log/slog.
	Logger *slog.Logger
	// Log is the zerolog logger; new and migrated code logs through it (logging.Ctx).
	Log      zerolog.Logger
	Registry *prometheus.Registry

	// RED signals for the HTTP surface (bounded cardinality: chi route pattern, method, status).
	HTTPDuration  *prometheus.HistogramVec
	Requests      *prometheus.CounterVec
	RequestErrors *prometheus.CounterVec
	GRPCDuration  *prometheus.HistogramVec
	// AdmissionDecisions counts admission-control verdicts by result and rule id.
	AdmissionDecisions *prometheus.CounterVec

	Tracer     trace.Tracer
	LoggerOTel otellog.Logger // nil when no OTLP endpoint is configured

	otelHTTPHist   metric.Float64Histogram
	otelReqCounter metric.Int64Counter
	shutdowns      []func(context.Context) error

	dbTracerOnce sync.Once
	dbTracer     *DBQueryTracer
}

// Init wires the SDK. When metric initialisation fails after the tracer provider was created,
// the tracer provider is shut down again so no half-initialised provider leaks.
func Init(ctx context.Context, cfg Config) (*Telemetry, error) {
	if cfg.ServiceName == "" {
		return nil, errors.New("telemetry: ServiceName is required")
	}
	if cfg.ServiceVersion == "" {
		cfg.ServiceVersion = version.Version
	}
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	if cfg.SampleRate <= 0 || cfg.SampleRate > 1 {
		cfg.SampleRate = 1
	}

	zl := newLogger(cfg)
	logger := logging.NewSlogLogger(zl)
	// Code that still reaches for slog.Default() emits through the same zerolog logger.
	slog.SetDefault(logger)
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	t := &Telemetry{
		ServiceName: cfg.ServiceName,
		Logger:      logger,
		Log:         zl,
		Registry:    reg,
		HTTPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "constellation_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds.",
			Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		}, []string{"method", "route", "status"}),
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "requests_total",
			Help: "HTTP requests by chi route pattern, method and status class.",
		}, []string{"route", "method", "status_class"}),
		RequestErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "request_errors_total",
			Help: "HTTP requests that ended in a 4xx/5xx, by route and bounded reason.",
		}, []string{"route", "reason"}),
		GRPCDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "constellation_grpc_server_duration_seconds",
			Help:    "gRPC server handler duration in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"service", "method", "code"}),
		AdmissionDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "admission_decisions_total",
			Help: "Admission control decisions by result and rule.",
		}, []string{"result", "rule"}),
		Tracer: noop.NewTracerProvider().Tracer(cfg.ServiceName),
	}
	reg.MustRegister(t.HTTPDuration, t.Requests, t.RequestErrors, t.GRPCDuration, t.AdmissionDecisions)

	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "service_build_info",
		Help: "Build identity of the running binary; always 1.",
	}, []string{"service", "version", "commit", "build_time", "go_version"})
	reg.MustRegister(buildInfo)
	buildInfo.WithLabelValues(cfg.ServiceName, cfg.ServiceVersion, version.Commit, version.BuildTime, runtime.Version()).Set(1)

	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))

	res, err := resource.New(ctx, resource.WithAttributes(
		semconv.ServiceName(cfg.ServiceName),
		semconv.ServiceVersion(cfg.ServiceVersion),
		semconv.DeploymentEnvironmentName(cfg.Environment),
	))
	if err != nil {
		return nil, fmt.Errorf("telemetry: resource: %w", err)
	}

	// Metrics: the Prometheus exporter is always a reader so /metrics carries OTel-recorded
	// instruments too; OTLP push is added only when an endpoint is configured.
	promReader, err := otelprom.New(otelprom.WithRegisterer(reg), otelprom.WithoutScopeInfo())
	if err != nil {
		return nil, fmt.Errorf("telemetry: prometheus exporter: %w", err)
	}
	meterOpts := []sdkmetric.Option{sdkmetric.WithReader(promReader), sdkmetric.WithResource(res)}

	if cfg.Endpoint == "" {
		logger.Info("telemetry: prometheus-only mode (no OTLP endpoint configured)")
		mp := sdkmetric.NewMeterProvider(meterOpts...)
		otel.SetMeterProvider(mp)
		t.shutdowns = append(t.shutdowns, mp.Shutdown)
		t.instruments(mp.Meter(cfg.ServiceName))
		return t, nil
	}

	if err := t.wireOTLP(ctx, cfg, res, meterOpts); err != nil {
		return nil, err
	}
	logger.Info("telemetry: OTLP/gRPC exporters wired",
		slog.String("endpoint", cfg.Endpoint), slog.Bool("insecure", cfg.Insecure), slog.Float64("sample_rate", cfg.SampleRate),
		slog.Bool("metrics_otlp", cfg.MetricsOTLP), slog.Bool("logs_otlp", cfg.LogsOTLP))
	return t, nil
}

// wireOTLP installs the OTLP/gRPC trace exporter (always, once an endpoint is
// configured) and the opt-in metric and log exporters. On failure every
// provider created so far is shut down so nothing half-initialised leaks.
func (t *Telemetry) wireOTLP(ctx context.Context, cfg Config, res *resource.Resource, meterOpts []sdkmetric.Option) error {
	traceExp, err := otlptracegrpc.New(ctx, grpcTraceOpts(cfg)...)
	if err != nil {
		return fmt.Errorf("telemetry: trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp, sdktrace.WithBatchTimeout(2*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(cfg.SampleRate))),
	)
	otel.SetTracerProvider(tp)
	t.Tracer = tp.Tracer(cfg.ServiceName)
	t.shutdowns = append(t.shutdowns, tp.Shutdown)

	if cfg.MetricsOTLP {
		metricExp, err := otlpmetricgrpc.New(ctx, grpcMetricOpts(cfg)...)
		if err != nil {
			_ = tp.Shutdown(ctx)
			return fmt.Errorf("telemetry: metric exporter: %w", err)
		}
		meterOpts = append(meterOpts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp, sdkmetric.WithInterval(15*time.Second))))
	}
	mp := sdkmetric.NewMeterProvider(meterOpts...)
	otel.SetMeterProvider(mp)
	t.shutdowns = append(t.shutdowns, mp.Shutdown)
	t.instruments(mp.Meter(cfg.ServiceName))

	if cfg.LogsOTLP {
		logExp, err := otlploggrpc.New(ctx, grpcLogOpts(cfg)...)
		if err != nil {
			_ = mp.Shutdown(ctx)
			_ = tp.Shutdown(ctx)
			return fmt.Errorf("telemetry: log exporter: %w", err)
		}
		lp := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)), sdklog.WithResource(res))
		otel.SetLoggerProvider(lp)
		t.LoggerOTel = lp.Logger(cfg.ServiceName)
		t.shutdowns = append(t.shutdowns, lp.Shutdown)
	}

	return nil
}

func (t *Telemetry) instruments(m metric.Meter) {
	if hist, err := m.Float64Histogram("http.server.duration", metric.WithUnit("s"),
		metric.WithDescription("HTTP server request duration in seconds")); err == nil {
		t.otelHTTPHist = hist
	}
	if counter, err := m.Int64Counter("http.server.request_count",
		metric.WithDescription("Total HTTP requests served")); err == nil {
		t.otelReqCounter = counter
	}
}

// Shutdown drains exporters with the provided context's deadline. Shutdown order is the
// reverse of initialisation.
func (t *Telemetry) Shutdown(ctx context.Context) error {
	var combined error
	for i := len(t.shutdowns) - 1; i >= 0; i-- {
		if err := t.shutdowns[i](ctx); err != nil {
			combined = errors.Join(combined, err)
		}
	}
	return combined
}

// MetricsHandler returns the Prometheus /metrics handler bound to this Telemetry's registry.
func (t *Telemetry) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(t.Registry, promhttp.HandlerOpts{Registry: t.Registry})
}

// RecordAdmissionDecision increments admission_decisions_total. Nil-safe.
func (t *Telemetry) RecordAdmissionDecision(result, rule string) {
	if t == nil || t.AdmissionDecisions == nil {
		return
	}
	t.AdmissionDecisions.WithLabelValues(result, rule).Inc()
}

// HTTPTransport wraps base (nil = http.DefaultTransport) with otelhttp so every outbound
// request carries the trace context and produces a client span.
func HTTPTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

// HTTPClient returns an http.Client with the given timeout whose transport is instrumented.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: HTTPTransport(nil)}
}

// HTTPMiddleware starts a server span per request and records the RED metrics. The route label
// is the chi route pattern resolved AFTER the handler ran (chi only knows the pattern once routing
// finished), so label cardinality stays bounded to the registered routes instead of raw paths.
func (t *Telemetry) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := t.Tracer.Start(ctx, r.Method+" "+preRouteName(r), trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()

		start := time.Now()
		ww := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		r = r.WithContext(ctx)
		next.ServeHTTP(ww, r)

		route := routeOf(r)
		span.SetName(r.Method + " " + route)
		span.SetAttributes(
			attribute.String("http.request.method", r.Method),
			attribute.String("http.route", route),
			attribute.Int("http.response.status_code", ww.status),
		)
		dur := time.Since(start).Seconds()
		status := strconv.Itoa(ww.status)
		class := statusClass(ww.status)
		t.HTTPDuration.WithLabelValues(r.Method, route, status).Observe(dur)
		t.Requests.WithLabelValues(route, r.Method, class).Inc()
		if ww.status >= 400 {
			t.RequestErrors.WithLabelValues(route, errorReason(ww.status)).Inc()
		}
		if t.otelHTTPHist != nil {
			t.otelHTTPHist.Record(ctx, dur, metric.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", ww.status),
			))
		}
		if t.otelReqCounter != nil {
			t.otelReqCounter.Add(ctx, 1, metric.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("http.response.status_class", class),
			))
		}
		if t.LoggerOTel != nil {
			rec := otellog.Record{}
			rec.SetSeverity(otellog.SeverityInfo)
			rec.SetBody(attribute.StringValue(fmt.Sprintf("%s %s -> %d (%.3fs)", r.Method, route, ww.status, dur)))
			rec.SetTimestamp(time.Now())
			t.LoggerOTel.Emit(ctx, rec)
		}
	})
}

// StatusOf returns the status code a wrapped ResponseWriter recorded, for access-log middleware
// installed outside HTTPMiddleware. Returns 0 when w is not a telemetry recorder.
func StatusOf(w http.ResponseWriter) int {
	if sr, ok := w.(*statusRecorder); ok {
		return sr.status
	}
	return 0
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wroteHeader = true
	return s.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer (Flush/Hijack).
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func statusClass(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	case code >= 300:
		return "3xx"
	default:
		return "2xx"
	}
}

func errorReason(code int) string {
	switch code {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return "validation"
	case http.StatusUnauthorized:
		return "unauthenticated"
	case http.StatusForbidden:
		return "permission_denied"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return "timeout"
	case http.StatusBadGateway, http.StatusServiceUnavailable:
		return "upstream_unavailable"
	default:
		if code >= 500 {
			return "internal"
		}
		return "client_error"
	}
}

type routePatternKey struct{}

// routeOf resolves the chi route pattern after routing; falls back to an explicitly set pattern
// (SetRoutePattern) and finally to a constant so raw paths never become label values.
func routeOf(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	if v, ok := r.Context().Value(routePatternKey{}).(string); ok && v != "" {
		return v
	}
	return "unmatched"
}

func preRouteName(r *http.Request) string {
	if v, ok := r.Context().Value(routePatternKey{}).(string); ok && v != "" {
		return v
	}
	return "request"
}

// SetRoutePattern publishes a route pattern for handlers served outside a chi router
// (plain http.ServeMux admin endpoints, tests).
func SetRoutePattern(r *http.Request, pattern string) *http.Request {
	if pattern == "" {
		return r
	}
	return r.WithContext(context.WithValue(r.Context(), routePatternKey{}, pattern))
}

func grpcTraceOpts(cfg Config) []otlptracegrpc.Option {
	opts := []otlptracegrpc.Option{endpointTraceOpt(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	return opts
}

func grpcMetricOpts(cfg Config) []otlpmetricgrpc.Option {
	opts := []otlpmetricgrpc.Option{endpointMetricOpt(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	return opts
}

func grpcLogOpts(cfg Config) []otlploggrpc.Option {
	opts := []otlploggrpc.Option{endpointLogOpt(cfg.Endpoint)}
	if cfg.Insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}
	return opts
}

func endpointTraceOpt(ep string) otlptracegrpc.Option {
	if strings.Contains(ep, "://") {
		return otlptracegrpc.WithEndpointURL(ep)
	}
	return otlptracegrpc.WithEndpoint(ep)
}

func endpointMetricOpt(ep string) otlpmetricgrpc.Option {
	if strings.Contains(ep, "://") {
		return otlpmetricgrpc.WithEndpointURL(ep)
	}
	return otlpmetricgrpc.WithEndpoint(ep)
}

func endpointLogOpt(ep string) otlploggrpc.Option {
	if strings.Contains(ep, "://") {
		return otlploggrpc.WithEndpointURL(ep)
	}
	return otlploggrpc.WithEndpoint(ep)
}

func newLogger(cfg Config) zerolog.Logger {
	format := cfg.LogFormat
	if format == "" && cfg.DevMode {
		format = "text"
	}
	// Guide ch.05: zerolog is the logger; the slog bridge keeps every existing
	// slog call site emitting through it (one JSON object per line, correlation
	// and trace ids stamped from the context).
	return logging.New(logging.Config{Level: cfg.LogLevel.String(), Format: format, Service: cfg.ServiceName})
}

func parseLevel(raw string, dev bool) slog.Level {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	if dev {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "y", "yes", "on":
		return true
	}
	return false
}
