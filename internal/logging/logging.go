// Package logging is the thin zerolog wrapper the guide prescribes (ch.05):
// one JSON object per line on stderr, a console writer for dev, correlation
// IDs carried on the context, and an slog.Handler bridge so the code that
// still speaks log/slog emits through the same zerolog logger unchanged.
package logging

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

// Config selects level and format. Zero values mean info + json.
type Config struct {
	// Level is debug|info|warn|error (zerolog.ParseLevel); empty = info.
	Level string
	// Format is "json" (default) or "text"/"console" (zerolog.ConsoleWriter).
	Format string
	// Service is stamped on every line as service=<name>.
	Service string
}

// New returns a logger writing to stderr.
func New(cfg Config) zerolog.Logger { return NewWithWriter(os.Stderr, cfg) }

// NewWithWriter returns a logger writing to w (tests, files).
func NewWithWriter(w io.Writer, cfg Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(strings.ToLower(strings.TrimSpace(cfg.Level)))
	if err != nil || level == zerolog.NoLevel {
		level = zerolog.InfoLevel
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "text", "console":
		w = zerolog.ConsoleWriter{Out: w, TimeFormat: time.Kitchen}
	}
	ctx := zerolog.New(w).Level(level).With().Timestamp()
	if cfg.Service != "" {
		ctx = ctx.Str("service", cfg.Service)
	}
	return ctx.Logger()
}

type correlationKey struct{}

// WithCorrelationID stores the request correlation identifier on ctx.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationKey{}, id)
}

// CorrelationID returns the identifier stored by WithCorrelationID, or "".
func CorrelationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

// Ctx returns base enriched with the request's correlation_id and, when a span
// is active, trace_id/span_id, so every line written during a request can be
// joined to its summary line and its trace.
func Ctx(ctx context.Context, base zerolog.Logger) zerolog.Logger {
	c := base.With()
	if id := CorrelationID(ctx); id != "" {
		c = c.Str("correlation_id", id)
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		c = c.Str("trace_id", sc.TraceID().String()).Str("span_id", sc.SpanID().String())
	}
	return c.Logger()
}
