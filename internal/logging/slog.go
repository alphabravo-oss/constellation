package logging

import (
	"context"
	"log/slog"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/trace"
)

// SlogHandler bridges log/slog to zerolog: every slog record becomes one
// zerolog event on l, with the record's attrs as fields and, when the context
// carries them, correlation_id / trace_id / span_id. Callers that still use
// slog keep compiling; their output is zerolog's.
func SlogHandler(l zerolog.Logger) slog.Handler {
	return &slogHandler{logger: l}
}

// NewSlogLogger is the convenience constructor the composition roots use.
func NewSlogLogger(l zerolog.Logger) *slog.Logger { return slog.New(SlogHandler(l)) }

type slogHandler struct {
	logger zerolog.Logger
	groups []string
}

func (h *slogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return zerologLevel(level) >= h.logger.GetLevel() && h.logger.GetLevel() != zerolog.Disabled
}

func (h *slogHandler) Handle(ctx context.Context, rec slog.Record) error {
	ev := h.logger.WithLevel(zerologLevel(rec.Level))
	if ev == nil {
		return nil
	}
	if id := CorrelationID(ctx); id != "" {
		ev = ev.Str("correlation_id", id)
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		ev = ev.Str("trace_id", sc.TraceID().String()).Str("span_id", sc.SpanID().String())
	}
	prefix := h.prefix()
	rec.Attrs(func(a slog.Attr) bool {
		addAttr(ev, prefix, a)
		return true
	})
	ev.Msg(rec.Message)
	return nil
}

func (h *slogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := h.logger.With()
	prefix := h.prefix()
	for _, a := range attrs {
		c = withAttr(c, prefix, a)
	}
	return &slogHandler{logger: c.Logger(), groups: h.groups}
}

func (h *slogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	groups := append(append([]string(nil), h.groups...), name)
	return &slogHandler{logger: h.logger, groups: groups}
}

func (h *slogHandler) prefix() string {
	if len(h.groups) == 0 {
		return ""
	}
	return strings.Join(h.groups, ".") + "."
}

func zerologLevel(l slog.Level) zerolog.Level {
	switch {
	case l >= slog.LevelError:
		return zerolog.ErrorLevel
	case l >= slog.LevelWarn:
		return zerolog.WarnLevel
	case l >= slog.LevelInfo:
		return zerolog.InfoLevel
	default:
		return zerolog.DebugLevel
	}
}

// addAttr writes one slog attr onto an event, flattening groups as "a.b".
func addAttr(ev *zerolog.Event, prefix string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	key := prefix + a.Key
	switch a.Value.Kind() {
	case slog.KindGroup:
		p := key + "."
		if a.Key == "" {
			p = prefix
		}
		for _, g := range a.Value.Group() {
			addAttr(ev, p, g)
		}
	case slog.KindString:
		ev.Str(key, a.Value.String())
	case slog.KindInt64:
		ev.Int64(key, a.Value.Int64())
	case slog.KindUint64:
		ev.Uint64(key, a.Value.Uint64())
	case slog.KindFloat64:
		ev.Float64(key, a.Value.Float64())
	case slog.KindBool:
		ev.Bool(key, a.Value.Bool())
	case slog.KindDuration:
		ev.Dur(key, a.Value.Duration())
	case slog.KindTime:
		ev.Time(key, a.Value.Time())
	case slog.KindAny, slog.KindLogValuer:
		if err, ok := a.Value.Any().(error); ok {
			ev.AnErr(key, err)
			return
		}
		ev.Interface(key, a.Value.Any())
	}
}

// withAttr is addAttr for the pre-bound (With) path.
func withAttr(c zerolog.Context, prefix string, a slog.Attr) zerolog.Context {
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return c
	}
	key := prefix + a.Key
	switch a.Value.Kind() {
	case slog.KindGroup:
		p := key + "."
		if a.Key == "" {
			p = prefix
		}
		for _, g := range a.Value.Group() {
			c = withAttr(c, p, g)
		}
		return c
	case slog.KindString:
		return c.Str(key, a.Value.String())
	case slog.KindInt64:
		return c.Int64(key, a.Value.Int64())
	case slog.KindUint64:
		return c.Uint64(key, a.Value.Uint64())
	case slog.KindFloat64:
		return c.Float64(key, a.Value.Float64())
	case slog.KindBool:
		return c.Bool(key, a.Value.Bool())
	case slog.KindDuration:
		return c.Dur(key, a.Value.Duration())
	case slog.KindTime:
		return c.Time(key, a.Value.Time())
	case slog.KindAny, slog.KindLogValuer:
		if err, ok := a.Value.Any().(error); ok {
			return c.AnErr(key, err)
		}
		return c.Interface(key, a.Value.Any())
	}
	return c
}
