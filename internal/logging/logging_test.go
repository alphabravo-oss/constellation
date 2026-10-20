package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func parse(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("not one JSON object: %q: %v", line, err)
	}
	return m
}

func TestNewWithWriterJSONLevelAndService(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewWithWriter(&buf, Config{Level: "warn", Service: "svc"})
	l.Info().Msg("hidden")
	l.Warn().Str("k", "v").Msg("shown")
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d: %q", len(lines), buf.String())
	}
	m := parse(t, lines[0])
	if m["level"] != "warn" || m["service"] != "svc" || m["k"] != "v" || m["message"] != "shown" {
		t.Fatalf("unexpected line: %v", m)
	}
}

func TestNewWithWriterConsoleFormat(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	l := NewWithWriter(&buf, Config{Format: "text"})
	l.Info().Msg("hello")
	if strings.HasPrefix(strings.TrimSpace(buf.String()), "{") || !strings.Contains(buf.String(), "hello") {
		t.Fatalf("console writer expected: %q", buf.String())
	}
}

func TestCorrelationIDRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := WithCorrelationID(context.Background(), "abc")
	if CorrelationID(ctx) != "abc" || CorrelationID(context.Background()) != "" {
		t.Fatal("correlation id round trip")
	}
	var buf bytes.Buffer
	l := Ctx(ctx, NewWithWriter(&buf, Config{}))
	l.Info().Msg("x")
	if m := parse(t, strings.TrimSpace(buf.String())); m["correlation_id"] != "abc" {
		t.Fatalf("Ctx did not stamp correlation_id: %v", m)
	}
}

func TestSlogBridgeEmitsZerologLines(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	base := NewWithWriter(&buf, Config{Level: "debug", Service: "api"})
	sl := NewSlogLogger(base).With(slog.String("bound", "yes")).WithGroup("req")
	ctx := WithCorrelationID(context.Background(), "corr-1")
	sl.InfoContext(ctx, "http",
		slog.String("method", "GET"), slog.Int("status", 200), slog.Duration("dur", 1500*time.Millisecond),
		slog.Any("err", errors.New("boom")), slog.Group("g", slog.Bool("ok", true)))
	m := parse(t, strings.TrimSpace(buf.String()))
	want := map[string]any{"level": "info", "service": "api", "bound": "yes", "message": "http",
		"correlation_id": "corr-1", "req.method": "GET", "req.err": "boom", "req.g.ok": true}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s = %v, want %v (line %v)", k, m[k], v, m)
		}
	}
	if m["req.status"] != float64(200) || m["req.dur"] != float64(1500) {
		t.Fatalf("numeric fields: %v", m)
	}
	buf.Reset()
	sl.Debug("dbg")
	if !strings.Contains(buf.String(), `"level":"debug"`) {
		t.Fatalf("debug level not honoured: %q", buf.String())
	}
	quiet := NewSlogLogger(NewWithWriter(&buf, Config{Level: "error"}))
	if quiet.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("Enabled must follow the zerolog level")
	}
}
