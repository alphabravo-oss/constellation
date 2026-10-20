package telemetry

import (
	"log/slog"
	"sort"
	"strings"
)

// Egress is the startup manifest of every out-of-cluster endpoint a binary may
// contact (guide ch.08/09: air-gap first — operators grep one log line for
// the complete list, and an empty list means the process never leaves the
// cluster).
type Egress struct {
	entries map[string]string
}

// NewEgress starts an empty manifest.
func NewEgress() *Egress { return &Egress{entries: map[string]string{}} }

// Add records an endpoint under a purpose; empty endpoints are ignored so
// callers can pass config values unconditionally.
func (e *Egress) Add(purpose, endpoint string) *Egress {
	if ep := strings.TrimSpace(endpoint); ep != "" {
		e.entries[purpose] = ep
	}
	return e
}

// AddIf records endpoint only when enabled is true.
func (e *Egress) AddIf(enabled bool, purpose, endpoint string) *Egress {
	if enabled {
		e.Add(purpose, endpoint)
	}
	return e
}

// Endpoints returns purpose=endpoint pairs, sorted.
func (e *Egress) Endpoints() []string {
	out := make([]string, 0, len(e.entries))
	for k, v := range e.entries {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

// Log emits the single "egress endpoints" line.
func (e *Egress) Log(logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	attrs := []slog.Attr{slog.Int("count", len(e.entries)), slog.Bool("air_gapped", len(e.entries) == 0)}
	for _, k := range sortedKeys(e.entries) {
		attrs = append(attrs, slog.String(k, e.entries[k]))
	}
	logger.LogAttrs(nil, slog.LevelInfo, "egress endpoints", attrs...) //nolint:staticcheck // nil ctx: startup line, no request
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
