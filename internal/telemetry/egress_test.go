package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestEgressManifestLogsOneLine(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	e := NewEgress().Add("otlp", "tempo:4317").Add("nvd", "").AddIf(false, "kev", "https://kev").AddIf(true, "trivy_db", "ghcr.io/aquasecurity/trivy-db")
	e.Log(logger)
	line := strings.TrimSpace(buf.String())
	if strings.Count(line, "\n") != 0 || !strings.Contains(line, `"msg":"egress endpoints"`) || !strings.Contains(line, `"count":2`) || strings.Contains(line, "kev") {
		t.Fatalf("line: %s", line)
	}
	if got := e.Endpoints(); len(got) != 2 || got[0] != "otlp=tempo:4317" {
		t.Fatalf("endpoints: %v", got)
	}
	buf.Reset()
	NewEgress().Log(logger)
	if !strings.Contains(buf.String(), `"air_gapped":true`) {
		t.Fatalf("empty manifest must say air_gapped: %s", buf.String())
	}
}
