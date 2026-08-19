package handler

import (
	"strings"
	"testing"
)

// TestNeuVectorThreatFloodNames asserts the volume-based flood/DoS threat IDs
// (1001 SYN_FLOOD, 1002 ICMP_FLOOD, 1003 IP_SRC_SESSION) resolve to a real
// label instead of the "threat_<id>" fallback, and that each maps into the
// range-derived "ips" category used by the runtime threat pipeline.
func TestNeuVectorThreatFloodNames(t *testing.T) {
	// name -> expected label. Mirrors NeuVector's THRT_ID_* constant suffixes.
	want := map[uint32]string{
		1001: "SYN_FLOOD",
		1002: "ICMP_FLOOD",
		1003: "IP_SRC_SESSION",
	}
	for id, label := range want {
		got := NeuVectorThreatName(id)
		if got != label {
			t.Fatalf("NeuVectorThreatName(%d) = %q, want %q", id, got, label)
		}
		if got == "" || strings.HasPrefix(got, "threat_") {
			t.Fatalf("NeuVectorThreatName(%d) returned empty/fallback name %q", id, got)
		}
		// Category is range-derived: everything below the 20000 DLP floor is
		// the built-in IPS bucket, so 1001-1003 must land there.
		if cat := floodThreatCategory(id); cat != "ips" {
			t.Fatalf("category(%d) = %q, want \"ips\"", id, cat)
		}
	}
}

// floodThreatCategory mirrors the range discriminator in
// internal/handler/runtime.threatCategory (a different package) so this
// self-check can assert both a non-empty name and a category without an
// import cycle.
func floodThreatCategory(id uint32) string {
	switch {
	case id >= 40000 && id < 50000:
		return "waf"
	case id >= 20000 && id < 40000:
		return "dlp"
	default:
		return "ips"
	}
}
