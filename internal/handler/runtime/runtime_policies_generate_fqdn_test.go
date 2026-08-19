package runtime

import (
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// TestFlowFromRow_FqdnEgressToFQDNs is the F1 read-path proof: a network_flows
// row for an egress edge to an external peer that carries an observed DNS name
// must flow through flowFromRow (the per-row mapper used by
// fetchFlowsForGeneration) onto netpolicy.Flow.Fqdn, and GenerateCilium must
// then emit a toFQDNs matchName rule for that exact name.
//
// It also pins the two adversarial invariants from F1: Fqdn is NEVER set on an
// in-cluster ("cluster/<ip>") destination, and NEVER on an ingress edge (where
// the external side is the SOURCE).
func TestFlowFromRow_FqdnEgressToFQDNs(t *testing.T) {
	const target = "default/api"
	const targetNS = "default"

	t.Run("egress to external collapses but keeps fqdn -> toFQDNs matchName", func(t *testing.T) {
		// dst="external" mirrors the ingest collapse of "external/<ip>".
		f := flowFromRow(target, "external", "", "93.184.216.34", "tcp", "http",
			"api.github.com", "2026-06-30T00:00:00Z", 443)
		if f.Fqdn != "api.github.com" {
			t.Fatalf("Fqdn = %q, want api.github.com", f.Fqdn)
		}

		yaml := netpolicy.GenerateCilium(target, targetNS, nil, []netpolicy.Flow{f})
		if !strings.Contains(yaml, "toFQDNs") {
			t.Fatalf("generated policy has no toFQDNs rule:\n%s", yaml)
		}
		if !strings.Contains(yaml, "matchName: api.github.com") {
			t.Fatalf("generated policy missing matchName for the FQDN:\n%s", yaml)
		}
	})

	t.Run("uncollapsed external/<ip> dst also anchors fqdn", func(t *testing.T) {
		f := flowFromRow(target, "external/93.184.216.34", "", "93.184.216.34",
			"tcp", "", "api.github.com", "2026-06-30T00:00:00Z", 443)
		if f.Fqdn != "api.github.com" {
			t.Fatalf("Fqdn = %q, want api.github.com", f.Fqdn)
		}
	})

	t.Run("in-cluster destination never gets fqdn", func(t *testing.T) {
		// A "cluster/<ip>" peer is in-cluster; even if a stray fqdn value is
		// present it must not anchor an egress allow rule.
		f := flowFromRow(target, "cluster/10.43.0.10", "", "10.43.0.10", "tcp", "",
			"should-not-appear.svc", "2026-06-30T00:00:00Z", 8080)
		if f.Fqdn != "" {
			t.Fatalf("Fqdn = %q, want empty for in-cluster dst", f.Fqdn)
		}
	})

	t.Run("ingress edge (external is source) never gets fqdn", func(t *testing.T) {
		// Here our workload is the DESTINATION and the external side is the
		// SOURCE: this is ingress, and fqdn (a destination-side property) must
		// not be set on our in-cluster dst.
		f := flowFromRow("external/93.184.216.34", target, "93.184.216.34", "",
			"tcp", "", "api.github.com", "2026-06-30T00:00:00Z", 443)
		if f.Fqdn != "" {
			t.Fatalf("Fqdn = %q, want empty for ingress edge", f.Fqdn)
		}
	})
}
