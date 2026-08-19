package netpolicy

import (
	"strings"
	"testing"

	yamlpkg "gopkg.in/yaml.v3"
)

// egressOf unmarshals any generated manifest and returns spec.egress as []map.
func egressOf(t *testing.T, manifest string) []map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yamlpkg.Unmarshal([]byte(manifest), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, manifest)
	}
	spec, _ := doc["spec"].(map[string]any)
	raw, _ := spec["egress"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// A flow whose source is the target but with no FQDN / DstWorkload / DstIP has
// no L3 peer identity. Emitting a toPorts/ports-only rule would allow ALL
// destinations on the port. The generators must drop it (fail closed).
func TestFailClosed_NoPeerIdentity(t *testing.T) {
	flow := Flow{SrcNamespace: "default", SrcWorkload: "frontend", Protocol: "TCP", Port: 9999, Count: 1}

	t.Run("cilium", func(t *testing.T) {
		eg := egressOf(t, GenerateCilium("frontend", "default", nil, []Flow{flow}))
		// Only the DNS-visibility rule should remain.
		if len(eg) != 1 {
			t.Fatalf("expected only DNS-visibility egress, got %d rules: %+v", len(eg), eg)
		}
		for _, r := range eg {
			if _, hasFqdn := r["toFQDNs"]; hasFqdn {
				t.Fatalf("unexpected toFQDNs for no-identity flow: %+v", r)
			}
			if r["toEndpoints"] == nil && r["toCIDR"] == nil && r["toPorts"] != nil {
				// The DNS rule has toEndpoints; a bare toPorts-only rule is the bug.
				if _, dns := dnsRules(r); !dns {
					t.Fatalf("toPorts-only allow-all egress rule leaked: %+v", r)
				}
			}
		}
	})

	t.Run("native", func(t *testing.T) {
		eg := egressOf(t, GenerateNative("frontend", "default", nil, []Flow{flow}))
		for _, r := range eg {
			if r["to"] == nil {
				t.Fatalf("native egress rule with no `to` (allow-all) leaked: %+v", r)
			}
		}
	})

	t.Run("calico", func(t *testing.T) {
		eg := egressOf(t, GenerateCalico("frontend", "default", nil, []Flow{flow}))
		for _, r := range eg {
			dst, _ := r["destination"].(map[string]any)
			if dst["selector"] == nil && dst["nets"] == nil {
				t.Fatalf("calico egress with no selector/nets (allow-all) leaked: %+v", r)
			}
		}
	})
}

// ingressOf unmarshals any generated manifest and returns spec.ingress as []map.
func ingressOf(t *testing.T, manifest string) []map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yamlpkg.Unmarshal([]byte(manifest), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, manifest)
	}
	spec, _ := doc["spec"].(map[string]any)
	raw, _ := spec["ingress"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// Symmetric to TestFailClosed_NoPeerIdentity but for ingress: a flow whose
// destination is the target but with no SrcWorkload has no L3 peer identity.
// Emitting a ports-only ingress rule would allow ALL sources on the port. The
// generators must drop it (fail closed).
func TestFailClosed_NoPeerIdentity_Ingress(t *testing.T) {
	flow := Flow{DstNamespace: "default", DstWorkload: "frontend", Protocol: "TCP", Port: 9999, Count: 1}

	t.Run("cilium", func(t *testing.T) {
		in := ingressOf(t, GenerateCilium("frontend", "default", nil, []Flow{flow}))
		if len(in) != 0 {
			t.Fatalf("toPorts-only allow-all ingress rule leaked: %+v", in)
		}
	})

	t.Run("native", func(t *testing.T) {
		in := ingressOf(t, GenerateNative("frontend", "default", nil, []Flow{flow}))
		for _, r := range in {
			if r["from"] == nil {
				t.Fatalf("native ingress rule with no `from` (allow-all) leaked: %+v", r)
			}
		}
		if len(in) != 0 {
			t.Fatalf("no-identity ingress flow should be dropped, got: %+v", in)
		}
	})

	t.Run("calico", func(t *testing.T) {
		in := ingressOf(t, GenerateCalico("frontend", "default", nil, []Flow{flow}))
		for _, r := range in {
			src, _ := r["source"].(map[string]any)
			if src["selector"] == nil && src["nets"] == nil {
				t.Fatalf("calico ingress with no selector/nets (allow-all) leaked: %+v", r)
			}
		}
		if len(in) != 0 {
			t.Fatalf("no-identity ingress flow should be dropped, got: %+v", in)
		}
	})
}

// dnsRules reports whether a Cilium egress rule is the DNS-visibility rule.
func dnsRules(rule map[string]any) (any, bool) {
	toPorts, _ := rule["toPorts"].([]any)
	for _, tp := range toPorts {
		tpm, _ := tp.(map[string]any)
		if rules, ok := tpm["rules"].(map[string]any); ok {
			if _, ok := rules["dns"]; ok {
				return rules, true
			}
		}
	}
	return nil, false
}

// A bare/over-broad wildcard ("*") would compile to matchPattern "*" and match
// every DNS name — allow-egress-to-any-FQDN. It must be rejected and, lacking
// any other peer identity, the flow dropped.
func TestFailClosed_BareWildcardFqdn(t *testing.T) {
	flow := Flow{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "*", Protocol: "TCP", Port: 443, Count: 1}
	manifest := GenerateCilium("frontend", "default", nil, []Flow{flow})
	// (The DNS-visibility rule legitimately carries dns matchPattern "*"; the
	// bug would be a toFQDNs selector, which must be absent.)
	if strings.Contains(manifest, "toFQDNs") {
		t.Fatalf("bare wildcard must not produce a toFQDNs rule:\n%s", manifest)
	}
	eg := egressOf(t, manifest)
	if len(eg) != 1 { // DNS-visibility only
		t.Fatalf("bare-wildcard flow should be dropped, got %d egress rules:\n%s", len(eg), manifest)
	}
}

// An exact name with surrounding whitespace, mixed case, and a trailing dot
// must normalize to a clean matchName.
func TestFqdn_NormalizationDedup(t *testing.T) {
	flows := []Flow{
		{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "API.GitHub.com.", Protocol: "TCP", Port: 443, Count: 1},
		{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "api.github.com", Protocol: "TCP", Port: 443, Count: 1},
	}
	manifest := GenerateCilium("frontend", "default", nil, flows)
	if !strings.Contains(manifest, "matchName: api.github.com") {
		t.Fatalf("expected normalized matchName api.github.com:\n%s", manifest)
	}
	if n := strings.Count(manifest, "matchName:"); n != 1 {
		t.Fatalf("equivalent names should dedupe to one matchName, got %d:\n%s", n, manifest)
	}
}

// DNS pinholes must open both UDP and TCP/53 (DNS-over-TCP) on the native and
// Calico flavors.
func TestDNSPinhole_UDPAndTCP(t *testing.T) {
	native := GenerateNative("frontend", "default", nil, nil)
	if !strings.Contains(native, "protocol: UDP") || !strings.Contains(native, "protocol: TCP") {
		t.Fatalf("native DNS pinhole must allow UDP and TCP/53:\n%s", native)
	}
	calico := GenerateCalico("frontend", "default", nil, nil)
	if strings.Count(calico, "k8s-app == 'kube-dns'") < 2 {
		t.Fatalf("calico DNS allow must cover UDP and TCP:\n%s", calico)
	}
}
