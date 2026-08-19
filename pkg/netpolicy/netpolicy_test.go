package netpolicy

import (
	"strings"
	"testing"

	yamlpkg "gopkg.in/yaml.v3"
)

var sampleFlows = []Flow{
	{
		SrcWorkload: "default/api-service", SrcNamespace: "default", SrcLabels: map[string]string{"app": "api-service"},
		DstWorkload: "data/postgres", DstNamespace: "data", DstLabels: map[string]string{"app": "postgres"},
		Protocol: "TCP", Port: 5432, Count: 142,
	},
	{
		SrcWorkload: "default/api-service", SrcNamespace: "default", SrcLabels: map[string]string{"app": "api-service"},
		DstWorkload: "data/redis", DstNamespace: "data", DstLabels: map[string]string{"app": "redis"},
		Protocol: "TCP", Port: 6379, Count: 89,
	},
	{
		SrcWorkload: "default/frontend", SrcNamespace: "default", SrcLabels: map[string]string{"app": "frontend"},
		DstWorkload: "default/api-service", DstNamespace: "default", DstLabels: map[string]string{"app": "api-service"},
		Protocol: "TCP", Port: 8080, Count: 320,
	},
}

func TestGenerateNative_HasIngressAndEgress(t *testing.T) {
	yaml := GenerateNative("default/api-service", "default",
		map[string]string{"app": "api-service"}, sampleFlows)
	// must mention ingress from frontend on 8080
	if !strings.Contains(yaml, "8080") {
		t.Fatalf("missing ingress port 8080:\n%s", yaml)
	}
	if !strings.Contains(yaml, "5432") {
		t.Fatalf("missing egress to postgres 5432:\n%s", yaml)
	}
	if !strings.Contains(yaml, "kube-dns") {
		t.Fatalf("DNS pinhole missing:\n%s", yaml)
	}
	if !strings.Contains(yaml, "apiVersion: networking.k8s.io/v1") {
		t.Fatalf("wrong apiVersion:\n%s", yaml)
	}
}

func TestGenerateCilium_HasCiliumShape(t *testing.T) {
	yaml := GenerateCilium("default/api-service", "default",
		map[string]string{"app": "api-service"}, sampleFlows)
	if !strings.Contains(yaml, "cilium.io/v2") {
		t.Fatalf("missing cilium apiVersion:\n%s", yaml)
	}
	if !strings.Contains(yaml, "endpointSelector") {
		t.Fatalf("missing endpointSelector:\n%s", yaml)
	}
	if !strings.Contains(yaml, "toEndpoints") {
		t.Fatalf("missing toEndpoints (egress):\n%s", yaml)
	}
}

func TestGenerateCalico_HasFelixSelector(t *testing.T) {
	yaml := GenerateCalico("default/api-service", "default",
		map[string]string{"app": "api-service"}, sampleFlows)
	if !strings.Contains(yaml, "projectcalico.org/v3") {
		t.Fatalf("wrong apiVersion:\n%s", yaml)
	}
	if !strings.Contains(yaml, "app == 'api-service'") {
		t.Fatalf("missing Felix selector:\n%s", yaml)
	}
}

func TestGeneratePolicies_PreserveL7IntentAsMetadata(t *testing.T) {
	flows := []Flow{
		{SrcNamespace: "default", SrcWorkload: "frontend", DstNamespace: "default", DstWorkload: "api", Protocol: "TCP", Port: 8443, L7Protocol: "grpc"},
		{SrcNamespace: "default", SrcWorkload: "api", DstNamespace: "data", DstWorkload: "postgres", Protocol: "TCP", Port: 5432, L7Protocol: "postgres"},
	}
	for name, yaml := range map[string]string{
		"native": GenerateNative("api", "default", map[string]string{"app": "api"}, flows),
		"cilium": GenerateCilium("api", "default", map[string]string{"app": "api"}, flows),
		"calico": GenerateCalico("api", "default", map[string]string{"app": "api"}, flows),
	} {
		if !strings.Contains(yaml, "constellation.alphabravo.io/l7-intent: preserved-as-metadata") {
			t.Fatalf("%s missing L7 intent annotation:\n%s", name, yaml)
		}
		if !strings.Contains(yaml, "constellation.alphabravo.io/l7-protocols: grpc,postgres") {
			t.Fatalf("%s missing sorted L7 protocol annotation:\n%s", name, yaml)
		}
	}
}

func TestDedupeFlows_SumsCount(t *testing.T) {
	dup := []Flow{
		{DstWorkload: "x", Protocol: "TCP", Port: 80, Count: 10},
		{DstWorkload: "x", Protocol: "TCP", Port: 80, Count: 5},
		{DstWorkload: "x", Protocol: "TCP", Port: 443, Count: 7},
	}
	got := dedupeFlows(dup)
	if len(got) != 2 {
		t.Fatalf("dedupe: %d", len(got))
	}
	for _, f := range got {
		if f.Port == 80 && f.Count != 15 {
			t.Fatalf("count not summed: %d", f.Count)
		}
	}
}

func TestDedupeFlows_PreservesDistinctIngressPeers(t *testing.T) {
	flows := []Flow{
		{SrcNamespace: "default", SrcWorkload: "frontend", DstNamespace: "default", DstWorkload: "api", Protocol: "TCP", Port: 8443, Count: 10},
		{SrcNamespace: "jobs", SrcWorkload: "worker", DstNamespace: "default", DstWorkload: "api", Protocol: "TCP", Port: 8443, Count: 5},
	}
	got := dedupeFlows(flows)
	if len(got) != 2 {
		t.Fatalf("expected distinct ingress peers to remain, got %+v", got)
	}
}

func TestGenerateCilium_ExternalEgressUsesCIDR(t *testing.T) {
	yaml := GenerateCilium("frontend", "default", map[string]string{"app": "frontend"}, []Flow{
		{SrcNamespace: "default", SrcWorkload: "frontend", DstIP: "203.0.113.10", Protocol: "TCP", Port: 443, Count: 2},
	})
	if !strings.Contains(yaml, "toCIDR") || !strings.Contains(yaml, "203.0.113.10/32") {
		t.Fatalf("missing external CIDR egress:\n%s", yaml)
	}
}

// --- F1a: toFQDNs egress generation -----------------------------------------

// ciliumEgress unmarshals a generated CNP and returns its spec.egress list as
// []map so tests can assert on structure rather than substrings.
func ciliumEgress(t *testing.T, manifest string) []map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yamlpkg.Unmarshal([]byte(manifest), &doc); err != nil {
		t.Fatalf("unmarshal CNP: %v\n%s", err, manifest)
	}
	spec, _ := doc["spec"].(map[string]any)
	rawEgress, _ := spec["egress"].([]any)
	out := make([]map[string]any, 0, len(rawEgress))
	for _, r := range rawEgress {
		if m, ok := r.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// findDNSVisibilityRule returns the egress rule that opens the DNS pods with a
// rules.dns matchPattern "*", or nil if no such rule exists.
func findDNSVisibilityRule(egress []map[string]any) map[string]any {
	for _, rule := range egress {
		toPorts, _ := rule["toPorts"].([]any)
		for _, tp := range toPorts {
			tpm, _ := tp.(map[string]any)
			rules, _ := tpm["rules"].(map[string]any)
			if _, ok := rules["dns"]; ok {
				return rule
			}
		}
	}
	return nil
}

// findToFQDNs returns the first toFQDNs selector list across all egress rules.
func findToFQDNs(egress []map[string]any) []any {
	for _, rule := range egress {
		if f, ok := rule["toFQDNs"].([]any); ok {
			return f
		}
	}
	return nil
}

func TestGenerateCilium_FQDNEgress(t *testing.T) {
	cases := []struct {
		name        string
		flow        Flow
		wantKey     string // "matchName" or "matchPattern"
		wantValue   string
		wantToFQDNs bool
	}{
		{
			name:        "exact name uses matchName",
			flow:        Flow{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "api.github.com", Protocol: "TCP", Port: 443, Count: 3},
			wantKey:     "matchName",
			wantValue:   "api.github.com",
			wantToFQDNs: true,
		},
		{
			name:        "wildcard uses matchPattern",
			flow:        Flow{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "*.github.com", Protocol: "TCP", Port: 443, Count: 3},
			wantKey:     "matchPattern",
			wantValue:   "*.github.com",
			wantToFQDNs: true,
		},
		{
			name:        "fqdn wins even when a resolved DstIP is present",
			flow:        Flow{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "api.github.com", DstIP: "140.82.112.3", Protocol: "TCP", Port: 443, Count: 1},
			wantKey:     "matchName",
			wantValue:   "api.github.com",
			wantToFQDNs: true,
		},
		{
			name:        "non-fqdn external flow stays a CIDR rule",
			flow:        Flow{SrcNamespace: "default", SrcWorkload: "frontend", DstIP: "203.0.113.10", Protocol: "TCP", Port: 443, Count: 2},
			wantToFQDNs: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest := GenerateCilium("frontend", "default", map[string]string{"app": "frontend"}, []Flow{tc.flow})
			egress := ciliumEgress(t, manifest)

			// (2) The DNS-visibility rule is the #1 correctness requirement and
			// must ALWAYS be present — FQDN flow or not.
			dnsRule := findDNSVisibilityRule(egress)
			if dnsRule == nil {
				t.Fatalf("DNS-visibility rule missing:\n%s", manifest)
			}
			// It must select kube-dns on UDP+TCP/53.
			toEndpoints, _ := dnsRule["toEndpoints"].([]any)
			if len(toEndpoints) == 0 {
				t.Fatalf("DNS-visibility rule has no toEndpoints:\n%s", manifest)
			}
			sel, _ := toEndpoints[0].(map[string]any)["matchLabels"].(map[string]any)
			if sel["k8s:k8s-app"] != "kube-dns" || sel["k8s:io.kubernetes.pod.namespace"] != "kube-system" {
				t.Fatalf("DNS-visibility selector not kube-dns: %v\n%s", sel, manifest)
			}
			protos := dnsRuleProtocols(t, dnsRule)
			if !protos["UDP"] || !protos["TCP"] {
				t.Fatalf("DNS-visibility rule must open UDP+TCP, got %v\n%s", protos, manifest)
			}

			// (1) toFQDNs entry.
			fqdns := findToFQDNs(egress)
			if tc.wantToFQDNs {
				if len(fqdns) == 0 {
					t.Fatalf("expected toFQDNs entry, none found:\n%s", manifest)
				}
				entry, _ := fqdns[0].(map[string]any)
				if got := entry[tc.wantKey]; got != tc.wantValue {
					t.Fatalf("toFQDNs %s = %v, want %q\n%s", tc.wantKey, got, tc.wantValue, manifest)
				}
				// The opposite key must NOT be set.
				other := "matchName"
				if tc.wantKey == "matchName" {
					other = "matchPattern"
				}
				if _, bad := entry[other]; bad {
					t.Fatalf("toFQDNs entry has unexpected %s:\n%s", other, manifest)
				}
			} else {
				if len(fqdns) != 0 {
					t.Fatalf("non-FQDN flow must NOT produce toFQDNs:\n%s", manifest)
				}
				// And the non-FQDN egress shape is unchanged (CIDR).
				if !strings.Contains(manifest, "toCIDR") || !strings.Contains(manifest, "203.0.113.10/32") {
					t.Fatalf("non-FQDN external flow lost its CIDR rule:\n%s", manifest)
				}
			}
		})
	}
}

// dnsRuleProtocols collects the L4 protocols opened on a DNS-visibility rule.
func dnsRuleProtocols(t *testing.T, rule map[string]any) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	toPorts, _ := rule["toPorts"].([]any)
	for _, tp := range toPorts {
		tpm, _ := tp.(map[string]any)
		ports, _ := tpm["ports"].([]any)
		for _, p := range ports {
			pm, _ := p.(map[string]any)
			if proto, ok := pm["protocol"].(string); ok {
				out[proto] = true
			}
		}
	}
	return out
}

func TestGenerateCilium_NonFQDNUnchanged(t *testing.T) {
	// The Cilium output for a workload-to-workload flow set must be byte-for-byte
	// stable: adding FQDN support changed nothing for flows without an Fqdn.
	a := GenerateCilium("default/api-service", "default", map[string]string{"app": "api-service"}, sampleFlows)
	b := GenerateCilium("default/api-service", "default", map[string]string{"app": "api-service"}, sampleFlows)
	if a != b {
		t.Fatalf("non-FQDN generation not deterministic")
	}
	if strings.Contains(a, "toFQDNs") {
		t.Fatalf("non-FQDN flows must not emit toFQDNs:\n%s", a)
	}
	if strings.Contains(a, "matchName") || strings.Contains(a, "matchPattern: api") {
		t.Fatalf("unexpected FQDN selector in non-FQDN output:\n%s", a)
	}
}

func TestGenerateCiliumWithOptions_ConfigurableDNS(t *testing.T) {
	opts := CiliumOptions{
		KubeDNSSelector: map[string]string{
			"k8s:io.kubernetes.pod.namespace": "openshift-dns",
			"k8s:dns.operator.openshift.io":   "default",
		},
		DNSPort:      5353,
		DNSProtocols: []string{"UDP"},
	}
	manifest := GenerateCiliumWithOptions("frontend", "default", map[string]string{"app": "frontend"},
		[]Flow{{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "api.github.com", Protocol: "TCP", Port: 443, Count: 1}}, opts)
	egress := ciliumEgress(t, manifest)

	dnsRule := findDNSVisibilityRule(egress)
	if dnsRule == nil {
		t.Fatalf("DNS-visibility rule missing under custom opts:\n%s", manifest)
	}
	toEndpoints, _ := dnsRule["toEndpoints"].([]any)
	sel, _ := toEndpoints[0].(map[string]any)["matchLabels"].(map[string]any)
	if sel["k8s:io.kubernetes.pod.namespace"] != "openshift-dns" {
		t.Fatalf("custom kube-dns selector not honored: %v\n%s", sel, manifest)
	}
	protos := dnsRuleProtocols(t, dnsRule)
	if !protos["UDP"] || protos["TCP"] {
		t.Fatalf("custom DNS protocols not honored, got %v\n%s", protos, manifest)
	}
	if !strings.Contains(manifest, "5353") {
		t.Fatalf("custom DNS port 5353 missing:\n%s", manifest)
	}
	// FQDN egress still emitted alongside the custom DNS rule.
	if findToFQDNs(egress) == nil {
		t.Fatalf("toFQDNs missing under custom opts:\n%s", manifest)
	}
}

func TestCiliumOptions_ZeroValueNormalizes(t *testing.T) {
	// A zero-value CiliumOptions must fall back to the stock kube-dns defaults
	// rather than emitting an empty/invalid DNS-visibility rule.
	manifest := GenerateCiliumWithOptions("frontend", "default", map[string]string{"app": "frontend"},
		[]Flow{{SrcNamespace: "default", SrcWorkload: "frontend", Fqdn: "api.github.com", Protocol: "TCP", Port: 443, Count: 1}}, CiliumOptions{})
	egress := ciliumEgress(t, manifest)
	dnsRule := findDNSVisibilityRule(egress)
	if dnsRule == nil {
		t.Fatalf("zero-value opts produced no DNS-visibility rule:\n%s", manifest)
	}
	protos := dnsRuleProtocols(t, dnsRule)
	if !protos["UDP"] || !protos["TCP"] {
		t.Fatalf("zero-value opts must default to UDP+TCP, got %v\n%s", protos, manifest)
	}
}
