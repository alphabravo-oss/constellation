package netpolicy

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestBuildDPRules_DefaultDeny_AllowDNS(t *testing.T) {
	rules, def, dir := BuildDPRules("default/api", nil, DefaultBuildDPRulesOptions())
	if def != dp.PolicyActionDeny {
		t.Errorf("def_action = %d want %d (deny)", def, dp.PolicyActionDeny)
	}
	if dir != dp.ApplyDirBoth {
		t.Errorf("apply_dir = %d want %d (both)", dir, dp.ApplyDirBoth)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d want 1 (DNS allow only)", len(rules))
	}
	if rules[0].Ingress || rules[0].IPProto != 17 || rules[0].Port != 53 {
		t.Errorf("DNS allow rule wrong shape: %+v", rules[0])
	}
}

func TestBuildDPRules_DedupAndDirection(t *testing.T) {
	// Three flows, two are dups by (peer, port, protocol). Expect one rule
	// per unique edge plus the DNS allow.
	flows := []Flow{
		{SrcWorkload: "default/api", DstWorkload: "external", DstIP: "1.1.1.1", Port: 443, Protocol: "TCP"},
		{SrcWorkload: "default/api", DstWorkload: "external", DstIP: "1.1.1.1", Port: 443, Protocol: "TCP"},
		{SrcWorkload: "default/api", DstWorkload: "external", DstIP: "1.1.1.1", Port: 80, Protocol: "TCP"},
		// Ingress (api is dst).
		{SrcWorkload: "external", DstWorkload: "default/api", DstIP: "10.0.0.5", Port: 8080, Protocol: "TCP"},
	}
	rules, _, _ := BuildDPRules("default/api", flows, DefaultBuildDPRulesOptions())
	// Expected: 1 DNS + 2 egress (1.1.1.1:80, 1.1.1.1:443) + 1 ingress (8080)
	if len(rules) != 4 {
		t.Fatalf("got %d rules: %+v", len(rules), rules)
	}
	// Confirm ordering: ingress first, then egress by port ascending.
	if !rules[0].Ingress {
		t.Errorf("rules[0] should be ingress (8080): %+v", rules[0])
	}
	if rules[0].Port != 8080 {
		t.Errorf("ingress port = %d want 8080", rules[0].Port)
	}
	// Egress rules: DNS:53, http:80, https:443.
	for i := 1; i < 4; i++ {
		if rules[i].Ingress {
			t.Errorf("rules[%d] should be egress: %+v", i, rules[i])
		}
	}
}

func TestBuildDPRules_DefaultActionToggle(t *testing.T) {
	opts := BuildDPRulesOptions{AllowDNS: false, DefaultDeny: false}
	rules, def, _ := BuildDPRules("default/api", []Flow{
		{SrcWorkload: "default/api", DstWorkload: "external", Port: 443, Protocol: "TCP"},
	}, opts)
	if def != dp.PolicyActionAllow {
		t.Errorf("def_action with DefaultDeny=false: %d want %d", def, dp.PolicyActionAllow)
	}
	if len(rules) != 1 {
		t.Fatalf("rules = %d want 1 (no DNS)", len(rules))
	}
}

func TestBuildDPRules_SkipFlowsNotMatchingTarget(t *testing.T) {
	flows := []Flow{
		{SrcWorkload: "other/wl", DstWorkload: "another/wl", Port: 80, Protocol: "TCP"},
	}
	rules, _, _ := BuildDPRules("default/api", flows, DefaultBuildDPRulesOptions())
	// Only the DNS allow — the flow doesn't touch default/api.
	if len(rules) != 1 || !(rules[0].Port == 53 && rules[0].IPProto == 17) {
		t.Errorf("expected only DNS rule, got %+v", rules)
	}
}

func TestBuildDPRules_FqdnEgressPopulated(t *testing.T) {
	flows := []Flow{
		// Egress to an FQDN — Fqdn must land on the rule, DstIP left empty.
		{SrcWorkload: "default/api", DstWorkload: "external", Fqdn: "api.github.com", Port: 443, Protocol: "TCP"},
		// Wildcard FQDN egress.
		{SrcWorkload: "default/api", DstWorkload: "external", Fqdn: "*.s3.amazonaws.com", Port: 443, Protocol: "TCP"},
		// Same Fqdn+port repeated → deduped.
		{SrcWorkload: "default/api", DstWorkload: "external", Fqdn: "api.github.com", Port: 443, Protocol: "TCP"},
		// Ingress flow carrying a Fqdn → Fqdn must be ignored (egress-only).
		{SrcWorkload: "external", DstWorkload: "default/api", Fqdn: "should.be.ignored", DstIP: "10.0.0.5", Port: 8080, Protocol: "TCP"},
	}
	rules, _, _ := BuildDPRules("default/api", flows, BuildDPRulesOptions{AllowDNS: false, DefaultDeny: true})
	// Expect: 1 ingress (8080, no fqdn) + 2 egress FQDN rules.
	if len(rules) != 3 {
		t.Fatalf("got %d rules: %+v", len(rules), rules)
	}
	var fqdns []string
	for _, r := range rules {
		if r.Ingress {
			if r.Fqdn != "" {
				t.Errorf("ingress rule must not carry Fqdn: %+v", r)
			}
			continue
		}
		if r.Fqdn == "" {
			t.Errorf("egress FQDN rule missing Fqdn: %+v", r)
		}
		if len(r.DstIP) != 0 {
			t.Errorf("FQDN rule should not pin a DstIP: %+v", r)
		}
		fqdns = append(fqdns, r.Fqdn)
	}
	// Deterministic sort: "*.s3.amazonaws.com" < "api.github.com".
	if len(fqdns) != 2 || fqdns[0] != "*.s3.amazonaws.com" || fqdns[1] != "api.github.com" {
		t.Fatalf("unexpected fqdn rules/order: %v", fqdns)
	}

	if got := FormatRuleSummary(rules[1]); got != "egress fqdn:*.s3.amazonaws.com tcp/443 allow" {
		t.Errorf("FormatRuleSummary fqdn = %q", got)
	}
}

func TestFormatRuleSummary(t *testing.T) {
	r := &dp.PolicyRule{
		Ingress: false,
		Port:    443,
		IPProto: 6,
		Action:  dp.PolicyActionAllow,
	}
	got := FormatRuleSummary(r)
	want := "egress any tcp/443 allow"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
