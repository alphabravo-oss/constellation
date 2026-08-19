package netpolicy

import (
	"net"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func ingressRule(port uint16, ip string) *dp.PolicyRule {
	return &dp.PolicyRule{Ingress: true, IPProto: 6, Port: port, SrcIP: net.ParseIP(ip), Action: dp.PolicyActionAllow}
}
func egressRule(port uint16, ip string) *dp.PolicyRule {
	return &dp.PolicyRule{Ingress: false, IPProto: 6, Port: port, DstIP: net.ParseIP(ip), Action: dp.PolicyActionAllow}
}

func TestMergeRulesPreservesUserDropsLearned(t *testing.T) {
	existing := []*SourcedRule{
		{PolicyRule: ingressRule(443, "10.0.0.1"), CfgType: CfgTypeUser},
		{PolicyRule: egressRule(80, "10.0.0.2"), CfgType: CfgTypeLearned},
	}
	fresh := []*SourcedRule{
		{PolicyRule: egressRule(80, "10.0.0.3"), CfgType: CfgTypeLearned}, // new learned edge
		{PolicyRule: ingressRule(443, "10.0.0.1"), CfgType: CfgTypeLearned}, // collides with user rule
	}

	got := MergeRules(existing, fresh)

	// Expect: user 443→10.0.0.1 preserved; old learned egress 80→.0.2 gone;
	// new learned egress 80→.0.3 kept; learned 443→.0.1 dropped (user shadows).
	if len(got) != 2 {
		t.Fatalf("expected 2 merged rules, got %d", len(got))
	}
	var haveUser443, haveLearned80to3 bool
	for _, r := range got {
		id := identityOf(r.PolicyRule)
		if id.ingress && id.port == 443 && id.peer == "10.0.0.1" {
			haveUser443 = true
			if r.CfgType != CfgTypeUser {
				t.Errorf("443 rule provenance = %q, want user", r.CfgType)
			}
		}
		if !id.ingress && id.port == 80 && id.peer == "10.0.0.3" {
			haveLearned80to3 = true
		}
		if !id.ingress && id.port == 80 && id.peer == "10.0.0.2" {
			t.Errorf("stale learned egress 80→10.0.0.2 should have been replaced")
		}
	}
	if !haveUser443 {
		t.Error("user rule 443→10.0.0.1 was not preserved")
	}
	if !haveLearned80to3 {
		t.Error("fresh learned egress 80→10.0.0.3 was not added")
	}
}

func TestMergeRulesTreatsEmptyCfgAsUser(t *testing.T) {
	// A rule stored before provenance existed (empty cfg) must be preserved, not
	// treated as learned and dropped.
	existing := []*SourcedRule{{PolicyRule: ingressRule(22, "10.1.0.1")}} // cfg ""
	fresh := []*SourcedRule{{PolicyRule: ingressRule(22, "10.1.0.1"), CfgType: CfgTypeLearned}}
	got := MergeRules(existing, fresh)
	if len(got) != 1 || got[0].CfgType != CfgTypeUser {
		t.Fatalf("expected the pre-provenance rule preserved as user, got %+v", got)
	}
}
