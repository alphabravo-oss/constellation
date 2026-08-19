package main

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// ruleIDs returns the dp rule IDs in a push, for terse assertions.
func ruleIDs(p dlpPush) []uint32 {
	out := make([]uint32, 0, len(p.rules))
	for _, r := range p.rules {
		out = append(out, r.ID)
	}
	return out
}

func TestPlanDLPPushes_UnscopedAppliesToAllMACs(t *testing.T) {
	rules := []dlpRuleWire{
		{DPRuleID: 9001, Name: "a", Mode: "monitor", Patterns: []string{"x"}},
		{DPRuleID: 9002, Name: "b", Mode: "monitor", Patterns: []string{"y"}},
	}
	macs := []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}
	pushes := planDLPPushes(rules, macs, false)
	if len(pushes) != 1 {
		t.Fatalf("want 1 group (all MACs share the same rule set), got %d", len(pushes))
	}
	if len(pushes[0].macs) != 2 {
		t.Fatalf("want both MACs in the group, got %v", pushes[0].macs)
	}
	if got := ruleIDs(pushes[0]); len(got) != 2 {
		t.Fatalf("want 2 rules, got %v", got)
	}
}

func TestPlanDLPPushes_ScopeRestrictsToNamedMAC(t *testing.T) {
	rules := []dlpRuleWire{
		{DPRuleID: 9001, Name: "global", Mode: "monitor", Patterns: []string{"x"}},
		// Scoped to MAC bb only (upper-case in the rule to prove normalisation).
		{DPRuleID: 9002, Name: "scoped", Mode: "monitor", Patterns: []string{"y"},
			ScopeMACs: []string{"BB:BB:BB:BB:BB:BB"}},
	}
	macs := []string{"aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb"}
	pushes := planDLPPushes(rules, macs, false)
	if len(pushes) != 2 {
		t.Fatalf("want 2 groups (aa gets only global; bb gets both), got %d", len(pushes))
	}
	// Find the group that contains MAC aa and assert it only has the global rule.
	for _, p := range pushes {
		has := func(m string) bool {
			for _, x := range p.macs {
				if x == m {
					return true
				}
			}
			return false
		}
		switch {
		case has("aa:aa:aa:aa:aa:aa"):
			if got := ruleIDs(p); len(got) != 1 || got[0] != dp.DLPSigID(9001) {
				t.Fatalf("aa MAC should get only the global rule (dp sig %d), got %v", dp.DLPSigID(9001), got)
			}
		case has("bb:bb:bb:bb:bb:bb"):
			if got := ruleIDs(p); len(got) != 2 {
				t.Fatalf("bb MAC should get both rules, got %v", got)
			}
		}
	}
}

func TestPlanDLPPushes_EnforceGate(t *testing.T) {
	rules := []dlpRuleWire{
		{DPRuleID: 9001, Name: "drop-me", Mode: "enforce", Patterns: []string{"x"}},
	}
	macs := []string{"aa:aa:aa:aa:aa:aa"}

	// Gate OFF: enforce degrades to monitor → dp binds ALLOW (alert-only).
	off := planDLPPushes(rules, macs, false)
	if len(off) != 1 || len(off[0].rules) != 1 {
		t.Fatalf("unexpected plan: %+v", off)
	}
	if act := dp.DLPModeAction(off[0].rules[0].Mode); act != dp.DPIActionAllow {
		t.Fatalf("enforce gate OFF must yield ALLOW action, got %d (mode %q)",
			act, off[0].rules[0].Mode)
	}

	// Gate ON: enforce stays enforce → dp binds DROP.
	on := planDLPPushes(rules, macs, true)
	if act := dp.DLPModeAction(on[0].rules[0].Mode); act != dp.DPIActionDrop {
		t.Fatalf("enforce gate ON must yield DROP action, got %d (mode %q)",
			act, on[0].rules[0].Mode)
	}
}

func TestEffectiveDLPMode(t *testing.T) {
	cases := []struct {
		mode    string
		enforce bool
		want    string
	}{
		{"enforce", true, "enforce"},
		{"enforce", false, "monitor"},
		{"monitor", true, "monitor"},
		{"monitor", false, "monitor"},
	}
	for _, c := range cases {
		if got := effectiveDLPMode(c.mode, c.enforce); got != c.want {
			t.Errorf("effectiveDLPMode(%q,%v)=%q want %q", c.mode, c.enforce, got, c.want)
		}
	}
}
