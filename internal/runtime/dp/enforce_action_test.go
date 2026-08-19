package dp

import "testing"

// TestEnforceAction asserts the enforce mapping: an L7/threat hit escalates to
// RESET (inject a TCP RST for fast teardown), while a network-policy Deny stays
// a silent DROP.
func TestEnforceAction(t *testing.T) {
	if got := EnforceAction(HitThreat); got != DPIActionReset {
		t.Errorf("threat hit → %d, want RESET (%d)", got, DPIActionReset)
	}
	if got := EnforceAction(HitPolicyDeny); got != DPIActionDrop {
		t.Errorf("policy deny → %d, want DROP (%d)", got, DPIActionDrop)
	}
	// Mirror defs.h wire values so we never drift from the dp C enum.
	if DPIActionReset != 3 || DPIActionBlock != 5 {
		t.Errorf("DPI action codes drifted from defs.h: reset=%d block=%d", DPIActionReset, DPIActionBlock)
	}
}
