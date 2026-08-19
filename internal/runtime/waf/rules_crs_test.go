package waf

import "testing"

// Item #9: rule 942120 (SQLi comment evasion) was dropped for noise; make sure
// it stays gone from the builtin CRS set.
func TestCRSNoCommentEvasionRule(t *testing.T) {
	for _, r := range BuiltinCRS().Rules {
		if r.ID == 942120 {
			t.Fatalf("rule 942120 (comment evasion) should have been removed")
		}
	}
}
