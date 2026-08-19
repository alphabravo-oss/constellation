package netpolicy

import "testing"

func TestNextModeForAction_Flow(t *testing.T) {
	cases := []struct {
		name, cur, action, forced, want string
	}{
		{"promote from discover", "discover", "promote", "", "monitor"},
		{"promote from monitor", "monitor", "promote", "", "protect"},
		{"promote caps at protect", "protect", "promote", "", "protect"},
		{"empty defaults to discover then promote", "", "promote", "", "monitor"},
		{"demote from protect", "protect", "demote", "", "monitor"},
		{"demote from monitor", "monitor", "demote", "", "discover"},
		{"force to protect", "discover", "force", "protect", "protect"},
		{"force to discover", "protect", "force", "discover", "discover"},
		{"force invalid holds", "monitor", "force", "bogus", "monitor"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := nextModeForAction(networkPolicyLifecycleDTO{CurrentMode: c.cur, ForcedMode: c.forced}, c.action)
			if got != c.want {
				t.Fatalf("nextModeForAction(%q,%q,forced=%q) = %q, want %q", c.cur, c.action, c.forced, got, c.want)
			}
		})
	}
}
