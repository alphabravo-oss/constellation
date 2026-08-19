package runtime

import "testing"

// TestEdgePolicyPosture is the P0-07 regression guard: a 'protect' edge must yield an ENFORCING
// default-deny policy, while discover/monitor stay informational (monitor + allow default).
func TestEdgePolicyPosture(t *testing.T) {
	cases := []struct {
		mode        string
		wantMode    PolicyMode
		wantDeny    bool
		wantAllowNS bool
	}{
		{"protect", PolicyModeEnforce, true, true},
		{"monitor", PolicyModeMonitor, false, false},
		{"discover", PolicyModeMonitor, false, false},
		{"", PolicyModeMonitor, false, false}, // defensive: unnormalized empty stays informational
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			mode, opts := edgePolicyPosture(tc.mode)
			if mode != tc.wantMode {
				t.Fatalf("mode %q: got policy mode %q, want %q", tc.mode, mode, tc.wantMode)
			}
			if opts.DefaultDeny != tc.wantDeny {
				t.Fatalf("mode %q: got DefaultDeny=%v, want %v", tc.mode, opts.DefaultDeny, tc.wantDeny)
			}
			if opts.AllowDNS != tc.wantAllowNS {
				t.Fatalf("mode %q: got AllowDNS=%v, want %v", tc.mode, opts.AllowDNS, tc.wantAllowNS)
			}
		})
	}
}
