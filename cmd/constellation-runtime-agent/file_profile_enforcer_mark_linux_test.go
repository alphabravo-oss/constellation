package main

import "testing"

// This test is the "are you sure the host is protected" proof. execEnforcerShouldMarkRoot
// is the ONLY gate that decides whether a blocking FAN_MARK_MOUNT is armed on a root.
// If any of these cases regresses, protect mode could freeze the node — so they are
// asserted explicitly.
func TestExecEnforcerShouldMarkRoot(t *testing.T) {
	protected := newProtectedSet("constellation-system", []string{"monitoring"})
	const hostDev = uint64(2049)  // arbitrary host root device id
	const overlayDev = uint64(64) // a container's private overlay device id

	cases := []struct {
		name      string
		cid       string
		ns        string
		rootDev   uint64
		rootDevOK bool
		hostDevOK bool
		wantMark  bool
	}{
		// The dangerous cases — must NEVER mark:
		{"host process (no container id)", "", "", overlayDev, true, true, false},
		{"own namespace (constellation-system)", "c1", "constellation-system", overlayDev, true, true, false},
		{"kube-system", "c2", "kube-system", overlayDev, true, true, false},
		{"kube-node-lease", "c3", "kube-node-lease", overlayDev, true, true, false},
		{"operator-added namespace", "c4", "monitoring", overlayDev, true, true, false},
		{"root shares host mount device", "c5", "default", hostDev, true, true, false},
		{"root device unknown", "c6", "default", 0, false, true, false},
		// The only case that SHOULD mark: a normal workload on its own private mount.
		{"normal workload, private overlay", "c7", "default", overlayDev, true, true, true},
		// If we can't even determine the host device, we still mark a clearly-private
		// container (host protection then rests on the protected-set + unknown-dev skip).
		{"private overlay, host device unknown", "c8", "default", overlayDev, true, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := execEnforcerShouldMarkRoot(protected, tc.cid, tc.ns, tc.rootDev, tc.rootDevOK, hostDev, tc.hostDevOK)
			if got != tc.wantMark {
				t.Fatalf("shouldMark=%v want %v", got, tc.wantMark)
			}
		})
	}
}
