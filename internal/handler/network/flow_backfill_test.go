package network

import (
	"testing"
	"time"
)

// fakeResolver stands in for (*handler.IPResolver).Resolve: it maps an address
// to a label from a static table, ignoring the time bracket. relabelFlow only
// needs the seam's shape, so this keeps the test DB-free.
func fakeResolver(byAddr map[string]string) resolveFunc {
	return func(workload, addr, _ string, _ time.Time) (string, bool) {
		if label, ok := byAddr[addr]; ok {
			return label, true
		}
		return workload, false // unresolved: unchanged
	}
}

func TestRelabelFlow(t *testing.T) {
	at := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	res := fakeResolver(map[string]string{
		"10.42.0.4": "team-a/api",
		"10.42.0.9": "team-a/worker",
	})

	tests := []struct {
		name                       string
		src, dst, srcAddr, dstAddr string
		wantSrc, wantDst           string
		wantChanged                bool
	}{
		{
			name: "both resolve",
			src:  "cluster/10.42.0.4", dst: "cluster/10.42.0.9",
			srcAddr: "10.42.0.4", dstAddr: "10.42.0.9",
			wantSrc: "team-a/api", wantDst: "team-a/worker", wantChanged: true,
		},
		{
			name: "only dst resolves",
			src:  "cluster/10.42.0.7", dst: "cluster/10.42.0.9",
			srcAddr: "10.42.0.7", dstAddr: "10.42.0.9",
			wantSrc: "cluster/10.42.0.7", wantDst: "team-a/worker", wantChanged: true,
		},
		{
			name: "neither resolves stays unchanged",
			src:  "cluster/10.42.0.7", dst: "cluster/10.42.0.8",
			srcAddr: "10.42.0.7", dstAddr: "10.42.0.8",
			wantSrc: "cluster/10.42.0.7", wantDst: "cluster/10.42.0.8", wantChanged: false,
		},
		{
			name: "already-named row is not disturbed",
			src:  "team-a/api", dst: "cluster/10.42.0.9",
			srcAddr: "", dstAddr: "10.42.0.9",
			wantSrc: "team-a/api", wantDst: "team-a/worker", wantChanged: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSrc, gotDst, changed := relabelFlow(res, tc.src, tc.dst, tc.srcAddr, tc.dstAddr, at)
			if gotSrc != tc.wantSrc || gotDst != tc.wantDst || changed != tc.wantChanged {
				t.Fatalf("relabelFlow = (%q, %q, %v), want (%q, %q, %v)",
					gotSrc, gotDst, changed, tc.wantSrc, tc.wantDst, tc.wantChanged)
			}
		})
	}
}
