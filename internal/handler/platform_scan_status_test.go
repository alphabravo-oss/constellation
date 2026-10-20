package handler

import "testing"

func TestPlatformScanStatusRequiresMatchingClaimedInventory(t *testing.T) {
	facts := &ClusterPlatformFacts{}
	target := &PlatformScanTargetView{InventoryHash: "current"}
	evidence := &PlatformEvidenceView{InventoryHash: "current"}
	for _, tc := range []struct{ state, hash, want string }{
		{"completed", "current", "scanned"}, {"completed", "old", "outdated"}, {"completed", "", "unverified"},
		{"running", "current", "running"}, {"running", "old", "outdated"}, {"running", "", "unverified"},
		{"failed", "current", "failed"}, {"failed", "old", "outdated"}, {"pending", "", "pending"},
	} {
		t.Run(tc.state+"/"+tc.hash, func(t *testing.T) {
			job := &PlatformScanJobView{Status: tc.state, ClaimedInventoryHash: tc.hash}
			if got := platformFactsStatus(facts, target, evidence, job); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
	if got := platformFactsStatus(facts, target, nil, &PlatformScanJobView{Status: "completed", ClaimedInventoryHash: "current"}); got != "reported" {
		t.Fatal(got)
	}
	if got := platformFactsStatus(facts, target, &PlatformEvidenceView{InventoryHash: "old"}, &PlatformScanJobView{Status: "completed", ClaimedInventoryHash: "old"}); got != "unverified" {
		t.Fatal(got)
	}
}
