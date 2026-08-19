package runtime

import (
	"encoding/json"
	"testing"
)

// TestAppendFedFileProfileRows is the P2-3 master→joint→agent data-contract check:
// the exact row a master ships when it federates a file-profile rule
// (fedFileProfileBundleRow marshaled onto a revision, replicated verbatim into
// fed_runtime_profiles) round-trips through the joint's bundle merge so the agent
// receives it read-only alongside its own cluster-scoped rules.
func TestAppendFedFileProfileRows(t *testing.T) {
	// What the master authors on a rule mutation.
	master := fedFileProfileBundleRow(
		observedWorkload{WorkloadID: "prod/api", Namespace: "prod", Name: "api"},
		fileProfileRule{Filter: "/etc/*", Path: "/etc", Recursive: true, Behavior: "block_access",
			Applications: []string{"nginx"}, Description: "protect etc", Enabled: true},
	)
	// The revision payload the joint stores verbatim in fed_runtime_profiles.
	payload, err := json.Marshal(master)
	if err != nil {
		t.Fatalf("marshal fed payload: %v", err)
	}

	// An agent's own cluster-scoped rule for this cluster.
	local := []fileProfileRuleBundleRow{{ID: "local-1", WorkloadID: "prod/db", Filter: "/var/*"}}

	merged := appendFedFileProfileRows(local, [][]byte{payload})
	if len(merged) != 2 {
		t.Fatalf("merged rows = %d, want 2 (local + federated)", len(merged))
	}
	if merged[0].ID != "local-1" {
		t.Errorf("local rule not preserved as first row: %+v", merged[0])
	}
	fed := merged[1]
	if fed.WorkloadID != "prod/api" || fed.Filter != "/etc/*" || fed.Behavior != "block_access" {
		t.Errorf("federated row not delivered intact: %+v", fed)
	}
	if len(fed.Applications) != 1 || fed.Applications[0] != "nginx" {
		t.Errorf("federated applications lost: %+v", fed.Applications)
	}

	// A malformed fed payload must be skipped, never break the bundle.
	if got := appendFedFileProfileRows(nil, [][]byte{[]byte("{not json")}); len(got) != 0 {
		t.Errorf("malformed payload not skipped: %+v", got)
	}
}

// TestAppendFedProcessBaselineRows covers the process-baseline federation path:
// the master's authored baseline row reaches a joint agent's bundle intact.
func TestAppendFedProcessBaselineRows(t *testing.T) {
	master := processBaselineBundleRow{
		WorkloadID: "prod/api", Namespace: "prod", Name: "api", Mode: "enforce",
		Processes: []string{"nginx", "sh"}, UpdatedAt: "2026-07-07T00:00:00Z",
	}
	payload, err := json.Marshal(master)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	merged := appendFedProcessBaselineRows(nil, [][]byte{payload})
	if len(merged) != 1 {
		t.Fatalf("merged rows = %d, want 1", len(merged))
	}
	if merged[0].Mode != "enforce" || len(merged[0].Processes) != 2 {
		t.Errorf("federated baseline not delivered intact: %+v", merged[0])
	}
	// nil Processes must normalize to a non-nil slice for a stable bundle.
	nilProc := processBaselineBundleRow{WorkloadID: "prod/db", Mode: "learn"}
	np, _ := json.Marshal(nilProc)
	got := appendFedProcessBaselineRows(nil, [][]byte{np})
	if got[0].Processes == nil {
		t.Errorf("nil Processes not normalized")
	}
}
