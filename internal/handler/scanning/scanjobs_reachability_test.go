package scanning

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

// TestScannerFindingDetail_Reachable proves G1: govulncheck reachability is surfaced into the
// finding's detail_json when computed, and left ABSENT (not false) when not computed, so it
// reads as "unknown" rather than "unreachable". The risk_inputs.reachable_static persistence is
// exercised by the DB-backed upsert/promote integration tests.
func TestScannerFindingDetail_Reachable(t *testing.T) {
	reach, unreach := true, false
	for _, tc := range []struct {
		name    string
		r       *bool
		present bool
		want    bool
	}{
		{"reachable", &reach, true, true},
		{"unreachable", &unreach, true, false},
		{"not computed", nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := scannerFindingDetail(scanner.Finding{Reachable: tc.r}, scanFindingContext{})
			got, ok := d["reachable_static"]
			if ok != tc.present {
				t.Fatalf("reachable_static present=%v, want %v (value=%v)", ok, tc.present, got)
			}
			if tc.present && got != tc.want {
				t.Fatalf("reachable_static = %v, want %v", got, tc.want)
			}
		})
	}
}
