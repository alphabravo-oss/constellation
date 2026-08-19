package handler

import (
	"testing"

	"github.com/alphabravocompany/constellation/pkg/group"
)

// Relocated from cve_import_test.go during the D2 god-package split: this tests
// baselineModeForGroupMode (defined in groups.go), which stays in the parent
// handler package, so its test stays here too.
func TestBaselineModeForGroupMode(t *testing.T) {
	cases := map[string]string{"discover": "learn", "monitor": "monitor", "protect": "enforce", "": "", "bogus": ""}
	for in, want := range cases {
		if got := baselineModeForGroupMode(group.Mode(in)); got != want {
			t.Fatalf("baselineModeForGroupMode(%q)=%q want %q", in, got, want)
		}
	}
}
