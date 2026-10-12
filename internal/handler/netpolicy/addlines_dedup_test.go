package netpolicy

import (
	"testing"

	netpolicy "github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func TestObservedPolicyAddedLines_Dedup(t *testing.T) {
	flows := []netpolicy.Flow{
		{SrcWorkload: "api", Protocol: "TCP", Port: 443, DstNamespace: "external", DstWorkload: "external"},
		{SrcWorkload: "api", Protocol: "TCP", Port: 443, DstNamespace: "external", DstWorkload: "external"},
		{SrcWorkload: "api", Protocol: "TCP", Port: 443, DstNamespace: "external", DstWorkload: "external"},
		{SrcWorkload: "api", Protocol: "TCP", Port: 5432, DstNamespace: "db", DstWorkload: "postgres"},
	}
	got := observedPolicyAddedLines("ns/api", flows)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct lines, got %d: %v", len(got), got)
	}
}
