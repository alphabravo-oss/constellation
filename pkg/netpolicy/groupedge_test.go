package netpolicy

import "testing"

func TestExpandEdgeFansOutMembersAndPorts(t *testing.T) {
	e := GroupEdge{
		FromGroup: "frontend", ToGroup: "backend",
		Ports: []PortSpec{{Protocol: "tcp", Port: 5432}, {Protocol: "tcp", Port: 6379}},
	}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	from := []string{"web/a", "web/b"}
	to := []string{"data/x"}
	flows := ExpandEdge(e, from, to)
	// 2 from × 1 to × 2 ports = 4 flows.
	if len(flows) != 4 {
		t.Fatalf("expected 4 expanded flows, got %d", len(flows))
	}
	for _, f := range flows {
		if f.DstWorkload != "data/x" {
			t.Errorf("dst = %q, want data/x", f.DstWorkload)
		}
		if f.SrcNamespace != "web" || f.DstNamespace != "data" {
			t.Errorf("namespaces derived wrong: %q → %q", f.SrcNamespace, f.DstNamespace)
		}
		if f.Protocol != "TCP" {
			t.Errorf("protocol not upper-cased: %q", f.Protocol)
		}
	}
}

func TestExpandEdgeSkipsSelfPairs(t *testing.T) {
	e := GroupEdge{FromGroup: "g", ToGroup: "g", Ports: []PortSpec{{Protocol: "TCP", Port: 8080}}}
	_ = e.Validate()
	members := []string{"ns/a", "ns/b"}
	flows := ExpandEdge(e, members, members)
	// a→b and b→a only; a→a and b→b skipped.
	if len(flows) != 2 {
		t.Fatalf("expected 2 flows (no self-pairs), got %d", len(flows))
	}
	for _, f := range flows {
		if f.SrcWorkload == f.DstWorkload {
			t.Errorf("self-pair leaked: %s", f.SrcWorkload)
		}
	}
}

func TestGroupEdgeValidateDefaultsMonitor(t *testing.T) {
	e := GroupEdge{FromGroup: "a", ToGroup: "b"}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	if e.Mode != "monitor" {
		t.Fatalf("empty mode should default to monitor, got %q", e.Mode)
	}
	bad := GroupEdge{FromGroup: "a", ToGroup: "b", Mode: "enforce"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid mode error")
	}
	empty := GroupEdge{FromGroup: "", ToGroup: "b"}
	if err := empty.Validate(); err == nil {
		t.Fatal("expected missing from_group error")
	}
}
