package main

import "testing"

// The protected set is a security guardrail: the core (self + kube-system family +
// host) must be present and NON-removable, and host processes must always be
// protected. If any of this breaks, a rule could kill Constellation or the node.
func TestProtectedSetGuarantees(t *testing.T) {
	p := newProtectedSet("constellation-system", []string{"team-a", "  ", "team-b"})

	// Host / node processes (no container id) are ALWAYS protected.
	if !p.protects("", "") {
		t.Fatal("host process (empty container id) must be protected")
	}
	if !p.protects("", "kube-system") {
		t.Fatal("host process must be protected regardless of namespace")
	}

	// Core system namespaces are protected.
	for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease"} {
		if !p.protects("abc123", ns) {
			t.Fatalf("core namespace %q must be protected", ns)
		}
	}
	// Self namespace is protected.
	if !p.protects("abc123", "constellation-system") {
		t.Fatal("own namespace must be protected")
	}
	// Operator additions are protected.
	if !p.protects("abc123", "team-a") || !p.protects("abc123", "team-b") {
		t.Fatal("operator-added namespaces must be protected")
	}
	// A normal workload namespace is NOT protected.
	if p.protects("abc123", "default") {
		t.Fatal("normal workload namespace must not be protected")
	}

	// Config CANNOT remove the core: an "extra" list that tries to omit/override
	// still leaves the core intact (additive-only). Even an empty extra keeps core.
	empty := newProtectedSet("", nil)
	for _, ns := range coreProtectedNamespaces {
		if !empty.protects("cid", ns) {
			t.Fatalf("core namespace %q must survive an empty config", ns)
		}
	}

	// Nil receiver is safe and protects only the host (never a container).
	var nilSet *protectedSet
	if !nilSet.protects("", "") {
		t.Fatal("nil set must still protect the host")
	}
	if nilSet.protects("cid", "kube-system") {
		t.Fatal("nil set must not claim to protect containers")
	}
}

func TestParseProtectedNamespaceList(t *testing.T) {
	got := parseProtectedNamespaceList(" a , b ,, c ")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if parseProtectedNamespaceList("   ") != nil {
		t.Fatal("blank input must yield nil")
	}
}
