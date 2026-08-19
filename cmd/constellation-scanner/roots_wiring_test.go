package main

import (
	"testing"

	"github.com/alphabravocompany/constellation/pkg/sigverify"
)

// TestBuildSignatureRoots asserts the flag policy is always the default root and that
// extra JSON-configured roots (including private-sigstore fields) are appended, so the
// scanner's real verify path reaches VerifyWithRoots' "ANY root verifies" aggregation.
func TestBuildSignatureRoots(t *testing.T) {
	policy := sigverify.TrustPolicy{Mode: "keyless", Identities: []string{"a@example.com"}}

	// No extra config: single default root, unchanged behaviour.
	single, err := buildSignatureRoots(policy, "")
	if err != nil {
		t.Fatalf("single: unexpected error: %v", err)
	}
	if len(single) != 1 || single[0].Name != "default" || single[0].Mode != "keyless" {
		t.Fatalf("single root = %+v, want one default root with policy", single)
	}

	// Extra roots via inline JSON are appended after the default, carrying private fields.
	roots, err := buildSignatureRoots(policy, `[{"Name":"airgap","Mode":"keyless","RekorURL":"https://rekor.internal","TUFMirror":"https://tuf.internal"}]`)
	if err != nil {
		t.Fatalf("multi: unexpected error: %v", err)
	}
	if len(roots) != 2 {
		t.Fatalf("len(roots) = %d, want 2", len(roots))
	}
	if roots[0].Name != "default" {
		t.Fatalf("roots[0].Name = %q, want default", roots[0].Name)
	}
	if roots[1].Name != "airgap" || roots[1].RekorURL != "https://rekor.internal" || roots[1].TUFMirror != "https://tuf.internal" {
		t.Fatalf("roots[1] = %+v, want airgap root with private fields", roots[1])
	}

	// Malformed config surfaces an error rather than silently dropping roots.
	if _, err := buildSignatureRoots(policy, "not-json"); err == nil {
		t.Fatal("expected error for malformed signature-roots config")
	}
}
