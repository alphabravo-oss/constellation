package main

import (
	"encoding/json"
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

// TestSignatureRootsForJob asserts a job's DB-managed org roots (delivered on the scanJob
// envelope) are unioned onto the static flag roots for THAT job only, without mutating the
// static roots — so the slice reaching VerifyWithRoots holds both, and org A's roots never
// bleed into a later job's static set.
func TestSignatureRootsForJob(t *testing.T) {
	static := sigverify.SingleRoot(sigverify.TrustPolicy{Mode: "keyless"})

	// A job whose envelope carries org-specific roots parses them into scanJob.SignatureRoots.
	var j scanJob
	if err := json.Unmarshal([]byte(`{"id":"j1","org_id":"o1","target_type":"image","signature_roots":[{"Name":"org-airgap","Mode":"public-key","PublicKeyPEM":"-----BEGIN PUBLIC KEY-----\nZmFrZQ==\n-----END PUBLIC KEY-----"}]}`), &j); err != nil {
		t.Fatalf("unmarshal job: %v", err)
	}
	if len(j.SignatureRoots) != 1 || j.SignatureRoots[0].Name != "org-airgap" {
		t.Fatalf("job.SignatureRoots = %+v, want one org-airgap root", j.SignatureRoots)
	}

	got := signatureRootsForJob(static, j.SignatureRoots)
	if len(got) != 2 {
		t.Fatalf("len(union) = %d, want 2 (static default + org root)", len(got))
	}
	if got[0].Name != "default" {
		t.Fatalf("union[0].Name = %q, want default (static root first)", got[0].Name)
	}
	if got[1].Name != "org-airgap" || got[1].Mode != "public-key" || got[1].PublicKeyPEM == "" {
		t.Fatalf("union[1] = %+v, want the org root with its public key", got[1])
	}

	// The static roots must be untouched, so the next job (a different org) starts clean.
	if len(static) != 1 {
		t.Fatalf("static roots mutated: len = %d, want 1", len(static))
	}

	// A job with no roots leaves the static set exactly as-is.
	if same := signatureRootsForJob(static, nil); len(same) != 1 || same[0].Name != "default" {
		t.Fatalf("no-op union = %+v, want the single static default root", same)
	}
}
