package sigverify

import "testing"

// TestSelectTrustedRootAnyRootVerifies is the load-bearing multi-root regression: an image is
// trusted when ANY configured named root verifies its signature (here only the SECOND root's
// verifier accepts it), and is rejected when no root does. selectTrustedRoot is the cosign-free
// core of VerifyWithRoots; the fake verify stands in for the per-root cosign shell-out.
func TestSelectTrustedRootAnyRootVerifies(t *testing.T) {
	roots := []RootOfTrust{
		{Name: "first"},
		{Name: "second"},
	}

	// Only the second named root trusts the signature.
	verify := func(r RootOfTrust) (*Result, error) {
		return &Result{Signed: true, Trusted: r.Name == "second", Reason: "signature trusted"}, nil
	}
	res, err := selectTrustedRoot("img", roots, verify)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Trusted {
		t.Fatalf("image must be trusted when the second root verifies: %+v", res)
	}
	if want := `signature trusted (root "second")`; res.Reason != want {
		t.Fatalf("reason = %q, want %q", res.Reason, want)
	}

	// No root trusts the signature -> untrusted, with an aggregated per-root reason.
	verifyNone := func(_ RootOfTrust) (*Result, error) {
		return &Result{Signed: true, Trusted: false, Reason: "identity not in trust policy"}, nil
	}
	res, err = selectTrustedRoot("img", roots, verifyNone)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Trusted {
		t.Fatalf("image must be untrusted when no root verifies: %+v", res)
	}
}
