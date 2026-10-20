package sigverify

import (
	"context"
	"os"
	"testing"
)

// The fixture is an image signed and attested by the previous Cosign major
// version, using an ephemeral test key and no transparency log.
func TestBundledCosignLegacyVerification(t *testing.T) {
	t.Parallel()
	ref := os.Getenv("CONSTELLATION_TEST_SIGNED_IMAGE")
	key := os.Getenv("CONSTELLATION_TEST_SIGNING_PUBLIC_KEY")
	if ref == "" || key == "" {
		t.Skip("set real Cosign fixture image and public key")
	}
	v := New()
	policy := TrustPolicy{Mode: "public-key", PublicKeyPath: key, RequireAttestations: []string{"https://slsa.dev/provenance/v1"}}
	result, err := v.Verify(context.Background(), ref, policy)
	if err != nil || result == nil || !result.Signed || !result.Trusted {
		t.Fatalf("legacy signature: result=%+v err=%v", result, err)
	}
	attestation, err := v.VerifyAttestation(context.Background(), ref, policy)
	if err != nil || attestation == nil || !attestation.Trusted || attestation.PayloadSHA256 == "" {
		t.Fatalf("legacy attestation: result=%+v err=%v", attestation, err)
	}
	policy.RequireAttestations = []string{"https://constellation.test/wrong-predicate"}
	attestation, err = v.VerifyAttestation(context.Background(), ref, policy)
	if err == nil || (attestation != nil && attestation.Trusted) {
		t.Fatal("unexpected predicate was trusted")
	}
	wrongKey := os.Getenv("CONSTELLATION_TEST_WRONG_PUBLIC_KEY")
	if wrongKey == "" {
		t.Fatal("wrong-key fixture required for negative verification")
	}
	policy.PublicKeyPath = wrongKey
	result, err = v.Verify(context.Background(), ref, policy)
	if result != nil && result.Trusted {
		t.Fatalf("wrong signing key trusted: %+v err=%v", result, err)
	}
}

func TestBundledCosignKeylessVerification(t *testing.T) {
	t.Parallel()
	ref := os.Getenv("CONSTELLATION_TEST_KEYLESS_IMAGE")
	if ref == "" {
		t.Skip("set a digest-pinned keyless fixture")
	}
	policy := TrustPolicy{Identities: []string{"keyless@distroless.iam.gserviceaccount.com"}, Issuers: []string{"https://accounts.google.com"}, RequireRekor: true}
	v := New()
	result, err := v.Verify(context.Background(), ref, policy)
	if err != nil || result == nil || !result.Trusted {
		t.Fatalf("keyless signature: result=%+v err=%v", result, err)
	}
	policy.Identities = []string{"untrusted@example.test"}
	result, err = v.Verify(context.Background(), ref, policy)
	if result != nil && result.Trusted {
		t.Fatalf("wrong identity trusted: %+v err=%v", result, err)
	}
}
