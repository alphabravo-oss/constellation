package bundle

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

// vendorKeyFingerprint is the SHA-256 of the DER SubjectPublicKeyInfo of the
// release bundle-signing key (docs/deployment-helm.md "Bundle-signing key").
// Changing trust/bundle-signing.pub is a key rotation: update both together.
const vendorKeyFingerprint = "b7ca3ba6fe84afb131c20440589dc8c2fa5431647e11b550d2d8c880a6adad91"

func TestEmbeddedVendorKeyIsTheReleaseKey(t *testing.T) {
	t.Parallel()
	pub, err := TrustedKey()
	if err != nil {
		t.Fatalf("embedded key: %v", err)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("embedded key curve = %s, want P-256", pub.Curve.Params().Name)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(der)
	if got := hex.EncodeToString(sum[:]); got != vendorKeyFingerprint {
		t.Fatalf("embedded bundle-signing key fingerprint = %s, want %s (rotation must update the docs and this test)", got, vendorKeyFingerprint)
	}
}
