package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/google/uuid"
)

// genRSAKeyPEM returns a fresh PKCS1 RSA private key PEM for the RS256 tests.
func genRSAKeyPEM(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
}

func TestRS256IssueVerifyRoundTrip(t *testing.T) {
	s, err := NewSigner("constellation", "api", 5*time.Minute, genRSAKeyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.Issue(uuid.New(), uuid.New(), "a@example.com", []string{"GlobalAdmin"}, 3)
	if err != nil {
		t.Fatal(err)
	}
	// The header alg must be RS256, not HS256.
	c, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Epoch != 3 {
		t.Fatalf("epoch mismatch: got %d want 3", c.Epoch)
	}
}

// TestRS256RotationKeepsOldTokensValid mirrors the acceptance check: a token signed with the
// previous key must still verify after rotation, while new tokens use the new key.
func TestRS256RotationKeepsOldTokensValid(t *testing.T) {
	oldKey := genRSAKeyPEM(t)
	newKey := genRSAKeyPEM(t)

	oldSigner, err := NewSigner("constellation", "api", 5*time.Minute, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	oldTok, _, err := oldSigner.Issue(uuid.New(), uuid.New(), "a@example.com", nil, 1)
	if err != nil {
		t.Fatal(err)
	}

	// After rotation the active signer is newKey, with oldKey retained as the previous key.
	rotated, err := NewSigner("constellation", "api", 5*time.Minute, newKey, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(oldTok); err != nil {
		t.Fatalf("token from previous key must still verify after rotation: %v", err)
	}
	newTok, _, err := rotated.Issue(uuid.New(), uuid.New(), "b@example.com", nil, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Verify(newTok); err != nil {
		t.Fatalf("new token must verify: %v", err)
	}
	// A signer that only knows the new key must reject the old token (proves keys differ).
	newOnly, err := NewSigner("constellation", "api", 5*time.Minute, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newOnly.Verify(oldTok); err == nil {
		t.Fatal("expected old token to fail against new-only signer")
	}
}

// TestHS256RejectedByDefault proves a raw (non-PEM) secret no longer silently
// downgrades sessions to HS256 unless the operator explicitly opts in. This is the
// A5 guard: production never injects a symmetric secret, so the asymmetric default
// cannot be quietly weakened by a 32-byte blob landing in JWT_KEYS.
func TestHS256RejectedByDefault(t *testing.T) {
	hsKey := make([]byte, 32)
	if _, err := rand.Read(hsKey); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSigner("constellation", "api", 5*time.Minute, hsKey); err == nil {
		t.Fatal("expected NewSigner to reject a raw HS256 secret without CONSTELLATION_ALLOW_HS256_JWT")
	}
	// With the explicit opt-in it is accepted again.
	t.Setenv("CONSTELLATION_ALLOW_HS256_JWT", "true")
	if _, err := NewSigner("constellation", "api", 5*time.Minute, hsKey); err != nil {
		t.Fatalf("HS256 opt-in should be accepted: %v", err)
	}
}

// TestAlgConfusionRejected proves a token forged with a mismatched algorithm is rejected:
// the verifier pins the key's own method, so an HS256 token cannot pass an RS256 key slot.
func TestAlgConfusionRejected(t *testing.T) {
	t.Setenv("CONSTELLATION_ALLOW_HS256_JWT", "true") // exercise the opt-in HS256 path
	hsKey := make([]byte, 32)
	if _, err := rand.Read(hsKey); err != nil {
		t.Fatal(err)
	}
	hsSigner, err := NewSigner("constellation", "api", 5*time.Minute, hsKey)
	if err != nil {
		t.Fatal(err)
	}
	hsTok, _, err := hsSigner.Issue(uuid.New(), uuid.New(), "a@example.com", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	rsSigner, err := NewSigner("constellation", "api", 5*time.Minute, genRSAKeyPEM(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rsSigner.Verify(hsTok); err == nil {
		t.Fatal("expected HS256 token to be rejected by RS256 signer")
	}
}

func TestIssueVerifyRoundTrip(t *testing.T) {
	t.Setenv("CONSTELLATION_ALLOW_HS256_JWT", "true") // exercise the opt-in HS256 path
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner("constellation", "api", 5*time.Minute, key)
	if err != nil {
		t.Fatal(err)
	}
	uid := uuid.New()
	oid := uuid.New()
	tok, _, err := s.Issue(uid, oid, "a@example.com", []string{"SecurityAdmin"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.UserID != uid || c.OrgID != oid {
		t.Fatalf("subject mismatch: got %+v", c)
	}
	if c.Epoch != 7 {
		t.Fatalf("epoch mismatch: got %d want 7", c.Epoch)
	}
}

func TestArgonRoundTrip(t *testing.T) {
	enc, err := HashPassword("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(enc, "hunter2"); err != nil {
		t.Fatalf("verify correct password: %v", err)
	}
	if err := VerifyPassword(enc, "wrong"); err == nil {
		t.Fatalf("expected mismatch error")
	}
}
