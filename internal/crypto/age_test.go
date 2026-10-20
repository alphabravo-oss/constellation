package crypto

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTripAndKeyIDs(t *testing.T) {
	t.Parallel()
	a, aid, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEncryptor(a)
	if err != nil {
		t.Fatal(err)
	}
	if e.KeyID() != aid || !strings.HasPrefix(aid, "age1") {
		t.Fatalf("key id %q", e.KeyID())
	}
	s, err := e.Encrypt([]byte("hunter2"))
	if err != nil || s.Algorithm != Algorithm || s.KeyID != aid || len(s.Ciphertext) == 0 || s.Nonce != nil {
		t.Fatalf("sealed: %+v %v", s, err)
	}
	pt, err := e.Decrypt(s)
	if err != nil || string(pt) != "hunter2" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	if _, err := e.Decrypt(Sealed{KeyID: aid, Algorithm: "AES-256-GCM", Ciphertext: s.Ciphertext}); err == nil {
		t.Fatal("foreign algorithm accepted")
	}
}

func TestRotationKeepsOldRowsReadable(t *testing.T) {
	t.Parallel()
	a, aid, _ := GenerateKey()
	b, bid, _ := GenerateKey()
	old, _ := NewEncryptor(a)
	sealed, _ := old.Encrypt([]byte("secret-under-a"))
	rotated, err := NewEncryptor(b + "\n# previous\n" + a)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.KeyID() != bid || len(rotated.KeyIDs()) != 2 || rotated.Current(aid) {
		t.Fatalf("key set: %v", rotated.KeyIDs())
	}
	if pt, err := rotated.Decrypt(sealed); err != nil || string(pt) != "secret-under-a" {
		t.Fatalf("old key id lookup: %q %v", pt, err)
	}
	// Legacy row without key id: every identity is tried.
	if pt, err := rotated.Open(sealed.Ciphertext); err != nil || string(pt) != "secret-under-a" {
		t.Fatalf("open without key id: %q %v", pt, err)
	}
	re, _ := rotated.Encrypt([]byte("secret-under-a"))
	if re.KeyID != bid {
		t.Fatalf("re-seal must use the current key, got %s", re.KeyID)
	}
	only, _ := NewEncryptor(b)
	if _, err := only.Decrypt(sealed); err == nil {
		t.Fatal("row sealed under a retired key must not decrypt without it")
	}
}

func TestDefaultRequiresEnvOrFile(t *testing.T) {
	t.Parallel()
	// Default is process-wide; this test runs without the env set.
	if _, err := Default(); err == nil && (strings.TrimSpace(envOr(EnvKey)) == "" && strings.TrimSpace(envOr(EnvKeyFile)) == "") {
		t.Fatal("Default must fail closed without a key")
	}
}
