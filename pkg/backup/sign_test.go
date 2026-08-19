package backup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEd25519RoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath := filepath.Join(dir, "test.key")
	pubPath := filepath.Join(dir, "test.pub")
	if err := GenerateEd25519Keypair(privPath, pubPath); err != nil {
		t.Fatalf("gen: %v", err)
	}

	msg := []byte("constellation-backup-manifest:v1")
	sig, cert, identity, err := Sign(msg, SignerOptions{Mode: SignModeStaticKey, KeyPath: privPath})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if cert != nil {
		t.Errorf("static-key sign should return nil cert, got %d bytes", len(cert))
	}
	if identity == "" {
		t.Errorf("identity should be populated")
	}

	gotID, err := Verify(msg, sig, nil, VerifierOptions{Mode: SignModeStaticKey, KeyPath: pubPath})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if gotID != identity {
		t.Errorf("identity round-trip mismatch: got=%s want=%s", gotID, identity)
	}

	// Tamper test: flip a byte; verify must fail.
	tampered := append([]byte{}, msg...)
	tampered[0] ^= 0xff
	if _, err := Verify(tampered, sig, nil, VerifierOptions{Mode: SignModeStaticKey, KeyPath: pubPath}); err == nil {
		t.Errorf("verify on tampered manifest should fail")
	}
}

func TestComputeRootHashStable(t *testing.T) {
	a := []TableEntry{
		{Name: "clusters", SHA256: "aaaa", Rows: 2},
		{Name: "orgs", SHA256: "bbbb", Rows: 1},
	}
	b := []TableEntry{
		{Name: "orgs", SHA256: "bbbb", Rows: 1},
		{Name: "clusters", SHA256: "aaaa", Rows: 2},
	}
	hA, err := ComputeRootHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hB, err := ComputeRootHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if hA != hB {
		t.Errorf("root hash should be order-independent: %s vs %s", hA, hB)
	}
	// Change a SHA — the hash must differ.
	c := []TableEntry{
		{Name: "clusters", SHA256: "cccc", Rows: 2},
		{Name: "orgs", SHA256: "bbbb", Rows: 1},
	}
	hC, _ := ComputeRootHash(c)
	if hC == hA {
		t.Errorf("root hash should change when a table digest changes")
	}
	_ = os.TempDir
}

func TestOrderedTablesIncludesAll(t *testing.T) {
	must := []string{"orgs", "clusters", "deployments", "assets", "policies", "receivers", "audit_events_recent"}
	for _, m := range must {
		found := false
		for _, t := range OrderedTables {
			if t == m {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("OrderedTables missing required entry %q", m)
		}
	}
}
