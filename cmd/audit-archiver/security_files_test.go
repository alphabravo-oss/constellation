package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalAuditArtifactsPrivateAndSymlinkSafe(t *testing.T) {
	t.Parallel()
	source := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(source, []byte("retained audit evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "output")
	keys := archiveKeys{Archive: "audit/archive.gz", Manifest: "audit/archive.manifest", Signature: "audit/archive.sig", Cert: "audit/archive.cert"}
	if err := writeLocalArtifacts(dir, keys, source, []byte("manifest"), []byte("sig"), []byte("cert")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{keys.Archive, keys.Manifest, keys.Signature, keys.Cert} {
		info, err := os.Stat(filepath.Join(dir, filepath.Base(name)))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("artifact mode %s %v", name, err)
		}
	}
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Fatal("audit directory public")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "archive.gz")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "archive.gz")); err != nil {
		t.Fatal(err)
	}
	if err := writeLocalArtifacts(dir, keys, source, []byte("manifest"), nil, nil); err == nil {
		t.Fatal("accepted output symlink")
	}
	body, _ := readSecurityFixture(t, outside)
	if string(body) != "unchanged" {
		t.Fatal("modified outside file")
	}
}

func readSecurityFixture(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	return root.ReadFile(filepath.Base(path))
}
