package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectOSForPackagesReadsVersionID(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "etc/os-release")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	distro, version := detectOSForPackages(root)
	if distro != "ubuntu" || version != "24.04" {
		t.Fatalf("detectOSForPackages = %q/%q, want ubuntu/24.04", distro, version)
	}
}
