package scanner

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func extractionArchive(t *testing.T, names ...string) string {
	t.Helper()
	var data bytes.Buffer
	writer := zip.NewWriter(&data)
	for _, name := range names {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if name[len(name)-1] != '/' {
			if _, err := entry.Write([]byte("package-data")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.zip")
	if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServerlessExtractionRejectsAmbiguousPathsAndDirectoryBomb(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries []string
		limit   int
	}{
		{"parent traversal", []string{"../escape"}, 10},
		{"absolute path", []string{"/escape"}, 10},
		{"backslash path", []string{`nested\..\escape`}, 10},
		{"duplicate path", []string{"package.json", "package.json"}, 10},
		{"directory entry budget", []string{"a/", "b/", "c/"}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive := extractionArchive(t, tc.entries...)
			if _, _, err := unzipInto(archive, t.TempDir(), 1024, tc.limit); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}

func TestServerlessExtractionCannotFollowOutsideSymlink(t *testing.T) {
	destination, outside := t.TempDir(), t.TempDir()
	protected := filepath.Join(outside, "package.json")
	if err := os.WriteFile(protected, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(destination, "nested")); err != nil {
		t.Fatal(err)
	}
	archive := extractionArchive(t, "nested/package.json")
	if _, _, err := unzipInto(archive, destination, 1024, 10); err == nil {
		t.Fatal("extraction followed a link outside the root")
	}
	root, err := os.OpenRoot(outside)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	data, err := root.ReadFile("package.json")
	if err != nil || string(data) != "original" {
		t.Fatalf("outside file modified: err=%v", err)
	}
}

func TestServerlessExtractionKeepsPackageFilesPrivate(t *testing.T) {
	destination := t.TempDir()
	archive := extractionArchive(t, "nested/package.json")
	files, size, err := unzipInto(archive, destination, 1024, 10)
	if err != nil || files != 1 || size != int64(len("package-data")) {
		t.Fatalf("files=%d bytes=%d err=%v", files, size, err)
	}
	for path, mode := range map[string]os.FileMode{"nested": 0o700, "nested/package.json": 0o600} {
		info, err := os.Stat(filepath.Join(destination, path))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatalf("%s permissions=%o, want %o", path, info.Mode().Perm(), mode)
		}
	}
}
