package securefiles

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateArtifactAtomicReplacementAndPermissions(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "evidence")
	if err := mkdirSecurityFixture(dir); err != nil {
		t.Fatal(err)
	}
	root, err := OpenPrivateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Fatalf("directory permissions %o", info.Mode().Perm())
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := writeSecurityFixture(outside, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(dir, "report")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(root, "report", []byte("confidential"), 0o600); err != nil {
		t.Fatal(err)
	}
	if body, _ := readSecurityFixture(t, outside); string(body) != "original" {
		t.Fatal("atomic replacement modified outside hard link")
	}
	if info, _ := root.Stat("report"); info.Mode().Perm() != 0o600 {
		t.Fatal("private file mode")
	}
	if err := WriteFile(root, "public.key", []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	if info, _ := root.Stat("public.key"); info.Mode().Perm() != 0o644 {
		t.Fatal("public key must remain readable")
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(root, "linked", []byte("do not write"), 0o600); err == nil {
		t.Fatal("accepted symlink output")
	}
	if body, _ := readSecurityFixture(t, outside); string(body) != "original" {
		t.Fatal("modified symlink target")
	}
	for _, name := range []string{"../outside", "nested/report", "/absolute", "."} {
		if err := WriteFile(root, name, nil, 0o600); err == nil {
			t.Fatalf("accepted escape %q", name)
		}
	}
}

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("source unavailable") }
func TestFailedCopyPreservesPriorArtifactAndRemovesTemporary(t *testing.T) {
	t.Parallel()
	root, err := OpenPrivateDir(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err = WriteFile(root, "record", []byte("prior complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = CopyFile(root, "record", io.MultiReader(strings.NewReader("partial"), failedReader{}), 0o600); err == nil {
		t.Fatal("source error hidden")
	}
	body, err := root.ReadFile("record")
	if err != nil || string(body) != "prior complete" {
		t.Fatal("partial file published")
	}
	entries, err := os.ReadDir(root.Name())
	if err != nil || len(entries) != 1 {
		t.Fatal("pending file leaked")
	}
}
func TestPrivateDirectoryRejectsSharedRootsAndSymlink(t *testing.T) {
	t.Parallel()
	for _, dir := range []string{string(filepath.Separator), os.TempDir()} {
		if root, err := OpenPrivateDir(dir); err == nil {
			_ = root.Close()
			t.Fatalf("accepted shared root %q", dir)
		}
	}
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := mkdirSecurityFixture(target); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if root, err := OpenPrivateDir(link); err == nil {
		_ = root.Close()
		t.Fatal("accepted linked managed directory")
	}
	if info, _ := os.Stat(target); info.Mode().Perm() != 0o755 {
		t.Fatal("changed linked target permissions")
	}
}
func TestPinnedDirectoryNeverUsesReplacementPath(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	dir := filepath.Join(parent, "store")
	root, err := OpenPrivateDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	moved := filepath.Join(parent, "moved")
	if err = os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err = os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	if err = WriteFile(root, "secret", []byte("retained in pinned directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(outside, "secret")); !os.IsNotExist(err) {
		t.Fatal("followed replacement directory")
	}
	if _, err = os.Stat(filepath.Join(moved, "secret")); err != nil {
		t.Fatal(err)
	}
}
func TestManagedDirectoryRejectsAnotherOwner(t *testing.T) {
	t.Parallel()
	if os.Geteuid() != 0 {
		t.Skip("requires root to construct another-owned directory")
	}
	dir := filepath.Join(t.TempDir(), "foreign")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Skip("filesystem does not support ownership fixture")
	}
	if root, err := OpenPrivateDir(dir); err == nil {
		_ = root.Close()
		t.Fatal("accepted attacker-owned artifact directory")
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
func writeSecurityFixture(path string, body []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
func mkdirSecurityFixture(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	file, err := root.Open(".")
	closeRootErr := root.Close()
	if err != nil {
		return err
	}
	chmodErr := errors.Join(closeRootErr, file.Chmod(0o755))
	return errors.Join(chmodErr, file.Close())
}
