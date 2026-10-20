package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	compliancehandler "github.com/alphabravocompany/constellation/internal/handler/compliance"
)

func TestFileDeliveryPrivateAtomicAndConfined(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "delivery")
	d := daemon{outDir: filepath.Dir(dir), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	target := compliancehandler.DeliveryTarget{Kind: "file", Target: "file://" + dir}
	if err := d.deliver(context.Background(), target, dueSchedule{}, "/rendered/report.csv", []byte("sensitive"), "signature", "csv"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"report.csv", "report.csv.sig"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatal("public evidence", name, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "report.csv")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "report.csv")); err != nil {
		t.Fatal(err)
	}
	if err := d.deliver(context.Background(), target, dueSchedule{}, "/rendered/report.csv", []byte("new"), "", "csv"); err == nil {
		t.Fatal("followed delivery symlink")
	}
	if b, _ := readSecurityFixture(t, outside); string(b) != "outside" {
		t.Fatal("outside modified")
	}
}
func TestGeneratedSigningKeyRejectsSymlinkAndHardensExistingKey(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COSIGN_BIN", bin)
	t.Setenv("COSIGN_KEY", "")
	dir := t.TempDir()
	keyDir := filepath.Join(dir, ".cosign")
	if err := mkdirSecurityFixture(keyDir); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(keyDir, "cosign.key")
	if err := writeSecurityFixture(key, []byte("existing private key"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCosignKey(t.Context(), dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(key); info.Mode().Perm() != 0o600 {
		t.Fatal("existing private key permissions not repaired")
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, key); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureCosignKey(t.Context(), dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("accepted generated-key symlink")
	}
	// An explicitly mounted external key is a trusted operator input, and retains
	// compatibility with Kubernetes Secret symlinks.
	t.Setenv("COSIGN_KEY", key)
	if _, err := ensureCosignKey(t.Context(), dir, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
}
func TestNewCosignKeypairPublishedWithExplicitPermissions(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cosign")
	script := `#!/bin/sh
set -eu
[ "$1" = generate-key-pair ]
[ "$2" = --output-key-prefix ]
printf 'fixture private key' > "$3.key"
printf 'fixture public key' > "$3.pub"
`
	if err := writeSecurityFixture(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("COSIGN_BIN", bin)
	t.Setenv("COSIGN_KEY", "")
	dir := t.TempDir()
	signer, err := ensureCosignKey(t.Context(), dir, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{signer.keyPath: 0o600, filepath.Join(dir, ".cosign", "cosign.pub"): 0o644} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("key mode %s %v", path, err)
		}
	}
	if body, _ := readSecurityFixture(t, signer.keyPath); string(body) != "fixture private key" {
		t.Fatal("key content changed")
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
func TestFileDeliveryCannotEscapeConfiguredReportRoot(t *testing.T) {
	allowed := filepath.Join(t.TempDir(), "reports")
	outside := t.TempDir()
	before, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	d := daemon{outDir: allowed, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	etcBefore, err := os.Stat("/etc")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"file://" + outside, "file:///etc"} {
		if err := d.deliver(context.Background(), compliancehandler.DeliveryTarget{Kind: "file", Target: target}, dueSchedule{}, "/source/security-boundary-report.csv", []byte("sensitive"), "signature", "csv"); err == nil {
			t.Fatal("accepted external file target")
		}
	}
	etcAfter, err := os.Stat("/etc")
	if err != nil || etcBefore.Mode().Perm() != etcAfter.Mode().Perm() {
		t.Fatal("changed system directory permissions")
	}
	if _, err := os.Stat("/etc/security-boundary-report.csv"); !os.IsNotExist(err) {
		t.Fatal("wrote report in system directory")
	}
	after, err := os.Stat(outside)
	if err != nil || before.Mode().Perm() != after.Mode().Perm() {
		t.Fatal("changed outside directory permissions")
	}
	entries, err := os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("wrote outside configured root")
	}
	if err := os.MkdirAll(allowed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(allowed, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := d.deliver(context.Background(), compliancehandler.DeliveryTarget{Kind: "file", Target: "file://" + filepath.Join(allowed, "escape", "nested")}, dueSchedule{}, "/source/report.csv", []byte("sensitive"), "", "csv"); err == nil {
		t.Fatal("followed child symlink outside trusted root")
	}
	entries, err = os.ReadDir(outside)
	if err != nil || len(entries) != 0 {
		t.Fatal("created external nested directory")
	}
	if err := d.deliver(context.Background(), compliancehandler.DeliveryTarget{Kind: "file", Target: "file://" + filepath.Join(allowed, "customer", "exports")}, dueSchedule{}, "/source/report.csv", []byte("sensitive"), "signature", "csv"); err != nil {
		t.Fatal("allowed child delivery failed", err)
	}
	body, err := readSecurityFixture(t, filepath.Join(allowed, "customer", "exports", "report.csv"))
	if err != nil || string(body) != "sensitive" {
		t.Fatal("allowed child delivery missing")
	}
}
