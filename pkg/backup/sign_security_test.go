package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedKeypairReplacesPermissiveKeysWithoutFollowingLinks(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if err := writeSecurityFixture(private, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{private: 0o600, public: 0o644} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("key mode %s %v", path, err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(private); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, private); err != nil {
		t.Fatal(err)
	}
	if err := GenerateEd25519Keypair(private, public); err == nil {
		t.Fatal("accepted private output symlink")
	}
	body, _ := readSecurityFixture(t, outside)
	if string(body) != "unchanged" {
		t.Fatal("overwrote outside key")
	}
	if err := GenerateEd25519Keypair(public, public); err == nil {
		t.Fatal("accepted shared private/public path")
	}
}
func TestExplicitSecretSymlinkStillSignsAndVerifies(t *testing.T) {
	dir := t.TempDir()
	data := filepath.Join(dir, "..data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	private, public := filepath.Join(data, "key"), filepath.Join(data, "key.pub")
	if err := GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	privateLink, publicLink := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if err := os.Symlink("..data/key", privateLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..data/key.pub", publicLink); err != nil {
		t.Fatal(err)
	}
	body := []byte("manifest fixture")
	sig, _, id, err := Sign(context.Background(), body, SignerOptions{Mode: SignModeStaticKey, KeyPath: privateLink})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(context.Background(), body, sig, nil, VerifierOptions{Mode: SignModeStaticKey, KeyPath: publicLink})
	if err != nil || verified != id {
		t.Fatal("mounted Secret compatibility", err)
	}
}
func TestKeylessArtifactsStayInPrivateDirectoryAndAreRemoved(t *testing.T) {
	dir := t.TempDir()
	bin, record := filepath.Join(dir, "cosign"), filepath.Join(dir, "record")
	t.Setenv("TMPDIR", dir)
	// This fake records filesystem permissions, never real credentials or keys.
	script := `#!/bin/sh
set -eu
operation="$1"
shift
sig=""; cert=""; blob=""
while [ "$#" -gt 0 ]; do
 case "$1" in
 --output-signature|--signature) sig="$2"; shift 2;;
 --output-certificate|--certificate) cert="$2"; shift 2;;
 --certificate-identity) shift 2;;
 --yes) shift;;
 *) blob="$1"; shift;;
 esac
done
private_dir="${blob%/*}"
printf '%s\n' "$private_dir" > "$TEST_ARTIFACT_RECORD"
stat -c '%a' "$private_dir" >> "$TEST_ARTIFACT_RECORD"
stat -c '%a' "$blob" >> "$TEST_ARTIFACT_RECORD"
if [ "$operation" = sign-blob ]; then
 printf 'fixture signature' > "$sig"
 printf 'fixture certificate' > "$cert"
else
 stat -c '%a' "$sig" "$cert" >> "$TEST_ARTIFACT_RECORD"
fi
`
	if err := writeSecurityFixture(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_ARTIFACT_RECORD", record)
	for _, operation := range []string{"sign", "verify"} {
		if operation == "sign" {
			if _, _, _, err := Sign(context.Background(), []byte("manifest"), SignerOptions{Mode: SignModeKeyless, CosignBin: bin}); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := Verify(context.Background(), []byte("manifest"), []byte("signature"), []byte("cert"), VerifierOptions{Mode: SignModeKeyless, CosignBin: bin}); err != nil {
				t.Fatal(err)
			}
		}
		assertPrivateSigningArtifacts(t, dir, record, operation == "verify")
	}
}
func TestKeylessTempFailureReturnsErrorWithoutPanic(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "cosign")
	if err := writeSecurityFixture(bin, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	if _, _, _, err := Sign(context.Background(), []byte("manifest"), SignerOptions{Mode: SignModeKeyless, CosignBin: bin}); err == nil {
		t.Fatal("ignored signing staging error")
	}
	if _, err := Verify(context.Background(), []byte("manifest"), []byte("signature"), nil, VerifierOptions{Mode: SignModeKeyless, CosignBin: bin}); err == nil {
		t.Fatal("ignored verification staging error")
	}
}
func TestKeypairRejectsPublicSymlinkBeforeReplacingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "key"), filepath.Join(dir, "key.pub")
	if err := os.WriteFile(private, []byte("preserved private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := writeSecurityFixture(outside, []byte("public target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, public); err != nil {
		t.Fatal(err)
	}
	if err := GenerateEd25519Keypair(private, public); err == nil {
		t.Fatal("accepted public output symlink")
	}
	if body, _ := readSecurityFixture(t, private); string(body) != "preserved private key" {
		t.Fatal("partially replaced keypair after invalid destination")
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

func assertPrivateSigningArtifacts(t *testing.T, dir, record string, verify bool) {
	t.Helper()
	body, err := readSecurityFixture(t, record)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(body))
	if len(lines) < 3 || lines[1] != "700" || lines[2] != "600" {
		t.Fatalf("private artifact modes %q", body)
	}
	if verify && (len(lines) != 5 || lines[3] != "600" || lines[4] != "600") {
		t.Fatal("verification artifacts public")
	}
	temporaryRoot, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, statErr := temporaryRoot.Stat(filepath.Base(lines[0]))
	if err := temporaryRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if !os.IsNotExist(statErr) {
		t.Fatal("temporary signing data retained")
	}
}
