package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMain(m *testing.M) {
	if os.Getenv("CONSTELLATION_BACKUP_AWS_FIXTURE") == "1" {
		awsFixture()
		return
	}
	os.Exit(m.Run())
}
func awsFixture() {
	root, err := os.OpenRoot(os.Getenv("CONSTELLATION_BACKUP_AWS_FIXTURE_DIR"))
	if err != nil {
		os.Exit(90)
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		os.Exit(91)
	}
	sum := sha256.Sum256(body)
	receipt := map[string]any{"argv": os.Args[1:], "body_sha256": hex.EncodeToString(sum[:]), "database_url_present": os.Getenv("DATABASE_URL") != "", "pgpassword_present": os.Getenv("PGPASSWORD") != ""}
	file, err := root.OpenFile("receipt.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(92)
	}
	if err = json.NewEncoder(file).Encode(receipt); err != nil {
		os.Exit(93)
	}
	if err = file.Close(); err != nil {
		os.Exit(94)
	}
	if err = root.Close(); err != nil {
		os.Exit(95)
	}
	if os.Getenv("CONSTELLATION_BACKUP_AWS_FIXTURE_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "fixture-credential-must-not-escape")
		os.Exit(5)
	}
	os.Exit(0)
}
func TestS3DestinationsUseUniqueIdentityAtSameInstant(t *testing.T) {
	at := time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC)
	first, second := uuid.New(), uuid.New()
	a, err := S3BackupURI("s3://backups/team//one/", "../../Org A", first, at)
	if err != nil {
		t.Fatal(err)
	}
	b, err := S3BackupURI("s3://backups/team//one/", "../../Org A", second, at)
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, "s3://backups/team//one/constellation-backup-Org-A-") || !strings.Contains(a, first.String()) {
		t.Fatal("not unique/sanitized or prefix changed")
	}
	for _, dest := range []string{"backups/x", "s3:///x", "s3://user:secret@bucket/x", "s3://bucket/x\nvalue"} {
		if _, err := S3BackupURI(dest, "org", first, at); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
	if _, err := S3BackupURI("s3://backups", "org", uuid.Nil, at); err == nil {
		t.Fatal("empty identity accepted")
	}
}
func TestCLIWorkspaceOwnsOnlyItsPrivateDirectory(t *testing.T) {
	w, err := NewCLIWorkspace("org", uuid.New(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(w.Path)
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatal("workspace not private")
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("workspace not removed")
	}
}
func TestCLIWorkspacePreserveAndDiscard(t *testing.T) {
	w, err := NewCLIWorkspace("org", uuid.New(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	w.Preserve()
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Dir(w.Path)); err != nil {
		t.Fatal("preserved artifact removed")
	}
	w.Discard()
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestCLIFlagPreflightRejectsContradictions(t *testing.T) {
	for _, item := range []struct {
		key     string
		keyless bool
		verify  string
	}{{"private", true, ""}, {"", false, "public"}, {"", true, "public"}} {
		if _, err := ValidateCLIBackupSigning(item.key, item.keyless, item.verify); err == nil {
			t.Fatal("invalid signing flags accepted")
		}
	}
	mode, err := ValidateCLIBackupSigning("private", false, "")
	if err != nil || mode != SignModeStaticKey {
		t.Fatal("optional verification changed")
	}
}
func prepareAWSFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(executable, filepath.Join(bin, "aws")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("CONSTELLATION_BACKUP_AWS_FIXTURE", "1")
	t.Setenv("CONSTELLATION_BACKUP_AWS_FIXTURE_DIR", dir)
	return dir
}
func TestS3UploadUsesPinnedHandleAndStripsDatabaseCredentials(t *testing.T) {
	dir := prepareAWSFixture(t)
	t.Setenv("DATABASE_URL", "fixture-credential-must-not-escape")
	t.Setenv("PGPASSWORD", "fixture-credential-must-not-escape")
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	file, err := root.OpenFile("archive", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	body := []byte("retained-artifact")
	if _, err = file.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = UploadS3Artifact(t.Context(), "s3://backups/prefix/archive", "http://127.0.0.1:9000", file, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	raw := []byte(readArtifactTestFile(t, filepath.Join(dir, "receipt.json")))
	var receipt struct {
		Argv     []string `json:"argv"`
		SHA      string   `json:"body_sha256"`
		Database bool     `json:"database_url_present"`
		Password bool     `json:"pgpassword_present"`
	}
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	if receipt.SHA != hex.EncodeToString(sum[:]) || receipt.Database || receipt.Password || !strings.Contains(strings.Join(receipt.Argv, " "), "s3 cp - s3://backups/prefix/archive") {
		t.Fatal("upload did not preserve reviewed stream/credential boundary")
	}
}
func TestS3UploadDoesNotEchoChildDiagnostics(t *testing.T) {
	prepareAWSFixture(t)
	t.Setenv("CONSTELLATION_BACKUP_AWS_FIXTURE_FAIL", "1")
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	file, err := root.OpenFile("archive", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err = file.WriteString("artifact"); err != nil {
		t.Fatal(err)
	}
	err = UploadS3Artifact(t.Context(), "s3://backups/archive", "", file, 8)
	if err == nil || strings.Contains(err.Error(), "fixture-credential") {
		t.Fatal("child failure leaked or returned success")
	}
}
