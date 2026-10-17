package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgservicefile"
)

func TestMain(m *testing.M) {
	if os.Getenv("CONSTELLATION_CATALOG_UPLOAD_FIXTURE") != "" && filepath.Base(os.Args[0]) == "aws" {
		catalogUploadFixture()
		return
	}
	if os.Getenv("CONSTELLATION_PGDUMP_FIXTURE") == "1" && filepath.Base(os.Args[0]) == "pg_dump" {
		pgdumpFixture()
		return
	}
	if os.Getenv("CONSTELLATION_BACKUP_MAIN_FIXTURE") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}
func pgdumpFixture() {
	root, err := os.OpenRoot(os.Getenv("CONSTELLATION_PGDUMP_FIXTURE_DIR"))
	if err != nil {
		os.Exit(80)
	}
	profile, err := os.Open(os.Getenv("PGSERVICEFILE"))
	if err != nil {
		os.Exit(81)
	}
	info, err := profile.Stat()
	if err != nil {
		os.Exit(82)
	}
	parsed, err := pgservicefile.ParseServicefile(profile)
	if err != nil {
		os.Exit(83)
	}
	if err = profile.Close(); err != nil {
		os.Exit(84)
	}
	service, err := parsed.GetService("constellation_backup")
	if err != nil {
		os.Exit(85)
	}
	receipt := map[string]any{"argv": os.Args[1:], "database_url_present": os.Getenv("DATABASE_URL") != "", "password_exact": os.Getenv("PGPASSWORD") == " fixture-password\n ", "profile_mode": uint32(info.Mode().Perm()), "host": service.Settings["host"], "dbname": service.Settings["dbname"], "sslmode": service.Settings["sslmode"], "options": service.Settings["options"], "profile_has_password": service.Settings["password"] != ""}
	file, err := root.OpenFile("receipt.json", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(86)
	}
	if err = json.NewEncoder(file).Encode(receipt); err != nil {
		os.Exit(87)
	}
	if err = file.Close(); err != nil {
		os.Exit(88)
	}
	if err = root.Close(); err != nil {
		os.Exit(89)
	}
	if _, err = fmt.Fprint(os.Stdout, "PGDMP-fixture-only"); err != nil {
		os.Exit(79)
	}
	if os.Getenv("CONSTELLATION_PGDUMP_FIXTURE_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "fixture-password-must-not-escape")
		os.Exit(3)
	}
	if os.Getenv("CONSTELLATION_PGDUMP_FIXTURE_WAIT") == "1" {
		time.Sleep(30 * time.Second)
	}
	os.Exit(0)
}
func preparePgDumpFixture(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	receipt := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(executable, filepath.Join(bin, "pg_dump")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	t.Setenv("PGSERVICE", "")
	t.Setenv("PGSERVICEFILE", "")
	t.Setenv("CONSTELLATION_PGDUMP_FIXTURE", "1")
	t.Setenv("CONSTELLATION_PGDUMP_FIXTURE_DIR", receipt)
	return receipt
}
func TestPgDumpPrivateUniqueDryRunAndCredentialBoundary(t *testing.T) {
	dir := preparePgDumpFixture(t)
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	t.Setenv("DATABASE_URL", "fixture-parent-credential")
	var log bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&log, nil))
	for i := 0; i < 2; i++ {
		if err := runPgDumpMode(t.Context(), logger, "postgresql://user:%20fixture-password%0A%20@localhost/database?sslmode=disable&options=-c%20statement_timeout%3D5000", "", "", "", true); err != nil {
			t.Fatal(err)
		}
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(log.String()), "\n") {
		var event map[string]any
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		if path, ok := event["path"].(string); ok {
			paths = append(paths, path)
		}
	}
	if len(paths) != 2 || paths[0] == paths[1] {
		t.Fatal("same-time dry runs collided")
	}
	for _, path := range paths {
		assertPrivateDump(t, path)
	}
	raw, err := readCLIFileFixture(filepath.Join(dir, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		Argv            []string `json:"argv"`
		Database        bool     `json:"database_url_present"`
		Password        bool     `json:"password_exact"`
		ProfilePassword bool     `json:"profile_has_password"`
		Mode            uint32   `json:"profile_mode"`
		Host            string   `json:"host"`
	}
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.Database || !r.Password || r.ProfilePassword || r.Mode != 0o600 || r.Host != "localhost" || strings.Contains(strings.Join(r.Argv, " "), "fixture-password") || strings.Contains(log.String(), "fixture-password") {
		t.Fatal("credential transport or redaction boundary violated")
	}
}
func TestPgDumpFailureRemovesPartialArtifactAndHidesChildOutput(t *testing.T) {
	preparePgDumpFixture(t)
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	t.Setenv("CONSTELLATION_PGDUMP_FIXTURE_FAIL", "1")
	var logs bytes.Buffer
	err := runPgDumpMode(t.Context(), slog.New(slog.NewJSONHandler(&logs, nil)), "host=localhost dbname=database password=fixture-password-must-not-escape", "bucket", "prefix", "", false)
	if err == nil || strings.Contains(err.Error()+logs.String(), "fixture-password") {
		t.Fatal("child failure accepted or credential disclosed")
	}
	entries, e := os.ReadDir(temp)
	if e != nil {
		t.Fatal(e)
	}
	if len(entries) != 0 {
		t.Fatal("partial workspace remains")
	}
}
func TestPgDumpRejectsExistingSymlinkWithoutTouchingSentinel(t *testing.T) {
	preparePgDumpFixture(t)
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	if err := os.WriteFile(sentinel, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "dump")
	if err := os.Symlink(sentinel, out); err != nil {
		t.Fatal(err)
	}
	if err := runPgDump(t.Context(), "host=localhost dbname=database", out); err == nil {
		t.Fatal("existing symlink accepted")
	}
	body, err := readCLIFileFixture(sentinel)
	if err != nil || string(body) != "untouched" {
		t.Fatal("sentinel changed")
	}
}
func TestPgDumpCancellationRemovesPartialWorkspace(t *testing.T) {
	receipt := preparePgDumpFixture(t)
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	t.Setenv("CONSTELLATION_PGDUMP_FIXTURE_WAIT", "1")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runPgDumpMode(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), "host=localhost dbname=database", "", "", "", true)
	}()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(receipt, "receipt.json")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child fixture did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled dump succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled dump did not stop")
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatal("canceled partial workspace retained")
	}
}
func TestOrgBackupInvalidSigningFailsBeforeDatabaseOrArtifact(t *testing.T) {
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	err := runOrgBackup(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), "not-a-database", orgBackupArgs{S3URI: "s3://backups/test", SignKey: "private", SignKeyless: true})
	if err == nil || strings.Contains(err.Error(), "database") {
		t.Fatal("invalid flags reached database")
	}
	entries, e := os.ReadDir(temp)
	if e != nil || len(entries) != 0 {
		t.Fatal("invalid flags created artifact")
	}
}
func TestOrgBackupMalformedDatabaseDoesNotExposeQueryPassword(t *testing.T) {
	err := runOrgBackup(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), "postgres://user@host/db?password=fixture-secret&sslmode=invalid", orgBackupArgs{OutPath: filepath.Join(t.TempDir(), "backup")})
	if err == nil || strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("database parse failure leaked or succeeded")
	}
}
func TestPgDumpDoesNotRemovePreexistingCredentialProfile(t *testing.T) {
	preparePgDumpFixture(t)
	dir := t.TempDir()
	profile := filepath.Join(dir, "pg_service.conf")
	if err := os.WriteFile(profile, []byte("existing-owned-configuration"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runPgDump(t.Context(), "host=localhost dbname=database", filepath.Join(dir, "dump")); err == nil {
		t.Fatal("profile collision accepted")
	}
	body, err := readCLIFileFixture(profile)
	if err != nil || string(body) != "existing-owned-configuration" {
		t.Fatal("preexisting profile removed or changed")
	}
}

func TestSignatureInspectionRejectsCorruptGzipTrailer(t *testing.T) {
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	writer := tar.NewWriter(gz)
	body := []byte("{\"format_version\":\"fixture\"}")
	if err := writer.WriteHeader(&tar.Header{Name: "manifest.json", Size: int64(len(body)), Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	valid := append([]byte(nil), archive.Bytes()...)
	if _, _, _, err := extractManifestAndSig(bytes.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	valid[len(valid)-8] ^= 0xff
	if _, _, _, err := extractManifestAndSig(bytes.NewReader(valid)); err == nil {
		t.Fatal("corrupt completed artifact accepted for verification")
	}
}

func TestMainRejectsInapplicableOrEmptySigningFlagsBeforeEffects(t *testing.T) {
	receipt := preparePgDumpFixture(t)
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"--mode=pg-dump", "--verify-key=unused"},
		{"--mode=pg-dump", "--verify-key="},
		{"--mode=pg-dump", "--sign-key="},
		{"--mode=pg-dump", "--sign-keyless=false"},
		{"--mode=org-backup", "--verify-key="},
		{"--mode=org-backup", "--sign-key="},
	}
	for _, flags := range cases {
		args := append([]string{"--database-url=fixture-credential-do-not-log", "--dry-run"}, flags...)
		command := exec.CommandContext(t.Context(), executable, args...)
		command.Env = append(os.Environ(), "CONSTELLATION_BACKUP_MAIN_FIXTURE=1")
		body, err := command.CombinedOutput()
		if err == nil || (!bytes.Contains(body, []byte("require --mode=org-backup")) && !bytes.Contains(body, []byte("must not be empty"))) || bytes.Contains(body, []byte("fixture-credential")) {
			t.Fatal("invalid explicit signing flags accepted or input disclosed")
		}
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid flags created artifact")
	}
	entries, err = os.ReadDir(receipt)
	if err != nil || len(entries) != 0 {
		t.Fatal("invalid flags started pg_dump")
	}
}

func assertPrivateDump(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || parent.Mode().Perm() != 0o700 {
		t.Fatal("dump artifact is not private")
	}
	if _, err = os.Stat(filepath.Join(filepath.Dir(path), "pg_service.conf")); !os.IsNotExist(err) {
		t.Fatal("database profile retained with artifact")
	}
}

func catalogUploadFixture() {
	root, err := os.OpenRoot(os.Getenv("CONSTELLATION_CATALOG_UPLOAD_FIXTURE"))
	if err != nil {
		os.Exit(90)
	}
	file, err := root.OpenFile("uploaded.tar.gz", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(91)
	}
	if _, err = io.Copy(file, io.LimitReader(os.Stdin, 64<<20)); err != nil {
		os.Exit(92)
	}
	if err = file.Close(); err != nil {
		os.Exit(93)
	}
	uri := ""
	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "s3://") {
			uri = arg
		}
	}
	if err = root.WriteFile("uri.txt", []byte(uri), 0o600); err != nil {
		os.Exit(94)
	}
	if err = root.Close(); err != nil {
		os.Exit(95)
	}
	os.Exit(0)
}

func TestEnvironmentCredentialsNeverAppearInFlagUsage(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://fixture:fixture-env-password@localhost/db?password=fixture-query-password")
	t.Setenv("BACKUP_S3_ENDPOINT", "https://fixture:fixture-endpoint-password@localhost")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"--help", "--unknown-fixture-flag"} {
		command := exec.CommandContext(t.Context(), executable, arg)
		command.Env = append(os.Environ(), "CONSTELLATION_BACKUP_MAIN_FIXTURE=1")
		body, _ := command.CombinedOutput()
		if bytes.Contains(body, []byte("fixture-env-password")) || bytes.Contains(body, []byte("fixture-query-password")) || bytes.Contains(body, []byte("fixture-endpoint-password")) {
			t.Fatal("environment credential appeared in flag usage")
		}
	}
}

func readCLIFileFixture(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	body, readErr := root.ReadFile(filepath.Base(path))
	return body, errors.Join(readErr, root.Close())
}
