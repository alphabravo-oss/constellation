package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupCLIInvalidSigningFlagsPrecedeDatabase(t *testing.T) {
	cases := [][]string{{"--sign-key", "private", "--sign-keyless"}, {"--verify-key", "public"}, {"--sign-keyless", "--verify-key", "public"}, {"--sign-key="}, {"--verify-key="}}
	for _, flags := range cases {
		command := backupCmd()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		args := []string{"create", "--database-url", "postgres://user@invalid/db?password=fixture-secret&sslmode=invalid", "--s3", "s3://backups/prefix"}
		args = append(args, flags...)
		command.SetArgs(args)
		err := command.Execute()
		if err == nil || strings.Contains(err.Error()+output.String(), "fixture-secret") || strings.Contains(err.Error(), "database") {
			t.Fatal("invalid signing flags reached database or leaked credential")
		}
	}
}
func TestBackupCLIConfigurationFailureHidesQueryPassword(t *testing.T) {
	command := backupCmd()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"create", "--database-url", "postgres://user@invalid/db?password=fixture-secret&sslmode=invalid", "--s3", "s3://backups/prefix"})
	err := command.Execute()
	if err == nil || strings.Contains(err.Error()+output.String(), "fixture-secret") {
		t.Fatal("configuration failure leaked or succeeded")
	}
}

func TestBackupDatabaseConfigurationErrorsAreCategorical(t *testing.T) {
	for _, args := range [][]string{{"list"}, {"restore", "unused"}} {
		cmd := backupCmd()
		cmd.SetArgs(append(args, "--database-url", "postgres://user@host/db?password=fixture-query-secret&sslmode=invalid"))
		if args[0] == "restore" { // Open a harmless private archive before parsing the DB options.
			path := filepath.Join(t.TempDir(), "archive")
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			cmd.SetArgs([]string{"restore", path, "--database-url", "postgres://user@host/db?password=fixture-query-secret&sslmode=invalid"})
		}
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		err := cmd.Execute()
		if err == nil || strings.Contains(err.Error(), "fixture-query-secret") {
			t.Fatal("database parse error leaked or succeeded")
		}
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
	if _, _, _, err := extractCLIManifestAndSig(bytes.NewReader(valid)); err != nil {
		t.Fatal(err)
	}
	valid[len(valid)-8] ^= 0xff
	if _, _, _, err := extractCLIManifestAndSig(bytes.NewReader(valid)); err == nil {
		t.Fatal("corrupt completed artifact accepted for verification")
	}
}
