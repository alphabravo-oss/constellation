//go:build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestBackupCLIExplicitVerificationFailurePreventsUpload(t *testing.T) {
	pool := pgtest.Pool(t)
	org := uuid.New()
	if _, err := pool.Exec(t.Context(), "INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'CLI verification fixture')", org, "cli-"+org.String()); err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	private, public := filepath.Join(keys, "private"), filepath.Join(keys, "public")
	otherPrivate, otherPublic := filepath.Join(keys, "other-private"), filepath.Join(keys, "other-public")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	if err := backup.GenerateEd25519Keypair(otherPrivate, otherPublic); err != nil {
		t.Fatal(err)
	}
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	t.Setenv("PATH", t.TempDir())
	command := backupCmd()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"create", "--database-url", pgtest.URL(t), "--org-id", org.String(), "--s3", "s3://backups/prefix", "--sign-key", private, "--verify-key", otherPublic})
	err := command.Execute()
	if err == nil || !strings.Contains(err.Error(), "verification") {
		t.Fatal("failed verification did not stop upload")
	}
	var count int
	if err = pool.QueryRow(t.Context(), "SELECT count(*) FROM backups WHERE org_id=$1", org).Scan(&count); err != nil || count != 0 {
		t.Fatal("unverified backup reported in success catalog")
	}
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		t.Fatal("unverified temporary artifact retained")
	}
}

func TestBackupCLICatalogUncertaintyHasDiscoverableRecoveryReceipt(t *testing.T) {
	pool := pgtest.Pool(t)
	org := uuid.New()
	if _, err := pool.Exec(t.Context(), "INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'CLI catalog fixture')", org, "cli-"+org.String()); err != nil {
		t.Fatal(err)
	}
	name := "cli_catalog_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	function := pgx.Identifier{name}.Sanitize()
	trigger := pgx.Identifier{name + "_trigger"}.Sanitize()
	if _, err := pool.Exec(t.Context(), "CREATE FUNCTION "+function+"() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture-secret-must-not-escape'; END $$"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), "CREATE TRIGGER "+trigger+" BEFORE INSERT ON backups FOR EACH ROW WHEN(NEW.org_id='"+org.String()+"'::uuid) EXECUTE FUNCTION "+function+"()"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, e := pool.Exec(context.WithoutCancel(t.Context()), "DROP FUNCTION "+function+"() CASCADE"); e != nil {
			t.Error(e)
		}
	})
	upload := prepareCatalogUploadFixture(t)
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	command := backupCmd()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs([]string{"create", "--database-url", pgtest.URL(t), "--org-id", org.String(), "--s3", "s3://backups/catalog-proof"})
	err := command.Execute()
	if strings.Contains("\n"+output.String(), "\nuploaded ") {
		t.Fatal("unconfirmed catalog reported success")
	}
	assertCatalogRecoveryReceipt(t, err, temp, upload)
}

func TestMain(m *testing.M) {
	if os.Getenv("CONSTELLATION_CATALOG_UPLOAD_FIXTURE") != "" && filepath.Base(os.Args[0]) == "aws" {
		catalogUploadFixture()
		return
	}
	pgtest.Main(m)
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

func prepareCatalogUploadFixture(t *testing.T) string {
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
	t.Setenv("CONSTELLATION_CATALOG_UPLOAD_FIXTURE", dir)
	return dir
}

func assertCatalogRecoveryReceipt(t *testing.T, err error, temp, upload string) {
	t.Helper()
	if err == nil {
		t.Fatal("catalog failure returned success")
	}
	entries, e := os.ReadDir(temp)
	if e != nil || len(entries) != 1 || !entries[0].IsDir() {
		t.Fatal("completed temporary artifact was not preserved")
	}
	dir := filepath.Join(temp, entries[0].Name())
	files, e := os.ReadDir(dir)
	if e != nil || len(files) != 1 {
		t.Fatal("expected only the completed artifact")
	}
	path := filepath.Join(dir, files[0].Name())
	retained, e := readCLIFileFixture(path)
	if e != nil {
		t.Fatal(e)
	}
	uploaded, e := readCLIFileFixture(filepath.Join(upload, "uploaded.tar.gz"))
	if e != nil {
		t.Fatal(e)
	}
	uri, e := readCLIFileFixture(filepath.Join(upload, "uri.txt"))
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(retained, uploaded) {
		t.Fatal("preserved bytes differ from completed upload")
	}
	base := strings.TrimSuffix(files[0].Name(), ".tar.gz")
	if len(base) < 36 {
		t.Fatal("artifact UUID absent")
	}
	id := base[len(base)-36:]
	if !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), string(uri)) {
		t.Fatalf("catalog recovery receipt lacks path/job/object identity: %s", err)
	}
	if strings.Contains(err.Error(), "fixture-secret") {
		t.Fatal("raw catalog error escaped")
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
