//go:build integration

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func backupFixturePool(t *testing.T) (*pgxpool.Pool, string, uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("owned disposable database required")
	}
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal("fixture pool failed")
	}
	t.Cleanup(pool.Close)
	var name string
	if err = pool.QueryRow(t.Context(), "SELECT current_database()").Scan(&name); err != nil || name != "constellation_test" {
		t.Fatal("refusing non-disposable database")
	}
	org := uuid.New()
	_, err = pool.Exec(t.Context(), "INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'CLI fixture')", org, "cli-"+org.String())
	if err != nil {
		t.Fatal(err)
	}
	return pool, dsn, org
}
func failureTrigger(t *testing.T, pool *pgxpool.Pool, org uuid.UUID, event, condition string) {
	t.Helper()
	name := "cli_fail_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	function := pgx.Identifier{name}.Sanitize()
	trigger := pgx.Identifier{name + "_trigger"}.Sanitize()
	sql := "CREATE FUNCTION " + function + "() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture-secret-must-not-escape'; END $$"
	if _, err := pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	sql = "CREATE TRIGGER " + trigger + " BEFORE " + event + " ON backups FOR EACH ROW WHEN(NEW.org_id='" + org.String() + "'::uuid" + condition + ") EXECUTE FUNCTION " + function + "()"
	if _, err := pool.Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), "DROP FUNCTION "+function+"() CASCADE"); err != nil {
			t.Error(err)
		}
	})
}
func TestStandaloneCatalogInsertFailureStopsBeforeExport(t *testing.T) {
	pool, dsn, org := backupFixturePool(t)
	failureTrigger(t, pool, org, "INSERT", "")
	dir := t.TempDir()
	out := filepath.Join(dir, "backup.tar.gz")
	var logs bytes.Buffer
	err := runOrgBackup(t.Context(), slog.New(slog.NewJSONHandler(&logs, nil)), dsn, orgBackupArgs{OrgID: org.String(), OutPath: out})
	if err == nil || strings.Contains(err.Error()+logs.String(), "fixture-secret") {
		t.Fatal("catalog failure leaked or succeeded")
	}
	if _, err = os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("export continued after catalog insertion failure")
	}
}
func TestStandaloneExplicitVerificationFailurePreventsUpload(t *testing.T) {
	pool, dsn, org := backupFixturePool(t)
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
	t.Setenv("PATH", t.TempDir()) // No upload subprocess can run.
	err := runOrgBackup(t.Context(), slog.New(slog.NewTextHandler(io.Discard, nil)), dsn, orgBackupArgs{OrgID: org.String(), S3URI: "s3://backups/prefix", SignKey: private, VerifyKey: otherPublic})
	if err == nil || !strings.Contains(err.Error(), "verification") {
		t.Fatal("wrong verification key did not stop before upload")
	}
	var status string
	if e := pool.QueryRow(t.Context(), "SELECT status FROM backups WHERE org_id=$1", org).Scan(&status); e != nil || status != "failed" {
		t.Fatal("failed verification not recorded honestly")
	}
	entries, e := os.ReadDir(temp)
	if e != nil || len(entries) != 0 {
		t.Fatal("unverified temporary artifact retained")
	}
}
func TestStandaloneCatalogCompletionFailurePreservesValidExplicitArtifact(t *testing.T) {
	pool, dsn, org := backupFixturePool(t)
	failureTrigger(t, pool, org, "UPDATE", " AND NEW.status='succeeded'")
	out := filepath.Join(t.TempDir(), "retained.tar.gz")
	var logs bytes.Buffer
	err := runOrgBackup(t.Context(), slog.New(slog.NewJSONHandler(&logs, nil)), dsn, orgBackupArgs{OrgID: org.String(), OutPath: out})
	if err == nil || strings.Contains(err.Error()+logs.String(), "fixture-secret") || strings.Contains(logs.String(), "backup recorded") {
		t.Fatal("catalog acknowledgment failure leaked or reported success")
	}
	file, e := backup.OpenArtifact(out)
	if e != nil {
		t.Fatal("completed artifact deleted")
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestStandaloneCatalogUncertaintyHasDiscoverableRecoveryReceipt(t *testing.T) {
	pool, dsn, org := backupFixturePool(t)
	failureTrigger(t, pool, org, "UPDATE", " AND NEW.status='succeeded'")
	upload := prepareCatalogUploadFixture(t)
	temp := t.TempDir()
	t.Setenv("TMPDIR", temp)
	var logs bytes.Buffer
	err := runOrgBackup(t.Context(), slog.New(slog.NewJSONHandler(&logs, nil)), dsn, orgBackupArgs{OrgID: org.String(), S3URI: "s3://backups/catalog-proof"})
	if strings.Contains(logs.String(), "backup recorded") {
		t.Fatal("unconfirmed catalog reported success")
	}
	assertCatalogRecoveryReceipt(t, err, temp, upload)
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
