package backup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestExportAtomicSignedArchivePreservesExplicitCLIContract(t *testing.T) {
	pool := openConfigTestPool(t)
	t.Cleanup(pool.Close)
	org, cleanup := seedConfigOrg(t, pool)
	t.Cleanup(cleanup)
	const orgName = "../Human Org/\"original\""
	if _, err := pool.Exec(t.Context(), `UPDATE orgs SET name=$2 WHERE id=$1`, org, orgName); err != nil {
		t.Fatal(err)
	}
	keys := t.TempDir()
	private, public := filepath.Join(keys, "private"), filepath.Join(keys, "public")
	if err := GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "caller-parent")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "explicit.tar.gz")
	if err := os.WriteFile(path, []byte("prior output"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ExportToFile(t.Context(), pool, path, ExportOptions{OrgID: org, Sign: SignerOptions{Mode: SignModeStaticKey, KeyPath: private}})
	if err != nil {
		t.Fatal(err)
	}
	file, err := OpenArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	verified, verifyErr := VerifyArchive(RestoreOptions{In: file, Verify: VerifierOptions{KeyPath: public}})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if verifyErr != nil || !verified.Verified || verified.Manifest.OrgName != orgName {
		t.Fatalf("signed archive changed: %+v %v", verified, verifyErr)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || result.Bytes != info.Size() {
		t.Fatalf("file mode=%o size=%d result=%d", info.Mode().Perm(), info.Size(), result.Bytes)
	}
	parent, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm() != 0o750 {
		t.Fatal("explicit CLI parent permissions changed")
	}
	before := readArtifactTestFile(t, path)
	_, err = ExportToFile(t.Context(), pool, path, ExportOptions{OrgID: org, Sign: SignerOptions{Mode: SignModeStaticKey, KeyPath: filepath.Join(keys, "missing")}})
	if err == nil {
		t.Fatal("signing failure accepted")
	}
	after := readArtifactTestFile(t, path)
	if before != after {
		t.Fatal("signing failure destroyed prior complete signed artifact")
	}
}

func TestScheduledBackupsSameTimestampHaveIndependentArtifacts(t *testing.T) {
	pool := openConfigTestPool(t)
	t.Cleanup(pool.Close)
	org, cleanup := seedConfigOrg(t, pool)
	t.Cleanup(cleanup)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM backups WHERE org_id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	orgID := uuid.MustParse(org)
	name := "same organization"
	if _, err := pool.Exec(t.Context(), `UPDATE orgs SET name=$2 WHERE id=$1`, orgID, name); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 17, 1, 2, 3, 0, time.UTC)
	dir := t.TempDir()
	cfg := ScheduleExecutorConfig{BackupDir: dir}
	s := schedule{OrgID: orgID, OrgName: name, CronExpr: "0 3 * * *", SignMode: "none"}
	runScheduledBackup(t.Context(), pool, cfg, s, now, nil)
	runScheduledBackup(t.Context(), pool, cfg, s, now, nil)
	paths := scheduledArtifactPaths(t, pool, orgID, dir)
	if len(paths) != 2 {
		t.Fatalf("same-timestamp jobs shared artifact identity: unique paths=%d", len(paths))
	}
	for path, id := range paths {
		if filepath.Base(path) != ArtifactName(name, id, now) {
			t.Fatal("artifact lost job identity")
		}
		file, err := OpenArtifact(path)
		if err != nil {
			t.Fatal(err)
		}
		result, verifyErr := VerifyArchive(RestoreOptions{In: file, AllowUnverified: true})
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if verifyErr != nil || result.Manifest.OrgName != name {
			t.Fatalf("artifact invalid: %+v %v", result, verifyErr)
		}
	}
}

func scheduledArtifactPaths(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, dir string) map[string]uuid.UUID {
	t.Helper()
	rows, err := pool.Query(t.Context(), `SELECT id,local_path,status FROM backups WHERE org_id=$1 ORDER BY id`, orgID)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var path, status string
		if err := rows.Scan(&id, &path, &status); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if status != "succeeded" || filepath.Dir(path) != dir {
			rows.Close()
			t.Fatalf("identity id=%s path=%q status=%s", id, path, status)
		}
		paths[path] = id
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	return paths
}

func TestBackupRetentionPreservesCatalogOnUnsafeArtifact(t *testing.T) {
	pool := openConfigTestPool(t)
	t.Cleanup(pool.Close)
	org, cleanup := seedConfigOrg(t, pool)
	t.Cleanup(cleanup)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM backups WHERE org_id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	link := filepath.Join(root, "old-backup")
	if err := os.WriteFile(victim, []byte("unrelated private data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	old, newID := uuid.New(), uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(id,org_id,mode,status,started_at,local_path) VALUES($1,$2,'org-backup','succeeded',now()-interval '2 days',$3),($4,$2,'org-backup','succeeded',now(),NULL)`, old, org, link, newID); err != nil {
		t.Fatal(err)
	}
	if n := applyRetention(t.Context(), pool, uuid.MustParse(org), 1, 0, time.Now(), nil); n != 0 {
		t.Fatalf("unsafe artifact reported pruned=%d", n)
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM backups WHERE id=$1`, old).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("failed cleanup discarded catalog")
	}
	if readArtifactTestFile(t, victim) != "unrelated private data" {
		t.Fatal("retention changed symlink target")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("owned archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if n := applyRetention(t.Context(), pool, uuid.MustParse(org), 1, 0, time.Now(), nil); n != 1 {
		t.Fatalf("regular cleanup pruned=%d", n)
	}
	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("artifact not removed: %v", err)
	}
}

func TestBackupRetentionPreservesSharedCatalogArtifacts(t *testing.T) {
	pool := openConfigTestPool(t)
	t.Cleanup(pool.Close)
	org, cleanup := seedConfigOrg(t, pool)
	t.Cleanup(cleanup)
	foreign := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, foreign, foreign.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM orgs WHERE id=$1`, foreign); err != nil {
			t.Error(err)
		}
	})
	for _, kind := range []string{"same owner", "foreign owner", "null owner"} {
		t.Run(kind, func(t *testing.T) { assertSharedRetentionArtifact(t, pool, org, foreign, kind) })
	}
}

func assertSharedRetentionArtifact(t *testing.T, pool *pgxpool.Pool, org string, foreign uuid.UUID, kind string) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "legacy-shared.tar.gz")
	if err := os.WriteFile(path, []byte("still referenced"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, reference, keep := uuid.New(), uuid.New(), uuid.New()
	ids := []uuid.UUID{old, reference, keep}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM backups WHERE id=ANY($1)`, ids); err != nil {
			t.Error(err)
		}
	})
	owner := any(org)
	if kind == "foreign owner" {
		owner = foreign
	}
	if kind == "null owner" {
		owner = nil
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(id,org_id,mode,status,started_at,local_path) VALUES($1,$2,'org-backup','succeeded',now()-interval '2 days',$3),($4,$5,'org-backup','succeeded',now(),$3)`, old, org, path, reference, owner); err != nil {
		t.Fatal(err)
	}
	if kind != "same owner" {
		if _, err := pool.Exec(t.Context(), `INSERT INTO backups(id,org_id,mode,status,started_at) VALUES($1,$2,'org-backup','succeeded',now()+interval '1 hour')`, keep, org); err != nil {
			t.Fatal(err)
		}
	}
	if n := applyRetention(t.Context(), pool, uuid.MustParse(org), 1, 0, time.Now(), nil); n != 1 {
		t.Fatalf("catalog pruned=%d", n)
	}
	if readArtifactTestFile(t, path) != "still referenced" {
		t.Fatal("referenced artifact removed")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM backups WHERE id=$1`, reference).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("unselected reference deleted")
	}
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM backups WHERE id=$1`, old).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("selected owned catalog row retained")
	}
}
