//go:build integration

package backup

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func freshRestorePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), pgtest.FreshURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err = database.MigratePool(t.Context(), pool, slog.Default()); err != nil {
		t.Fatal(err)
	}
	return pool
}

func seedScheduledRestoreOrganization(t *testing.T, pool *pgxpool.Pool) (string, string, string) {
	t.Helper()
	org, _ := seedConfigOrg(t, pool)
	var name string
	if err := pool.QueryRow(t.Context(), `SELECT name FROM orgs WHERE id=$1`, org).Scan(&name); err != nil {
		t.Fatal(err)
	}
	var cluster string
	if err := pool.QueryRow(t.Context(), `INSERT INTO clusters(org_id,name) VALUES($1,'portable-cluster') RETURNING id::text`, org).Scan(&cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE policies SET cluster_id=$2 WHERE org_id=$1`, org, cluster); err != nil {
		t.Fatal(err)
	}
	return org, name, cluster
}

func TestScheduledArtifactIndependentRestore(t *testing.T) {
	t.Parallel()
	source := openConfigTestPool(t)
	org, name, cluster := seedScheduledRestoreOrganization(t, source)
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	if err := GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	runScheduledBackup(t.Context(), source, ScheduleExecutorConfig{BackupDir: t.TempDir(), SignKeyPath: private}, schedule{OrgID: uuid.MustParse(org), OrgName: name, CronExpr: "0 3 * * *", SignMode: "static-key"}, time.Now(), nil)
	var path string
	if err := source.QueryRow(t.Context(), `SELECT local_path FROM backups WHERE org_id=$1 AND status='succeeded'`, org).Scan(&path); err != nil {
		t.Fatal(err)
	}
	source.Close()
	// Separate database, with no source connection available to the restore path.
	dest := freshRestorePool(t)
	started := time.Now()
	for range 2 {
		file, err := OpenArtifact(path)
		if err != nil {
			t.Fatal(err)
		}
		result, restoreErr := Restore(t.Context(), dest, RestoreOptions{In: file, Verify: VerifierOptions{Mode: SignModeStaticKey, KeyPath: public}})
		closeErr := file.Close()
		if restoreErr != nil || closeErr != nil || result == nil || !result.Verified {
			t.Fatalf("independent signed restore failed: %v %v", restoreErr, closeErr)
		}
	}
	assertRestoredOrganization(t, dest, name, org, cluster)
	t.Logf("independent scheduled artifact restore and idempotent replay: %s", time.Since(started))
	// No test artifact is installed into the deployment's backup catalog or paths.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func assertRestoredOrganization(t *testing.T, pool *pgxpool.Pool, name, sourceOrg, sourceCluster string) {
	t.Helper()
	var org, cluster string
	if err := pool.QueryRow(t.Context(), `SELECT o.id::text,c.id::text FROM orgs o JOIN clusters c ON c.org_id=o.id WHERE o.name=$1 AND c.name='portable-cluster'`, name).Scan(&org, &cluster); err != nil {
		t.Fatal(err)
	}
	if org == sourceOrg || cluster == sourceCluster {
		t.Fatal("restore reused source database identities")
	}
	var users, roles, policies, tokens int
	var theme string
	var hasSecrets bool
	err := pool.QueryRow(t.Context(), `SELECT
 (SELECT count(*) FROM users WHERE org_id=$1),
 (SELECT count(*) FROM custom_roles WHERE org_id=$1),
 (SELECT count(*) FROM policies WHERE org_id=$1 AND cluster_id=$2),
 (SELECT count(*) FROM api_tokens t JOIN users u ON t.user_id=u.id WHERE u.org_id=$1),
 settings->>'theme',settings ?| ARRAY['registry_kek','slack_webhook_token','smtp_password']
 FROM org_settings WHERE org_id=$1`, org, cluster).Scan(&users, &roles, &policies, &tokens, &theme, &hasSecrets)
	if err != nil || users != 1 || roles != 1 || policies != 2 || tokens != 0 || theme != "dark" || hasSecrets {
		t.Fatalf("restored configuration mismatch: users=%d roles=%d policies=%d tokens=%d theme=%q secrets=%v err=%v", users, roles, policies, tokens, theme, hasSecrets, err)
	}
}
