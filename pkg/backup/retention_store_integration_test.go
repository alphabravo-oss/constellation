//go:build integration

package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func retentionFixture(t *testing.T) (*pgxpool.Pool, uuid.UUID, string) {
	t.Helper()
	pool := openConfigTestPool(t)
	org := uuid.New()
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, org.String()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "available.tar.gz")
	if err := os.WriteFile(path, []byte("nonempty protected artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	return pool, org, path
}

func TestRetentionHoldsWhenProtectedCopyUnavailable(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"no-path", "missing", "empty", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			pool, org, oldPath := retentionFixture(t)
			protected := filepath.Join(t.TempDir(), "protected")
			switch kind {
			case "no-path":
				protected = ""
			case "empty":
				if err := os.WriteFile(protected, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(oldPath, protected); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := pool.Exec(t.Context(), `INSERT INTO backups(org_id,status,started_at,local_path)
 VALUES($1,'succeeded',now()-interval '100 days',$2),($1,'succeeded',now()-interval '50 days',$3)`, org, oldPath, protected); err != nil {
				t.Fatal(err)
			}
			count, err := pruneLocalBackups(t.Context(), pool, org, 1, 1, time.Now(), nil)
			if err == nil || count != 0 {
				t.Fatalf("unavailable protected copy did not hold cleanup: count=%d err=%v", count, err)
			}
			var rows int
			if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM backups WHERE org_id=$1`, org).Scan(&rows); err != nil || rows != 2 {
				t.Fatalf("receipt lost: rows=%d err=%v", rows, err)
			}
			if _, err = os.Stat(oldPath); err != nil {
				t.Fatal("older available copy removed")
			}
		})
	}
}

func TestRetentionBoundedDrainAndConcurrentMaintainer(t *testing.T) {
	t.Parallel()
	pool, org, path := retentionFixture(t)
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(org_id,status,started_at,local_path)
 SELECT $1,'succeeded',now()-n*interval '1 minute',$2 FROM generate_series(0,204) n`, org, path); err != nil {
		t.Fatal(err)
	}
	locked, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = locked.Rollback(t.Context()) }()
	if _, err = locked.Exec(t.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "backup-retention:"+org.String()); err != nil {
		t.Fatal(err)
	}
	if got, err := pruneLocalBackups(t.Context(), pool, org, 1, 0, time.Now(), nil); err != nil || got != 0 {
		t.Fatalf("concurrent maintainer not skipped: count=%d err=%v", got, err)
	}
	if err = locked.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []int{100, 100, 4, 0} {
		if got, err := pruneLocalBackups(t.Context(), pool, org, 1, 0, time.Now(), nil); err != nil || got != want {
			t.Fatalf("bounded drain got=%d want=%d err=%v", got, want, err)
		}
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("shared protected artifact removed")
	}
	var rows int
	if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM backups WHERE org_id=$1`, org).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("minimum receipt floor: %d %v", rows, err)
	}
}

func TestRetentionCommitFailureKeepsFloorAndRetryReceipt(t *testing.T) {
	t.Parallel()
	pool, org, protected := retentionFixture(t)
	old := filepath.Join(t.TempDir(), "old")
	if err := os.WriteFile(old, []byte("eligible old backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO backups(org_id,status,started_at,local_path)
 VALUES($1,'succeeded',now(),$2),($1,'succeeded',now()-interval '10 days',$3)`, org, protected, old); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `CREATE FUNCTION reject_backup_prune() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'injected commit failure'; END$$;
 CREATE CONSTRAINT TRIGGER reject_backup_prune AFTER DELETE ON backups DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_backup_prune()`); err != nil {
		t.Fatal(err)
	}
	if got, err := pruneLocalBackups(t.Context(), pool, org, 1, 0, time.Now(), nil); err == nil || got != 0 {
		t.Fatalf("failed commit reported success: %d %v", got, err)
	}
	var rows int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM backups WHERE org_id=$1`, org).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("retry receipt lost: %d %v", rows, err)
	}
	if _, err := os.Stat(protected); err != nil {
		t.Fatal("protected artifact lost on failed commit")
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("expected file removal before injected commit failure: %v", err)
	}
	if _, err := pool.Exec(t.Context(), `DROP TRIGGER reject_backup_prune ON backups`); err != nil {
		t.Fatal(err)
	}
	if got, err := pruneLocalBackups(t.Context(), pool, org, 1, 0, time.Now(), nil); err != nil || got != 1 {
		t.Fatalf("missing-file retry failed: %d %v", got, err)
	}
}
