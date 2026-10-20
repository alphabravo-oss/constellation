//go:build integration

package backup

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestScheduledBackupRejectsUnknownModeAndKeepsStaticDefault(t *testing.T) {
	for _, mode := range []string{"static_key", ""} {
		t.Run(mode, func(t *testing.T) { assertScheduledSigningFailure(t, mode) })
	}
}

func assertScheduledSigningFailure(t *testing.T, mode string) {
	t.Helper()
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
	if _, err := pool.Exec(t.Context(), `INSERT INTO backup_schedules(org_id,sign_mode) VALUES($1,'static-key')`, orgID); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	s := schedule{OrgID: orgID, OrgName: "source name", CronExpr: "0 3 * * *", SignMode: mode}
	runScheduledBackup(t.Context(), pool, ScheduleExecutorConfig{BackupDir: dir}, s, time.Now(), nil)
	var status, path string
	if err := pool.QueryRow(t.Context(), `SELECT status,COALESCE(local_path,'') FROM backups WHERE org_id=$1`, orgID).Scan(&status, &path); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || path != "" {
		t.Fatalf("schedule mode %q downgraded: status=%s path=%q", mode, status, path)
	}
	var last string
	if err := pool.QueryRow(t.Context(), `SELECT last_status FROM backup_schedules WHERE org_id=$1`, orgID).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if last != "failed" {
		t.Fatalf("failed signing reported schedule=%q", last)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("invalid schedule published artifact")
	}
}
