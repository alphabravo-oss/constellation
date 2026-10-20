//go:build integration

package handler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
)

type backupTerminalLogs struct {
	mu   sync.Mutex
	body bytes.Buffer
}

func (logs *backupTerminalLogs) Write(body []byte) (int, error) {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	return logs.body.Write(body)
}

func (logs *backupTerminalLogs) String() string {
	logs.mu.Lock()
	defer logs.mu.Unlock()
	return logs.body.String()
}

func captureBackupTerminalLogs(t *testing.T) *backupTerminalLogs {
	t.Helper()
	logs := &backupTerminalLogs{}
	prior := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prior) })
	return logs
}

func insertBackupTerminalRow(t *testing.T, f backupSigningFixture, status string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := f.database.Pool().Exec(t.Context(), `
INSERT INTO backups(id,org_id,mode,status,error)
VALUES($1,$2,'org-backup',$3,'prior status')`, id, f.org, status); err != nil {
		t.Fatal(err)
	}
	return id
}

func backupTerminalRow(t *testing.T, f backupSigningFixture, id uuid.UUID) (string, string, *time.Time) {
	t.Helper()
	var status, message string
	var finished *time.Time
	if err := f.database.Pool().QueryRow(t.Context(), `
SELECT status, error, finished_at FROM backups WHERE id=$1 AND org_id=$2`, id, f.org).
		Scan(&status, &message, &finished); err != nil {
		t.Fatal(err)
	}
	return status, message, finished
}

func TestBackupExpiredExportContextStillRecordsTerminalFailure(t *testing.T) {
	for _, cause := range []string{"deadline", "cancellation"} {
		t.Run(cause, func(t *testing.T) {
			f := newBackupSigningFixture(t)
			id := insertBackupTerminalRow(t, f, "running")
			var exportCtx context.Context
			var cancel context.CancelFunc
			want := context.Canceled
			if cause == "deadline" {
				exportCtx, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			} else {
				exportCtx, cancel = context.WithCancel(t.Context())
				cancel()
			}
			defer cancel()
			if !errors.Is(exportCtx.Err(), want) {
				t.Fatal("export context fixture was not canceled")
			}
			f.h.markFailed(exportCtx, id, f.org.String(), "export: fixture stopped")
			status, message, finished := backupTerminalRow(t, f, id)
			if status != "failed" || message != "export: fixture stopped" || finished == nil {
				t.Fatal("expired export left its backup running or lost terminal failure evidence")
			}
			if !errors.Is(exportCtx.Err(), want) {
				t.Fatal("bookkeeping revived or replaced the canceled export context")
			}
		})
	}
}

func TestBackupTerminalFailureRequiresExactRunningOwner(t *testing.T) {
	f := newBackupSigningFixture(t)
	logs := captureBackupTerminalLogs(t)
	running := insertBackupTerminalRow(t, f, "running")
	completed := insertBackupTerminalRow(t, f, "succeeded")
	for _, target := range []struct {
		id  uuid.UUID
		org uuid.UUID
	}{{running, uuid.New()}, {uuid.New(), f.org}, {completed, f.org}} {
		f.h.markFailed(t.Context(), target.id, target.org.String(), "replacement failure")
	}
	for _, row := range []struct {
		id     uuid.UUID
		status string
	}{{running, "running"}, {completed, "succeeded"}} {
		status, message, finished := backupTerminalRow(t, f, row.id)
		if status != row.status || message != "prior status" || finished != nil {
			t.Fatal("failure bookkeeping changed a foreign, absent, or already terminal backup")
		}
	}
	if strings.Count(logs.String(), "backup: failed to record terminal status") != 3 {
		t.Fatal("unconfirmed terminal updates were reported as completed bookkeeping")
	}
}

func TestBackupTerminalFailureDatabaseErrorIsReportedCategorically(t *testing.T) {
	pool, err := pgxpool.New(t.Context(), "postgres://fixture@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	pool.Close()
	h := &Backups{db: db.NewFromPool(pool)}
	logs := captureBackupTerminalLogs(t)
	id, org := uuid.New(), uuid.New()
	exportCtx, cancel := context.WithCancel(t.Context())
	cancel()
	h.markFailed(exportCtx, id, org.String(), "fixture-private-export-failure")
	message := logs.String()
	if !strings.Contains(message, "backup: failed to record terminal status") || !strings.Contains(message, id.String()) || !strings.Contains(message, org.String()) {
		t.Fatal("failed database update was silently treated as completed bookkeeping")
	}
	for _, raw := range []string{"fixture-private-export-failure", "closed pool", "postgres://", "127.0.0.1"} {
		if strings.Contains(message, raw) {
			t.Fatal("terminal-status log exposed raw database or export diagnostics")
		}
	}
	if !errors.Is(exportCtx.Err(), context.Canceled) {
		t.Fatal("failed bookkeeping changed the canceled export context")
	}
}

func TestBackupTerminalFailureBookkeepingHasIndependentFiniteDeadline(t *testing.T) {
	f := newBackupSigningFixture(t)
	logs := captureBackupTerminalLogs(t)
	id := insertBackupTerminalRow(t, f, "running")
	lock, err := f.database.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if err := lock.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error(err)
		}
	}()
	if _, err := lock.Exec(t.Context(), `SELECT id FROM backups WHERE id=$1 AND org_id=$2 FOR UPDATE`, id, f.org); err != nil {
		t.Fatal(err)
	}
	exportCtx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	done := make(chan struct{})
	go func() { f.h.markFailed(exportCtx, id, f.org.String(), "export: fixture timed out"); close(done) }()
	select {
	case <-done:
	case <-time.After(7 * time.Second):
		// Release the owned row lock before failing so even an unbounded negative
		// control finishes its database operation and cannot outlive this fixture.
		if err := lock.Rollback(t.Context()); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("bookkeeping did not finish after its owned lock was released")
		}
		t.Fatal("terminal-status bookkeeping did not respect its short finite deadline")
	}
	status, message, finished := backupTerminalRow(t, f, id)
	if status != "running" || message != "prior status" || finished != nil || !strings.Contains(logs.String(), "backup: failed to record terminal status") {
		t.Fatal("blocked terminal update was claimed complete or its failure was hidden")
	}
	if !errors.Is(exportCtx.Err(), context.DeadlineExceeded) {
		t.Fatal("bounded bookkeeping revived its expired export context")
	}
}
