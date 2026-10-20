package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

type backupSigningFixture struct {
	h         *Backups
	database  *db.DB
	org, user uuid.UUID
}

func newBackupSigningFixture(t *testing.T) backupSigningFixture {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	f := backupSigningFixture{database: database, org: uuid.New(), user: uuid.New()}
	f.h = &Backups{db: database, audit: audit.New(database.Pool()), dir: t.TempDir()}
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, f.org, "signing-"+f.org.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		if _, err := database.Pool().Exec(ctx, `DELETE FROM backups WHERE org_id=$1`, f.org); err != nil {
			t.Error(err)
		}
		if _, err := database.Pool().Exec(ctx, `DELETE FROM orgs WHERE id=$1`, f.org); err != nil {
			t.Error(err)
		}
	})
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO users(id,org_id,email,display_name,password_hash) VALUES($1,$2,$3,'signing operator','test-only')`, f.user, f.org, "signing-"+f.user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f backupSigningFixture) post(t *testing.T, body string, schedule bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/backups", strings.NewReader(body))
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: f.org, UserID: f.user}))
	response := httptest.NewRecorder()
	if schedule {
		f.h.PutSchedule(response, request)
	} else {
		f.h.Create(response, request)
	}
	return response
}

func (f backupSigningFixture) waitJob(t *testing.T, id uuid.UUID) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var status string
		var complete bool
		if err := f.database.Pool().QueryRow(ctx, `SELECT status,
 EXISTS(SELECT 1 FROM audit_events WHERE org_id=$2 AND action='backup.complete' AND target_id=$1::uuid::text)
 FROM backups WHERE id=$1 AND org_id=$2`, id, f.org).Scan(&status, &complete); err != nil {
			t.Fatal(err)
		}
		// Success is published just before its final audit. Wait for both so a
		// test never tears down the owned org while that audit is still writing.
		if status != "running" && (status != "succeeded" || complete) {
			return status
		}
		select {
		case <-ctx.Done():
			t.Fatal("owned backup did not finish before fixture cleanup")
		case <-ticker.C:
		}
	}
}

func (f backupSigningFixture) requestJob(t *testing.T, body string) uuid.UUID {
	t.Helper()
	response := f.post(t, body, false)
	var receipt struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if response.Code != 202 || receipt.ID == uuid.Nil {
		t.Fatalf("start failed: %d %s", response.Code, response.Body.String())
	}
	return receipt.ID
}

func TestBackupInvalidSigningRequestHasNoJobAuditOrArtifact(t *testing.T) {
	f := newBackupSigningFixture(t)
	response := f.post(t, `{"sign_mode":"static_key"}`, false)
	if response.Code == 202 {
		// The unpatched negative control starts real owned work. Drain it before
		// fixture cleanup so the expected failure never leaves detached goroutines.
		var receipt struct {
			ID uuid.UUID `json:"id"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &receipt); err != nil {
			t.Fatal(err)
		}
		status := f.waitJob(t, receipt.ID)
		var signed bool
		if err := f.database.Pool().QueryRow(t.Context(), `SELECT signed FROM backups WHERE id=$1`, receipt.ID).Scan(&signed); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("invalid signing request started job: status=%s signed=%v", status, signed)
	}
	if response.Code != 400 {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	for _, query := range []string{`SELECT COUNT(*) FROM backups WHERE org_id=$1`, `SELECT COUNT(*) FROM audit_events WHERE org_id=$1`} {
		var count int
		if err := f.database.Pool().QueryRow(t.Context(), query, f.org).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("invalid request created side effects: count=%d", count)
		}
	}
	entries, err := os.ReadDir(f.h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("invalid request created artifact")
	}
}

func TestBackupOneOffDefaultsDoNotInheritScheduleAndStaticModeVerifies(t *testing.T) {
	f := newBackupSigningFixture(t)
	t.Setenv("CONSTELLATION_BACKUP_SIGN_KEY", "")
	if response := f.post(t, `{}`, true); response.Code != 200 {
		t.Fatalf("default schedule rejected: %s", response.Body.String())
	}
	for _, body := range []string{"", `{"sign_mode":""}`} {
		id := f.requestJob(t, body)
		if status := f.waitJob(t, id); status != "succeeded" {
			t.Fatalf("one-off default changed: %s", status)
		}
		var signed bool
		if err := f.database.Pool().QueryRow(t.Context(), `SELECT signed FROM backups WHERE id=$1`, id).Scan(&signed); err != nil {
			t.Fatal(err)
		}
		if signed {
			t.Fatal("one-off inherited schedule signing")
		}
	}
	private, public := filepath.Join(t.TempDir(), "private"), filepath.Join(t.TempDir(), "public")
	if err := backup.GenerateEd25519Keypair(private, public); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_BACKUP_SIGN_KEY", private)
	id := f.requestJob(t, `{"sign_mode":"static-key"}`)
	if status := f.waitJob(t, id); status != "succeeded" {
		t.Fatalf("static backup status=%s", status)
	}
	var path string
	var signed bool
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT local_path,signed FROM backups WHERE id=$1`, id).Scan(&path, &signed); err != nil {
		t.Fatal(err)
	}
	file, err := backup.OpenArtifact(path)
	if err != nil {
		t.Fatal(err)
	}
	result, verifyErr := backup.VerifyArchive(context.Background(), backup.RestoreOptions{In: file, Verify: backup.VerifierOptions{KeyPath: public}})
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if verifyErr != nil || !result.Verified || !signed {
		t.Fatalf("requested signing not honored: signed=%v result=%+v error=%v", signed, result, verifyErr)
	}
}

func TestBackupInvalidScheduleDoesNotMutateSavedModeOrAudit(t *testing.T) {
	f := newBackupSigningFixture(t)
	if response := f.post(t, `{"enabled":true,"sign_mode":"static-key"}`, true); response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	for _, body := range []string{`{"sign_mode":"static_key"}`, `{"sign_mode":"none"} {}`, `{"sign_mode":"none","sign_mode":"static-key"}`, `{"sign_mode":null}`} {
		response := f.post(t, body, true)
		if response.Code != 400 {
			t.Fatalf("schedule status=%d body=%s", response.Code, response.Body.String())
		}
	}
	var mode string
	var audits int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT sign_mode FROM backup_schedules WHERE org_id=$1`, f.org).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='backup.schedule.update'`, f.org).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if mode != "static-key" || audits != 1 {
		t.Fatalf("invalid schedule mutated state/audit: mode=%q audits=%d", mode, audits)
	}
	if _, err := f.database.Pool().Exec(t.Context(), `UPDATE backup_schedules SET sign_mode='static_key' WHERE org_id=$1`, f.org); err == nil {
		t.Fatal("database signing CHECK not enforced")
	}
}

func TestBackupWorkersNeverDowngradeInvalidOrUnavailableSigners(t *testing.T) {
	for _, mode := range []string{"static_key", "static-key", "keyless"} {
		t.Run(mode, func(t *testing.T) { assertBackupWorkerFailsClosed(t, mode) })
	}
}

func assertBackupWorkerFailsClosed(t *testing.T, mode string) {
	t.Helper()
	f := newBackupSigningFixture(t)
	t.Setenv("CONSTELLATION_BACKUP_SIGN_KEY", "")
	t.Setenv("PATH", t.TempDir())
	id := uuid.New()
	if _, err := f.database.Pool().Exec(t.Context(), `INSERT INTO backups(id,org_id,mode,status) VALUES($1,$2,'org-backup','running')`, id, f.org); err != nil {
		t.Fatal(err)
	}
	f.h.runBackupJob(id, f.org.String(), f.user.String(), mode)
	if status := f.waitJob(t, id); status != "failed" {
		t.Fatalf("mode %q downgraded: status=%s", mode, status)
	}
	var path string
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT COALESCE(local_path,'') FROM backups WHERE id=$1`, id).Scan(&path); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(f.h.dir)
	if err != nil {
		t.Fatal(err)
	}
	if path != "" || len(entries) != 0 {
		t.Fatal("failed signer published artifact")
	}
}
