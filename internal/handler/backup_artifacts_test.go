//go:build integration

package handler

import (
	"bytes"
	"context"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestBackupJobsOverlapWithoutArtifactCollision(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	pool := d.Pool()
	org, user := uuid.New(), uuid.New()
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	name := "../../human/organization\""
	if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, name); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'Backup operator')`, user, org, "backup-"+user.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		if _, err := pool.Exec(ctx, `DELETE FROM backups WHERE org_id=$1`, org); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org); err != nil {
			t.Error(err)
		}
	})
	for _, id := range ids {
		if _, err := pool.Exec(t.Context(), `INSERT INTO backups(id,org_id,mode,status) VALUES($1,$2,'org-backup','running')`, id, org); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), "managed")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	h := &Backups{db: d, audit: audit.New(pool), dir: dir}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; h.runBackupJob(id, org.String(), user.String(), "none") }()
	}
	close(start)
	wg.Wait()
	paths := map[string]bool{}
	for _, id := range ids {
		assertCompletedBackupArtifact(t, h, id, org, name, dir, paths)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatal("managed backup directory not private")
	}
}

func assertCompletedBackupArtifact(t *testing.T, h *Backups, id, org uuid.UUID, name, dir string, paths map[string]bool) {
	t.Helper()
	var status, path string
	var size int64
	if err := h.db.Pool().QueryRow(t.Context(), `SELECT status,COALESCE(local_path,''),size_bytes FROM backups WHERE id=$1 AND org_id=$2`, id, org).Scan(&status, &path, &size); err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" || paths[path] || filepath.Dir(path) != dir || !strings.Contains(filepath.Base(path), id.String()) {
		t.Fatalf("backup=%s status=%s path=%q", id, status, path)
	}
	paths[path] = true
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 || info.Size() != size {
		t.Fatalf("artifact mode=%o size=%d catalog=%d", info.Mode().Perm(), info.Size(), size)
	}
	f := &backupScopeFixture{handler: h}
	response := f.request(t.Context(), "download", id, org, true)
	if response.Code != http.StatusOK {
		t.Fatalf("download status=%d body=%s", response.Code, response.Body.String())
	}
	result, err := backup.VerifyArchive(context.Background(), backup.RestoreOptions{In: bytes.NewReader(response.Body.Bytes()), AllowUnverified: true})
	if err != nil || result.Manifest.OrgName != name {
		t.Fatalf("wrong downloaded archive: %+v %v", result, err)
	}
}

func TestBackupDownloadRejectsUnsafeFileBeforeArtifactHeaders(t *testing.T) {
	f := newBackupScopeFixture(t)
	id, org := f.ids[0], f.orgs[0]
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("must not disclose"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(root, kind)
			if kind == "symlink" {
				if err := os.Symlink(victim, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if _, err := f.handler.db.Pool().Exec(t.Context(), `UPDATE backups SET local_path=$2 WHERE id=$1`, id, path); err != nil {
				t.Fatal(err)
			}
			response := f.request(t.Context(), "download", id, org, true)
			if response.Code != http.StatusGone || response.Header().Get("Content-Disposition") != "" || strings.Contains(response.Body.String(), "must not disclose") || strings.Contains(response.Body.String(), root) {
				t.Fatalf("unsafe download status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
			}
		})
	}
}

func TestBackupDownloadPreservesLegacyExternalPathWithSafeFilename(t *testing.T) {
	f := newBackupScopeFixture(t)
	id, org := f.ids[0], f.orgs[0]
	external := filepath.Join(t.TempDir(), "legacy \"backup\".tar.gz")
	if err := os.WriteFile(external, []byte("legacy bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.handler.dir = filepath.Join(t.TempDir(), "different-managed-root")
	if _, err := f.handler.db.Pool().Exec(t.Context(), `UPDATE backups SET local_path=$2 WHERE id=$1`, id, external); err != nil {
		t.Fatal(err)
	}
	response := f.request(t.Context(), "download", id, org, true)
	media, params, err := mime.ParseMediaType(response.Header().Get("Content-Disposition"))
	if response.Code != 200 || response.Body.String() != "legacy bytes" || err != nil || media != "attachment" || params["filename"] != filepath.Base(external) {
		t.Fatalf("legacy download failed status=%d filename=%v error=%v", response.Code, params, err)
	}
}

func TestBackupCreateRejectsInvalidConfiguredDirectoryBeforeJob(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	configured := filepath.Join(root, "configured")
	if err := os.Symlink(target, configured); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSTELLATION_BACKUP_DIR", configured)
	h := NewBackups(nil, nil)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/backups", nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: uuid.New(), UserID: uuid.New()}))
	response := httptest.NewRecorder()
	h.Create(response, request)
	if response.Code != 500 || strings.Contains(response.Body.String(), root) {
		t.Fatalf("invalid configured directory status=%d body=%s", response.Code, response.Body.String())
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o750 {
		t.Fatal("configured symlink target was hardened")
	}
}
