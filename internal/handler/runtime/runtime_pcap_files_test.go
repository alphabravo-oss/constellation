package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/securefiles"
)

func privatePcapRoot(t *testing.T) *os.Root {
	t.Helper()
	t.Setenv("CONSTELLATION_DATA_DIR", t.TempDir())
	root, err := securefiles.OpenPrivateDir(pcapDataDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	return root
}
func requirePcapBody(t *testing.T, root *os.Root, name, want string) {
	t.Helper()
	body, err := root.ReadFile(name)
	if err != nil || string(body) != want {
		t.Fatalf("%s=%q err=%v", name, body, err)
	}
}
func requirePcapEntries(t *testing.T, root *os.Root, want int) {
	t.Helper()
	f, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := f.Readdirnames(-1)
	closeErr := f.Close()
	if err != nil || closeErr != nil || len(entries) != want {
		t.Fatalf("entries=%v err=%v/%v", entries, err, closeErr)
	}
}
func TestPcapPrivateUploadPermissionsHashAndHardlinkAtomicity(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	root := privatePcapRoot(t)
	id := uuid.New()
	outside := filepath.Join(t.TempDir(), "prior")
	if err := os.WriteFile(outside, []byte("outside prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(pcapDataDir(), pcapFileName(id))); err != nil {
		t.Fatal(err)
	}
	staged, err := stagePcapUpload(root, id, strings.NewReader("private packet bytes"))
	if err != nil {
		t.Fatal(err)
	}
	requirePcapBody(t, root, pcapFileName(id), "outside prior")
	info, err := root.Stat(staged.name)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("staged mode=%v err=%v", info, err)
	}
	hash := sha256.Sum256([]byte("private packet bytes"))
	if staged.size != 20 || staged.sha256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("metadata=%+v", staged)
	}
	if err = publishPcapUpload(root, staged, id); err != nil {
		t.Fatal(err)
	}
	requirePcapBody(t, root, pcapFileName(id), "private packet bytes")
	body, err := readPcapFixture(t, outside)
	if err != nil || string(body) != "outside prior" {
		t.Fatal("outside hardlink modified")
	}
	info, err = root.Stat(pcapFileName(id))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode=%v err=%v", info, err)
	}
	info, err = root.Stat(".")
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode=%v err=%v", info, err)
	}
	requirePcapEntries(t, root, 1)
}

type brokenPcapReader struct{}

func (brokenPcapReader) Read([]byte) (int, error) { return 0, errors.New("interrupted source") }

type zeroPcapReader struct{}

func (zeroPcapReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }
func TestPcapPrivateInterruptedAndOversizeCopiesNeverPublish(t *testing.T) {
	root := privatePcapRoot(t)
	id := uuid.New()
	if err := securefiles.WriteFile(root, pcapFileName(id), []byte("prior complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources := []io.Reader{io.MultiReader(strings.NewReader("partial"), brokenPcapReader{}), io.LimitReader(zeroPcapReader{}, maxPcapBytes+1)}
	for _, source := range sources {
		if _, err := stagePcapUpload(root, id, source); err == nil {
			t.Fatal("failed/oversize upload accepted")
		}
		requirePcapBody(t, root, pcapFileName(id), "prior complete")
		requirePcapEntries(t, root, 1)
	}
}
func TestPcapPrivateSymlinkRejectionAndPinnedParent(t *testing.T) {
	root := privatePcapRoot(t)
	id := uuid.New()
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(pcapDataDir(), pcapFileName(id))); err != nil {
		t.Fatal(err)
	}
	staged, err := stagePcapUpload(root, id, strings.NewReader("private"))
	if err != nil {
		t.Fatal(err)
	}
	if err = publishPcapUpload(root, staged, id); err == nil {
		t.Fatal("published to symlink destination")
	}
	if _, err = openPcapFile(root, id); err == nil {
		t.Fatal("download followed symlink")
	}
	if err = root.Remove(staged.name); err != nil {
		t.Fatal(err)
	}
	body, err := readPcapFixture(t, target)
	if err != nil || string(body) != "outside" {
		t.Fatal("outside target changed")
	}
	if err = root.Remove(pcapFileName(id)); err != nil {
		t.Fatal(err)
	}
	original := pcapDataDir()
	if err = os.Rename(original, original+"-pinned"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, original); err != nil {
		t.Fatal(err)
	}
	if untrusted, openErr := securefiles.OpenPrivateDir(original); openErr == nil {
		_ = untrusted.Close()
		t.Fatal("opened symlinked store")
	}
	staged, err = stagePcapUpload(root, id, strings.NewReader("pinned"))
	if err != nil {
		t.Fatal(err)
	}
	if err = publishPcapUpload(root, staged, id); err != nil {
		t.Fatal(err)
	}
	requirePcapBody(t, root, pcapFileName(id), "pinned")
	if _, err = os.Stat(filepath.Join(outside, pcapFileName(id))); !os.IsNotExist(err) {
		t.Fatal("followed replaced parent")
	}
}

type pcapFilesFixture struct {
	d                  *db.DB
	h                  *PcapHTTP
	org, cluster, user uuid.UUID
	token              string
	root               *os.Root
}

func pcapFilesDB(t *testing.T) *pcapFilesFixture {
	t.Helper()
	if os.Getenv("CONSTELLATION_TEST_DATABASE_URL") == "" {
		t.Skip("requires disposable PostgreSQL fixture")
	}
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := t.Context()
	f := &pcapFilesFixture{d: d, h: NewPcapHTTP(d), org: uuid.New(), cluster: uuid.New(), user: uuid.New(), root: privatePcapRoot(t)}
	t.Cleanup(func() {
		for _, query := range []string{`DELETE FROM runtime_pcap_captures WHERE org_id=$1`, `DELETE FROM cluster_init_bundles WHERE org_id=$1`, `DELETE FROM runtime_agent_tokens WHERE org_id=$1`, `DELETE FROM clusters WHERE org_id=$1`, `DELETE FROM users WHERE org_id=$1`, `DELETE FROM orgs WHERE id=$1`} {
			_, _ = d.Pool().Exec(context.WithoutCancel(ctx), query, f.org)
		}
	})
	for _, statement := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO orgs(id,name,display_name)VALUES($1::uuid,$1::text,'private pcap')`, []any{f.org}},
		{`INSERT INTO users(id,org_id,email,display_name)VALUES($1,$2,$3,'private pcap')`, []any{f.user, f.org, f.user.String() + "@example.test"}},
		{`INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'private pcap')`, []any{f.cluster, f.org}},
	} {
		if _, err := d.Pool().Exec(ctx, statement.q, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	raw, token, err := handler.IssueRuntimeAgentToken(ctx, d.Pool(), f.org, "pcap-files-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.token = raw
	if _, err = d.Pool().Exec(ctx, `INSERT INTO cluster_init_bundles(org_id,cluster_id,name,expires_at,runtime_agent_token_id,kek_fingerprint,contents_encrypted)VALUES($1,$2,'private pcap',now()+interval '1 hour',$3,'test','\x00')`, f.org, f.cluster, token); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *pcapFilesFixture) capture(t *testing.T, status string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.d.Pool().QueryRow(t.Context(), `INSERT INTO runtime_pcap_captures(org_id,cluster_id,workload,namespace,requested_by,duration_s,status)VALUES($1,$2,'prod/api','prod',$3,30,$4)RETURNING id`, f.org, f.cluster, f.user, status).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
func (f *pcapFilesFixture) upload(t *testing.T, id uuid.UUID, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), "POST", "/runtime-pcap/"+id.String()+"/upload", body)
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	handler.RuntimeAgentTokenMiddleware(f.d.Pool())(http.HandlerFunc(f.h.Upload)).ServeHTTP(w, r)
	return w
}
func (f *pcapFilesFixture) status(t *testing.T, id uuid.UUID) string {
	t.Helper()
	var status string
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT status FROM runtime_pcap_captures WHERE id=$1`, id).Scan(&status); err != nil {
		t.Fatal(err)
	}
	return status
}
func (f *pcapFilesFixture) operator(t *testing.T, method, path string, call http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: f.org, UserID: f.user}), method, path, nil)
	w := httptest.NewRecorder()
	call(w, r)
	return w
}
func TestPcapPrivateHTTPUploadDownloadAndCompletedOverwriteGuard(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	body := "sensitive packets"
	w := f.upload(t, id, strings.NewReader(body))
	if w.Code != 200 || f.status(t, id) != "completed" {
		t.Fatalf("upload=%d %s", w.Code, w.Body.String())
	}
	w = f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("download=%d %s", w.Code, w.Body.String())
	}
	w = f.upload(t, id, strings.NewReader("replacement"))
	if w.Code != 409 {
		t.Fatalf("completed upload=%d", w.Code)
	}
	requirePcapBody(t, f.root, pcapFileName(id), body)
	if err := f.root.Remove(pcapFileName(id)); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("foreign file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, pcapFilePath(id)); err != nil {
		t.Fatal(err)
	}
	w = f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 500 || strings.Contains(w.Body.String(), "foreign file") {
		t.Fatal("symlink download leaked bytes")
	}
	w = f.operator(t, "DELETE", "/runtime-pcap/"+id.String(), f.h.Delete)
	if w.Code != 200 {
		t.Fatalf("delete=%d", w.Code)
	}
	data, err := readPcapFixture(t, outside)
	if err != nil || string(data) != "foreign file" {
		t.Fatal("delete modified symlink target")
	}
}
func TestPcapPrivateHTTPInterruptedUploadKeepsRunningAndPriorBytes(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	if err := securefiles.WriteFile(f.root, pcapFileName(id), []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := f.upload(t, id, io.MultiReader(strings.NewReader("partial"), brokenPcapReader{}))
	if w.Code != 400 || f.status(t, id) != "running" {
		t.Fatalf("interrupted=%d %s", w.Code, w.Body.String())
	}
	requirePcapBody(t, f.root, pcapFileName(id), "prior")
	requirePcapEntries(t, f.root, 1)
	w = f.upload(t, id, io.LimitReader(zeroPcapReader{}, maxPcapBytes+1))
	if w.Code != 413 || f.status(t, id) != "running" {
		t.Fatalf("oversize=%d %s", w.Code, w.Body.String())
	}
	requirePcapBody(t, f.root, pcapFileName(id), "prior")
	requirePcapEntries(t, f.root, 1)

}
func installPcapFailure(t *testing.T, f *pcapFilesFixture, id uuid.UUID, deferred bool) {
	t.Helper()
	name := "pcap_fail_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err := f.d.Pool().Exec(t.Context(), `CREATE FUNCTION `+quoted+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture completion failure'; END $$`); err != nil {
		t.Fatal(err)
	}
	timing := ""
	if deferred {
		timing = " DEFERRABLE INITIALLY DEFERRED"
	}
	query := `CREATE CONSTRAINT TRIGGER ` + quoted + ` AFTER UPDATE ON runtime_pcap_captures` + timing + ` FOR EACH ROW WHEN(NEW.id='` + id.String() + `'::uuid) EXECUTE FUNCTION ` + quoted + `() `
	if _, err := f.d.Pool().Exec(t.Context(), query); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.d.Pool().Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER IF EXISTS `+quoted+` ON runtime_pcap_captures`)
		_, _ = f.d.Pool().Exec(context.WithoutCancel(t.Context()), `DROP FUNCTION IF EXISTS `+quoted+`()`)
	})
}
func TestPcapPrivateHTTPDatabaseFailureDoesNotPublishOrClaimSuccess(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	installPcapFailure(t, f, id, false)
	if err := securefiles.WriteFile(f.root, pcapFileName(id), []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := f.upload(t, id, strings.NewReader("uncommitted replacement"))
	if w.Code != 500 || f.status(t, id) != "running" {
		t.Fatalf("DB failure=%d %s", w.Code, w.Body.String())
	}
	requirePcapBody(t, f.root, pcapFileName(id), "prior")
	requirePcapEntries(t, f.root, 1)
}
func TestPcapPrivateHTTPCommitFailureKeepsPrivateOrphanWithoutReceipt(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	installPcapFailure(t, f, id, true)
	w := f.upload(t, id, strings.NewReader("complete private bytes"))
	if w.Code != 500 || f.status(t, id) != "running" {
		t.Fatalf("commit failure=%d %s", w.Code, w.Body.String())
	}
	requirePcapBody(t, f.root, pcapFileName(id), "complete private bytes")
	requirePcapEntries(t, f.root, 1)
	w = f.operator(t, "GET", "/runtime-pcap/"+id.String()+"/download", f.h.Download)
	if w.Code != 409 {
		t.Fatal("uncommitted artifact downloadable")
	}
}

type waitingPcapReader struct {
	io.Reader
	entered, release chan struct{}
	once             sync.Once
}

func (r *waitingPcapReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered); <-r.release })
	return r.Reader.Read(p)
}
func TestPcapPrivateUploadSerializesDeleteAndExpiry(t *testing.T) {
	for _, operation := range []string{"delete", "expiry"} {
		t.Run(operation, func(t *testing.T) { exercisePcapRemovalWhileUploading(t, operation) })
	}
}
func requirePcapRowLocked(t *testing.T, f *pcapFilesFixture, id uuid.UUID) {
	t.Helper()
	lock, err := f.d.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_, err = lock.Exec(t.Context(), `SELECT id FROM runtime_pcap_captures WHERE id=$1 FOR UPDATE NOWAIT`, id)
	_ = lock.Rollback(t.Context())
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
		t.Fatalf("upload row not locked: %v", err)
	}
}
func removePcapConcurrently(t *testing.T, f *pcapFilesFixture, id uuid.UUID, operation string) <-chan error {
	t.Helper()
	removed := make(chan error, 1)
	go func() {
		if operation == "expiry" {
			_, err := f.h.SweepExpired(t.Context(), nil)
			removed <- err
			return
		}
		w := f.operator(t, "DELETE", "/runtime-pcap/"+id.String(), f.h.Delete)
		if w.Code != 200 {
			removed <- fmt.Errorf("delete status %d", w.Code)
			return
		}
		removed <- nil
	}()
	return removed
}
func requirePcapUploadReceipt(t *testing.T, uploaded <-chan *httptest.ResponseRecorder) {
	t.Helper()
	select {
	case w := <-uploaded:
		if w.Code != 200 {
			t.Fatalf("upload=%d %s", w.Code, w.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upload remained blocked")
	}
}
func requirePcapRemovalReceipt(t *testing.T, removed <-chan error) {
	t.Helper()
	select {
	case err := <-removed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("removal remained blocked")
	}
}
func exercisePcapRemovalWhileUploading(t *testing.T, operation string) {
	t.Helper()
	f := pcapFilesDB(t)
	id := f.capture(t, "running")
	if operation == "expiry" {
		if _, err := f.d.Pool().Exec(t.Context(), `UPDATE runtime_pcap_captures SET expires_at=now()-interval '1 second' WHERE id=$1`, id); err != nil {
			t.Fatal(err)
		}
	}
	reader := &waitingPcapReader{Reader: strings.NewReader("complete"), entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(reader.release) }) })
	uploaded := make(chan *httptest.ResponseRecorder, 1)
	go func() { uploaded <- f.upload(t, id, reader) }()
	select {
	case <-reader.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("upload did not begin reading")
	}
	requirePcapRowLocked(t, f, id) // Actual database conflict, not just timing.
	removed := removePcapConcurrently(t, f, id, operation)
	select {
	case err := <-removed:
		t.Fatalf("removal bypassed upload lock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	release.Do(func() { close(reader.release) })
	requirePcapUploadReceipt(t, uploaded)
	requirePcapRemovalReceipt(t, removed)
	if _, err := f.root.Stat(pcapFileName(id)); !os.IsNotExist(err) {
		t.Fatal("serialized removal left published artifact")
	}
}

func TestPcapPrivateIgnoresPredictablePartialSymlink(t *testing.T) {
	root := privatePcapRoot(t)
	id := uuid.New()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("unmodified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, pcapFilePath(id)+".partial"); err != nil {
		t.Fatal(err)
	}
	staged, err := stagePcapUpload(root, id, strings.NewReader("new complete"))
	if err != nil {
		t.Fatal(err)
	}
	if err = publishPcapUpload(root, staged, id); err != nil {
		t.Fatal(err)
	}
	data, err := readPcapFixture(t, target)
	if err != nil || string(data) != "unmodified" {
		t.Fatal("predictable partial symlink followed")
	}
}
func TestPcapPrivateStoreConfigurationCompatibility(t *testing.T) {
	t.Setenv("CONSTELLATION_DATA_DIR", "")
	if pcapDataDir() != filepath.Join("/var/lib/constellation", "pcaps") {
		t.Fatal("default changed")
	}
	directory := t.TempDir()
	t.Setenv("CONSTELLATION_DATA_DIR", "  "+directory+"  ")
	if pcapDataDir() != filepath.Join(directory, "pcaps") {
		t.Fatal("configured data root changed")
	}
}

func readPcapFixture(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(path))
}
