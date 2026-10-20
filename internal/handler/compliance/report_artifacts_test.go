//go:build integration

package compliance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestComplianceArtifactRootConfiguration(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	for _, tc := range []struct{ configured, want string }{
		{"", "/tmp/compliance-out"},
		{"relative-reports", filepath.Join(base, "relative-reports")},
		{"../reports", filepath.Join(filepath.Dir(base), "reports")},
	} {
		t.Setenv("REPORT_OUT_DIR", tc.configured)
		got, err := complianceReportRoot()
		if err != nil || got != tc.want {
			t.Fatalf("configured root %q: got %q, %v", tc.configured, got, err)
		}
		if tc.configured != "" {
			if _, err := os.Lstat(got); !os.IsNotExist(err) {
				t.Fatalf("read configuration created a directory: %v", err)
			}
		}
	}
}

func TestOpenComplianceArtifactConfinedRegularFiles(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "reports")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_OUT_DIR", root)
	body := []byte("private report\x00exact bytes\n")
	valid := filepath.Join(root, "nested", "report.json")
	outside := filepath.Join(base, "outside.json")
	for _, path := range []string{valid, outside} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	file, err := openComplianceArtifact(valid)
	if err != nil {
		t.Fatal(err)
	}
	got, readErr := io.ReadAll(file)
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(got, body) {
		t.Fatalf("valid report changed: %q, %v, %v", got, readErr, closeErr)
	}
	for link, target := range map[string]string{
		"outside-link": outside, "inside-link": valid,
		"directory-link": base, "inside-directory-link": filepath.Join(root, "nested"),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(outside, filepath.Join(root, "hard-link")); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	paths := []string{outside, root + "/../outside.json", root + "-sibling/report.json", root,
		filepath.Join(root, "outside-link"), filepath.Join(root, "inside-link"),
		filepath.Join(root, "directory-link", "outside.json"), filepath.Join(root, "inside-directory-link", "report.json"),
		filepath.Join(root, "hard-link"), filepath.Join(root, "nested"), filepath.Join(root, "missing"), fifo}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			assertComplianceArtifactRejectedPromptly(t, path)
		})
	}
	// The configured root itself must not redirect through a symlink.
	alias := filepath.Join(base, "root-link")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_OUT_DIR", alias)
	if f, err := openComplianceArtifact(filepath.Join(alias, "nested", "report.json")); err == nil {
		_ = f.Close()
		t.Fatal("accepted symlink report root")
	}
	// A relative output directory and the scheduler's matching relative URI
	// continue to resolve against the process working directory.
	t.Chdir(filepath.Join(root, "nested"))
	t.Setenv("REPORT_OUT_DIR", "..")
	f, err := openComplianceArtifact("../nested/report.json")
	if err != nil {
		t.Fatal("relative REPORT_OUT_DIR no longer works", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestComplianceArtifactDownloadConfinesAuthenticatedRun(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	org, foreign := uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := d.Pool().Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "artifact-confinement-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.WithoutCancel(t.Context()), `DELETE FROM orgs WHERE id IN($1,$2)`, org, foreign)
	})
	base := t.TempDir()
	root := filepath.Join(base, "reports")
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_OUT_DIR", root)
	valid, outside := filepath.Join(root, "nested", "report.json"), filepath.Join(base, "outside.json")
	body := []byte("{\"evidence\":\"private exact bytes\"}\n")
	for _, path := range []string{valid, outside} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(root, "outside-link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(root, "directory-link")); err != nil {
		t.Fatal(err)
	}
	h := NewComplianceSchedulesDB(d, nil)
	router := chi.NewRouter()
	router.Get("/compliance/runs/{id}/artifact", h.Artifact)
	request := func(tenant, id uuid.UUID) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/compliance/runs/"+id.String()+"/artifact", nil)
		r = r.WithContext(authctx.WithSubject(r.Context(), authctx.Subject{OrgID: tenant, UserID: uuid.New()}))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		name, path string
		status     int
	}{
		{"owned", valid, http.StatusOK},
		{"outside", outside, http.StatusGone},
		{"traversal", root + "/../outside.json", http.StatusGone},
		{"symlink", filepath.Join(root, "outside-link"), http.StatusGone},
		{"parent-symlink", filepath.Join(root, "directory-link", "outside.json"), http.StatusGone},
		{"directory", filepath.Join(root, "nested"), http.StatusGone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := uuid.New()
			if _, err := d.Pool().Exec(t.Context(), `INSERT INTO compliance_runs(id,org_id,framework,status,artifact_uri,artifact_signature,artifact_format,artifact_media_type,artifact_filename) VALUES($1,$2,'fixture','succeeded',$3,'fixture-signature','json','application/json','recorded.json')`, id, org, "file://"+tc.path); err != nil {
				t.Fatal(err)
			}
			w := request(org, id)
			assertComplianceArtifactHTTPResponse(t, w, tc.name, tc.status, body, base)
			if other := request(foreign, id); other.Code != http.StatusNotFound || bytes.Contains(other.Body.Bytes(), body) {
				t.Fatalf("foreign org artifact status=%d body=%q", other.Code, other.Body.String())
			}
		})
	}
}

func assertComplianceArtifactRejectedPromptly(t *testing.T, path string) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		file, err := openComplianceArtifact(path)
		if file != nil {
			_ = file.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted unsafe/nonregular artifact", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("artifact rejection blocked", path)
	}
}

func assertComplianceArtifactHTTPResponse(t *testing.T, w *httptest.ResponseRecorder, name string, status int, body []byte, base string) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("artifact %s status=%d body=%q", name, w.Code, w.Body.String())
	}
	if status == http.StatusOK {
		if !bytes.Equal(w.Body.Bytes(), body) || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("Content-Disposition") != `attachment; filename="recorded.json"` || w.Header().Get("X-Constellation-Artifact-Metadata") != "recorded" || w.Header().Get("X-Constellation-Cosign-Signature") != "fixture-signature" {
			t.Fatalf("same-org bytes/headers changed: %q %v", w.Body.Bytes(), w.Header())
		}
	} else if bytes.Contains(w.Body.Bytes(), body) || strings.Contains(w.Body.String(), base) {
		t.Fatal("rejected artifact leaked bytes or private path")
	}
}
