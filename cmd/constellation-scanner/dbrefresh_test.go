package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	trivyDBRevision = "2026-09-25T12:34:56Z"
	grypeDBRevision = "2026-09-24T01:02:03Z"
)

func engineDBTestWorker(t *testing.T) (*worker, string, string) {
	t.Helper()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	trivyCache := filepath.Join(root, "trivy")
	grypeCache := filepath.Join(root, "grype")
	for _, dir := range []string{binDir, filepath.Join(trivyCache, "db"), grypeCache} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	trivySource := filepath.Join(root, "trivy-source.json")
	grypeSource := filepath.Join(root, "grype-source.json")
	grypeStatus := filepath.Join(root, "grype-status.json")
	if err := os.WriteFile(trivySource, []byte(`{"UpdatedAt":"`+trivyDBRevision+`","DownloadedAt":"2026-09-26T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grypeSource, []byte(`{"built":"`+grypeDBRevision+`","valid":true,"path":"/secret/grype.db"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"trivy": "#!/bin/sh\nif [ \"$TEST_REFRESH_FAIL\" = 1 ]; then exit 1; fi\ncp \"$TRIVY_TEST_SOURCE\" \"$TRIVY_CACHE_DIR/db/metadata.json\"\n",
		"grype": "#!/bin/sh\nif [ \"$1\" = db ] && [ \"$2\" = status ]; then cat \"$GRYPE_TEST_STATUS\"; exit 0; fi\nif [ \"$TEST_REFRESH_FAIL\" = 1 ]; then exit 1; fi\ncp \"$GRYPE_TEST_SOURCE\" \"$GRYPE_TEST_STATUS\"\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TRIVY_CACHE_DIR", trivyCache)
	t.Setenv("GRYPE_DB_CACHE_DIR", grypeCache)
	t.Setenv("TRIVY_TEST_SOURCE", trivySource)
	t.Setenv("GRYPE_TEST_SOURCE", grypeSource)
	t.Setenv("GRYPE_TEST_STATUS", grypeStatus)
	return &worker{
		engines:   map[string]bool{"trivy": true, "grype": true},
		cacheDirs: map[string]string{"trivy": trivyCache, "grype": grypeCache},
		logger:    nopLogger{},
	}, trivyCache, grypeStatus
}

func TestEngineDBSnapshotOfflinePreloaded(t *testing.T) {
	worker, trivyCache, grypeStatus := engineDBTestWorker(t)
	if err := os.WriteFile(filepath.Join(trivyCache, "db", "metadata.json"), []byte(`{"UpdatedAt":"`+trivyDBRevision+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grypeStatus, []byte(`{"built":"`+grypeDBRevision+`","valid":true,"path":"/secret/grype.db"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	worker.refreshVulnDBs(context.Background(), true)
	engineDB := worker.statusSnapshot()["engine_db"].(map[string]engineDBStatus)
	for engine, revision := range map[string]string{"trivy": trivyDBRevision, "grype": grypeDBRevision} {
		if got := engineDB[engine]; got.Status != "ready" || got.AppliedRevision != revision || got.DownloadRevision != "" {
			t.Fatalf("%s offline status = %+v", engine, got)
		}
	}
	encoded, err := json.Marshal(engineDB)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "/secret/") || strings.Contains(string(encoded), trivyCache) {
		t.Fatalf("engine DB metadata leaked a path: %s", encoded)
	}
}

func TestEngineDBRefreshSuccessAndFailure(t *testing.T) {
	worker, _, _ := engineDBTestWorker(t)
	worker.refreshVulnDBs(context.Background(), false)
	for engine, revision := range map[string]string{"trivy": trivyDBRevision, "grype": grypeDBRevision} {
		if got := worker.engineDBSnapshot(context.Background())[engine]; got.Status != "ready" || got.AppliedRevision != revision || got.DownloadRevision != revision {
			t.Fatalf("%s successful refresh status = %+v", engine, got)
		}
	}
	t.Setenv("TEST_REFRESH_FAIL", "1")
	worker.refreshVulnDBs(context.Background(), false)
	for engine, revision := range map[string]string{"trivy": trivyDBRevision, "grype": grypeDBRevision} {
		if got := worker.engineDBSnapshot(context.Background())[engine]; got.DownloadRevision != revision || got.AppliedRevision != revision {
			t.Fatalf("%s failed refresh changed revision = %+v", engine, got)
		}
	}
}

func TestEngineDBRefreshFailureDoesNotClaimDownload(t *testing.T) {
	worker, _, _ := engineDBTestWorker(t)
	t.Setenv("TEST_REFRESH_FAIL", "1")
	worker.refreshVulnDBs(context.Background(), false)
	engineDB := worker.engineDBSnapshot(context.Background())
	if engineDB["trivy"].DownloadRevision != "" || engineDB["grype"].DownloadRevision != "" {
		t.Fatalf("failed refresh claimed download: %+v", engineDB)
	}
}

func TestEngineDBSnapshotInvalidAndMissing(t *testing.T) {
	worker, trivyCache, grypeStatus := engineDBTestWorker(t)
	if got := worker.engineDBSnapshot(context.Background()); got["trivy"].Status != "missing" || got["trivy"].AppliedRevision != "" {
		t.Fatalf("missing Trivy status = %+v", got["trivy"])
	}
	if err := os.WriteFile(filepath.Join(trivyCache, "db", "metadata.json"), []byte(`{"UpdatedAt":"not-a-date"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grypeStatus, []byte(`{"built":"`+grypeDBRevision+`","valid":false,"path":"/secret/grype.db"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := worker.engineDBSnapshot(context.Background())
	if got["trivy"].Status != "invalid" || got["grype"].Status != "invalid" || got["trivy"].AppliedRevision != "" || got["grype"].AppliedRevision != "" {
		t.Fatalf("invalid DB status = %+v", got)
	}
	if err := os.WriteFile(grypeStatus, []byte(strings.Repeat("x", maxEngineDBMetadataBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := worker.engineDBSnapshot(context.Background())["grype"]; got.Status != "invalid" || got.AppliedRevision != "" {
		t.Fatalf("oversized Grype status = %+v", got)
	}
	worker.engines["grype"] = false
	if got := worker.engineDBSnapshot(context.Background())["grype"]; got.Status != "disabled" || got.AppliedRevision != "" {
		t.Fatalf("disabled Grype status = %+v", got)
	}
}

func TestEngineDBRefreshSnapshotRace(t *testing.T) {
	worker, _, _ := engineDBTestWorker(t)
	worker.engines["grype"] = false
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 10 {
				worker.refreshVulnDBs(context.Background(), false)
			}
		}()
		group.Add(1)
		go func() {
			defer group.Done()
			for range 10 {
				_ = worker.engineDBSnapshot(context.Background())
			}
		}()
	}
	group.Wait()
}

// The updater can exit zero while leaving a corrupt, already-current DB in place.
func TestEngineDBRefreshRecoversOnlyVerifiedArchive(t *testing.T) {
	for _, tc := range []struct {
		name, archive             string
		importFails, staysInvalid bool
		wantSuccess               bool
	}{
		{name: "repaired", archive: "https://grype.example/db.tar.zst?checksum=sha256:" + strings.Repeat("a", 64), wantSuccess: true},
		{name: "no checksum", archive: "https://grype.example/db.tar.zst"},
		{name: "insecure URL", archive: "http://grype.example/db.tar.zst?checksum=sha256:" + strings.Repeat("a", 64)},
		{name: "failed import", archive: "https://grype.example/db.tar.zst?checksum=sha256:" + strings.Repeat("a", 64), importFails: true},
		{name: "invalid after import", archive: "https://grype.example/db.tar.zst?checksum=sha256:" + strings.Repeat("a", 64), staysInvalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, _, statusPath := engineDBTestWorker(t)
			w.engines["trivy"] = false
			logger := &refreshTestLogger{}
			w.logger = logger
			initial, _ := json.Marshal(grypeDBStatus{Built: grypeDBRevision, From: tc.archive})
			if err := os.WriteFile(statusPath, initial, 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("IMPORT_FAIL", fmt.Sprint(tc.importFails))
			t.Setenv("STAYS_INVALID", fmt.Sprint(tc.staysInvalid))
			marker := filepath.Join(t.TempDir(), "imported")
			t.Setenv("IMPORT_MARKER", marker)
			script := `#!/bin/sh
if [ "$2" = status ]; then cat "$GRYPE_TEST_STATUS"; exit 1; fi
if [ "$2" = update ]; then exit 0; fi
if [ "$2" = import ]; then
 touch "$IMPORT_MARKER"
 if [ "$IMPORT_FAIL" = true ]; then exit 1; fi
 if [ "$STAYS_INVALID" = true ]; then exit 0; fi
 cp "$GRYPE_TEST_SOURCE" "$GRYPE_TEST_STATUS"
fi
`
			// The status command exits nonzero only for invalid content.
			script = strings.Replace(script, "cat \"$GRYPE_TEST_STATUS\"; exit 1", "cat \"$GRYPE_TEST_STATUS\"; if grep -q '\"valid\":true' \"$GRYPE_TEST_STATUS\"; then exit 0; else exit 1; fi", 1)
			if err := os.WriteFile(filepath.Join(strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))[0], "grype"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			w.refreshVulnDBs(context.Background(), false)
			if (w.engineDBDownloads["grype"] != "") != tc.wantSuccess || logger.success != tc.wantSuccess {
				t.Fatalf("download=%q success log=%v", w.engineDBDownloads["grype"], logger.success)
			}
			if !tc.wantSuccess {
				after, _ := os.ReadFile(statusPath)
				if string(after) != string(initial) {
					t.Fatal("failed recovery removed or changed original DB status")
				}
			}
			if _, err := grypeRecoveryArchive(tc.archive); err != nil {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("unsafe archive imported")
				}
			}
		})
	}
}

type refreshTestLogger struct{ success bool }

func (l *refreshTestLogger) Info(msg string, _ ...any) {
	if msg == "vuln DB refreshed" {
		l.success = true
	}
}
func (*refreshTestLogger) Warn(string, ...any)  {}
func (*refreshTestLogger) Error(string, ...any) {}

func TestGrypeRecoveryArchiveRejectsMalformedChecksums(t *testing.T) {
	for _, raw := range []string{"file:///tmp/db", "https://user:password@example.com/db?checksum=sha256:" + strings.Repeat("a", 64), "https://example.com/db?checksum=sha256:abc", "https://example.com/db?checksum=sha256:" + strings.Repeat("z", 64), "https://example.com/db?checksum=sha256:" + strings.Repeat("a", 64) + "&checksum=sha256:" + strings.Repeat("b", 64)} {
		if _, err := grypeRecoveryArchive(raw); err == nil {
			t.Fatal("accepted invalid archive URL")
		}
	}
}

func TestEngineDBRefreshDisabledDoesNotExecute(t *testing.T) {
	w, cache, status := engineDBTestWorker(t)
	w.engines = map[string]bool{}
	w.refreshVulnDBs(context.Background(), false)
	for _, p := range []string{filepath.Join(cache, "db", "metadata.json"), status} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatal("disabled engine executed")
		}
	}
}

// Opt-in real-tool acceptance: point GRYPE_RECOVERY_TEST_CACHE at an isolated
// cache with invalid import metadata and a checksum-protected source URL.
func TestGrypeRecoveryRealDatabase(t *testing.T) {
	cache := os.Getenv("GRYPE_RECOVERY_TEST_CACHE")
	if cache == "" {
		t.Skip("set GRYPE_RECOVERY_TEST_CACHE to an isolated corrupt cache")
	}
	realBinary, err := exec.LookPath("grype")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GRYPE_REAL_BINARY", realBinary)
	t.Setenv("GRYPE_DB_CACHE_DIR", cache)
	// Reproduce the observed updater no-op while using the real engine for both
	// checksum validation and archive import. This does not alter the live cache.
	bin := t.TempDir()
	script := `#!/bin/sh
if [ "$1" = db ] && [ "$2" = update ]; then exit 0; fi
exec "$GRYPE_REAL_BINARY" "$@"
`
	if err := os.WriteFile(filepath.Join(bin, "grype"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	w := &worker{engines: map[string]bool{"grype": true}, logger: nopLogger{}}
	before, err := readGrypeDBStatus(context.Background())
	if err != nil || before.Valid {
		t.Fatalf("fixture must be corrupt: valid=%v err=%v", before.Valid, err)
	}
	w.refreshVulnDBs(context.Background(), false)
	after := w.engineDBSnapshot(context.Background())["grype"]
	if after.Status != "ready" || after.DownloadRevision == "" || after.DownloadRevision != after.AppliedRevision {
		t.Fatalf("recovery failed: %+v", after)
	}
	t.Logf("real Grype recovered and verified database revision %s", after.AppliedRevision)
}

func TestGrypeStatusAllowsSlowChecksumAndCancellation(t *testing.T) {
	w, _, _ := engineDBTestWorker(t)
	bin := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))[0]
	script := "#!/bin/sh\nsleep 6\ncat \"$GRYPE_TEST_SOURCE\"\n"
	if err := os.WriteFile(filepath.Join(bin, "grype"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if _, status := w.installedDBRevision(context.Background(), "grype"); status != "ready" {
		t.Fatalf("slow checksum status=%s", status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := readGrypeDBStatus(ctx); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestEngineDBRefreshZeroExitInvalidMetadataIsFailure(t *testing.T) {
	w, _, _ := engineDBTestWorker(t)
	w.engines["grype"] = false
	logger := &refreshTestLogger{}
	w.logger = logger
	if err := os.WriteFile(os.Getenv("TRIVY_TEST_SOURCE"), []byte(`{"UpdatedAt":"invalid"}`), 0600); err != nil {
		t.Fatal(err)
	}
	w.refreshVulnDBs(context.Background(), false)
	if logger.success || w.engineDBDownloads["trivy"] != "" {
		t.Fatal("zero exit with invalid metadata claimed refresh success")
	}
}
