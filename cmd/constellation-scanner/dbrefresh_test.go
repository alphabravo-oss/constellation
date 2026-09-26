package main

import (
	"context"
	"encoding/json"
	"os"
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
