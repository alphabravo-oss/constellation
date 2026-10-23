package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stagingDir(t *testing.T, root, name string, age time.Duration) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "evidence"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-age)
	if err := os.Chtimes(path, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGrypeStagingCleanupSelection(t *testing.T) {
	root := filepath.Join(t.TempDir(), "cache[1]")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	stale := stagingDir(t, root, "grype-db-download-old", 48*time.Hour)
	keep := []string{
		stagingDir(t, root, "grype-db-download-recent", time.Hour),
		stagingDir(t, root, "grype-db-download-future", -time.Hour),
		stagingDir(t, root, "grype-db-download", 48*time.Hour),
		stagingDir(t, root, "6", 48*time.Hour),
		stagingDir(t, root, "other", 48*time.Hour),
	}
	plain := filepath.Join(root, "grype-db-download-file")
	if err := os.WriteFile(plain, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(plain, old, old); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, plain)
	outside := stagingDir(t, t.TempDir(), "outside", 48*time.Hour)
	link := filepath.Join(root, "grype-db-download-link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	keep = append(keep, link, filepath.Join(outside, "evidence"))
	// A symlink inside an eligible directory must not remove external contents.
	if err := os.Symlink(outside, filepath.Join(stale, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	removed, limited, err := pruneGrypeStagingAt(context.Background(), root, time.Now())
	if err != nil || removed != 1 || limited {
		t.Fatalf("cleanup = %d, %v, %v", removed, limited, err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale directory remains: %v", err)
	}
	for _, path := range keep {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("protected path removed: %s: %v", path, err)
		}
	}
}

func TestGrypeStagingCleanupLimits(t *testing.T) {
	t.Run("removals", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < grypeStagingRemovalLimit+1; i++ {
			stagingDir(t, root, fmt.Sprintf("grype-db-download-%d", i), 48*time.Hour)
		}
		removed, limited, err := pruneGrypeStagingAt(context.Background(), root, time.Now())
		if err != nil || removed != grypeStagingRemovalLimit || !limited {
			t.Fatalf("cleanup = %d, %v, %v", removed, limited, err)
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 1 {
			t.Fatalf("remaining entries = %d, error %v", len(entries), err)
		}
	})
	t.Run("enumeration", func(t *testing.T) {
		root := t.TempDir()
		for i := 0; i < grypeStagingEntryLimit+1; i++ {
			if err := os.WriteFile(filepath.Join(root, fmt.Sprint(i)), nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		removed, limited, err := pruneGrypeStagingAt(context.Background(), root, time.Now())
		if err != nil || removed != 0 || !limited {
			t.Fatalf("cleanup = %d, %v, %v", removed, limited, err)
		}
	})
}

func TestGrypeStagingCleanupCancellationAndMissing(t *testing.T) {
	root := t.TempDir()
	path := stagingDir(t, root, "grype-db-download-old", 48*time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	removed, _, err := pruneGrypeStagingAt(ctx, root, time.Now())
	if !errors.Is(err, context.Canceled) || removed != 0 {
		t.Fatalf("cleanup = %d, %v", removed, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("canceled cleanup deleted staging")
	}
	if _, _, err := pruneGrypeStagingAt(context.Background(), filepath.Join(root, "missing"), time.Now()); !os.IsNotExist(err) {
		t.Fatalf("missing root: %v", err)
	}
}

func TestGrypeStagingCleanupConfiguredRoot(t *testing.T) {
	configured, environment := t.TempDir(), t.TempDir()
	chosen := stagingDir(t, configured, "grype-db-download-old", 48*time.Hour)
	other := stagingDir(t, environment, "grype-db-download-old", 48*time.Hour)
	t.Setenv("GRYPE_DB_CACHE_DIR", environment)
	w := worker{cacheDirs: map[string]string{"grype": configured}, logger: nopLogger{}}
	w.pruneGrypeStaging(context.Background())
	if _, err := os.Stat(chosen); !os.IsNotExist(err) {
		t.Fatal("configured cache not cleaned")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("environment cache incorrectly cleaned")
	}
	w.cacheDirs = nil
	w.pruneGrypeStaging(context.Background())
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("explicit environment cache not cleaned")
	}
	t.Setenv("GRYPE_DB_CACHE_DIR", "")
	w.pruneGrypeStaging(context.Background())
}

func TestTrivyMetadataRequiresCompleteDocument(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "db"), 0700); err != nil {
		t.Fatal(err)
	}
	w := worker{cacheDirs: map[string]string{"trivy": root}}
	valid := `{"UpdatedAt":"` + trivyDBRevision + `"}`
	for _, tc := range []struct{ name, body, status string }{
		{"valid", valid, "ready"},
		{"whitespace", valid + "\n ", "ready"},
		{"second document", valid + "{}", "invalid"},
		{"trailing junk", valid + "x", "invalid"},
		{"oversized", valid + strings.Repeat(" ", maxEngineDBMetadataBytes), "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(root, "db", "metadata.json"), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}
			revision, status := w.installedDBRevision(context.Background(), "trivy")
			if status != tc.status {
				t.Fatalf("status = %s, want %s", status, tc.status)
			}
			if status == "ready" && revision != trivyDBRevision {
				t.Fatalf("revision = %s", revision)
			}
		})
	}
}

func TestGrypeRecoveryArchiveRejectsMalformedQuery(t *testing.T) {
	base := "https://example.com/db?checksum=sha256:" + strings.Repeat("a", 64)
	for _, suffix := range []string{"&other=%zz", "&other=x;y", "&checksum=%xx"} {
		if _, err := grypeRecoveryArchive(base + suffix); err == nil {
			t.Fatalf("accepted malformed query %q", suffix)
		}
	}
	if _, err := grypeRecoveryArchive(base + "&other=valid"); err != nil {
		t.Fatalf("rejected valid query: %v", err)
	}
}
