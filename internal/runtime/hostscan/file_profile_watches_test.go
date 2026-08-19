package hostscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCollectRuleFilesAtRoot(t *testing.T) {
	root := t.TempDir()
	writeWatchFile(t, root, "/etc/passwd", "root:x")
	writeWatchFile(t, root, "/var/run/secrets/kubernetes.io/serviceaccount/token", "token")
	writeWatchFile(t, root, "/usr/bin/cat", "bin")
	writeWatchFile(t, root, "/usr/bin/tools/nested", "bin")
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "usr/bin/shadow-link")); err != nil {
		t.Fatal(err)
	}
	container := Container{ID: "abc123", Name: "api", PodNS: "default", PodName: "api-7d9c"}

	exact := FileProfileRule{ID: "r1", Filter: "/etc/passwd", Path: "/etc/passwd"}
	files := collectRuleFilesAtRoot(root, container, exact, 10, 4, 0)
	if len(files) != 1 || files[0].Path != "/etc/passwd" || files[0].ContainerID != "abc123" {
		t.Fatalf("exact files = %+v", files)
	}

	nonRecursive := FileProfileRule{ID: "r2", Filter: "/usr/bin/*", Path: "/usr/bin", Regex: ".*"}
	files = collectRuleFilesAtRoot(root, container, nonRecursive, 10, 4, 0)
	if len(files) != 1 || files[0].Path != "/usr/bin/cat" {
		t.Fatalf("non-recursive files = %+v", files)
	}

	recursive := FileProfileRule{ID: "r3", Filter: "/usr/bin/*", Path: "/usr/bin", Regex: ".*", Recursive: true}
	files = collectRuleFilesAtRoot(root, container, recursive, 10, 4, 0)
	if len(files) != 2 || files[0].Path != "/usr/bin/cat" || files[1].Path != "/usr/bin/tools/nested" {
		t.Fatalf("recursive files = %+v", files)
	}

	files = collectRuleFilesAtRoot(root, container, recursive, 1, 4, 0)
	if len(files) != 1 {
		t.Fatalf("capped files = %+v", files)
	}
}

func TestCollectFileProfileWatchesUsesPodWorkloadIDs(t *testing.T) {
	root := t.TempDir()
	writeWatchFile(t, root, "/etc/passwd", "root:x")
	containers := Containers{
		Node: "node-a",
		Items: []Container{{
			ID:      "abc123",
			Name:    "api",
			State:   "CONTAINER_RUNNING",
			PodNS:   "default",
			PodName: "api-7d9c",
		}},
	}
	rules := []FileProfileRule{{
		ID:             "rule-1",
		WorkloadID:     "default/api",
		PodWorkloadIDs: []string{"default/pod/api-7d9c"},
		Filter:         "/etc/passwd",
		Path:           "/etc/passwd",
	}}

	got, err := CollectFileProfileWatches(context.Background(), FileProfileWatchOptions{
		NodeName:        "node-a",
		ProcRoot:        filepath.Dir(root),
		Containers:      containers,
		Rules:           rules,
		MaxFilesPerRule: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("rules = %+v", got.Rules)
	}
	if got.Rules[0].FilesCount != 0 {
		t.Fatalf("expected no files without CRI pid resolution, got %+v", got.Rules[0])
	}
	if !fileProfileContainerMatchesRule(containers.Items[0], rules[0]) {
		t.Fatal("pod workload id should match owner-scoped rule")
	}
}

func TestHashWatchFile(t *testing.T) {
	root := t.TempDir()
	// sha256("root:x") — the real-modification fingerprint B3 records.
	const wantHash = "fcdf07f41bc4b373f40adcfa6a90c7b5e7ce92de13ec60274bdce076b61f9a9a"

	small := filepath.Join(root, "small")
	if err := os.WriteFile(small, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	passwd := filepath.Join(root, "passwd")
	if err := os.WriteFile(passwd, []byte("root:x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := hashWatchFile(passwd, false, 6, 1<<20); got != wantHash {
		t.Fatalf("hash = %q want %q", got, wantHash)
	}
	// Disabled hashing (cap 0) -> no digest.
	if got := hashWatchFile(passwd, false, 6, 0); got != "" {
		t.Fatalf("cap 0 should disable hashing, got %q", got)
	}
	// Oversized file (size beyond cap) -> skipped.
	if got := hashWatchFile(small, false, 5, 4); got != "" {
		t.Fatalf("oversized file should be skipped, got %q", got)
	}
	// Directory -> never hashed.
	if got := hashWatchFile(root, true, 0, 1<<20); got != "" {
		t.Fatalf("directory should not be hashed, got %q", got)
	}
	// Missing file -> empty, no panic.
	if got := hashWatchFile(filepath.Join(root, "nope"), false, 1, 1<<20); got != "" {
		t.Fatalf("missing file should yield empty hash, got %q", got)
	}
}

func writeWatchFile(t *testing.T, root, containerPath, contents string) {
	t.Helper()
	full := filepath.Join(root, containerPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}
