package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestCacheProbePreservesPreexistingSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "evidence")
	if err := os.WriteFile(target, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	trap := filepath.Join(root, fmt.Sprintf(".constellation-cache-health-%d", os.Getpid()))
	if err := os.Symlink(target, trap); err != nil {
		t.Fatal(err)
	}
	if err := probeScannerCache(root); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "preserve" {
		t.Fatalf("probe modified target: %q %v", data, err)
	}
	if _, err := os.Lstat(trap); err != nil {
		t.Fatalf("probe removed existing link: %v", err)
	}
}

func TestCacheProbesConcurrentAndClean(t *testing.T) {
	root := t.TempDir()
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if err := probeScannerCache(root); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("probe leftovers: %v %v", entries, err)
	}
}

func TestCacheHealthPathStates(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(root, "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, status string }{
		{"", "not-configured"}, {filepath.Join(root, "missing"), "missing"}, {file, "not-directory"}, {loop, "unavailable"}, {root, "ready"},
	} {
		got := scannerCacheDirHealth(tc.path, false)
		if got["status"] != tc.status {
			t.Fatalf("%q: %v", tc.path, got)
		}
		if _, ok := got["record_count"]; ok {
			t.Fatal("heartbeat unexpectedly walked cache")
		}
	}
}

func TestCacheCapacityDistinguishesReservedBytesAndInodes(t *testing.T) {
	out := map[string]any{}
	addScannerCacheCapacity(out, syscall.Statfs_t{Blocks: 100, Bfree: 30, Bavail: 20, Bsize: 4096, Files: 50, Ffree: 10})
	for key, want := range map[string]any{"capacity_known": true, "capacity_bytes": int64(409600), "filesystem_free_bytes": int64(122880), "free_bytes": int64(81920), "inodes_known": true, "capacity_inodes": uint64(50), "free_inodes": uint64(10)} {
		if out[key] != want {
			t.Errorf("%s=%v want %v", key, out[key], want)
		}
	}
	for _, stat := range []syscall.Statfs_t{
		{Blocks: 10, Bfree: 11, Bsize: 4096}, {Blocks: 10, Bfree: 5, Bavail: 6, Bsize: 4096}, {Files: 2, Ffree: 3, Bsize: 4096}, {Blocks: 1, Bsize: 0},
		{Blocks: math.MaxUint64, Bsize: 4096},
	} {
		out := map[string]any{}
		addScannerCacheCapacity(out, stat)
		if out["capacity_known"] != false || out["capacity_error"] == nil {
			t.Fatalf("invalid counters accepted: %v", out)
		}
	}
	out = map[string]any{}
	addScannerCacheCapacity(out, syscall.Statfs_t{Bsize: 4096})
	if out["inodes_known"] != false || out["free_inodes"] != nil {
		t.Fatalf("unknown inode capacity became zero headroom: %v", out)
	}
}

func TestCacheUsageBoundedWideDirectory(t *testing.T) {
	root := t.TempDir()
	for i := range scannerCacheWalkLimit + 100 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d", i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string]any{}
	addScannerCacheUsage(out, root)
	if out["usage_entries_visited"] != scannerCacheWalkLimit || out["record_count"] != int64(scannerCacheWalkLimit) || out["record_size_bytes"] != int64(scannerCacheWalkLimit) || out["usage_complete"] != false || out["records_truncated"] != true {
		t.Fatalf("unbounded or falsely complete usage: %v", out)
	}
}

func TestCacheUsageExactLimitIsComplete(t *testing.T) {
	root := t.TempDir()
	for i := range scannerCacheWalkLimit {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := map[string]any{}
	addScannerCacheUsage(out, root)
	if out["usage_complete"] != true || out["records_truncated"] != true {
		t.Fatalf("full usage and record preview conflated: %v", out)
	}
}

func TestCacheUsageIgnoresLinksAndSpecialFiles(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"outside": outside, "file": filepath.Join(outside, "secret"), "cycle": root, "broken": filepath.Join(outside, "absent")} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	addScannerCacheUsage(out, root)
	if out["usage_complete"] != true || out["record_count"] != int64(0) || out["record_size_bytes"] != int64(0) {
		t.Fatalf("nonregular files counted: %v", out)
	}
}

func TestCacheUsageStableLargestRecords(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 25; i >= 0; i-- {
		if err := os.WriteFile(filepath.Join(root, "nested", fmt.Sprintf("%02d", i)), []byte("same"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "largest"), []byte(strings.Repeat("x", 100)), 0600); err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	addScannerCacheUsage(out, root)
	records := out["records"].([]map[string]any)
	if len(records) != scannerCacheRecordLimit || records[0]["layer"] != "largest" || out["record_count"] != int64(27) || out["record_size_bytes"] != int64(204) || out["usage_complete"] != true {
		t.Fatalf("incorrect totals/preview: %v", out)
	}
	for i := 1; i < len(records); i++ {
		if records[i]["layer"] != fmt.Sprintf("nested/%02d", i-1) {
			t.Fatalf("unstable tie: %v", records)
		}
	}
}

func TestCacheUsageErrorsAreNotEmptySuccess(t *testing.T) {
	out := map[string]any{}
	addScannerCacheUsage(out, filepath.Join(t.TempDir(), "missing"))
	if out["usage_complete"] != false || out["usage_error"] == nil || out["records_truncated"] != true {
		t.Fatalf("failed walk hidden: %v", out)
	}
}

func TestCacheUnrepresentableInodesRemainUnknown(t *testing.T) {
	out := map[string]any{}
	addScannerCacheCapacity(out, syscall.Statfs_t{Bsize: 4096, Files: math.MaxUint64, Ffree: math.MaxUint64})
	if out["capacity_known"] != true || out["inodes_known"] != false || out["capacity_inodes"] != nil || out["free_inodes"] != nil || out["capacity_error"] == nil {
		t.Fatalf("unrepresentable inode counters published: %v", out)
	}
}
