package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	scannerCacheRecordLimit = 20
	scannerCacheWalkLimit   = 2000
)

func scannerCacheHealth(dirs map[string]string, includeUsage bool) map[string]any {
	out := map[string]any{}
	for name, path := range dirs {
		out[name] = scannerCacheDirHealth(path, includeUsage)
	}
	return out
}

func scannerCacheDirHealth(path string, includeUsage bool) map[string]any {
	path = strings.TrimSpace(path)
	out := map[string]any{"path": path, "configured": path != "", "present": false, "writable": false, "capacity_known": false, "inodes_known": false}
	if path == "" {
		out["status"] = "not-configured"
		return out
	}
	info, err := os.Stat(path)
	if err != nil {
		out["status"] = "unavailable"
		if errors.Is(err, os.ErrNotExist) {
			out["status"] = "missing"
		}
		out["error"] = err.Error()
		return out
	}
	out["present"], out["is_dir"] = true, info.IsDir()
	if !info.IsDir() {
		out["status"] = "not-directory"
		return out
	}
	if err := probeScannerCache(path); err != nil {
		out["status"], out["error"] = "write-failed", err.Error()
	} else {
		out["writable"], out["status"] = true, "ready"
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		out["capacity_error"] = err.Error()
	} else {
		addScannerCacheCapacity(out, stat)
	}
	if includeUsage {
		addScannerCacheUsage(out, path)
	}
	return out
}

// CreateTemp uses exclusive creation: concurrent heartbeats cannot truncate or
// remove each other's probes, and a pre-existing symlink is never followed.
func probeScannerCache(path string) error {
	f, err := os.CreateTemp(path, ".constellation-cache-health-*")
	if err != nil {
		return err
	}
	_, writeErr := f.Write([]byte("ok"))
	closeErr := f.Close()
	removeErr := os.Remove(f.Name())
	return errors.Join(writeErr, closeErr, removeErr)
}

func scannerCacheBytes(blocks uint64, blockSize int64) (int64, bool) {
	if blockSize <= 0 || blocks > math.MaxInt64 || int64(blocks) > math.MaxInt64/blockSize {
		return 0, false
	}
	return int64(blocks) * blockSize, true
}

func scannerCacheFreeBytes(stat syscall.Statfs_t) (int64, bool) {
	return scannerCacheBytes(stat.Bavail, stat.Bsize)
}

func addScannerCacheCapacity(out map[string]any, stat syscall.Statfs_t) {
	out["capacity_known"] = false
	if stat.Bavail > stat.Bfree || stat.Bfree > stat.Blocks || stat.Ffree > stat.Files {
		out["capacity_error"] = "inconsistent filesystem counters"
		return
	}
	values := map[string]int64{}
	for name, blocks := range map[string]uint64{"free_bytes": stat.Bavail, "filesystem_free_bytes": stat.Bfree, "capacity_bytes": stat.Blocks} {
		value, ok := scannerCacheBytes(blocks, stat.Bsize)
		if !ok {
			out["capacity_error"] = "filesystem byte count is not representable"
			return
		}
		values[name] = value
	}
	for name, value := range values {
		out[name] = value
	}
	out["capacity_known"] = true
	// Zero inode totals mean the filesystem does not report inode capacity.
	out["inodes_known"] = stat.Files > 0
	if stat.Files > math.MaxInt64 {
		out["inodes_known"] = false
		out["capacity_error"] = "filesystem inode count is not representable"
	} else if stat.Files > 0 {
		out["capacity_inodes"], out["free_inodes"] = stat.Files, stat.Ffree
	}
}

// Read directories in small batches rather than WalkDir's whole-directory read.
// os.Root confines raced path replacements to the configured cache root.
func addScannerCacheUsage(out map[string]any, path string) {
	records := make([]map[string]any, 0, scannerCacheRecordLimit+1)
	var count, total int64
	visited := 0
	partial := false
	var usageErr error
	root, err := os.OpenRoot(path)
	if err != nil {
		usageErr = err
	} else {
		defer root.Close()
		pending := []string{"."}
		for len(pending) > 0 && !partial {
			dir := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			f, err := root.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
			if err != nil {
				usageErr = err
				continue
			}
			for !partial {
				entries, readErr := f.ReadDir(64)
				for _, entry := range entries {
					if visited == scannerCacheWalkLimit {
						partial = true
						break
					}
					visited++
					rel := filepath.Join(dir, entry.Name())
					if entry.Type()&os.ModeSymlink != 0 {
						continue
					}
					if entry.IsDir() {
						pending = append(pending, rel)
						continue
					}
					info, err := root.Lstat(rel)
					if err != nil {
						usageErr = err
						continue
					}
					if !info.Mode().IsRegular() {
						continue
					}
					size := info.Size()
					if size < 0 || size > math.MaxInt64-total {
						usageErr = fmt.Errorf("cache size exceeds supported range")
						partial = true
						break
					}
					count++
					total += size
					records = append(records, map[string]any{"layer": filepath.ToSlash(rel), "size": size, "ref_count": 1, "ref_last": info.ModTime().UTC().Format(time.RFC3339)})
					sort.Slice(records, func(i, j int) bool {
						left, right := records[i]["size"].(int64), records[j]["size"].(int64)
						if left == right {
							return records[i]["layer"].(string) < records[j]["layer"].(string)
						}
						return left > right
					})
					if len(records) > scannerCacheRecordLimit {
						records = records[:scannerCacheRecordLimit]
					}
				}
				if readErr != nil {
					if !errors.Is(readErr, io.EOF) {
						usageErr = readErr
					}
					break
				}
			}
			if err := f.Close(); err != nil {
				usageErr = err
			}
		}
	}
	if usageErr != nil {
		out["usage_error"] = usageErr.Error()
	}
	out["usage_complete"] = !partial && usageErr == nil
	out["usage_entries_visited"] = visited
	out["record_count"], out["record_size_bytes"] = count, total
	out["records_truncated"] = partial || usageErr != nil || count > int64(len(records))
	out["records"] = records
}
