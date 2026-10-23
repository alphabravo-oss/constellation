package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	grypeStagingMinAge       = 24 * time.Hour
	grypeStagingEntryLimit   = 2000
	grypeStagingRemovalLimit = 20
)

// Cleanup runs under dbRefreshMu after the engine commands finish. The cache
// must belong to this worker: age is not a lock against external importers.
func (w *worker) pruneGrypeStaging(ctx context.Context) {
	dir := w.cacheDirs["grype"]
	if dir == "" {
		dir = os.Getenv("GRYPE_DB_CACHE_DIR")
	}
	if dir == "" {
		return
	}
	removed, limited, err := pruneGrypeStagingAt(ctx, dir, time.Now())
	if err != nil {
		w.logger.Warn("grype staging cleanup incomplete", "err", err.Error())
	}
	if removed > 0 || limited {
		w.logger.Info("grype staging cleanup", "removed", removed, "limited", limited)
	}
}

// Root-relative operations prevent path replacement from escaping the opened
// cache. RemoveAll does not follow staging symlinks. Limits bound enumeration
// and selected directories, not the size or duration of one recursive removal.
func pruneGrypeStagingAt(ctx context.Context, dir string, now time.Time) (int, bool, error) {
	if err := ctx.Err(); err != nil {
		return 0, false, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return 0, false, err
	}
	defer root.Close()
	entries, err := root.Open(".")
	if err != nil {
		return 0, false, err
	}
	defer entries.Close()
	removed, visited := 0, 0
	for visited < grypeStagingEntryLimit && removed < grypeStagingRemovalLimit {
		if err := ctx.Err(); err != nil {
			return removed, false, err
		}
		batch, readErr := entries.ReadDir(min(64, grypeStagingEntryLimit-visited))
		for _, entry := range batch {
			if err := ctx.Err(); err != nil {
				return removed, false, err
			}
			visited++
			name := entry.Name()
			if !strings.HasPrefix(name, "grype-db-download") || name == "grype-db-download" {
				continue
			}
			info, err := root.Lstat(name)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return removed, false, fmt.Errorf("inspect staging: %w", err)
			}
			if !info.IsDir() || now.Sub(info.ModTime()) < grypeStagingMinAge {
				continue
			}
			if err := ctx.Err(); err != nil {
				return removed, false, err
			}
			if err := root.RemoveAll(name); err != nil {
				return removed, false, fmt.Errorf("remove staging: %w", err)
			}
			removed++
			if removed == grypeStagingRemovalLimit {
				return removed, true, nil
			}
		}
		if readErr == io.EOF {
			return removed, false, nil
		}
		if readErr != nil {
			return removed, false, readErr
		}
	}
	return removed, true, nil
}
