//go:build linux

// B3 (host-path FIM). Today file monitoring is scoped to CONTAINER roots — the
// file-profile enforcer/watcher only marks paths inside pods. This adds an
// opt-in HOST-path File Integrity Monitor that continuously watches the node's
// own sensitive paths (/etc, /boot, kubelet PKI, ...) and reports genuine
// content modifications, reusing the same fanotify machinery.
//
// Models NeuVector share/fsmon: continuous fanotify+inotify on host files with a
// per-file content hash so a metadata-only touch (atime/mtime) doesn't fire a
// false positive. Here we compute the sha256 on each change and hand it to the
// event pipeline; the server compares digests across reports to confirm a real
// modification.
//
// SAFETY: MONITOR-ONLY by construction. The mark uses FAN_CLASS_NOTIF (not the
// *_PERM permission class), so the kernel delivers a notification AFTER the write
// completes — it is physically incapable of blocking a write. It is also default
// OFF (opt-in via CONSTELLATION_HOST_FIM). There is no enforce path.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type hostFIMWatcher struct {
	fd int
}

func hostFIMLoop(ctx context.Context, cfg hostFIMConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Disabled {
		cfg.Logger.Info("host-fim: disabled")
		return
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.MaxWalkDepth <= 0 {
		cfg.MaxWalkDepth = 4
	}
	paths := hostFIMResolvePaths(cfg.HostRoot, cfg.Paths, cfg.Logger)
	if len(paths) == 0 {
		cfg.Logger.Info("host-fim: no watch paths resolved")
		return
	}
	cfg.Logger.Info("host-fim: started (monitor-only)",
		slog.Int("paths", len(paths)),
		slog.Int64("hash_max_bytes", cfg.HashMaxBytes))

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := newHostFIMWatcher()
		if err != nil {
			cfg.Logger.Warn("host-fim: fanotify unavailable", slog.String("err", err.Error()))
			if !sleepOrDone(ctx, cfg.Interval) {
				return
			}
			continue
		}
		marked, markErrs := watcher.markPaths(paths, cfg.MaxWalkDepth)
		cfg.Logger.Info("host-fim: refreshed marks",
			slog.Int("marked", marked), slog.Int("errors", markErrs))
		if marked == 0 {
			_ = watcher.Close()
			if !sleepOrDone(ctx, cfg.Interval) {
				return
			}
			continue
		}
		timer := time.NewTimer(cfg.Interval)
		watcher.serve(ctx, timer.C, cfg)
		timer.Stop()
		_ = watcher.Close()
	}
}

func newHostFIMWatcher() (*hostFIMWatcher, error) {
	// FAN_CLASS_NOTIF: notification-only. No permission decision is ever asked
	// of us, so a write can never be blocked here — monitor by construction.
	fd, err := unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_NOTIF|unix.FAN_NONBLOCK, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &hostFIMWatcher{fd: fd}, nil
}

func (w *hostFIMWatcher) Close() error {
	if w == nil || w.fd < 0 {
		return nil
	}
	err := unix.Close(w.fd)
	w.fd = -1
	return err
}

// markPaths marks each configured path for content-modification events. For a
// directory we add FAN_EVENT_ON_CHILD and walk a bounded number of levels so a
// nested tree (e.g. /var/lib/kubelet/pki) is covered without unbounded cost.
// fanotify inode marks are not recursive, so each directory is marked in turn.
func (w *hostFIMWatcher) markPaths(paths []string, maxDepth int) (int, int) {
	mask := uint64(unix.FAN_MODIFY | unix.FAN_CLOSE_WRITE)
	marked, errs := 0, 0
	seen := map[string]struct{}{}
	mark := func(p string, withChild bool) {
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		m := mask
		if withChild {
			m |= unix.FAN_EVENT_ON_CHILD
		}
		if err := unix.FanotifyMark(w.fd, unix.FAN_MARK_ADD, m, unix.AT_FDCWD, p); err != nil {
			errs++
			return
		}
		marked++
	}
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			errs++
			continue
		}
		if !st.IsDir() {
			mark(p, false)
			continue
		}
		rootDepth := hostFIMDepth(p)
		_ = filepath.WalkDir(p, func(full string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			if hostFIMDepth(full)-rootDepth > maxDepth {
				return filepath.SkipDir
			}
			mark(full, true)
			return nil
		})
	}
	return marked, errs
}

func (w *hostFIMWatcher) serve(ctx context.Context, refresh <-chan time.Time, cfg hostFIMConfig) {
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh:
			return
		default:
		}
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			cfg.Logger.Warn("host-fim: read failed", slog.String("err", err.Error()))
			return
		}
		w.handleEvents(cfg, buf[:n])
	}
}

func (w *hostFIMWatcher) handleEvents(cfg hostFIMConfig, buf []byte) {
	metaSize := int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
	for len(buf) >= metaSize {
		meta := (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[0]))
		if meta.Event_len < uint32(metaSize) || int(meta.Event_len) > len(buf) {
			return
		}
		if meta.Vers != unix.FANOTIFY_METADATA_VERSION {
			return
		}
		if meta.Fd >= 0 {
			if meta.Mask&(unix.FAN_MODIFY|unix.FAN_CLOSE_WRITE) != 0 {
				path := readlinkOrEmpty(fmt.Sprintf("/proc/self/fd/%d", meta.Fd))
				if path != "" {
					ev := hostFIMEvent{
						Path:   path,
						Sha256: hashHostFIMFile(path, cfg.HashMaxBytes),
						Pid:    meta.Pid,
						Comm:   hostFIMComm(cfg.HostRoot, meta.Pid),
					}
					cfg.Logger.Info("host-fim: file changed",
						slog.String("path", ev.Path),
						slog.String("sha256", ev.Sha256),
						slog.Int("pid", int(ev.Pid)),
						slog.String("comm", ev.Comm))
					if cfg.OnChange != nil {
						cfg.OnChange(ev)
					}
				}
			}
			_ = unix.Close(int(meta.Fd))
		}
		buf = buf[int(meta.Event_len):]
	}
}

// hostFIMComm best-effort reads the writing process's comm from the host proc.
func hostFIMComm(hostRoot string, pid int32) string {
	if pid <= 0 {
		return ""
	}
	return strings.TrimSpace(readFileOrEmpty(filepath.Join(fileProfileEnforcerProcRoot(hostRoot), strconv.Itoa(int(pid)), "comm")))
}

// hashHostFIMFile is the B3 real-modification confirmation: bounded sha256 of the
// changed file. Empty when hashing is disabled (maxBytes<=0), the file is too
// large, or it can't be read.
func hashHostFIMFile(path string, maxBytes int64) string {
	if maxBytes <= 0 {
		return ""
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > maxBytes {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxBytes)); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func hostFIMDepth(p string) int {
	p = strings.Trim(filepath.Clean(p), "/")
	if p == "" {
		return 0
	}
	return strings.Count(p, "/") + 1
}
