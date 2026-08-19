//go:build linux

package quarantine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ReadProcSnapshot reads cmdline, environ, maps, status, and the fd directory
// listing for `pid`. Failures on individual files are logged into the returned map
// as `<name>.err` files so the snapshot remains useful even on partially-readable
// pids (e.g. processes that have already exited).
func ReadProcSnapshot(_ context.Context, pid int) (map[string][]byte, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("quarantine: invalid pid %d", pid)
	}
	base := filepath.Join("/proc", fmt.Sprintf("%d", pid))
	if _, err := os.Stat(base); err != nil {
		return nil, fmt.Errorf("quarantine: pid %d not found: %w", pid, err)
	}
	out := map[string][]byte{}
	files := []string{"cmdline", "environ", "maps", "status", "stat", "comm"}
	for _, name := range files {
		body, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			out[name+".err"] = []byte(err.Error())
			continue
		}
		out[name] = body
	}
	if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		buf := make([]byte, 0, 4096)
		for _, e := range entries {
			target, _ := os.Readlink(filepath.Join(base, "fd", e.Name()))
			buf = append(buf, []byte(e.Name()+" -> "+target+"\n")...)
		}
		out["fd.list"] = buf
	}
	return out, nil
}
