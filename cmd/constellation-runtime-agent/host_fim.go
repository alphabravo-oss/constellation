package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Shared (platform-independent) surface for the B3 host-path File Integrity
// Monitor. The actual fanotify watcher lives in host_fim_linux.go; a stub in
// host_fim_other.go keeps non-linux builds green. main.go constructs the config
// on every platform, so the config/event types + helpers must be tag-free.

type hostFIMConfig struct {
	Disabled     bool
	NodeName     string
	HostRoot     string
	Paths        []string
	Interval     time.Duration
	MaxWalkDepth int
	HashMaxBytes int64
	Logger       *slog.Logger
	// OnChange receives every confirmed host-file change. Optional: when nil the
	// loop only logs. main.go wires this to the event-upload channel.
	OnChange func(hostFIMEvent)
}

type hostFIMEvent struct {
	Path   string
	Sha256 string
	Pid    int32
	Comm   string
}

// hostFIMEnabledFromEnv gates the whole host-path FIM. Default OFF: watching the
// node's own filesystem is opt-in even though it never blocks.
func hostFIMEnabledFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled", "monitor":
		return true
	default:
		return false
	}
}

// hostFIMDefaultPaths is the seeded monitor-by-default watch set: the node's
// most integrity-sensitive host paths. Overridable via CONSTELLATION_HOST_FIM_PATHS
// (comma-separated). These are CONTAINER-view absolute paths; hostFIMResolvePaths
// rebases them onto HostRoot (the mounted node root inside the DaemonSet).
func hostFIMDefaultPaths() []string {
	return []string{
		"/etc",
		"/boot",
		"/var/lib/kubelet/pki",
		"/etc/kubernetes/pki",
	}
}

// hostFIMPathsFromEnv parses the override list, falling back to defaults.
func hostFIMPathsFromEnv(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return hostFIMDefaultPaths()
	}
	out := []string{}
	for _, p := range strings.Split(value, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return hostFIMDefaultPaths()
	}
	return out
}

// hostFIMResolvePaths rebases each configured path onto HostRoot and keeps only
// the ones that currently exist. Non-existent paths (e.g. /boot on a node without
// a separate boot mount) are dropped with a debug log rather than erroring.
func hostFIMResolvePaths(hostRoot string, paths []string, logger *slog.Logger) []string {
	hostRoot = strings.TrimRight(strings.TrimSpace(hostRoot), "/")
	seen := map[string]struct{}{}
	out := []string{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") {
			continue
		}
		full := p
		if hostRoot != "" {
			full = filepath.Join(hostRoot, strings.TrimPrefix(p, "/"))
		}
		full = filepath.Clean(full)
		if _, dup := seen[full]; dup {
			continue
		}
		seen[full] = struct{}{}
		if _, err := os.Stat(full); err != nil {
			if logger != nil {
				logger.Debug("host-fim: watch path missing", slog.String("path", full))
			}
			continue
		}
		out = append(out, full)
	}
	return out
}
