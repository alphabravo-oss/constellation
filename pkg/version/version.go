// Package version exposes the per-binary build triplet so each Constellation
// component can self-identify on startup, on the /api/v1/version endpoint, and
// in the heartbeat payload it pushes to the control plane every 30 seconds.
//
// All three values are overridable at link time via -ldflags. A typical build
// invocation injects them like so:
//
//	CHART_VERSION=1.4.2
//	GIT_SHA=$(git rev-parse HEAD)
//	BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
//	go build -ldflags "\
//	  -X github.com/alphabravocompany/constellation/pkg/version.Version=$CHART_VERSION \
//	  -X github.com/alphabravocompany/constellation/pkg/version.Commit=$GIT_SHA \
//	  -X github.com/alphabravocompany/constellation/pkg/version.BuildTime=$BUILD_TIME"
//
// When the ldflags are not set (local `go run` / `go test`), Version, Commit,
// and BuildTime fall back to "dev"/zero so the rest of the platform still has
// something to render and operators can immediately spot "this is unreleased."
package version

import (
	"log/slog"
	"os"
	"runtime"
	"strconv"
	"time"
)

// Build-tagged identity. These are exported var (not const) so -ldflags -X can
// overwrite them at link time. Treat them as read-only at runtime.
var (
	// Version is the chart/release version, e.g. "1.4.2" or "dev".
	Version = "dev"
	// Commit is the full git SHA the binary was built from.
	Commit = "dev"
	// BuildTime is an RFC3339 UTC timestamp set at build time.
	BuildTime = ""
)

// Info is the structured triplet a component reports up.
type Info struct {
	Component   string    `json:"component"`
	Version     string    `json:"version"`
	Commit      string    `json:"commit"`
	BuildTime   time.Time `json:"build_time"`
	GoVersion   string    `json:"go_version"`
	Hostname    string    `json:"hostname"`
	StartedAt   time.Time `json:"started_at"`
	Pid         int       `json:"pid"`
	RestartHint string    `json:"restart_hint,omitempty"`
}

// startedAt is captured at package init so uptime is "this process",
// not "this request handler".
var startedAt = time.Now().UTC()

// Started returns the process start time (UTC). Used by the heartbeat loop
// to compute uptime_seconds without making each component thread its own
// clock through the call graph.
func Started() time.Time { return startedAt }

// Uptime returns time since the process started.
func Uptime() time.Duration { return time.Since(startedAt) }

// ShortCommit returns the first 7 chars of Commit (git-short style), or the
// commit unmodified if shorter. Useful for log lines + UI rendering.
func ShortCommit() string {
	if len(Commit) <= 7 {
		return Commit
	}
	return Commit[:7]
}

// BuildTimeParsed best-effort parses BuildTime as RFC3339. Returns zero time
// when BuildTime is empty or malformed — callers should treat zero as "unknown".
func BuildTimeParsed() time.Time {
	if BuildTime == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, BuildTime)
	if err != nil {
		// Some CI systems emit unix epoch seconds; tolerate that too.
		if n, err := strconv.ParseInt(BuildTime, 10, 64); err == nil {
			return time.Unix(n, 0).UTC()
		}
		return time.Time{}
	}
	return t.UTC()
}

// InfoFor builds a populated Info for the given logical component name.
// Hostname / PID / GoVersion are pulled from the live process so the API
// can correlate a heartbeat row with the actual node it came from.
func InfoFor(component string) Info {
	host, _ := os.Hostname()
	return Info{
		Component: component,
		Version:   Version,
		Commit:    Commit,
		BuildTime: BuildTimeParsed(),
		GoVersion: runtime.Version(),
		Hostname:  host,
		StartedAt: startedAt,
		Pid:       os.Getpid(),
	}
}

// LogStartup emits a single slog INFO line tagged "component.version" with the
// build triplet for the named component. Every binary calls this exactly once
// during startup so kubectl logs / journalctl always shows "what is running."
func LogStartup(logger *slog.Logger, component string) {
	if logger == nil {
		logger = slog.Default()
	}
	info := InfoFor(component)
	logger.Info("component.version",
		slog.String("component", component),
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
		slog.String("commit_short", ShortCommit()),
		slog.String("build_time", info.BuildTime.Format(time.RFC3339)),
		slog.String("go", info.GoVersion),
		slog.String("hostname", info.Hostname),
		slog.Int("pid", info.Pid),
	)
}
