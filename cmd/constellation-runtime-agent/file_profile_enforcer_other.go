//go:build !linux

package main

import (
	"context"
	"log/slog"
	"time"
)

type fileProfileEnforcerConfig struct {
	Disabled     bool
	NodeName     string
	Interval     time.Duration
	HostRoot     string
	CrictlBin    string
	RuleSync     *FileProfileRuleSyncWorker
	Workloads    *workloadResolver
	Status       *fileProfileEnforcementStatusStore
	Logger       *slog.Logger
	OnDeny       func(fanotifyDecisionEvent, string)
	MaxWalkDepth int
	OnExecDeny   func(event fanotifyDecisionEvent, reason string, denied bool)
}

type fanotifyDecisionEvent struct {
	Fd          int32
	Pid         int32
	Path        string
	Comm        string
	Exe         string
	ContainerID string
	WorkloadID  string
	RuleID      string
}

func fileProfileEnforcerLoop(ctx context.Context, cfg fileProfileEnforcerConfig) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	cfg.Logger.Info("file-profile-enforcer: disabled (fanotify is linux-only)")
	<-ctx.Done()
}

func fileProfileEnforcerEnabledFromEnv(value string) bool {
	return false
}

// fileCtimeUnixNano is linux-only in substance (zero-drift enforcement is
// fanotify/linux); the stub reports "unknown" so procFileWrittenAfter fails open.
func fileCtimeUnixNano(absPath string) (int64, bool) {
	return 0, false
}

func execProfileEnforcerEnabledFromEnv(value string) bool {
	return false
}

func execProfileEnforceModeFromEnv(value string) bool {
	return false
}
