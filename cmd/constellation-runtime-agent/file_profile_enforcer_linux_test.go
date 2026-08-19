package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/hostscan"
)

func TestEnforceableFileProfileRules(t *testing.T) {
	got := enforceableFileProfileRules([]fileProfileRuleWire{
		{ID: "learn", Mode: "learn", Behavior: "block_access", Filter: "/etc/passwd", Path: "/etc/passwd"},
		{ID: "monitor", Mode: "monitor", Behavior: "block_access", Filter: "/etc/passwd", Path: "/etc/passwd"},
		{ID: "observe", Mode: "enforce", Behavior: "monitor_change", Filter: "/etc/passwd", Path: "/etc/passwd"},
		{ID: "block", Mode: "enforce", Behavior: "block_access", WorkloadID: "default/api", Filter: "/etc/passwd", Path: "/etc/passwd"},
	})
	if len(got) != 1 || got[0].ID != "block" {
		t.Fatalf("enforceable rules = %+v", got)
	}
}

func TestFileProfileOpenDecision(t *testing.T) {
	rules := enforceableFileProfileRules([]fileProfileRuleWire{{
		ID:             "rule-1",
		WorkloadID:     "default/api",
		PodWorkloadIDs: []string{"default/pod/api-7d9c"},
		Mode:           "enforce",
		Filter:         "/var/run/secrets/kubernetes.io/serviceaccount/*",
		Path:           "/var/run/secrets/kubernetes\\.io/serviceaccount",
		Regex:          ".*",
		Recursive:      true,
		Behavior:       "block_access",
		Applications:   []string{"cat"},
		Exceptions: []fileProfileExceptionWire{{
			ID:           "exception-1",
			Filter:       "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
			Path:         "/var/run/secrets/kubernetes\\.io/serviceaccount/ca\\.crt",
			Applications: []string{"sh"},
		}},
	}})
	tests := []struct {
		name string
		ev   fanotifyDecisionEvent
		deny bool
	}{
		{
			name: "denies non-allowlisted app",
			ev: fanotifyDecisionEvent{
				Path:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
				Comm:       "sh",
				WorkloadID: "default/pod/api-7d9c",
			},
			deny: true,
		},
		{
			name: "allows matching exception",
			ev: fanotifyDecisionEvent{
				Path:       "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
				Comm:       "sh",
				WorkloadID: "default/pod/api-7d9c",
			},
			deny: false,
		},
		{
			name: "allows allowlisted app",
			ev: fanotifyDecisionEvent{
				Path:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
				Comm:       "cat",
				WorkloadID: "default/pod/api-7d9c",
			},
			deny: false,
		},
		{
			name: "ignores other workload",
			ev: fanotifyDecisionEvent{
				Path:       "/var/run/secrets/kubernetes.io/serviceaccount/token",
				Comm:       "sh",
				WorkloadID: "default/pod/other",
			},
			deny: false,
		},
		{
			name: "denies matching workload when fanotify path is host resolved",
			ev: fanotifyDecisionEvent{
				Path:       "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs/token",
				Comm:       "sh",
				WorkloadID: "default/pod/api-7d9c",
			},
			deny: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deny, ruleID := fileProfileOpenDecision(tt.ev, rules)
			if deny != tt.deny {
				t.Fatalf("deny=%v rule=%q want deny=%v", deny, ruleID, tt.deny)
			}
			if deny && ruleID != "rule-1" {
				t.Fatalf("rule id = %q", ruleID)
			}
		})
	}
}

// TestFileProfileOpenDecisionNoOverBlock guards the path-less-fallback fix: a
// glob rule for /etc/*shadow* marks the whole /etc dir (FAN_EVENT_ON_CHILD), so
// fanotify also delivers opens of unrelated siblings like /etc/hosts. Those must
// NOT be denied (basename doesn't match the rule), while the real target and a
// host-overlay path whose basename matches must still be denied.
func TestFileProfileOpenDecisionNoOverBlock(t *testing.T) {
	rules := enforceableFileProfileRules([]fileProfileRuleWire{{
		ID:         "shadow",
		WorkloadID: "default/api",
		Mode:       "enforce",
		Filter:     "/etc/*shadow*",
		Path:       "/etc",
		Regex:      ".*shadow.*",
		Behavior:   "block_access",
	}})
	tests := []struct {
		name string
		path string
		deny bool
	}{
		{"denies matching target", "/etc/shadow", true},
		{"denies shadow- sibling", "/etc/shadow-", true},
		{"allows unrelated sibling under marked dir", "/etc/hosts", false},
		{"allows another unrelated sibling", "/etc/passwd", false},
		// Host-overlay path: directory can't be matched textually, but the
		// basename matches the rule's filename glob → still denied.
		{"denies host-overlay path with matching basename", "/var/lib/containerd/snapshots/2/fs/etc-shadow", true},
		// Host-overlay path whose basename does NOT match → must be allowed.
		{"allows host-overlay path with non-matching basename", "/var/lib/containerd/snapshots/2/fs/hosts", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deny, _ := fileProfileOpenDecision(fanotifyDecisionEvent{
				Path: tt.path, WorkloadID: "default/api",
			}, rules)
			if deny != tt.deny {
				t.Fatalf("path %q: deny=%v want %v", tt.path, deny, tt.deny)
			}
		})
	}
}

func TestFileProfileEnforcerMarkPaths(t *testing.T) {
	root := t.TempDir()
	writeEnforcerFile(t, root, "/etc/passwd")
	writeEnforcerFile(t, root, "/usr/bin/cat")
	writeEnforcerFile(t, root, "/usr/bin/tools/nested")

	exact := fileProfileEnforceRule{ID: "exact", Filter: "/etc/passwd"}
	got := fileProfileEnforcerMarkPaths(root, exact, 4)
	if len(got) != 1 || got[0] != filepath.Join(root, "etc/passwd") {
		t.Fatalf("exact mark paths = %+v", got)
	}

	nonRecursive := fileProfileEnforceRule{ID: "wild", Filter: "/usr/bin/*"}
	got = fileProfileEnforcerMarkPaths(root, nonRecursive, 4)
	if len(got) != 1 || got[0] != filepath.Join(root, "usr/bin") {
		t.Fatalf("non-recursive mark paths = %+v", got)
	}

	recursive := fileProfileEnforceRule{ID: "wild", Filter: "/usr/bin/*", Recursive: true}
	got = fileProfileEnforcerMarkPaths(root, recursive, 4)
	if len(got) != 2 || got[0] != filepath.Join(root, "usr/bin") || got[1] != filepath.Join(root, "usr/bin/tools") {
		t.Fatalf("recursive mark paths = %+v", got)
	}
}

func TestFileProfileEnforcementStatusPropagation(t *testing.T) {
	store := newFileProfileEnforcementStatusStore()
	store.Replace(map[string]fileProfileEnforcementStatus{
		"rule-1": {Protect: true, State: "enforced"},
	})
	got := applyFileProfileEnforcementStatus([]hostscan.FileProfileWatchRule{
		{ID: "rule-1"},
		{ID: "rule-2"},
	}, store)
	if !got[0].Protect || got[0].Enforcement != "enforced" {
		t.Fatalf("rule-1 status = %+v", got[0])
	}
	if got[1].Protect || got[1].Enforcement != "" {
		t.Fatalf("rule-2 status = %+v", got[1])
	}
}

func TestContainerIDFromProcCgroup(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "123")
	if err := os.MkdirAll(proc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cgroup"), []byte("0::/kubepods.slice/cri-containerd-abcdef1234567890.scope\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := containerIDFromProcCgroup(root, 123); got != "abcdef1234567890" {
		t.Fatalf("container id = %q", got)
	}
}

func writeEnforcerFile(t *testing.T, root, p string) {
	t.Helper()
	full := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}
