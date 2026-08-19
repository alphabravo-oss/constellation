package main

import "testing"

func TestProcessEnforceShouldKill(t *testing.T) {
	rows := []processBaselineRowWire{
		{WorkloadID: "ns/api", Mode: "enforce", Processes: []string{"nginx", "sh"}},
		{WorkloadID: "ns/web", Mode: "monitor", Processes: []string{"nginx"}},
		{WorkloadID: "ns/new", Mode: "enforce", Processes: nil}, // not-yet-learned
		{WorkloadID: "ns/pod", PodWorkloadIDs: []string{"ns/pod-abc"}, Mode: "enforce", Processes: []string{"app"}},
	}
	cases := []struct {
		name               string
		wl, comm, filename string
		want               bool
	}{
		{"enforce out-of-baseline kills", "ns/api", "curl", "/usr/bin/curl", true},
		{"enforce baselined comm allowed", "ns/api", "sh", "", false},
		{"enforce baselined by filename base allowed", "ns/api", "", "/usr/sbin/nginx", false},
		{"monitor never kills", "ns/web", "curl", "/usr/bin/curl", false},
		{"empty baseline never kills", "ns/new", "anything", "/x", false},
		{"unknown workload never kills", "ns/missing", "curl", "/c", false},
		{"empty workload never kills", "", "curl", "/c", false},
		{"pod-workload-id match enforces", "ns/pod-abc", "curl", "/usr/bin/curl", true},
		{"pod-workload-id baselined allowed", "ns/pod-abc", "app", "/app", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := processEnforceShouldKill(rows, c.wl, c.comm, c.filename); got != c.want {
				t.Fatalf("shouldKill(%q,%q,%q)=%v want %v", c.wl, c.comm, c.filename, got, c.want)
			}
		})
	}
}

func TestProcessEnforcerNilSafe(t *testing.T) {
	var e *processEnforcer
	e.onExec(1, "cid", "sh", "/bin/sh", "ns/api") // must not panic
	// disabled config also no-ops
	newProcessEnforcer(processEnforcerConfig{Disabled: true}).onExec(1, "cid", "sh", "/bin/sh", "ns/api")
}

func TestProcessEnforcerEnabledFromEnv(t *testing.T) {
	for _, v := range []string{"", "0", "false", "no", "off"} {
		if processEnforcerEnabledFromEnv(v) {
			t.Fatalf("%q should be disabled (kill-on-exec is opt-in)", v)
		}
	}
	for _, v := range []string{"1", "true", "on"} {
		if !processEnforcerEnabledFromEnv(v) {
			t.Fatalf("%q should be enabled", v)
		}
	}
}
