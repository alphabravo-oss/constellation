package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProcessProfileDecision(t *testing.T) {
	entries := []processProfileEntry{
		{Path: "/usr/sbin/nginx", Action: processActionAllow},
		{Basename: "sh", Action: processActionAllow},
		{Basename: "curl", Action: processActionDeny},
	}
	cases := []struct {
		name        string
		ex          processExecContext
		wantAction  string
		wantMatched bool
	}{
		{"exact path allow", processExecContext{ExePath: "/usr/sbin/nginx"}, processActionAllow, true},
		{"renamed nginx at other path not matched", processExecContext{ExePath: "/bin/nginx", Comm: "nginx"}, "", false},
		{"basename allow via comm", processExecContext{Comm: "sh", ExePath: "/bin/sh"}, processActionAllow, true},
		{"explicit deny wins", processExecContext{Comm: "curl", ExePath: "/usr/bin/curl"}, processActionDeny, true},
		{"unknown not matched", processExecContext{Comm: "python", ExePath: "/usr/bin/python"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			action, matched := processProfileDecision(entries, c.ex)
			if action != c.wantAction || matched != c.wantMatched {
				t.Fatalf("decision=(%q,%v) want (%q,%v)", action, matched, c.wantAction, c.wantMatched)
			}
		})
	}
}

func TestProcessProfileHashParentUid(t *testing.T) {
	uid := int64(0)
	entries := []processProfileEntry{
		{Path: "/bin/nginx", Sha256: "abc123", ParentName: "init", Uid: uid, UidSet: true, Action: processActionAllow},
	}
	good := processExecContext{ExePath: "/bin/nginx", Sha256: "ABC123", ParentName: "init", Uid: 0, UidKnown: true}
	if !processProfileAllows(entries, good) {
		t.Fatalf("expected allow for exact path+hash+parent+uid match (hash case-insensitive)")
	}
	// Swapped binary: same path, different hash -> not allowed (the mv evil /bin/nginx case).
	swapped := processExecContext{ExePath: "/bin/nginx", Sha256: "deadbeef", ParentName: "init", Uid: 0, UidKnown: true}
	if processProfileAllows(entries, swapped) {
		t.Fatalf("expected DENY for /bin/nginx with a different sha256 (swapped binary)")
	}
	// Wrong parent.
	if processProfileAllows(entries, processExecContext{ExePath: "/bin/nginx", Sha256: "abc123", ParentName: "bash", Uid: 0, UidKnown: true}) {
		t.Fatalf("expected DENY for wrong parent")
	}
	// Wrong uid.
	if processProfileAllows(entries, processExecContext{ExePath: "/bin/nginx", Sha256: "abc123", ParentName: "init", Uid: 1000, UidKnown: true}) {
		t.Fatalf("expected DENY for wrong uid")
	}
}

func TestProcessProfileAllowsEmpty(t *testing.T) {
	// Empty profile allows everything (nothing learned -> never block).
	if !processProfileAllows(nil, processExecContext{Comm: "anything"}) {
		t.Fatalf("empty profile must allow")
	}
	// Non-empty allowlist with no match -> out-of-profile.
	if processProfileAllows([]processProfileEntry{{Basename: "nginx", Action: processActionAllow}},
		processExecContext{Comm: "curl", ExePath: "/usr/bin/curl"}) {
		t.Fatalf("out-of-profile exec must not be allowed under an allowlist")
	}
}

func TestBridgeBasenameEntries(t *testing.T) {
	entries := bridgeBasenameEntries([]string{"nginx", " ", "sh"})
	if len(entries) != 2 {
		t.Fatalf("want 2 entries (blank dropped), got %d", len(entries))
	}
	if !processProfileAllows(entries, processExecContext{Comm: "sh"}) {
		t.Fatalf("bridged basename should allow matching comm")
	}
	if processProfileAllows(entries, processExecContext{Comm: "curl"}) {
		t.Fatalf("bridged basename should not allow non-listed comm")
	}
}

// TestEntriesFromBundleRejectsRenamedBinary is the RT-MATCH-16 acceptance at the
// matcher layer: a bundle that pins the learned nginx to its full path rejects a
// binary renamed to the allowed basename at a DIFFERENT path, whereas the legacy
// basename-only bundle would wrongly allow it.
func TestEntriesFromBundleRejectsRenamedBinary(t *testing.T) {
	// Rich bundle: nginx learned at its real path.
	rich := entriesFromBundle([]processBaselineEntryWire{
		{Basename: "nginx", Path: "/usr/sbin/nginx", Action: "allow"},
	})
	legit := processExecContext{Comm: "nginx", ExePath: "/usr/sbin/nginx"}
	renamed := processExecContext{Comm: "nginx", ExePath: "/tmp/nginx"} // evil renamed to allowed name

	if !processProfileAllows(rich, legit) {
		t.Fatalf("legit nginx at learned path must be allowed")
	}
	if processProfileAllows(rich, renamed) {
		t.Fatalf("RT-MATCH-16: renamed binary at /tmp/nginx must be REJECTED by full-path match")
	}

	// The legacy basename bundle (what shipped before) would allow the rename — this
	// asserts the fix actually changed behavior, not that the matcher was always strict.
	legacy := bridgeBasenameEntries([]string{"nginx"})
	if !processProfileAllows(legacy, renamed) {
		t.Fatalf("sanity: legacy basename-only match should (wrongly) allow the rename")
	}
}

// TestEntriesFromBundleFallback verifies an entry with no absolute path stays a
// basename wildcard (the documented fallback for older rows).
func TestEntriesFromBundleFallback(t *testing.T) {
	entries := entriesFromBundle([]processBaselineEntryWire{{Basename: "sh", Action: "allow"}})
	if !processProfileAllows(entries, processExecContext{Comm: "sh", ExePath: "/bin/sh"}) {
		t.Fatalf("basename-only entry must allow any path for that basename")
	}
	// A deny entry from an authored rule wins.
	deny := entriesFromBundle([]processBaselineEntryWire{
		{Basename: "sh", Action: "allow"},
		{Basename: "curl", Action: "deny"},
	})
	if processProfileAllows(deny, processExecContext{Comm: "curl", ExePath: "/usr/bin/curl"}) {
		t.Fatalf("authored deny entry must reject curl")
	}
	// Empty entries -> nil so the caller falls back to basename bridging.
	if entriesFromBundle(nil) != nil {
		t.Fatalf("no entries must return nil for fallback")
	}
}

// TestDetectSetuidEscalations is the RT-SETUID-49 agent-side pure detection: a pid
// that escalates its effective UID to 0 on the same process instance (no exec) is
// reported; pid reuse and non-escalations are not.
func TestDetectSetuidEscalations(t *testing.T) {
	prev := map[uint32]uidSample{
		100: {euid: 1000, startTicks: 5, comm: "app", container: "c1"}, // will escalate
		200: {euid: 0, startTicks: 7, comm: "root", container: "c1"},   // already root
		300: {euid: 1000, startTicks: 9, comm: "gone", container: "c1"},
	}
	cur := map[uint32]uidSample{
		100: {euid: 0, startTicks: 5, comm: "app", container: "c1"},  // escalated, same instance
		200: {euid: 0, startTicks: 7, comm: "root", container: "c1"}, // unchanged root
		300: {euid: 0, startTicks: 99, comm: "reuse", container: "c1"}, // pid reused (diff startTicks)
	}
	got := detectSetuidEscalations(prev, cur)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 escalation, got %d: %+v", len(got), got)
	}
	if got[0].PID != 100 || got[0].PrevUID != 1000 || got[0].UID != 0 {
		t.Fatalf("unexpected escalation: %+v", got[0])
	}
}

func TestExecTrackerExcludesExecDriven(t *testing.T) {
	tr := newExecTracker()
	base := time.Now()
	tr.Record(100, base.Add(1*time.Second))
	if !tr.ExecedSince(100, base) {
		t.Fatalf("pid that exec'd after the sample window must be reported")
	}
	if tr.ExecedSince(200, base) {
		t.Fatalf("pid that never exec'd must not be reported")
	}
	// A nil tracker is safe and reports false.
	var nilTr *execTracker
	nilTr.Record(1, base)
	if nilTr.ExecedSince(1, base) {
		t.Fatalf("nil tracker must report false")
	}
}

func TestExecIsDrift(t *testing.T) {
	cases := []struct {
		z    zeroDriftContext
		want bool
	}{
		{zeroDriftContext{IsRootProcess: true}, false},              // root always ok
		{zeroDriftContext{Anchored: true, FromImage: true}, false},  // anchored + image
		{zeroDriftContext{Anchored: false, FromImage: true}, true},  // unanchored
		{zeroDriftContext{Anchored: true, FromImage: false}, true},  // image drift
		{zeroDriftContext{Anchored: false, FromImage: false}, true}, // both
	}
	for i, c := range cases {
		if got := execIsDrift(c.z); got != c.want {
			t.Fatalf("case %d: execIsDrift(%+v)=%v want %v", i, c.z, got, c.want)
		}
	}
}

func TestExecIsAnchored(t *testing.T) {
	// Lineage: 100(init,NSpid1) <- 200 <- 300(exec). All in container "c".
	parents := map[uint32]uint32{300: 200, 200: 100, 100: 1}
	inContainer := map[uint32]bool{300: true, 200: true, 100: true}
	init := map[uint32]bool{100: true}
	getParent := func(p uint32) (uint32, bool) { v, ok := parents[p]; return v, ok }
	sameContainer := func(p uint32) bool { return inContainer[p] }
	isInit := func(p uint32) bool { return init[p] }

	if !execIsAnchored(300, "c", getParent, sameContainer, isInit) {
		t.Fatalf("expected anchored for an intact lineage to the container init")
	}

	// Injected exec (kubectl/docker exec): pid 400's parent 999 is the runtime shim
	// (outside the container), and 400 is NOT the init -> unanchored.
	parents2 := map[uint32]uint32{400: 999}
	inContainer2 := map[uint32]bool{400: true, 999: false}
	getParent2 := func(p uint32) (uint32, bool) { v, ok := parents2[p]; return v, ok }
	sameContainer2 := func(p uint32) bool { return inContainer2[p] }
	isInit2 := func(p uint32) bool { return false }
	if execIsAnchored(400, "c", getParent2, sameContainer2, isInit2) {
		t.Fatalf("expected UNANCHORED for an injected exec")
	}

	// Non-container exec -> never anchored.
	if execIsAnchored(300, "", getParent, sameContainer, isInit) {
		t.Fatalf("empty containerID must not anchor")
	}
}

func TestReadPPID(t *testing.T) {
	dir := t.TempDir()
	// comm with spaces + parens to exercise the LastIndex(")") split.
	stat := filepath.Join(dir, "stat")
	if err := os.WriteFile(stat, []byte("1234 (weird )name) S 42 1 1 0 -1 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	ppid, ok := readPPID(stat)
	if !ok || ppid != 42 {
		t.Fatalf("readPPID=(%d,%v) want (42,true)", ppid, ok)
	}
	if _, ok := readPPID(filepath.Join(dir, "absent")); ok {
		t.Fatalf("missing stat should report ok=false")
	}
}

func TestProcFileWrittenAfter(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(f, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Hour).UnixNano()
	future := time.Now().Add(time.Hour).UnixNano()

	if drifted, ok := procFileWrittenAfter(f, past); !ok || !drifted {
		t.Fatalf("file created now vs past start should be drifted: (%v,%v)", drifted, ok)
	}
	if drifted, ok := procFileWrittenAfter(f, future); !ok || drifted {
		t.Fatalf("file created now vs future start should not be drifted: (%v,%v)", drifted, ok)
	}
	if _, ok := procFileWrittenAfter(filepath.Join(t.TempDir(), "gone"), past); ok {
		t.Fatalf("missing file should report ok=false (fail-open)")
	}
	if _, ok := procFileWrittenAfter(f, 0); ok {
		t.Fatalf("zero start time should report ok=false")
	}
}

func TestNormalizeZeroDriftMode(t *testing.T) {
	for _, v := range []string{"", "off", "nonsense", "disabled"} {
		if got := normalizeZeroDriftMode(v); got != "off" {
			t.Fatalf("normalizeZeroDriftMode(%q)=%q want off", v, got)
		}
	}
	if normalizeZeroDriftMode("monitor") != "monitor" || normalizeZeroDriftMode("alert") != "monitor" {
		t.Fatalf("monitor aliases should map to monitor")
	}
	if normalizeZeroDriftMode("enforce") != "enforce" || normalizeZeroDriftMode("block") != "enforce" {
		t.Fatalf("enforce aliases should map to enforce")
	}
}

func TestExecProfileEnforcerEnvDefaults(t *testing.T) {
	// Both pre-exec gates default OFF / MONITOR.
	if execProfileEnforcerEnabledFromEnv("") || execProfileEnforcerEnabledFromEnv("0") {
		t.Fatalf("exec enforcer must default OFF")
	}
	if !execProfileEnforcerEnabledFromEnv("on") {
		t.Fatalf("exec enforcer should enable on 'on'")
	}
	if execProfileEnforceModeFromEnv("") || execProfileEnforceModeFromEnv("monitor") {
		t.Fatalf("exec enforce mode must default MONITOR")
	}
	if !execProfileEnforceModeFromEnv("enforce") {
		t.Fatalf("exec enforce mode should enable on 'enforce'")
	}
}
