package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestProcessEnforcerOnKillCarriesReason proves the enforce-mode kill path reports WHY the
// process was killed (P1-05 fix): block() SIGKILLs a real child and OnKill fires with the
// drift cause, so the server can distinguish a zero-drift kill from a baseline kill instead
// of only seeing Blocked=true. Uses a real short-lived process so the SIGKILL actually lands.
func TestProcessEnforcerOnKillCarriesReason(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })

	var gotReason string
	var killed int
	e := newProcessEnforcer(processEnforcerConfig{
		Sync: &ProcessBaselineSyncWorker{},
		OnKill: func(_ int, _, _, _, _, reason string) {
			killed++
			gotReason = reason
		},
	})
	e.block(cmd.Process.Pid, "cid", "sleep", "/bin/sleep", "default/api", "zero-drift:image-drift")

	if killed != 1 {
		t.Fatalf("OnKill fired %d times, want 1", killed)
	}
	if gotReason != "zero-drift:image-drift" {
		t.Fatalf("OnKill reason = %q, want zero-drift:image-drift", gotReason)
	}
	// The child must actually be dead now.
	_, _ = cmd.Process.Wait()
	if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("process should have been killed")
	}
}

// TestProcessEnforcerOnAlertWiring proves the P0-4 zero-drift path is live once
// Workloads is wired (as main.go now does): a drifted exec in monitor mode fires
// OnAlert with the drift reason, and the same config with Workloads==nil stays
// dormant (the pre-fix production behavior). Pure /proc + tmpfile, no DB, no kill.
func TestProcessEnforcerOnAlertWiring(t *testing.T) {
	root := t.TempDir()
	cid := "abcdef012345abcdef01" // >=12 hex, passes looksLikeContainerID

	// A binary whose ctime post-dates container start => image drift (mv-swapped).
	exe := filepath.Join(t.TempDir(), "evil")
	if err := os.WriteFile(exe, []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour).UnixNano() // start BEFORE the exe ctime -> drift

	// init(100, NSpid 1) <- 300(exec, NSpid 5), lineage anchored to container init.
	fakeProcPid(t, root, 100, 1, "1", cid, "")
	fakeProcPid(t, root, 300, 100, "5", cid, exe)

	// driftViolation reads the global procRoot; point it at the fake tree.
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	wl := newWorkloadResolver()
	wl.byID = map[string]workloadIdentity{
		cid:      {ContainerID: cid, StartUnixNano: start},
		cid[:12]: {ContainerID: cid, StartUnixNano: start},
	}

	newEnforcer := func(w *workloadResolver) (*processEnforcer, *[]string) {
		var reasons []string
		e := newProcessEnforcer(processEnforcerConfig{
			Sync:      &ProcessBaselineSyncWorker{}, // non-nil, empty baseline -> never kills
			Workloads: w,
			ZeroDrift: "monitor",
			OnAlert: func(_ int, _, _, _, _, reason string) {
				reasons = append(reasons, reason)
			},
		})
		return e, &reasons
	}

	// Wired: drift is observed and OnAlert fires with the drift reason.
	e, reasons := newEnforcer(wl)
	e.onExec(300, cid, "evil", exe, "default/api")
	if len(*reasons) != 1 || (*reasons)[0] != "zero-drift:image-drift" {
		t.Fatalf("wired zero-drift: OnAlert reasons = %v, want [zero-drift:image-drift]", *reasons)
	}

	// Dormant: with Workloads==nil (the pre-fix state) driftViolation short-circuits
	// and OnAlert never fires, even in monitor mode.
	eNil, reasonsNil := newEnforcer(nil)
	eNil.onExec(300, cid, "evil", exe, "default/api")
	if len(*reasonsNil) != 0 {
		t.Fatalf("dormant (Workloads==nil): OnAlert should not fire, got %v", *reasonsNil)
	}
}
