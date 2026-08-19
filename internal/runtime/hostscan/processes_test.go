package hostscan

import (
	"strings"
	"testing"
)

// TestCollectProcesses_LiveProc exercises the real /proc on the test
// runner. We can't pin to specific pids but we CAN assert structural
// invariants (we see ourselves; pid 1 exists; comm names look sane).
func TestCollectProcesses_LiveProc(t *testing.T) {
	p := CollectProcesses(ProcessOptions{NodeName: "test"})
	if p.Node != "test" {
		t.Errorf("Node = %q", p.Node)
	}
	if p.Count == 0 {
		t.Fatal("no userspace processes found — /proc walk broken")
	}
	// Find pid 1 — it always exists on a running system and is userspace.
	var hasPid1 bool
	for _, proc := range p.Items {
		if proc.PID == 1 {
			hasPid1 = true
			if proc.Comm == "" {
				t.Errorf("pid 1 has empty Comm")
			}
			break
		}
	}
	if !hasPid1 {
		t.Errorf("pid 1 missing from snapshot (have %d items)", len(p.Items))
	}
}

func TestCollectProcesses_RespectsMaxItems(t *testing.T) {
	p := CollectProcesses(ProcessOptions{MaxItems: 5})
	if len(p.Items) > 5 {
		t.Errorf("len(Items) = %d, want ≤ 5", len(p.Items))
	}
	if p.Count < len(p.Items) {
		t.Errorf("Count=%d < len(Items)=%d — must be ≥", p.Count, len(p.Items))
	}
}

func TestCollectProcesses_CmdlineCap(t *testing.T) {
	p := CollectProcesses(ProcessOptions{CmdlineCap: 4, MaxItems: 1000})
	for _, proc := range p.Items {
		if len(proc.Cmdline) > 4 {
			t.Errorf("pid %d cmdline %q exceeds cap 4", proc.PID, proc.Cmdline)
		}
	}
}

func TestCollectProcesses_ExcludesKernelThreadsByDefault(t *testing.T) {
	p := CollectProcesses(ProcessOptions{MaxItems: 100000})
	// Kernel threads have an empty cmdline; with IncludeKernelThreads
	// false (default), they shouldn't appear in the snapshot.
	for _, proc := range p.Items {
		if proc.Cmdline == "" && !strings.HasPrefix(proc.Comm, "k") {
			// Userspace processes with empty cmdline are rare but
			// possible (e.g. some daemons re-exec via prctl). Only
			// flag if the comm name looks like a kernel thread
			// (k* prefix is the kthread convention).
			continue
		}
		if proc.Cmdline == "" {
			t.Errorf("pid %d (comm=%q) has empty cmdline — kernel thread leaked through filter",
				proc.PID, proc.Comm)
		}
	}
}
