package main

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const responseFixtureBoot = "2a46e2a1-9485-4bd6-a622-b1fcd6ee4130"

type responseTestHandle struct {
	signal func() error
	closed *int
}

func (h *responseTestHandle) Signal() error {
	if h.signal != nil {
		return h.signal()
	}
	return nil
}
func (h *responseTestHandle) Close() error {
	if h.closed != nil {
		*h.closed++
	}
	return nil
}
func responseFixtureAction() processActionV2 {
	return processActionV2{Version: 2, ID: uuid.NewString(), ActionToken: uuid.NewString(), Type: "kill_process", Node: "node-a", WorkloadID: "test/pod/worker", ContainerID: strings.Repeat("a", 64), PID: 4242, Comm: "nginx", BootID: responseFixtureBoot, StartTicks: "1234", StartBootNS: "12349999999"}
}
func writeResponseIdentityFixture(t *testing.T, root string, pid int, ticks string) {
	t.Helper()
	files := map[string]string{
		"sys/kernel/random/boot_id":   responseFixtureBoot + "\n",
		strconv.Itoa(pid) + "/cgroup": "0::/docker/" + strings.Repeat("a", 64) + "\n",
		strconv.Itoa(pid) + "/stat":   strconv.Itoa(pid) + " (nginx) S " + strings.Repeat("0 ", 18) + ticks + "\n",
	}
	for name, body := range files {
		path := filepath.Join(root, "proc", name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
func TestResponseProcessKernelIdentityCapture(t *testing.T) {
	root := t.TempDir()
	writeResponseIdentityFixture(t, root, 4242, "1234")
	boot, ticks := captureResponseProcessIdentity(filepath.Join(root, "proc"), 4242, 12349999999)
	if boot != responseFixtureBoot || ticks != "1234" {
		t.Fatalf("identity %q %q", boot, ticks)
	}
	for _, source := range []uint64{0, 12350000000} {
		boot, ticks = captureResponseProcessIdentity(filepath.Join(root, "proc"), 4242, source)
		if boot != "" || ticks != "" {
			t.Fatal("missing/reused kernel identity was rebound to current PID")
		}
	}
}
func TestResponseProcessV2NeverFallsBackFromPidfd(t *testing.T) {
	root := t.TempDir()
	writeResponseIdentityFixture(t, root, 4242, "1234")
	r := newResponder(responderConfig{Workloads: responseFixtureWorkloads(), Protected: newProtectedSet("platform", nil), Node: "node-a", HostRoot: root, KillProcessEnabled: true, currentProcessStart: func(uint32) (uint64, bool) { return 12349999999, true }, openProcess: func(int) (responseProcessHandle, error) { return nil, errors.New("ENOSYS") }})
	if res := r.ExecuteProcessV2(responseFixtureAction()); res.Outcome != "refused" || !strings.Contains(res.Reason, "no PID fallback") {
		t.Fatalf("unsafe result %+v", res)
	}
}
func TestResponseProcessV2RechecksIdentityThroughHandle(t *testing.T) {
	for _, change := range []string{"boot", "start", "node", "missing start"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			writeResponseIdentityFixture(t, root, 4242, "1234")
			a := responseFixtureAction()
			signals, closed := 0, 0
			r := newResponder(responderConfig{Workloads: responseFixtureWorkloads(), Protected: newProtectedSet("platform", nil), Node: "node-a", HostRoot: root, KillProcessEnabled: true, currentProcessStart: func(uint32) (uint64, bool) { return 12349999999, true }, openProcess: func(int) (responseProcessHandle, error) {
				// Simulate PID reuse between pidfd open and reading /proc. The pinned
				// handle can never be replaced with a later task's numeric PID.
				if change == "start" {
					writeResponseIdentityFixture(t, root, 4242, "1235")
				}
				return &responseTestHandle{closed: &closed, signal: func() error { signals++; return nil }}, nil
			}})
			switch change {
			case "boot":
				a.BootID = "396e9474-e0f6-4e59-9c8e-64cb617d89d2"
			case "node":
				a.Node = "node-b"
			case "missing start":
				a.StartTicks = ""
			}
			if res := r.ExecuteProcessV2(a); res.Outcome != "refused" || signals != 0 {
				t.Fatalf("changed identity signaled: %+v signals%d", res, signals)
			}
			if change == "start" && closed != 1 {
				t.Fatal("refused pinned handle was not closed")
			}
		})
	}
}

func TestResponseProcessV2RequiresExactKernelNanoseconds(t *testing.T) {
	for _, scenario := range []string{"same tick different process", "evicted identity", "unsupported map"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			writeResponseIdentityFixture(t, root, 4242, "1234")
			if err := os.WriteFile(filepath.Join(root, "proc/4242/comm"), []byte("nginx\n"), 0600); err != nil {
				t.Fatal(err)
			}
			signals, closed, opened := 0, 0, false
			provider := func(uint32) (uint64, bool) {
				if !opened {
					t.Fatal("identity checked before process handle was pinned")
				}
				if scenario == "same tick different process" {
					return 12349999998, true
				}
				return 0, false
			}
			if scenario == "unsupported map" {
				provider = nil
			}
			r := newResponder(responderConfig{Workloads: responseFixtureWorkloads(), Protected: newProtectedSet("platform", nil), Node: "node-a", HostRoot: root, KillProcessEnabled: true, currentProcessStart: provider, openProcess: func(int) (responseProcessHandle, error) {
				opened = true
				return &responseTestHandle{closed: &closed, signal: func() error { signals++; return nil }}, nil
			}})
			result := r.ExecuteProcessV2(responseFixtureAction())
			if result.Outcome != "refused" || result.Reason != "kernel process identity unavailable or changed" || signals != 0 || closed != 1 {
				t.Fatalf("lossy/missing identity signaled %+v signals%d closed%d", result, signals, closed)
			}
		})
	}
}

func responseFixtureWorkloads() *workloadResolver {
	a := responseFixtureAction()
	return &workloadResolver{byID: map[string]workloadIdentity{a.ContainerID: {
		ContainerID: a.ContainerID, Namespace: "test", Pod: "worker", WorkloadID: a.WorkloadID,
	}}}
}

func TestResponseProcessV2ProtectsExactWorkload(t *testing.T) {
	for _, scenario := range []string{"host", "unknown", "prefix only", "changed workload", "self", "system", "no protection"} {
		t.Run(scenario, func(t *testing.T) {
			a := responseFixtureAction()
			workloads := responseFixtureWorkloads()
			protection := newProtectedSet("platform", nil)
			switch scenario {
			case "host":
				a.ContainerID = ""
			case "unknown":
				a.ContainerID = strings.Repeat("b", 64)
			case "prefix only":
				a.ContainerID = a.ContainerID[:12]
			case "changed workload":
				a.WorkloadID = "test/pod/other"
			case "self", "system":
				identity := workloads.byID[a.ContainerID]
				identity.Namespace = "platform"
				if scenario == "system" {
					identity.Namespace = "kube-system"
				}
				identity.WorkloadID = workloadIDFromPod(identity.Namespace, identity.Pod)
				a.WorkloadID = identity.WorkloadID
				workloads.byID[a.ContainerID] = identity
			case "no protection":
				protection = nil
			}
			r := newResponder(responderConfig{Node: a.Node, Workloads: workloads, Protected: protection, KillProcessEnabled: true,
				openProcess: func(int) (responseProcessHandle, error) {
					t.Fatal("unsafe scope reached process handle")
					return nil, nil
				}})
			if result := r.ExecuteProcessV2(a); result.Outcome != "refused" {
				t.Fatalf("unsafe workload applied: %+v", result)
			}
		})
	}
}
