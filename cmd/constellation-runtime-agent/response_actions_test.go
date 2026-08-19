package main

import (
	"context"
	"syscall"
	"testing"
)

func TestKillProcessDecision(t *testing.T) {
	cases := []struct {
		name            string
		action          responseAction
		procComm        string
		procContainerID string
		wantOK          bool
		wantReason      string
	}{
		{
			name:   "refuses init pid",
			action: responseAction{PID: 1, Comm: "systemd"},
			wantOK: false, wantReason: "invalid pid",
		},
		{
			name:   "refuses pid 0",
			action: responseAction{PID: 0},
			wantOK: false, wantReason: "invalid pid",
		},
		{
			name:     "comm mismatch (pid reuse guard)",
			action:   responseAction{PID: 4242, Comm: "nginx"},
			procComm: "sshd",
			wantOK:   false, wantReason: "comm mismatch",
		},
		{
			name:            "container mismatch",
			action:          responseAction{PID: 4242, Comm: "nginx", ContainerID: "containerd://aaa"},
			procComm:        "nginx",
			procContainerID: "bbb",
			wantOK:          false, wantReason: "container mismatch",
		},
		{
			name:            "match by comm and container",
			action:          responseAction{PID: 4242, Comm: "nginx", ContainerID: "containerd://aaa"},
			procComm:        "nginx",
			procContainerID: "aaa",
			wantOK:          true,
		},
		{
			name:   "unknown comm falls open on that dimension",
			action: responseAction{PID: 4242, Comm: "nginx"},
			// procComm empty (unreadable) -> comm check skipped, pid in range -> ok
			wantOK: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := killProcessDecision(tc.action, tc.procComm, tc.procContainerID)
			if ok != tc.wantOK || (!ok && reason != tc.wantReason) {
				t.Fatalf("killProcessDecision = (%v,%q), want (%v,%q)", ok, reason, tc.wantOK, tc.wantReason)
			}
		})
	}
}

func TestConntrackDeleteArgs(t *testing.T) {
	// Complete tcp tuple -> full arg vector.
	args, reason := conntrackDeleteArgs(responseAction{
		Protocol: "tcp", SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 443,
	})
	if args == nil {
		t.Fatalf("expected args, got reason %q", reason)
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	want := "-D -s 10.0.0.1 -d 10.0.0.2 -p tcp --sport 12345 --dport 443 "
	if joined != want {
		t.Fatalf("args = %q, want %q", joined, want)
	}

	// Missing/invalid endpoints -> refused.
	if a, r := conntrackDeleteArgs(responseAction{SrcIP: "nope", DstIP: "10.0.0.2"}); a != nil || r != "invalid src/dst ip" {
		t.Fatalf("invalid ip = (%v,%q)", a, r)
	}
	// Unsupported protocol -> refused.
	if a, r := conntrackDeleteArgs(responseAction{Protocol: "icmp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2"}); a != nil || r != "unsupported protocol" {
		t.Fatalf("icmp = (%v,%q)", a, r)
	}
}

func TestResponderExecute_DisabledAndGated(t *testing.T) {
	killed := 0
	r := newResponder(responderConfig{
		Node:               "node-a",
		KillProcessEnabled: false, // gated OFF
		killFn:             func(pid int, sig syscall.Signal) error { killed++; return nil },
	})
	res := r.Execute(context.Background(), responseAction{ID: "a1", Type: "kill_process", PID: 4242})
	if res.Applied || res.Reason != "disabled" {
		t.Fatalf("disabled kill_process should refuse, got %+v", res)
	}
	if killed != 0 {
		t.Fatalf("kill should not have fired when disabled")
	}

	// Unknown type is always refused.
	res = r.Execute(context.Background(), responseAction{ID: "a2", Type: "reboot"})
	if res.Applied || res.Reason != "unknown action type" {
		t.Fatalf("unknown type should refuse, got %+v", res)
	}
}

func TestResponderExecute_KillProcessEnabled(t *testing.T) {
	var gotPID int
	var gotSig syscall.Signal
	r := newResponder(responderConfig{
		Node:               "node-a",
		KillProcessEnabled: true,
		killFn: func(pid int, sig syscall.Signal) error {
			gotPID, gotSig = pid, sig
			return nil
		},
	})
	// No comm/container constraints and a valid pid -> applied (killFn invoked).
	res := r.Execute(context.Background(), responseAction{ID: "a3", Type: "kill_process", PID: 4242})
	if !res.Applied {
		t.Fatalf("expected applied, got %+v", res)
	}
	if gotPID != 4242 || gotSig != syscall.SIGKILL {
		t.Fatalf("killFn called with (%d,%v), want (4242,SIGKILL)", gotPID, gotSig)
	}
}
