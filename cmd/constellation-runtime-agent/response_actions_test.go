package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
			name:   "unknown live comm refused",
			action: responseAction{PID: 4242, Comm: "nginx"},
			wantOK: false, wantReason: "process comm unavailable",
		},
		{name: "negative pid", action: responseAction{PID: -2}, wantReason: "invalid pid"},
		{name: "whitespace target comm", action: responseAction{PID: 4242, Comm: " \t"}, procComm: "nginx", wantReason: "missing target comm"},
		{name: "whitespace live comm", action: responseAction{PID: 4242, Comm: "nginx"}, procComm: " \n", wantReason: "process comm unavailable"},
		{name: "normalized empty live container", action: responseAction{PID: 4242, Comm: "nginx", ContainerID: "aaa"}, procComm: "nginx", procContainerID: "containerd://", wantReason: "process container unavailable"},
		{name: "normalized empty target container", action: responseAction{PID: 4242, Comm: "nginx", ContainerID: "containerd://"}, procComm: "nginx", wantReason: "invalid target container"},
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
	for _, field := range []string{"src", "dst"} {
		for _, port := range []int{-1, 0, 65536} {
			a := responseAction{Protocol: "udp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 443}
			if field == "src" {
				a.SrcPort = port
			} else {
				a.DstPort = port
			}
			if args, reason := conntrackDeleteArgs(a); args != nil || reason != "invalid src/dst port" {
				t.Errorf("%s port %d = (%v,%q), want refusal", field, port, args, reason)
			}
		}
	}
	args, reason = conntrackDeleteArgs(responseAction{Protocol: " UDP ", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 1, DstPort: 65535})
	if reason != "" || !reflect.DeepEqual(args, []string{"-D", "-s", "10.0.0.1", "-d", "10.0.0.2", "-p", "udp", "--sport", "1", "--dport", "65535"}) {
		t.Fatalf("explicit UDP boundary ports = (%v,%q)", args, reason)
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

// Temporary /proc files and an injected kill function ensure successful cases
// cannot signal a real process.
func TestResponderExecute_KillProcessIdentity(t *testing.T) {
	containerID := strings.Repeat("a", 64)
	cases := []struct {
		name, comm, cgroup string
		action             responseAction
		want               bool
		reason             string
		killError          error
	}{
		{name: "missing proc entry", action: responseAction{PID: 4242, Comm: "nginx"}, reason: "process comm unavailable"},
		{name: "empty comm file", comm: "\n", action: responseAction{PID: 4242, Comm: "nginx"}, reason: "process comm unavailable"},
		{name: "reused pid", comm: "sshd\n", action: responseAction{PID: 4242, Comm: "nginx"}, reason: "comm mismatch"},
		{name: "missing cgroup file", comm: "nginx\n", action: responseAction{PID: 4242, Comm: "nginx", ContainerID: containerID}, reason: "process container unavailable"},
		{name: "unrecognized cgroup", comm: "nginx\n", cgroup: "0::/user.slice\n", action: responseAction{PID: 4242, Comm: "nginx", ContainerID: containerID}, reason: "process container unavailable"},
		{name: "different container", comm: "nginx\n", cgroup: "0::/docker/" + strings.Repeat("b", 64) + "\n", action: responseAction{PID: 4242, Comm: "nginx", ContainerID: containerID}, reason: "container mismatch"},
		{name: "bare pid", comm: "nginx\n", action: responseAction{PID: 4242}, reason: "missing target comm"},
		{name: "verified host process", comm: "nginx\n", action: responseAction{PID: 4242, Comm: "nginx"}, want: true},
		{name: "verified container process", comm: "nginx\n", cgroup: "0::/kubepods.slice/cri-containerd-" + containerID + ".scope\n", action: responseAction{PID: 4242, Comm: "nginx", ContainerID: "containerd://" + containerID}, want: true},
		{name: "kill failure not applied", comm: "nginx\n", action: responseAction{PID: 4242, Comm: "nginx"}, killError: errors.New("denied"), reason: "kill failed: denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			proc := filepath.Join(root, "proc", "4242")
			if err := os.MkdirAll(proc, 0700); err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]string{"comm": tc.comm, "cgroup": tc.cgroup} {
				if value != "" {
					if err := os.WriteFile(filepath.Join(proc, name), []byte(value), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			calls := 0
			r := newResponder(responderConfig{Node: "node-a", HostRoot: root, KillProcessEnabled: true, killFn: func(pid int, sig syscall.Signal) error {
				calls++
				if pid != 4242 || sig != syscall.SIGKILL {
					t.Fatalf("unexpected kill target (%d,%v)", pid, sig)
				}
				return tc.killError
			}})
			a := tc.action
			a.ID, a.Type = "action", "kill_process"
			res := r.Execute(context.Background(), a)
			if res.Applied != tc.want || res.Reason != tc.reason {
				t.Fatalf("result=%+v, want applied=%v reason=%q", res, tc.want, tc.reason)
			}
			wantCalls := 0
			if tc.want || tc.killError != nil {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("kill called %d times, want %d", calls, wantCalls)
			}
		})
	}
}

func TestResponderExecute_KillSessionRequiresExactTuple(t *testing.T) {
	// This private executable only records arguments. Never invoke conntrack.
	root := t.TempDir()
	program := filepath.Join(root, "fake-conntrack")
	marker := program + ".called"
	if err := os.WriteFile(program, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.called\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	r := newResponder(responderConfig{KillSessionEnabled: true, conntrackBin: program})
	a := responseAction{ID: "session", Type: "kill_session", Protocol: "tcp", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12345, DstPort: 443}
	for _, missing := range []string{"src", "dst", "protocol"} {
		t.Run(missing, func(t *testing.T) {
			incomplete := a
			switch missing {
			case "src":
				incomplete.SrcPort = 0
			case "dst":
				incomplete.DstPort = 0
			case "protocol":
				incomplete.Protocol = ""
			}
			if res := r.Execute(context.Background(), incomplete); res.Applied || res.Reason == "" {
				t.Fatalf("incomplete tuple reported applied: %+v", res)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("incomplete tuple invoked executable: %v", err)
			}
		})
	}
	if res := r.Execute(context.Background(), a); !res.Applied || res.Reason != "" {
		t.Fatalf("complete tuple not applied: %+v", res)
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	want := "-D\n-s\n10.0.0.1\n-d\n10.0.0.2\n-p\ntcp\n--sport\n12345\n--dport\n443\n"
	if string(raw) != want {
		t.Fatalf("executable arguments=%q, want %q", raw, want)
	}
}
