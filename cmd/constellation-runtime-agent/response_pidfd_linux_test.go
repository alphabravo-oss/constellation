//go:build linux

package main

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// This test can only signal its own disposable child; it never selects a PID
// from the host or runtime inventory.
func TestResponseProcessPIDFDDisposableChild(t *testing.T) {
	child := exec.CommandContext(t.Context(), "/bin/sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	handle, err := openResponseProcess(child.Process.Pid)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("pidfd unsupported by kernel: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Signal(); err != nil {
		t.Fatal(err)
	}
	err = child.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("child did not exit through signal: %v", err)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("unexpected child termination: %v", exit.Sys())
	}
	if err := handle.Signal(); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("reaped handle must not select another task: %v", err)
	}
}
