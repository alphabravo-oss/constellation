//go:build linux && integration

package ebpf

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Opt in only on an isolated privileged Linux host. This is capture/map proof,
// not an enforcement test: the sole child exits normally when stdin closes.
func TestProcessIdentityRealKernelLifecycle(t *testing.T) {
	t.Parallel()
	if os.Getenv("CONSTELLATION_TEST_BPF_IDENTITY") != "1" {
		t.Skip("requires explicit isolated privileged BPF acceptance")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	loaded, err := newLoader(Options{AttachExec: true, Logger: slog.Default()})
	if err != nil {
		t.Fatalf("real BPF loader required: %v", err)
	}
	defer func() { _ = loaded.Close() }()
	kernel, ok := loaded.(*linuxLoader)
	if !ok {
		t.Fatal("real Linux loader required")
	}
	events := make(chan Event, 1024)
	if err := kernel.Start(ctx, func(event Event) {
		select {
		case events <- event:
		default:
		}
	}); err != nil {
		t.Fatal(err)
	}
	if !kernel.identityReady.Load() {
		t.Fatal("exec and leader-exit hooks must both attach")
	}
	child, input, ready := startProcessIdentityKernelChild(t, ctx)
	defer func() { _ = input.Close() }()
	childPID, err := strconv.ParseUint(strconv.Itoa(child.Process.Pid), 10, 32)
	if err != nil || childPID <= 1 {
		t.Fatal("invalid owned child PID")
	}
	pid := uint32(childPID)
	event := awaitKernelProcessEvent(t, ctx, events, pid)
	if event.StartBootNS == 0 || event.CgroupID == 0 {
		t.Fatalf("missing real kernel source identity: %+v", event)
	}
	awaitKernelChildReady(t, ctx, ready)
	if actual, known := kernel.ProcessStartIdentity(pid); !known || actual != event.StartBootNS {
		t.Fatalf("nonleader thread exit erased/changed leader: actual%d known%v expected%d", actual, known, event.StartBootNS)
	}
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if _, known := kernel.ProcessStartIdentity(pid); !known {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("leader exit retained actionable identity")
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
}

func startProcessIdentityKernelChild(t *testing.T, ctx context.Context) (*exec.Cmd, *os.File, <-chan string) {
	t.Helper()
	child := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestProcessIdentityKernelChild$")
	child.Env = append(os.Environ(), "CONSTELLATION_BPF_IDENTITY_CHILD=1")
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stdin = input
	childOutput, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	_ = input.Close()
	ready := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(childOutput)
		if scanner.Scan() {
			ready <- scanner.Text()
		} else {
			ready <- ""
		}
	}()
	t.Cleanup(func() { _ = output.Close() })
	return child, output, ready
}

func awaitKernelProcessEvent(t *testing.T, ctx context.Context, events <-chan Event, pid uint32) *ProcessEvent {
	t.Helper()
	for {
		select {
		case event := <-events:
			if event.Process != nil && event.Process.PID == pid {
				return event.Process
			}
		case <-ctx.Done():
			t.Fatal("exact child exec not captured: ", ctx.Err())
			return nil
		}
	}
}
func awaitKernelChildReady(t *testing.T, ctx context.Context, ready <-chan string) {
	t.Helper()
	select {
	case value := <-ready:
		if value != "threads-exited" {
			t.Fatalf("child thread proof failed: %q", value)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestProcessIdentityKernelChild(t *testing.T) {
	t.Parallel()
	if os.Getenv("CONSTELLATION_BPF_IDENTITY_CHILD") != "1" {
		t.Skip("only invoked by owned child fixture")
	}
	exited := make(chan int, 2)
	release := make(chan struct{})
	for range 2 {
		go func() {
			runtime.LockOSThread()
			tid := unix.Gettid()
			exited <- tid
			<-release
			if tid == os.Getpid() {
				runtime.UnlockOSThread()
			}
		}()
	}
	first, second := <-exited, <-exited
	close(release)
	tid := first
	if tid == os.Getpid() {
		tid = second
	}
	if tid == os.Getpid() {
		t.Fatal("fixture needs nonleader thread")
	}
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat("/proc/self/task/" + strconv.Itoa(tid)); os.IsNotExist(err) {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("owned thread did not exit")
		case <-ticker.C:
		}
	}
	fmt.Println("threads-exited")
	_, _ = bufio.NewReader(os.Stdin).ReadByte()
}
