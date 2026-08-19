//go:build linux && integration

package ebpf

import (
	"context"
	"testing"
	"time"
)

// TestLoad attaches the real eBPF object on a Linux host. Requires:
//   - root / CAP_BPF + CAP_PERFMON (or use `sudo`)
//   - BTF available at /sys/kernel/btf/vmlinux
//   - runtime.bpf.o compiled (run `make -C internal/runtime/ebpf/bpf` first)
//
// Run with:
//   sudo -E env "PATH=$PATH" go test -tags=linux,integration \
//       ./internal/runtime/ebpf/... -run TestLoad
func TestLoad(t *testing.T) {
	a, err := New(Options{
		AttachExec: true, AttachNetwork: true, AttachFile: true,
		EventChannelBuffer: 64,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	// Drain whatever the kernel emits while we wait.
	deadline := time.After(2 * time.Second)
	var count int
loop:
	for {
		select {
		case <-deadline:
			break loop
		case _, ok := <-a.Events():
			if !ok {
				break loop
			}
			count++
		}
	}
	t.Logf("observed %d kernel events (dropped=%d)", count, a.Dropped())
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}
}
