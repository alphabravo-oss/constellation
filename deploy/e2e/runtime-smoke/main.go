// runtime-smoke is a live-capture smoke driver for the Constellation eBPF runtime
// agent. It loads the kernel data plane via internal/runtime/ebpf, forks a worker
// that produces deterministic exec + outbound-TCP activity, and counts what the
// kernel actually emits.
//
// Run (needs root for BPF/LSM attach + BTF):
//
//	sudo -E env CONSTELLATION_BPF_OBJ=$(pwd)/internal/runtime/ebpf/bpf/runtime.bpf.o \
//	    PATH=$PATH go run ./deploy/e2e/runtime-smoke
//
// Exit code is non-zero if the captured-event thresholds aren't met.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/ebpf"
)

func main() {
	var (
		duration  = flag.Duration("duration", 10*time.Second, "smoke window")
		minExec   = flag.Int("min-exec", 10, "minimum /bin/true exec events to require")
		minTCP    = flag.Int("min-tcp", 1, "minimum tcp_connect events to require")
		showFile  = flag.Bool("show-file", false, "log first file_open events")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	a, err := ebpf.New(ebpf.Options{
		Logger:             logger,
		AttachExec:         true,
		AttachNetwork:      true,
		AttachFile:         true,
		EventChannelBuffer: 4096,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent New: %v\n", err)
		os.Exit(2)
	}
	defer a.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *duration+2*time.Second)
	defer cancel()

	runDone := make(chan error, 1)
	go func() { runDone <- a.Run(ctx) }()

	// Counters.
	var (
		execTotal  atomic.Uint64
		execTrue   atomic.Uint64
		netConnect atomic.Uint64
		netAccept  atomic.Uint64
		fileTotal  atomic.Uint64
	)

	// Consumer.
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		var firstFiles int
		for evt := range a.Events() {
			switch evt.Kind {
			case ebpf.EventKindProcess:
				execTotal.Add(1)
				if evt.Process != nil {
					fn := evt.Process.Filename
					if fn == "/bin/true" || fn == "/usr/bin/true" || strings.HasSuffix(fn, "/true") {
						execTrue.Add(1)
					}
				}
			case ebpf.EventKindNetwork:
				if evt.Network == nil {
					continue
				}
				switch evt.Network.Direction {
				case "connect":
					netConnect.Add(1)
				case "accept":
					netAccept.Add(1)
				}
			case ebpf.EventKindFile:
				fileTotal.Add(1)
				if *showFile && firstFiles < 5 && evt.File != nil {
					logger.Info("file_open", slog.String("comm", evt.File.Comm), slog.String("path", evt.File.Path))
					firstFiles++
				}
			}
		}
	}()

	// Workload generator: 20 iterations of /bin/true + a curl that issues a
	// genuine outbound TCP connect. We use 127.0.0.1:9 (discard) so we never
	// hit the network; the kernel still records tcp_connect.
	workloadCtx, workloadCancel := context.WithTimeout(ctx, *duration)
	defer workloadCancel()

	logger.Info("smoke: starting workload", slog.Duration("window", *duration))
	script := `for i in $(seq 1 20); do /bin/true; curl -sS --max-time 1 -o /dev/null http://127.0.0.1:9 || true; sleep 0.2; done`
	cmd := exec.CommandContext(workloadCtx, "sh", "-c", script)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil && !errors.Is(workloadCtx.Err(), context.DeadlineExceeded) {
		logger.Warn("workload finished with error", slog.String("err", err.Error()))
	}

	// Give the kernel a moment to flush.
	time.Sleep(500 * time.Millisecond)
	cancel()
	if err := <-runDone; err != nil {
		logger.Warn("Run returned error", slog.String("err", err.Error()))
	}
	<-consumerDone

	dropped := a.Dropped()
	et := execTotal.Load()
	etrue := execTrue.Load()
	nc := netConnect.Load()
	na := netAccept.Load()
	ft := fileTotal.Load()

	fmt.Printf("== Constellation runtime-smoke ==\n")
	fmt.Printf("duration            : %s\n", *duration)
	fmt.Printf("exec events (total) : %d\n", et)
	fmt.Printf("exec /bin/true      : %d\n", etrue)
	fmt.Printf("tcp_connect events  : %d\n", nc)
	fmt.Printf("tcp_accept events   : %d\n", na)
	fmt.Printf("file_open events    : %d\n", ft)
	fmt.Printf("dropped (chan full) : %d\n", dropped)

	failed := false
	if int(etrue) < *minExec {
		fmt.Fprintf(os.Stderr, "FAIL: /bin/true exec events %d < required %d\n", etrue, *minExec)
		failed = true
	}
	if int(nc) < *minTCP {
		fmt.Fprintf(os.Stderr, "FAIL: tcp_connect events %d < required %d\n", nc, *minTCP)
		failed = true
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("OK")
}
