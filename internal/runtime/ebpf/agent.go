package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// Options configures a new Agent.
type Options struct {
	// Logger receives structured progress + verifier errors. Defaults to slog.Default.
	Logger *slog.Logger
	// RingBufferSize is the size, in bytes, of the kernel ring buffer. Must be a power
	// of two and a multiple of the page size. Defaults to 256 KiB.
	RingBufferSize int
	// EventChannelBuffer sizes the userspace Go channel that fans out events.
	// Defaults to 1024. When full the loader drops events and increments a counter.
	EventChannelBuffer int
	// AttachExec — when false, skip the sched_process_exec tracepoint.
	AttachExec bool
	// AttachNetwork is retained for ABI compatibility but is a no-op since
	// Wave 7 retired the BPF network probes. The NeuVector C dp data-plane
	// (internal/runtime/dp) owns the network path end-to-end.
	AttachNetwork bool
	// AttachFile — when false, skip the security_file_open LSM hook.
	AttachFile bool
}

// DefaultOptions returns an Options struct with all hooks enabled and sensible sizes.
func DefaultOptions() Options {
	return Options{
		Logger:             slog.Default(),
		RingBufferSize:     256 << 10,
		EventChannelBuffer: 1024,
		AttachExec:         true,
		AttachFile:         true,
	}
}

// Agent is the kernel data-plane handle. Construct with New; use Events() to consume.
type Agent struct {
	opts   Options
	events chan Event

	mu      sync.Mutex
	closed  bool
	running bool
	dropped uint64
	loader  loader // nil on non-Linux or when degraded
}

// New builds an Agent. On non-Linux, or when kernel features aren't available, returns
// a degraded Agent whose Run loop is a no-op. Callers should still call Close().
func New(opts Options) (*Agent, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.RingBufferSize == 0 {
		opts.RingBufferSize = 256 << 10
	}
	if opts.EventChannelBuffer == 0 {
		opts.EventChannelBuffer = 1024
	}
	a := &Agent{
		opts:   opts,
		events: make(chan Event, opts.EventChannelBuffer),
	}
	l, err := newLoader(opts)
	if err != nil {
		// Non-fatal: report degraded mode and proceed. Caller can still pump events
		// from synthetic sources for tests or non-Linux dev.
		opts.Logger.Warn("ebpf: degraded mode; no kernel events will be produced",
			slog.String("err", err.Error()))
		a.loader = nil
		return a, nil
	}
	a.loader = l
	return a, nil
}

// Events returns the read-only event channel. Closed when Run returns.
func (a *Agent) Events() <-chan Event { return a.events }

// Dropped returns the number of events the loader has dropped because the userspace
// channel was full.
func (a *Agent) Dropped() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dropped
}

// Run starts the kernel-event pump. Blocks until ctx is cancelled or a fatal load
// error occurs. Safe to call once; subsequent calls return ErrAlreadyRunning.
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	if a.running {
		a.mu.Unlock()
		return ErrAlreadyRunning
	}
	if a.closed {
		a.mu.Unlock()
		return errors.New("ebpf: agent closed")
	}
	a.running = true
	a.mu.Unlock()
	return a.run(ctx)
}

func (a *Agent) run(ctx context.Context) error {
	defer close(a.events)
	if a.loader == nil {
		// Degraded: just block until ctx is done so the channel can be ranged.
		a.opts.Logger.Info("ebpf: running in degraded mode (no kernel hooks)")
		<-ctx.Done()
		return nil
	}
	if err := a.loader.Start(ctx, a.deliver); err != nil {
		return fmt.Errorf("ebpf: loader start: %w", err)
	}
	<-ctx.Done()
	return a.loader.Close()
}

// deliver is the loader's per-event callback. It tries the channel first; if full it
// increments a counter so callers can alarm on backpressure.
func (a *Agent) deliver(e Event) {
	select {
	case a.events <- e:
	default:
		a.mu.Lock()
		a.dropped++
		a.mu.Unlock()
	}
}

// Inject is the test/dev hook: deliver a synthetic event into the agent's stream.
// Returns an error if the agent has been closed.
func (a *Agent) Inject(e Event) error {
	a.mu.Lock()
	closed := a.closed
	a.mu.Unlock()
	if closed {
		return errors.New("ebpf: agent closed")
	}
	a.deliver(e)
	return nil
}

// Close releases kernel resources. Safe to call multiple times.
func (a *Agent) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()
	if a.loader != nil {
		return a.loader.Close()
	}
	return nil
}

// loader is the kernel-side implementation. Linux build attaches real eBPF programs;
// fallback build returns nil from newLoader so the Agent runs in degraded mode.
type loader interface {
	Start(ctx context.Context, cb func(Event)) error
	Close() error
}

// ErrAlreadyRunning is returned by Run when the agent has already been started.
var ErrAlreadyRunning = errors.New("ebpf: agent already running")
