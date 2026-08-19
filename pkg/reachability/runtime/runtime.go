// Package runtime is the eBPF/uprobe coupling that confirms a static reachability
// verdict at runtime ("reachable-confirmed=true"). Given a static verdict like:
//
//	Verdict{VulnerabilityID: "CVE-2024-9999", Symbol: "golang.org/x/example/badpkg.BadFunc",
//	         Module: "golang.org/x/example", Reachable: true /* static */}
//
// the Confirmer:
//
//	1. tries to attach a uprobe to the binary symbol (when the symbol is known and
//	   the target process is running with a resolvable executable),
//	2. if the symbol can't be resolved (e.g. a non-Go binary, a stripped build), it
//	   falls back to a coarse "process loaded library X" mark from the eBPF
//	   library-load events.
//
// Either way, when the runtime mark fires, MarkConfirmed is called with the verdict
// id + container/pid context; callers persist this onto the corresponding finding
// (reachable_confirmed=true, reachable_confirmed_at=now, runtime_source=uprobe|libload).
package runtime

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/ebpf"
	"github.com/alphabravocompany/constellation/pkg/reachability"
)

// Subject ties a static verdict to a runnable binary so the Confirmer knows where to
// attach. PID + ExePath identify the live process; LibraryName, if set, is the
// library whose load implies the symbol is reachable (e.g. "libssl.so.3").
type Subject struct {
	VulnerabilityID string
	Symbol          string // golang.org/x/example/badpkg.BadFunc — engine-agnostic
	Module          string
	PID             int
	ExePath         string
	LibraryName     string // "" if symbol-based confirmation
}

// Source enumerates how a confirmation arrived.
type Source string

const (
	SourceUprobe  Source = "uprobe"
	SourceLibLoad Source = "libload"
	SourceProcess Source = "process" // process exec'd a binary whose path matches
)

// Mark is a per-verdict confirmation record.
type Mark struct {
	VulnerabilityID string
	ContainerID     string
	PID             uint32
	Source          Source
	At              time.Time
}

// Sink consumes Marks. Production wires this to the findings DB.
type Sink func(Mark)

// Confirmer is the runtime-confirmation engine.
type Confirmer struct {
	mu       sync.RWMutex
	subjects []Subject
	logger   *slog.Logger
	sink     Sink

	// per-subject debounce so a chatty process doesn't spam findings updates.
	lastFire map[string]time.Time
	dedup    time.Duration
}

// New constructs a Confirmer. sink may be nil for tests.
func New(logger *slog.Logger, sink Sink) *Confirmer {
	if logger == nil {
		logger = slog.Default()
	}
	return &Confirmer{
		logger:   logger,
		sink:     sink,
		lastFire: map[string]time.Time{},
		dedup:    30 * time.Second,
	}
}

// LoadFromVerdicts seeds the Confirmer from a slice of static verdicts. Verdicts
// with empty symbol AND empty module are skipped.
func (c *Confirmer) LoadFromVerdicts(vs []reachability.Verdict) {
	subs := make([]Subject, 0, len(vs))
	for _, v := range vs {
		if v.Symbol == "" && v.Module == "" {
			continue
		}
		subs = append(subs, Subject{
			VulnerabilityID: v.VulnerabilityID,
			Symbol:          v.Symbol,
			Module:          v.Module,
		})
	}
	c.mu.Lock()
	c.subjects = subs
	c.mu.Unlock()
}

// AddSubject pushes one custom subject (used by tests + the manual API).
func (c *Confirmer) AddSubject(s Subject) {
	c.mu.Lock()
	c.subjects = append(c.subjects, s)
	c.mu.Unlock()
}

// Subjects returns a snapshot.
func (c *Confirmer) Subjects() []Subject {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]Subject, len(c.subjects))
	copy(out, c.subjects)
	return out
}

// OnEvent is the eBPF event callback. Process events with a matching exe path mark
// the subject SourceProcess; file events that open a library matching the subject's
// LibraryName mark it SourceLibLoad. The actual uprobe attach happens out-of-band
// via AttachUprobe (Linux-only, integration-tested).
func (c *Confirmer) OnEvent(evt ebpf.Event) {
	switch evt.Kind {
	case ebpf.EventKindProcess:
		c.handleProcess(evt)
	case ebpf.EventKindFile:
		c.handleFile(evt)
	}
}

func (c *Confirmer) handleProcess(evt ebpf.Event) {
	p := evt.Process
	if p == nil {
		return
	}
	c.mu.RLock()
	subjects := c.subjects
	c.mu.RUnlock()
	for _, s := range subjects {
		if s.ExePath != "" && p.Filename == s.ExePath {
			c.fire(s, p.ContainerID, p.PID, SourceProcess)
		}
	}
}

func (c *Confirmer) handleFile(evt ebpf.Event) {
	f := evt.File
	if f == nil {
		return
	}
	c.mu.RLock()
	subjects := c.subjects
	c.mu.RUnlock()
	for _, s := range subjects {
		if s.LibraryName == "" {
			continue
		}
		if strings.Contains(f.Path, s.LibraryName) {
			c.fire(s, f.ContainerID, f.PID, SourceLibLoad)
		}
	}
}

// MarkConfirmed is the manual / uprobe-callback entry point.
func (c *Confirmer) MarkConfirmed(s Subject, containerID string, pid uint32, src Source) {
	c.fire(s, containerID, pid, src)
}

func (c *Confirmer) fire(s Subject, containerID string, pid uint32, src Source) {
	now := time.Now()
	c.mu.Lock()
	last := c.lastFire[s.VulnerabilityID]
	if !last.IsZero() && now.Sub(last) < c.dedup {
		c.mu.Unlock()
		return
	}
	c.lastFire[s.VulnerabilityID] = now
	c.mu.Unlock()

	mark := Mark{
		VulnerabilityID: s.VulnerabilityID,
		ContainerID:     containerID,
		PID:             pid,
		Source:          src,
		At:              now,
	}
	c.logger.Info("reachability/runtime: confirmed",
		slog.String("cve", s.VulnerabilityID),
		slog.String("symbol", s.Symbol),
		slog.String("source", string(src)),
		slog.Any("pid", pid))
	if c.sink != nil {
		c.sink(mark)
	}
}

// Run drains an eBPF event channel into the confirmer. Blocks until ctx is done.
func (c *Confirmer) Run(ctx context.Context, events <-chan ebpf.Event) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case evt, ok := <-events:
			if !ok {
				return nil
			}
			c.OnEvent(evt)
		}
	}
}

// AttachUprobe asks the Linux eBPF subsystem to attach a uprobe at `symbol` inside
// `exePath`. On non-Linux this returns ErrUnsupported. The real attach lives in
// uprobe_linux.go.
func AttachUprobe(exePath, symbol string, onHit func()) (Detacher, error) {
	return attachUprobe(exePath, symbol, onHit)
}

// Detacher is what AttachUprobe returns; call Close() to detach.
type Detacher interface {
	Close() error
}

// ErrUnsupported is returned by AttachUprobe on non-Linux.
var ErrUnsupported = errors.New("reachability/runtime: uprobes require linux")

// String renders a Subject for log messages.
func (s Subject) String() string {
	return fmt.Sprintf("Subject{CVE=%s sym=%s mod=%s lib=%s pid=%d exe=%s}",
		s.VulnerabilityID, s.Symbol, s.Module, s.LibraryName, s.PID, s.ExePath)
}
