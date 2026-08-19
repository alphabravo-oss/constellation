// Package baseline implements the process + API-endpoint baselining lifecycle that the
// spec calls out separately from the network-policy baseline. NeuVector parity.
//
// Lifecycle:
//
//	Learn   — observe; record processes/endpoints into the baseline; emit no alerts
//	Monitor — observe; alert on out-of-baseline; never block
//	Enforce — observe; alert; block (via quarantine API)
//
// At v1 the agent feeds in process samples + HTTP samples via gRPC and we compute drift
// in-process. The kernel-side event capture (eBPF) is Phase 4 BLOCKED on Linux; this
// package operates against any source of normalized samples, so the userspace simulator
// can drive it end-to-end.
package baseline

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Mode is the per-workload baseline mode (mirrors netpolicy.Mode names).
type Mode string

const (
	ModeLearn   Mode = "learn"
	ModeMonitor Mode = "monitor"
	ModeEnforce Mode = "enforce"
)

// ProcessSample is one observed process exec.
type ProcessSample struct {
	WorkloadID string
	Process    string // basename of the exec (e.g. "bash")
	FullCmd    string
	At         time.Time
}

// EndpointSample is one observed HTTP / gRPC request seen at the workload's ingress.
type EndpointSample struct {
	WorkloadID string
	Method     string // GET | POST | gRPC method
	Path       string // normalized — IDs replaced with :id (e.g. /v1/users/:id)
	At         time.Time
}

// WorkloadBaseline holds the learned baseline for one workload.
type WorkloadBaseline struct {
	WorkloadID string
	Mode       Mode
	LearnUntil time.Time

	Processes map[string]int    // process basename → observation count
	Endpoints map[string]int    // "METHOD path" → observation count

	mu sync.RWMutex
}

// Alert is what the engine emits when out-of-baseline samples are seen in monitor or
// enforce mode.
type Alert struct {
	WorkloadID string
	Kind       string // process | endpoint
	Detail     string
	At         time.Time
	Block      bool // true when mode=enforce
}

// Engine drives the lifecycle. Caller persists baselines and feeds samples in.
type Engine struct {
	mu         sync.Mutex
	baselines  map[string]*WorkloadBaseline
	now        func() time.Time
}

// NewEngine constructs an Engine. Pass nil for `now` to use time.Now.
func NewEngine() *Engine {
	return &Engine{baselines: map[string]*WorkloadBaseline{}, now: time.Now}
}

// SetClock injects a clock (for tests).
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

// StartLearn initializes a baseline in learn mode for `window`.
func (e *Engine) StartLearn(workload string, window time.Duration) *WorkloadBaseline {
	e.mu.Lock()
	defer e.mu.Unlock()
	b := &WorkloadBaseline{
		WorkloadID: workload,
		Mode:       ModeLearn,
		LearnUntil: e.now().Add(window),
		Processes:  map[string]int{},
		Endpoints:  map[string]int{},
	}
	e.baselines[workload] = b
	return b
}

// Promote advances the workload's mode (learn→monitor→enforce). Returns the new mode or
// an error when the transition isn't valid.
func (e *Engine) Promote(workload string) (Mode, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.baselines[workload]
	if !ok {
		return "", errNotFound
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.Mode {
	case ModeLearn:
		b.Mode = ModeMonitor
	case ModeMonitor:
		b.Mode = ModeEnforce
	case ModeEnforce:
		return ModeEnforce, errAlreadyEnforce
	}
	return b.Mode, nil
}

// IngestProcess observes one process sample; returns an Alert when it's drift in
// monitor/enforce mode.
func (e *Engine) IngestProcess(sample ProcessSample) *Alert {
	b := e.get(sample.WorkloadID)
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	proc := strings.TrimSpace(sample.Process)
	switch b.Mode {
	case ModeLearn:
		b.Processes[proc]++
		return nil
	case ModeMonitor, ModeEnforce:
		if b.Processes[proc] == 0 {
			return &Alert{
				WorkloadID: sample.WorkloadID, Kind: "process",
				Detail: "unbaselined process: " + proc + " (cmd=" + sample.FullCmd + ")",
				At:     sample.At, Block: b.Mode == ModeEnforce,
			}
		}
		return nil
	}
	return nil
}

// IngestEndpoint observes one endpoint sample.
func (e *Engine) IngestEndpoint(sample EndpointSample) *Alert {
	b := e.get(sample.WorkloadID)
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := sample.Method + " " + sample.Path
	switch b.Mode {
	case ModeLearn:
		b.Endpoints[key]++
		return nil
	case ModeMonitor, ModeEnforce:
		if b.Endpoints[key] == 0 {
			return &Alert{
				WorkloadID: sample.WorkloadID, Kind: "endpoint",
				Detail: "unbaselined endpoint: " + key,
				At:     sample.At, Block: b.Mode == ModeEnforce,
			}
		}
		return nil
	}
	return nil
}

// Baseline returns a snapshot of the workload's baseline (for the UI).
func (e *Engine) Baseline(workload string) *WorkloadBaseline {
	return e.get(workload)
}

func (e *Engine) get(workload string) *WorkloadBaseline {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.baselines[workload]
}

// Sorted returns the baseline's processes + endpoints in lexicographic order.
func (b *WorkloadBaseline) Sorted() (processes, endpoints []string) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for k := range b.Processes {
		processes = append(processes, k)
	}
	for k := range b.Endpoints {
		endpoints = append(endpoints, k)
	}
	sort.Strings(processes)
	sort.Strings(endpoints)
	return
}

var (
	errNotFound       = errString("baseline: workload not learned")
	errAlreadyEnforce = errString("baseline: already in enforce mode")
)

type errString string

func (e errString) Error() string { return string(e) }
