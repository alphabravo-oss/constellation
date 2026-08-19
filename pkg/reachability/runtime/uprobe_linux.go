//go:build linux

package runtime

// attachUprobe is the Linux entry point. v1 does NOT implement direct uprobe
// attachment in this package — the runtime agent (internal/runtime/ebpf) owns the
// shared BPF collection and is the right place to attach symbol probes that need to
// emit into the agent's ringbuffer.
//
// Instead, the runtime Confirmer relies on the agent's existing process + file
// events to detect reachability:
//
//   - SourceProcess  : an exec event for the verdict's binary fires confirmation.
//   - SourceLibLoad  : a security_file_open for the verdict's library fires it.
//   - SourceUprobe   : reserved for the future, when the agent is wired to emit
//                       uprobe-hit events into a typed channel that this package
//                       can subscribe to.
//
// Callers that need a "real" uprobe today should use cilium/ebpf directly against
// their own collection and call Confirmer.MarkConfirmed when the program fires.
func attachUprobe(_, _ string, _ func()) (Detacher, error) {
	return nil, ErrUnsupported
}
