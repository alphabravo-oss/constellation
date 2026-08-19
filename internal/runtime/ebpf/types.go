package ebpf

import (
	"net/netip"
	"time"
)

// EventKind enumerates the typed payload variants of Event.
type EventKind uint8

const (
	EventKindUnknown EventKind = iota
	EventKindProcess
	EventKindNetwork
	EventKindFile
)

// Event is the typed sum-type emitted by the agent. Exactly one of Process / Network /
// File is non-nil; Kind tells you which.
type Event struct {
	Kind    EventKind
	At      time.Time
	Process *ProcessEvent
	Network *NetworkEvent
	File    *FileEvent
}

// ProcessEvent is an exec/execveat observation.
type ProcessEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	CgroupID    uint64 // for container correlation
	Comm        string // task->comm (16 bytes)
	Filename    string // exe path
	Args        []string
	ContainerID string // resolved from cgroup path (best-effort)
}

// NetworkEvent was the wire shape of a tcp_connect or inet_csk_accept
// observation. Retained as an exported type for ABI stability (Wave 7 removed
// the BPF probes that produced it); the kernel decoder no longer emits these
// — the dp package now owns the network observation path. Callers can still
// construct NetworkEvent values in tests via Agent.Inject().
type NetworkEvent struct {
	PID         uint32
	CgroupID    uint64
	Comm        string
	Direction   string // "connect" | "accept"
	Protocol    string // "tcp" | "udp"
	Family      uint8  // AF_INET (2) | AF_INET6 (10)
	Src         netip.AddrPort
	Dst         netip.AddrPort
	ContainerID string
}

// FileEvent is a security_file_open LSM observation.
type FileEvent struct {
	PID         uint32
	CgroupID    uint64
	Comm        string
	Path        string
	Flags       uint32 // open(2) flags
	Mode        uint32
	ContainerID string
}
