//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// runtimeObjects is the compiled CO-RE object set produced by `make ebpf-objs`. The
// file is expected at internal/runtime/ebpf/bpf/runtime.bpf.o relative to the binary's
// source tree. When absent (e.g. a clean checkout where `make ebpf-objs` hasn't been
// run yet), newLoader returns an error and the Agent runs in degraded mode.
const objectRelPath = "bpf/runtime.bpf.o"

// linuxLoader is the real-kernel loader. It owns the cilium/ebpf collection, the
// attached links, and the ring-buffer reader goroutines.
type linuxLoader struct {
	opts    Options
	coll    *ciliumebpf.Collection
	links   []link.Link
	rb      *ringbuf.Reader
	closeMu sync.Mutex
	closed  bool
	wg      sync.WaitGroup
}

// newLoader resolves the object file, lifts the memlock rlimit, and prepares — but
// does NOT yet attach — the eBPF collection. Attaching happens in Start so that the
// caller can control program lifetime via ctx.
func newLoader(opts Options) (loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock rlimit: %w", err)
	}
	objPath, err := resolveObjectPath()
	if err != nil {
		return nil, err
	}
	spec, err := ciliumebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("ebpf: load collection spec %s: %w", objPath, err)
	}
	// Adjust the ring-buffer size if user asked for a non-default.
	if opts.RingBufferSize > 0 {
		if m, ok := spec.Maps["events"]; ok {
			m.MaxEntries = uint32(opts.RingBufferSize)
		}
	}
	coll, err := ciliumebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("ebpf: new collection: %w", err)
	}
	return &linuxLoader{opts: opts, coll: coll}, nil
}

// resolveObjectPath walks a few candidate locations: $CONSTELLATION_BPF_OBJ,
// ./bpf/runtime.bpf.o, and the directory of the current source file (dev mode).
func resolveObjectPath() (string, error) {
	if p := os.Getenv("CONSTELLATION_BPF_OBJ"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	candidates := []string{
		objectRelPath,
		"internal/runtime/ebpf/" + objectRelPath,
		filepath.Join("/usr/lib/constellation", filepath.Base(objectRelPath)),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("ebpf: compiled object %s not found (run `make ebpf-objs`)", objectRelPath)
}

// Start attaches programs in the collection to their kernel hooks per opts, opens the
// shared ring buffer, and launches the pump goroutine.
func (l *linuxLoader) Start(ctx context.Context, cb func(Event)) error {
	if l.opts.AttachExec {
		if err := l.attachTracepoint("sched", "sched_process_exec", "trace_sched_exec"); err != nil {
			return err
		}
	}
	if l.opts.AttachFile {
		_ = l.attachLSM("file_open", "lsm_file_open")
	}
	// Wave 7: AttachNetwork is retired. The Options field is kept for ABI
	// compat (so older callers compile) but is a no-op — the NeuVector C dp
	// owns the network observation path.
	rbMap, ok := l.coll.Maps["events"]
	if !ok {
		return errors.New("ebpf: ringbuf map 'events' missing from object")
	}
	rb, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("ebpf: open ringbuf reader: %w", err)
	}
	l.rb = rb
	l.wg.Add(1)
	go l.pump(ctx, cb)
	return nil
}

func (l *linuxLoader) attachTracepoint(group, name, progName string) error {
	prog := l.coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("ebpf: program %s missing", progName)
	}
	tp, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		l.opts.Logger.Warn("ebpf: tracepoint attach failed",
			slog.String("tp", group+"/"+name), slog.String("err", err.Error()))
		return nil // non-fatal — keep going so partial telemetry still flows
	}
	l.links = append(l.links, tp)
	return nil
}

func (l *linuxLoader) attachLSM(hook, progName string) error {
	prog := l.coll.Programs[progName]
	if prog == nil {
		return fmt.Errorf("ebpf: program %s missing", progName)
	}
	lk, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		l.opts.Logger.Warn("ebpf: LSM attach failed",
			slog.String("hook", hook), slog.String("err", err.Error()))
		return nil
	}
	l.links = append(l.links, lk)
	return nil
}

// pump reads records from the ring buffer, decodes them into Event values, and calls cb.
func (l *linuxLoader) pump(ctx context.Context, cb func(Event)) {
	defer l.wg.Done()
	go func() {
		<-ctx.Done()
		// Closing the reader wakes the blocked Read call.
		_ = l.rb.Close()
	}()
	for {
		rec, err := l.rb.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			l.opts.Logger.Error("ebpf: ringbuf read", slog.String("err", err.Error()))
			return
		}
		evt, ok := decodeRecord(rec.RawSample)
		if !ok {
			continue
		}
		cb(evt)
	}
}

// Close detaches programs, closes the reader, and frees the collection.
func (l *linuxLoader) Close() error {
	l.closeMu.Lock()
	if l.closed {
		l.closeMu.Unlock()
		return nil
	}
	l.closed = true
	l.closeMu.Unlock()

	var firstErr error
	if l.rb != nil {
		if err := l.rb.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, lk := range l.links {
		if err := lk.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if l.coll != nil {
		l.coll.Close()
	}
	l.wg.Wait()
	return firstErr
}

// On-wire record header — kept in sync with bpf/runtime.bpf.c.
type recordHeader struct {
	Kind     uint8
	_        [3]byte
	PID      uint32
	PPID     uint32
	UID      uint32
	GID      uint32
	CgroupID uint64
	TS       uint64 // ns since boot
}

const (
	recKindExec = 1
	recKindFile = 4
	// Kinds 2 (connect) and 3 (accept) were emitted by the retired BPF
	// network probes (Wave 7). Numbers preserved in the userspace contract
	// so a kernel that's still running the old BPF object — if it somehow
	// loads — won't have its records misinterpreted; we simply ignore them.
)

func decodeRecord(b []byte) (Event, bool) {
	const hdrSz = int(unsafe.Sizeof(recordHeader{}))
	if len(b) < hdrSz {
		return Event{}, false
	}
	var hdr recordHeader
	if err := binary.Read(bytes.NewReader(b[:hdrSz]), binary.LittleEndian, &hdr); err != nil {
		return Event{}, false
	}
	body := b[hdrSz:]
	at := time.Now() // we lose the boot-relative ns; pin to wall time at receive
	switch hdr.Kind {
	case recKindExec:
		// body: comm[16] filename[256] args[256]
		if len(body) < 16+256+256 {
			return Event{}, false
		}
		comm := readCStr(body[:16])
		filename := readCStr(body[16 : 16+256])
		argsBlob := readCStr(body[16+256 : 16+256+256])
		args := splitArgs(argsBlob)
		return Event{
			Kind: EventKindProcess, At: at,
			Process: &ProcessEvent{
				PID: hdr.PID, PPID: hdr.PPID, UID: hdr.UID, GID: hdr.GID,
				CgroupID: hdr.CgroupID, Comm: comm, Filename: filename, Args: args,
				ContainerID: containerIDFromCgroup(hdr.CgroupID),
			},
		}, true
	case recKindFile:
		// body: flags(4) mode(4) comm[16] path[256]
		if len(body) < 4+4+16+256 {
			return Event{}, false
		}
		flags := binary.LittleEndian.Uint32(body[0:4])
		mode := binary.LittleEndian.Uint32(body[4:8])
		comm := readCStr(body[8:24])
		path := readCStr(body[24 : 24+256])
		return Event{
			Kind: EventKindFile, At: at,
			File: &FileEvent{
				PID: hdr.PID, CgroupID: hdr.CgroupID, Comm: comm,
				Path: path, Flags: flags, Mode: mode,
				ContainerID: containerIDFromCgroup(hdr.CgroupID),
			},
		}, true
	}
	return Event{}, false
}

func readCStr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func splitArgs(s string) []string {
	if s == "" {
		return nil
	}
	// args are NUL-separated in kernel; readCStr stopped at the first NUL, so we have
	// only the first arg. If the program packs them differently, fall back to space split.
	if strings.ContainsRune(s, ' ') {
		return strings.Fields(s)
	}
	return []string{s}
}

var cgroupContainerIDCache sync.Map

// containerIDFromCgroup is best-effort: walks cgroupfs and matches the cgroup
// inode returned by bpf_get_current_cgroup_id().
// On v2 cgroups the BPF helper bpf_get_current_cgroup_id() returns the cgroupfs inode;
// userspace can read /sys/fs/cgroup/<path> to find the matching container id.
// For v1 or non-container host processes this returns "" and callers retain
// PID/container fallback behavior.
func containerIDFromCgroup(cgroupID uint64) string {
	if cgroupID == 0 {
		return ""
	}
	if cached, ok := cgroupContainerIDCache.Load(cgroupID); ok {
		return cached.(string)
	}
	id := containerIDFromCgroupRoot("/sys/fs/cgroup", cgroupID)
	if id != "" {
		cgroupContainerIDCache.Store(cgroupID, id)
	}
	return id
}

func containerIDFromCgroupRoot(root string, cgroupID uint64) string {
	var id string
	errFound := errors.New("cgroup found")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Ino != cgroupID {
			return nil
		}
		id = containerIDFromCgroupPath(path)
		return errFound
	})
	return id
}

func containerIDFromCgroupPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		part := strings.TrimSpace(parts[i])
		if part == "" {
			continue
		}
		part = strings.TrimSuffix(part, ".scope")
		for _, prefix := range []string{"cri-containerd-", "containerd-", "docker-", "crio-", "libpod-", "podman-"} {
			part = strings.TrimPrefix(part, prefix)
		}
		if looksLikeContainerID(part) {
			return part
		}
	}
	return ""
}

func looksLikeContainerID(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			continue
		}
		return false
	}
	return true
}
