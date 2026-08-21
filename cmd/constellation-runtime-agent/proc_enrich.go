// Per-exec /proc enrichment for RT-4 (reverse-shell + real-uid escalation).
//
// The eBPF exec record carries only pid/ppid/uid(effective)/comm/filename. Two NeuVector
// runtime behaviors need data the kernel record does not include:
//
//   - checkReverseShell (neuvector agent/probe/process.go ~1723) flags a process whose
//     stdio (fd 0/1/2) is redirected to a socket — the classic `bash -i >& /dev/tcp/...`
//     reverse shell. We approximate it by reading /proc/<pid>/fd and reporting whether any
//     of fd 0/1/2 is a socket symlink.
//   - rootEscalationCheck (~865) compares real-uid vs effective-uid. The kernel record's UID
//     is the effective uid; we read the real uid (ruid) from /proc/<pid>/status (Uid: line,
//     first field) so the server can flag ruid!=0 && euid==0.
//
// Both reads are best-effort and cheap: one Readdirnames + up to three Readlinks for the fd
// scan, one small ReadFile + line scan for the status. A missing /proc entry (the short-lived
// exec already exited) simply yields the zero result and the server falls back to current
// behavior — the new wire fields are optional.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
)

// procRoot is the proc filesystem root, overridable in tests. Defaults to "/proc".
var procRoot = "/proc"

// execHashEnabled gates RT-MATCH-16 per-exec binary hashing on the ingest path.
// Default OFF: hashing (a bounded prefix of) every exec's binary is a hot-path cost;
// full-path + parent matching already catches the rename-to-allowed-name case, and
// the hash only adds same-path content-swap detection. Opt-in via
// CONSTELLATION_PROCESS_EXEC_HASH so operators who want content matching can enable it.
var execHashEnabled = procBoolFromEnv(os.Getenv("CONSTELLATION_PROCESS_EXEC_HASH"))

func procBoolFromEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

// procExecMaxAncestorWalk bounds the lineage walk in execIsAnchored. Mirrors
// NeuVector's "up to 4 ancestors" runc-child walk in IsAllowedShieldProcess.
const procExecMaxAncestorWalk = 16

// procCmdlineMaxArgs / procCmdlineMaxBytes bound the per-exec /proc/<pid>/cmdline read
// (RT-ARGV-15). The eBPF exec record does not carry argv — the tracepoint hard-codes
// args[0]=0 (internal/runtime/ebpf/bpf/runtime.bpf.c) — so argument-based detections
// (download cradles like `curl|bash`, base64-decode-to-shell) depend on this userspace
// read. The caps keep the cost fixed regardless of a pathological argv.
const (
	procCmdlineMaxArgs  = 64
	procCmdlineMaxBytes = 4096
)

// procExecHashMaxBytes caps how much of an executable we sha256 for the P0-2 hash
// key. Hashing the whole binary of every exec would be a hot-path cost; the first
// few MiB is enough to distinguish a swapped binary (the `mv evil /bin/nginx`
// case) in practice. ponytail: a true content identity would hash the full file
// or reuse the dp file-notification digest (fsn.go GetUpperFileInfo.hashValue).
const procExecHashMaxBytes = 4 << 20

// procExecMeta is the per-exec /proc enrichment the granular matcher (P0-2) and
// zero-drift check (P0-4) need beyond what the eBPF record carries. All fields are
// best-effort; a missing /proc entry (short-lived exec) leaves them zero.
type procExecMeta struct {
	ExePath    string // resolved /proc/<pid>/exe target
	Sha256     string // lowercase hex of the exe (best-effort, capped)
	PPID       uint32
	ParentComm string
}

// readProcCmdline reads /proc/<pid>/cmdline (NUL-separated, NUL-terminated argv) under
// procRoot and returns the argument vector, best-effort. This is the RT-ARGV-15 userspace
// fallback for the argv the eBPF exec record omits (args[0] hard-coded to 0 in the BPF
// tracepoint). It is bounded to procCmdlineMaxBytes read and procCmdlineMaxArgs entries so
// the per-exec cost is fixed. A short-lived exec that already exited yields an unreadable or
// empty file -> nil (no error); the caller keeps whatever argv it already had.
func readProcCmdline(pid uint32) []string {
	raw := procReadFile(procRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline")
	if len(raw) == 0 {
		return nil
	}
	if len(raw) > procCmdlineMaxBytes {
		raw = raw[:procCmdlineMaxBytes]
	}
	// cmdline separates and terminates each arg with a NUL, so a trailing NUL produces an
	// empty final field; skip empties and cap the count.
	parts := strings.Split(raw, "\x00")
	args := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		args = append(args, p)
		if len(args) >= procCmdlineMaxArgs {
			break
		}
	}
	if len(args) == 0 {
		return nil
	}
	return args
}

// enrichExecMeta reads the resolved exe path, parent pid+comm for pid under
// procRoot. The sha256 is filled lazily by the caller (withHash) so a monitor-only
// or basename-only path never pays the read cost.
func enrichExecMeta(pid uint32) procExecMeta {
	root := procRoot + "/" + strconv.FormatUint(uint64(pid), 10)
	meta := procExecMeta{ExePath: procReadlink(root + "/exe")}
	if ppid, ok := readPPID(root + "/stat"); ok {
		meta.PPID = ppid
		meta.ParentComm = strings.TrimSpace(procReadFile(procRoot + "/" + strconv.FormatUint(uint64(ppid), 10) + "/comm"))
	}
	return meta
}

// withHash fills Sha256 from the exe file (via /proc/<pid>/exe, which stays valid
// even if the on-disk path was replaced). Best-effort; a read error leaves it "".
func (m procExecMeta) withHash(pid uint32) procExecMeta {
	m.Sha256 = hashExe(pid)
	return m
}

// hashExe sha256s (a bounded prefix of) the executable behind /proc/<pid>/exe.
func hashExe(pid uint32) string {
	f, err := os.Open(procRoot + "/" + strconv.FormatUint(uint64(pid), 10) + "/exe")
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, f, procExecHashMaxBytes); err != nil && err != io.EOF {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// readPPID parses the parent pid (field 4) from a /proc/<pid>/stat line. The comm
// field (2) is wrapped in parens and can contain spaces/parens, so we split after
// the LAST ')'.
func readPPID(statPath string) (uint32, bool) {
	raw := procReadFile(statPath)
	idx := strings.LastIndex(raw, ")")
	if idx < 0 || idx+1 >= len(raw) {
		return 0, false
	}
	fields := strings.Fields(raw[idx+1:])
	// After ')': fields[0]=state, fields[1]=ppid.
	if len(fields) < 2 {
		return 0, false
	}
	v, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

// nspidIsOneAt reports whether pid's innermost (container-local) pid is 1 — i.e. pid
// is a container init — reading status under procRootDir. Uses the LAST field of the
// "NSpid:" line; a single-namespace host process has just one field.
func nspidIsOneAt(procRootDir string, pid uint32) bool {
	raw := procReadFile(procRootDir + "/" + strconv.FormatUint(uint64(pid), 10) + "/status")
	for _, line := range strings.Split(raw, "\n") {
		rest, ok := strings.CutPrefix(line, "NSpid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return false
		}
		return fields[len(fields)-1] == "1"
	}
	return false
}

// execIsAnchored reports whether the exec at pid descends from its container's root
// process with an intact lineage (P0-4 anchor). It walks the ppid chain while every
// hop stays in the same container (same cgroup-derived containerID) and returns
// true iff the topmost in-container ancestor is that container's init (NSpid==1).
//
// A process injected by `kubectl exec`/`docker exec`/nsenter is re-parented onto
// the container-runtime shim (outside the container), so the topmost in-container
// process is the injected process itself, whose NSpid != 1 -> not anchored, exactly
// like NeuVector's shield rejecting non-runc-child entries.
//
// The three /proc lookups are injected so the pure lineage logic is testable
// without a real /proc.
func execIsAnchored(pid uint32, containerID string, getParent func(uint32) (uint32, bool), sameContainer func(uint32) bool, isInit func(uint32) bool) bool {
	if strings.TrimSpace(containerID) == "" {
		return false // not a container exec -> zero-drift does not apply/anchor
	}
	cur := pid
	for i := 0; i < procExecMaxAncestorWalk; i++ {
		if isInit(cur) {
			return true // reached the container init with lineage intact
		}
		parent, ok := getParent(cur)
		if !ok || parent == 0 || parent == cur {
			return false // hit the top without seeing an init
		}
		if !sameContainer(parent) {
			// parent is outside the container: cur is the topmost in-container
			// process. Anchored only if cur itself is the container init.
			return isInit(cur)
		}
		cur = parent
	}
	return false
}

// zeroDriftContextFromProc builds the P0-4 zero-drift context for pid (in container
// cid, started at startNano) from /proc: root-process, lineage anchor, and image
// provenance. It wires the /proc-backed closures around the pure execIsAnchored and
// procFileWrittenAfter cores.
func zeroDriftContextFromProc(procRootDir string, pid uint32, cid string, startNano int64) zeroDriftContext {
	getParent := func(p uint32) (uint32, bool) {
		return readPPID(procRootDir + "/" + strconv.FormatUint(uint64(p), 10) + "/stat")
	}
	sameContainer := func(p uint32) bool {
		return containerIDFromProcCgroup(procRootDir, int(p)) == cid
	}
	isInit := func(p uint32) bool { return nspidIsOneAt(procRootDir, p) }

	z := zeroDriftContext{
		IsRootProcess: isInit(pid),
		Anchored:      execIsAnchored(pid, cid, getParent, sameContainer, isInit),
	}
	// Image provenance via the /proc/<pid>/exe magic symlink, which resolves to the
	// real (possibly `mv`-swapped) executable inode. Fail-open (treat as image) when
	// the stat is unavailable so we never block on missing data.
	drifted, ok := procFileWrittenAfter(procRootDir+"/"+strconv.FormatUint(uint64(pid), 10)+"/exe", startNano)
	z.FromImage = !(ok && drifted)
	return z
}

// procFileWrittenAfter reports whether the file at absPath was last changed (ctime)
// strictly after startUnixNano — a proxy for "written after container start", i.e.
// NOT part of the original image (NeuVector fsn.go IsNotExistingImageFile). Image
// files carry the image build ctime, which precedes container start; a dropped or
// `mv`-swapped binary carries a later ctime. ponytail: this is a heuristic — true
// image-layer membership needs overlayfs upperdir inspection or the dp
// file-notification snapshot (fsn.go rootsByID). Returns (drifted, ok); ok=false
// when the file can't be stat'd (caller decides fail-open vs fail-closed).
func procFileWrittenAfter(absPath string, startUnixNano int64) (bool, bool) {
	if strings.TrimSpace(absPath) == "" || startUnixNano <= 0 {
		return false, false
	}
	changedNano, ok := fileCtimeUnixNano(absPath)
	if !ok {
		return false, false
	}
	return changedNano > startUnixNano, true
}

// procReadFile / procReadlink are platform-neutral best-effort helpers (proc_enrich
// builds on all platforms; the linux-only readFileOrEmpty/readlinkOrEmpty live in
// file_profile_enforcer_linux.go and are unavailable here).
func procReadFile(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

func procReadlink(p string) string {
	v, err := os.Readlink(p)
	if err != nil {
		return ""
	}
	return v
}

// containerIDFromProcCgroup extracts a container ID from /proc/<pid>/cgroup under
// procRootDir. Platform-neutral (used by both the untagged process_enforcer and the
// linux fanotify enforcer).
func containerIDFromProcCgroup(procRootDir string, pid int) string {
	raw := procReadFile(procRootDir + "/" + strconv.Itoa(pid) + "/cgroup")
	for _, line := range strings.Split(raw, "\n") {
		for _, part := range strings.Split(line, "/") {
			id := normalizeContainerID(strings.TrimSpace(part))
			id = strings.TrimSuffix(id, ".scope")
			if looksLikeContainerID(id) {
				return id
			}
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

// procExecEnrichment is the result of enriching an exec event from /proc. Zero value
// (StdioSocket=false, Ruid=0, RuidOK=false) means "no data" and is wire-omitted.
type procExecEnrichment struct {
	// StdioSocket is true if any of fd 0/1/2 of the pid is a socket — a reverse-shell tell.
	StdioSocket bool
	// Ruid is the real uid parsed from /proc/<pid>/status; RuidOK reports whether it was read.
	Ruid   uint32
	RuidOK bool
}

// enrichProcExec reads the fd table and status of pid under procRoot. Best-effort: a missing
// /proc entry yields the zero enrichment (RuidOK=false, StdioSocket=false).
func enrichProcExec(pid uint32) procExecEnrichment {
	root := procRoot + "/" + strconv.FormatUint(uint64(pid), 10)
	return procExecEnrichment{
		StdioSocket: stdioIsSocket(root),
		Ruid:        0, // set below
	}.withRuid(root)
}

// withRuid fills Ruid/RuidOK from <root>/status. Kept as a method so enrichProcExec stays a
// single expression; returns the updated copy.
func (e procExecEnrichment) withRuid(root string) procExecEnrichment {
	if ruid, ok := readRuid(root + "/status"); ok {
		e.Ruid, e.RuidOK = ruid, true
	}
	return e
}

// stdioIsSocket reports whether any of fd 0/1/2 under procRoot/<pid>/fd is a socket symlink
// (target "socket:[<inode>]"). Mirrors neuvector osutil.GetFDSocketInode's socket-prefix test
// but only cares whether stdio is a socket, not which inode.
func stdioIsSocket(procPidRoot string) bool {
	for _, fd := range []string{"0", "1", "2"} {
		target, err := os.Readlink(procPidRoot + "/fd/" + fd)
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, "socket:") {
			return true
		}
	}
	return false
}

// readRuid parses the real uid (first field of the "Uid:" line) from a /proc/<pid>/status
// file. The Uid line is "Uid:\t<real>\t<effective>\t<saved>\t<fs>". Returns ok=false if the
// file is unreadable or has no parseable Uid line. Mirrors neuvector GetProcessUIDs.
func readRuid(statusPath string) (uint32, bool) {
	dat, err := os.ReadFile(statusPath)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(dat), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		v, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return 0, false
		}
		return uint32(v), true
	}
	return 0, false
}
