// Runtime behavioral detection helpers shared by the events-ingest classifier.
//
// This file broadens process-exec and file-write detection beyond the original
// shell-only heuristic so the ingest path approaches NeuVector's runtime behavioral
// depth (agent/probe/process.go suspicProcMap / rootEscalationCheck and
// share/fsmon/monitor.go ImportantFiles).
//
// Three process signals are layered on top of the shell heuristic:
//
//   - image-provenance drift: an exec whose basename is not in the workload's learned
//     baseline set. In enforce mode this is high/alert; in monitor mode medium/alert.
//     (mirrors NeuVector IsAllowedShieldProcess — anything not in the allow-list is a
//     violation once the group is protected.)
//   - suspicious binaries: a categorically dangerous tool (netcat/socat/nmap/tcpdump,
//     wget|curl piped to a shell, base64-decode-exec, ...) -> high regardless of
//     baseline (mirrors suspicProcMap + checkReverseShell).
//   - privilege escalation: a child process whose effective UID is 0 while its parent
//     (correlated within the batch by PID/PPID) ran as non-root -> high (mirrors
//     rootEscalationCheck, which flags a root child of a non-root ancestor).
//
// And a default File Integrity Monitoring watch-set (defaultFIMRules) mirroring
// NeuVector's ImportantFiles so writes to package DBs, credential files, ssh keys and
// system bin dirs classify as file_modified findings even before an operator has
// authored an explicit file-profile.
package runtime

import (
	"os"
	"strings"

	"github.com/alphabravocompany/constellation/pkg/attack"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

// suspiciousBinaries are tools whose presence in a running container is, on its own,
// strong evidence of post-exploitation / lateral-movement activity. An exec of any of
// these is high severity regardless of baseline state. Mirrors NeuVector's
// suspicProcMap (agent/probe/process.go ~98) plus a few container-relevant additions.
var suspiciousBinaries = map[string]struct{}{
	"nc":             {},
	"ncat":           {},
	"netcat":         {},
	"nc.openbsd":     {},
	"nc.traditional": {},
	"socat":          {},
	"nmap":           {},
	"ncrack":         {},
	"masscan":        {},
	"tcpdump":        {},
	"tshark":         {},
	"telnet":         {},
	"iodine":         {},
	"iodined":        {},
	"dnscat":         {},
	"dnscat2":        {},
	"dns2tcpc":       {},
	"dns2tcpd":       {},
	"hydra":          {},
	"msfvenom":       {},
	"msfconsole":     {},
	"chisel":         {},
	"meterpreter":    {},
}

// suspiciousArgSubstrings are command-line shapes that indicate a download-and-execute
// or decode-and-execute primitive. Matched against the joined argv of a process_exec.
// These mirror the "wget|sh" / base64-decode-exec patterns called out for WS-F3.
var suspiciousArgSubstrings = []string{
	"| sh",
	"| bash",
	"|sh",
	"|bash",
	"curl -s | sh",
	"base64 -d | sh",
	"base64 -d | bash",
	"base64 --decode | sh",
	"echo | base64 -d",
}

// suspiciousProcess reports whether an exec is categorically dangerous: either the
// binary itself is in suspiciousBinaries, or its argv exhibits a download/decode-to-shell
// pattern. The returned ok=true => high severity regardless of baseline.
func suspiciousProcess(bin string, args []string) bool {
	if _, ok := suspiciousBinaries[bin]; ok {
		return true
	}
	if len(args) == 0 {
		return false
	}
	joined := strings.ToLower(strings.Join(args, " "))
	// wget/curl piping into a shell (download-cradle).
	if (strings.Contains(joined, "wget") || strings.Contains(joined, "curl")) &&
		(strings.Contains(joined, "|sh") || strings.Contains(joined, "| sh") ||
			strings.Contains(joined, "|bash") || strings.Contains(joined, "| bash")) {
		return true
	}
	// base64-decode piped to a shell.
	if strings.Contains(joined, "base64") &&
		(strings.Contains(joined, "-d") || strings.Contains(joined, "--decode") || strings.Contains(joined, "decode")) &&
		(strings.Contains(joined, "|sh") || strings.Contains(joined, "| sh") ||
			strings.Contains(joined, "|bash") || strings.Contains(joined, "| bash") ||
			strings.Contains(joined, "eval") || strings.Contains(joined, "exec")) {
		return true
	}
	for _, sub := range suspiciousArgSubstrings {
		if strings.Contains(joined, sub) {
			return true
		}
	}
	return false
}

// privEscFromBatch reports whether ev is a privilege escalation: its effective UID is
// root (0) while the parent process — correlated within the same ingest batch by
// PID/PPID — ran as a non-root UID. This is the single-event-stream analogue of
// NeuVector's rootEscalationCheck (a root child of a non-root ancestor).
//
// uidByPID maps PID -> effective UID for every process_exec in the batch.
func privEscFromBatch(ev *IngestEvent, uidByPID map[uint32]uint32) bool {
	if ev == nil || ev.Kind != "process_exec" {
		return false
	}
	if ev.UID != 0 || ev.PPID == 0 {
		return false
	}
	parentUID, ok := uidByPID[ev.PPID]
	if !ok {
		return false
	}
	return parentUID != 0
}

// realUIDEscalation reports whether an exec runs with effective UID root (0) while its REAL
// uid is a non-root user — i.e. the process gained root authority (setuid binary, sudo, a
// userns mapping, ...) rather than having been root all along. This is the single-event
// analogue of NeuVector rootEscalationCheck's ruid-vs-euid comparison (process.go ~865), and
// unlike privEscFromBatch it needs no parent correlation: the ruid/euid pair on the event
// alone is conclusive. Requires the agent's /proc enrichment (RuidKnown); absent => false so
// events without the new field keep their current classification.
func realUIDEscalation(ev *IngestEvent) bool {
	if ev == nil || ev.Kind != "process_exec" {
		return false
	}
	return ev.RuidKnown && ev.UID == 0 && ev.Ruid != 0
}

// reverseShell reports whether an exec is a likely reverse shell: its stdio (fd 0/1/2) was a
// socket at exec time (the agent's StdioSocket enrichment) AND it is not an exec we'd expect
// to legitimately have socket stdio. We combine the StdioSocket tell with the existing
// suspicious-binary / download-cradle heuristic OR a shell interpreter for confidence,
// mirroring NeuVector checkReverseShell (process.go ~1723), which fires on a process whose
// stdin/stdout are the same socket. Requires the agent enrichment; absent => false.
func reverseShell(ev *IngestEvent, isShell bool) bool {
	if ev == nil || ev.Kind != "process_exec" || !ev.StdioSocket {
		return false
	}
	bin := commBasename(ev.Comm, ev.Filename)
	return isShell || suspiciousProcess(bin, ev.Args)
}

// buildUIDByPID indexes effective UID by PID across a batch so privEscFromBatch can
// correlate a child exec against its parent's UID.
func buildUIDByPID(events []IngestEvent) map[uint32]uint32 {
	m := make(map[uint32]uint32, len(events))
	for i := range events {
		ev := &events[i]
		if ev.Kind == "process_exec" && ev.PID != 0 {
			m[ev.PID] = ev.UID
		}
	}
	return m
}

// fileWriteFlag bits (open(2)). A file_open whose flags request write access is treated
// as a modification for FIM purposes.
const (
	oWRONLY = 0x1
	oRDWR   = 0x2
	oCREAT  = 0x40
	oTRUNC  = 0x200
	oAPPEND = 0x400
)

// isFileWrite reports whether an open(2) flags value requests write access (and is thus
// a candidate file modification rather than a pure read).
func isFileWrite(flags uint32) bool {
	return flags&(oWRONLY|oRDWR|oCREAT|oTRUNC|oAPPEND) != 0
}

// defaultFIMEnabled keeps the default File Integrity Monitoring watch-set on by default
// while remaining configurable: an operator can disable it via the
// CONSTELLATION_FIM_DEFAULT env var ("0"/"false"/"off"). Evaluated once at package init.
var defaultFIMEnabled = fimDefaultFromEnv()

func fimDefaultFromEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("CONSTELLATION_FIM_DEFAULT"))) {
	case "0", "false", "off", "no", "disable", "disabled":
		return false
	}
	return true
}

// fimWatch is one entry of the default File Integrity Monitoring watch-set.
type fimWatch struct {
	// prefix matches a path either exactly or, when dir=true, as a directory prefix.
	prefix string
	dir    bool
	// severity for a write to this path; "" => "medium".
	severity string
	// label is a short human description surfaced in the payload.
	label string
}

// defaultFIMRules is the default watch-set mirroring NeuVector share/fsmon/monitor.go
// ImportantFiles (~33-55): package databases, credential files, ssh host keys +
// authorized_keys, and the common system bin directories. Writes to these paths are
// classified as file_modified findings even with no operator-authored file-profile.
//
// Severity is graded by path sensitivity: credential stores (shadow/sudoers/ssh keys)
// are high; package DBs and identity files are medium; system bin dirs (tamper of an
// on-disk binary) are high.
var defaultFIMRules = []fimWatch{
	// Package databases — tampering hides installed-package provenance (T1574).
	{prefix: "/var/lib/dpkg/status", severity: "medium", label: "dpkg package database"},
	{prefix: "/var/lib/rpm/", dir: true, severity: "medium", label: "rpm package database"},
	{prefix: "/lib/apk/db/installed", severity: "medium", label: "apk package database"},

	// Identity / credential files.
	{prefix: "/etc/passwd", severity: "high", label: "user account database"},
	{prefix: "/etc/shadow", severity: "high", label: "shadow password database"},
	{prefix: "/etc/gshadow", severity: "high", label: "group shadow database"},
	{prefix: "/etc/group", severity: "medium", label: "group database"},
	{prefix: "/etc/sudoers", severity: "high", label: "sudoers policy"},
	{prefix: "/etc/sudoers.d/", dir: true, severity: "high", label: "sudoers policy"},

	// SSH host keys + authorized_keys.
	{prefix: "/etc/ssh/", dir: true, severity: "high", label: "ssh host key / config"},
	{prefix: "/root/.ssh/", dir: true, severity: "high", label: "root ssh keys"},

	// Shared-library directories — ld.so/libc/libpthread tamper or preload
	// implant (T1574.006). NeuVector watches these (share/fsmon/monitor.go).
	{prefix: "/lib/", dir: true, severity: "high", label: "shared library directory"},
	{prefix: "/lib64/", dir: true, severity: "high", label: "shared library directory"},

	// System binary directories — on-disk binary tamper / implant.
	{prefix: "/bin/", dir: true, severity: "high", label: "system binary directory"},
	{prefix: "/sbin/", dir: true, severity: "high", label: "system binary directory"},
	{prefix: "/usr/bin/", dir: true, severity: "high", label: "system binary directory"},
	{prefix: "/usr/sbin/", dir: true, severity: "high", label: "system binary directory"},
	{prefix: "/usr/local/bin/", dir: true, severity: "high", label: "system binary directory"},
	{prefix: "/usr/local/sbin/", dir: true, severity: "high", label: "system binary directory"},
}

// matchDefaultFIM returns the first default-watch entry a path matches, or nil. Also
// matches authorized_keys / ssh keys nested under /home/<user>/.ssh.
func matchDefaultFIM(path string) *fimWatch {
	if path == "" || !strings.HasPrefix(path, "/") {
		return nil
	}
	for i := range defaultFIMRules {
		w := &defaultFIMRules[i]
		if w.dir {
			if strings.HasPrefix(path, w.prefix) {
				return w
			}
		} else if path == w.prefix {
			return w
		}
	}
	// /home/<user>/.ssh/... (authorized_keys, id_*) — modeled per-user.
	if strings.HasPrefix(path, "/home/") {
		if i := strings.Index(path, "/.ssh/"); i >= 0 || strings.HasSuffix(path, "/.ssh") {
			return &fimWatch{prefix: path, severity: "high", label: "user ssh keys"}
		}
	}
	return nil
}

// fimSeverity normalizes the watch severity ("" => "medium").
func (w *fimWatch) fimSeverity() string {
	if w == nil {
		return "medium"
	}
	if w.severity == "" {
		return "medium"
	}
	return w.severity
}

// processSignal is the outcome of broadened process-exec classification.
type processSignal struct {
	severity   string
	verdict    string
	techniques []string // explicit ATT&CK override; empty => use techniquesFor
	reason     string
}

// classifyProcessExec applies the broadened process detections to a single exec. It is
// a pure function so it is straightforward to unit-test:
//
//	bin           process basename
//	args          argv
//	inBaseline    whether bin is in the workload's learned baseline set
//	haveBaseline  whether a baseline mode is known for this workload
//	mode          the baseline mode (only meaningful when haveBaseline)
//	isShell       whether bin is a shell/interpreter (shellBinaries)
//	privEsc       whether this exec is a within-batch/cross-batch ancestry privilege escalation
//	revShell      whether this exec is a likely reverse shell (StdioSocket + suspicious/shell)
//	ruidEsc       whether this exec is a real-uid escalation (ruid!=0 && euid==0)
//
// Returns ok=false when no signal fired (caller keeps its prior classification).
func classifyProcessExec(bin string, args []string, inBaseline, haveBaseline bool, mode baseline.Mode, isShell, privEsc, revShell, ruidEsc bool) (processSignal, bool) {
	// (d) reverse shell — an active intrusion in progress (stdio redirected to a socket).
	// Highest confidence, evaluated first. Mirrors NeuVector checkReverseShell.
	if revShell {
		return processSignal{
			severity:   "high",
			verdict:    "alert",
			techniques: attack.Map(attack.EventReverseShell),
			reason:     "reverse-shell",
		}, true
	}
	// (c) privilege escalation — root child of a non-root ancestor, OR a real-uid->euid-root
	// escalation reported directly by the agent's /proc enrichment.
	if privEsc || ruidEsc {
		reason := "privilege-escalation"
		if ruidEsc && !privEsc {
			reason = "real-uid-escalation"
		}
		return processSignal{
			severity:   "high",
			verdict:    "alert",
			techniques: attack.Map(attack.EventPrivilegeEscalation),
			reason:     reason,
		}, true
	}
	// (b) suspicious binary / download-cradle — high regardless of baseline.
	if suspiciousProcess(bin, args) {
		return processSignal{
			severity:   "high",
			verdict:    "alert",
			techniques: attack.Map(attack.EventReverseShell),
			reason:     "suspicious-binary",
		}, true
	}
	// (a) image-provenance drift — exec not in the workload's baseline set. Only
	// meaningful once we actually have a baseline AND the workload has left learn mode.
	if haveBaseline && !inBaseline {
		switch mode {
		case baseline.ModeEnforce:
			// Protect mode: out-of-baseline exec is blocked, not just alerted.
			// Mirrors NeuVector PolicyActionDeny in ProfileMode=Protect. This is
			// the recorded decision; agent-side kill-on-exec is a separate piece.
			return processSignal{
				severity:   "high",
				verdict:    "block",
				techniques: driftTechniques(isShell),
				reason:     "provenance-drift",
			}, true
		case baseline.ModeMonitor:
			return processSignal{
				severity:   "medium",
				verdict:    "alert",
				techniques: driftTechniques(isShell),
				reason:     "provenance-drift",
			}, true
		}
	}
	return processSignal{}, false
}

// driftTechniques maps a provenance-drift exec to ATT&CK. A drifted shell is still a
// shell-spawn (T1059.004); a drifted non-shell binary is unauthorized execution
// (T1204/T1059) — we surface it via EventShellSpawn for the shell case and otherwise
// leave the technique set to the generic exec mapping computed by techniquesFor.
func driftTechniques(isShell bool) []string {
	if isShell {
		return attack.Map(attack.EventShellSpawn)
	}
	return nil
}
