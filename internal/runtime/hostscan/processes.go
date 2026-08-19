// Process snapshot collector — periodic walk of /proc that the
// runtime-agent uploads via POST /api/v1/host-processes:report.
//
// Complements the BPF exec stream (one-event-per-exec) with a current
// inventory: who's running RIGHT NOW. Useful for the UI's "what's on
// this node?" view, for incident response ("was this process running
// at 14:32?"), and as a fallback when the BPF stream is gappy.
//
// Mirrors what NeuVector's agent/probe collects via the netlink proc
// connector, but as a periodic snapshot rather than a streaming
// monitor — the streaming part is what BPF already gives us. The
// snapshot complements it.
package hostscan

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Process is one row in a Processes snapshot.
type Process struct {
	PID       int32  `json:"pid"`
	PPID      int32  `json:"ppid"`
	UID       int32  `json:"uid"`
	Comm      string `json:"comm"`               // /proc/[pid]/comm
	Cmdline   string `json:"cmdline,omitempty"`  // NUL-joined to spaces
	StartTime int64  `json:"start_time"`         // unix seconds since boot of pid 1
	State     string `json:"state,omitempty"`    // R/S/D/Z/T from /proc/[pid]/stat
}

// Processes is the wire shape POSTed by the agent.
type Processes struct {
	Node       string    `json:"node"`
	ObservedAt time.Time `json:"observed_at"`
	// Count is the total number of userspace pids the collector saw;
	// Items may be shorter than Count when MaxItems caps the report
	// (useful for cluster-wide aggregation: count is the true total).
	Count int       `json:"count"`
	Items []Process `json:"items"`
}

// ProcessOptions controls collection caps.
type ProcessOptions struct {
	// HostRoot is the bind-mount prefix for the host's /proc. In the
	// runtime-agent container the chart mounts /proc at /host/proc
	// (set HOSTSCAN_ROOT=/host) so the collector sees host PIDs. Empty
	// reads /proc directly (useful for unit tests).
	HostRoot string

	// NodeName is stamped on every snapshot.
	NodeName string

	// MaxItems caps how many processes get serialized (>= 0). The
	// total host count is preserved in Processes.Count even when
	// Items is truncated. Default 1000 if 0.
	MaxItems int

	// CmdlineCap truncates each cmdline to this many bytes. Default 2048.
	CmdlineCap int

	// IncludeKernelThreads, when false (default), drops processes
	// whose /proc/[pid]/cmdline is empty — those are kernel threads
	// (kworker/*, ksoftirqd/*, etc.) which aren't useful for
	// userland inventory.
	IncludeKernelThreads bool
}

// CollectProcesses walks /proc, parses each numeric entry, and returns
// a Processes snapshot. Best-effort: any per-pid error is silently
// skipped (the pid may have exited mid-walk; the next snapshot picks
// up). Never returns an error.
func CollectProcesses(opts ProcessOptions) Processes {
	if opts.MaxItems == 0 {
		opts.MaxItems = 1000
	}
	if opts.CmdlineCap == 0 {
		opts.CmdlineCap = 2048
	}
	procDir := "/proc"
	if opts.HostRoot != "" {
		procDir = filepath.Join(opts.HostRoot, "proc")
	}

	p := Processes{
		Node:       opts.NodeName,
		ObservedAt: time.Now().UTC(),
	}
	if p.Node == "" {
		if h, _ := os.Hostname(); h != "" {
			p.Node = h
		}
	}

	entries, err := os.ReadDir(procDir)
	if err != nil {
		return p
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid64, err := strconv.ParseInt(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := int32(pid64)
		proc, ok := readProcess(procDir, pid, opts)
		if !ok {
			continue
		}
		p.Count++
		p.Items = append(p.Items, proc)
	}

	// Stable order helps diffing snapshots. Sort by pid ascending.
	sort.Slice(p.Items, func(i, j int) bool {
		return p.Items[i].PID < p.Items[j].PID
	})

	if len(p.Items) > opts.MaxItems {
		p.Items = p.Items[:opts.MaxItems]
	}
	return p
}

func readProcess(procDir string, pid int32, opts ProcessOptions) (Process, bool) {
	base := filepath.Join(procDir, strconv.Itoa(int(pid)))

	// cmdline: NUL-separated argv. Empty for kernel threads.
	cmdlineB, _ := os.ReadFile(filepath.Join(base, "cmdline"))
	cmdline := string(cmdlineB)
	cmdline = strings.TrimRight(cmdline, "\x00")
	if cmdline == "" && !opts.IncludeKernelThreads {
		return Process{}, false
	}
	if len(cmdline) > opts.CmdlineCap {
		cmdline = cmdline[:opts.CmdlineCap]
	}
	cmdline = strings.ReplaceAll(cmdline, "\x00", " ")

	// /proc/[pid]/status: short labelled fields. Pull Uid + PPid + Name.
	statusF, err := os.Open(filepath.Join(base, "status"))
	if err != nil {
		return Process{}, false
	}
	defer statusF.Close()

	var (
		ppid int32
		uid  int32 = -1
		comm string
	)
	sc := bufio.NewScanner(statusF)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			if v, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), 10, 32); err == nil {
				ppid = int32(v)
			}
		case strings.HasPrefix(line, "Uid:"):
			// Real, Effective, Saved-set, Filesystem — first one is real uid.
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				if v, err := strconv.ParseInt(fields[0], 10, 32); err == nil {
					uid = int32(v)
				}
			}
		}
	}

	// /proc/[pid]/stat: field 22 is starttime in clock ticks since boot.
	// Field 3 is state (R/S/D/Z/T). We parse the right end of the line
	// past the parenthesized comm to avoid the (..) confusion.
	var startTime int64
	var state string
	if b, err := os.ReadFile(filepath.Join(base, "stat")); err == nil {
		// Find the LAST ')' — comm is parenthesized and may contain
		// arbitrary chars including spaces and parens.
		s := string(b)
		idx := strings.LastIndex(s, ")")
		if idx > 0 && idx+2 < len(s) {
			rest := s[idx+2:]
			fields := strings.Fields(rest)
			// rest fields[0] is state; fields[19] is starttime
			// (field 22 in 1-indexed, but we've consumed pid + (comm)
			// so it's 19 in 0-indexed here).
			if len(fields) > 0 {
				state = fields[0]
			}
			if len(fields) > 19 {
				if v, err := strconv.ParseInt(fields[19], 10, 64); err == nil {
					startTime = v
				}
			}
		}
	}

	return Process{
		PID:       pid,
		PPID:      ppid,
		UID:       uid,
		Comm:      comm,
		Cmdline:   cmdline,
		State:     state,
		StartTime: startTime,
	}, true
}
