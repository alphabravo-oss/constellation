// Wave C3.5: agent-side PCAP capture worker.
//
// Every few seconds the agent:
//   1. GET /api/v1/runtime-pcap/claim?cluster_id=...&node=... (atomic claim)
//      - 204 → nothing to do, sleep till next tick
//      - 200 → PcapCapture body to execute
//   2. Spawn `tcpdump -i any -w /tmp/cap-<id>.pcap -G <duration_s> -W 1 <filter>`
//      where filter is built from the capture's 5-tuple fields
//   3. POST the resulting .pcap to /runtime-pcap/{id}/upload (multipart)
//      OR POST /runtime-pcap/{id}/status with failed + error_message
//
// Why `-i any`:
//   Mapping "namespace/deployment" → host-side veth requires either a
//   per-pod-IP join (we'd have to pull pod_ips for this cluster) or
//   nsenter into the pod's netns. Both are doable but add a moving part.
//   `-i any` captures every interface; the operator's 5-tuple filter
//   (always present when called from the threat drilldown) scopes the
//   output to one conversation. Trade: slightly more kernel work; gain:
//   one fewer correlation path to maintain.
//
// Lifecycle: the worker is killed when ctx is canceled. An in-flight
// tcpdump subprocess is `kill`ed too — we use exec.CommandContext.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// PcapWorkerConfig — knobs for the worker.
type PcapWorkerConfig struct {
	APIBaseURL string
	Token      string
	ClusterID  string
	Node       string
	Interval   time.Duration // claim poll interval; default 5s
	HTTPClient *http.Client
	Logger     *slog.Logger
	// TempDir defaults to /tmp; tcpdump writes there before upload.
	TempDir string
	// TcpdumpPath defaults to "tcpdump" (PATH lookup); override for tests.
	TcpdumpPath string
}

// pcapCaptureWire mirrors handler.PcapCapture's JSON shape — only the
// fields the worker needs to act on.
type pcapCaptureWire struct {
	ID        string `json:"id"`
	Workload  string `json:"workload"`
	DurationS int    `json:"duration_s"`
	SrcIP     string `json:"src_ip,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   int    `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`

	// --- G2.3: optional richness knobs (absent → legacy behavior) ---

	// BPFFilter is an OPTIONAL operator-supplied pcap-filter(7) expression.
	// It is a trust boundary: validated (character allowlist + dry
	// `tcpdump -d` parse) before being handed to tcpdump, and ANDed with
	// the 5-tuple-derived filter.
	BPFFilter string `json:"bpf_filter,omitempty"`
	// Interface scopes capture to a specific host interface (e.g. the
	// workload's veth) instead of "-i any". Validated as an iface name.
	Interface string `json:"interface,omitempty"`
	// FileCount + FileSizeMB request a rolling ring-buffer capture: up to
	// FileCount files of ~FileSizeMB each, capped at the 100MB total
	// ceiling. FileCount <= 1 → single-file legacy behavior.
	FileCount  int `json:"file_count,omitempty"`
	FileSizeMB int `json:"file_size_mb,omitempty"`
}

const (
	// maxPcapDurationS is the hard cap on a single capture's runtime. The
	// operator may request a longer-than-legacy window (legacy capped at
	// 60s) but never unbounded — 300s mirrors "grab a few minutes of
	// traffic" without turning the worker into a long-running collector.
	maxPcapDurationS = 300
	// maxPcapTotalMB is the hard ceiling on total captured bytes across
	// all rolling files, matching the server's 100MB upload cap.
	maxPcapTotalMB = 100
	// maxPcapFiles bounds the ring-buffer file count.
	maxPcapFiles = 20
)

// PcapWorker pulls the queue, runs tcpdump, uploads results.
type PcapWorker struct {
	cfg PcapWorkerConfig

	captured  atomic.Uint64
	uploaded  atomic.Uint64
	failed    atomic.Uint64
	lastClaim atomic.Int64
}

func NewPcapWorker(cfg PcapWorkerConfig) *PcapWorker {
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 120 * time.Second}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.TempDir == "" {
		cfg.TempDir = "/tmp"
	}
	if cfg.TcpdumpPath == "" {
		cfg.TcpdumpPath = "tcpdump"
	}
	return &PcapWorker{cfg: cfg}
}

// Run blocks until ctx is canceled. On every tick, claim the next pending
// capture (if any) and execute it serially. Serial execution intentional:
// running two captures concurrently competes for tcpdump-bandwidth and
// the operator doesn't expect simultaneous captures per node anyway.
func (w *PcapWorker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cap := w.claim(ctx)
			if cap == nil {
				continue
			}
			w.execute(ctx, cap)
		}
	}
}

// claim hits /runtime-pcap/claim. Returns nil on empty queue (204) or any
// transient failure (logged at debug). Returns the parsed capture row on
// 200.
func (w *PcapWorker) claim(ctx context.Context) *pcapCaptureWire {
	w.lastClaim.Store(time.Now().Unix())
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") +
		"/api/v1/runtime-pcap/claim?cluster_id=" + w.cfg.ClusterID +
		"&node=" + w.cfg.Node
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		w.cfg.Logger.Debug("pcap claim: transport error", slog.String("err", err.Error()))
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == 204 {
		return nil
	}
	if resp.StatusCode != 200 {
		w.cfg.Logger.Debug("pcap claim: non-200",
			slog.Int("code", resp.StatusCode))
		return nil
	}
	var cap pcapCaptureWire
	if err := json.NewDecoder(resp.Body).Decode(&cap); err != nil {
		w.cfg.Logger.Warn("pcap claim: decode", slog.String("err", err.Error()))
		return nil
	}
	if cap.ID == "" {
		return nil
	}
	return &cap
}

// execute runs tcpdump for the capture's duration, then uploads the
// resulting file. Any failure path POSTs status=failed so the row doesn't
// hang in `running` indefinitely.
func (w *PcapWorker) execute(ctx context.Context, cap *pcapCaptureWire) {
	w.cfg.Logger.Info("pcap: starting capture",
		slog.String("id", cap.ID),
		slog.String("workload", cap.Workload),
		slog.Int("duration_s", cap.DurationS))

	dur := cap.DurationS
	if dur <= 0 {
		dur = 30
	}
	if dur > maxPcapDurationS {
		dur = maxPcapDurationS
	}

	// Interface scoping: a specific veth/iface if provided (and valid),
	// otherwise the legacy "-i any".
	iface := "any"
	if name := strings.TrimSpace(cap.Interface); name != "" {
		if !validIfaceName(name) {
			w.fail(ctx, cap.ID, "invalid interface name: "+name)
			return
		}
		iface = name
	}

	// Filter = 5-tuple (trusted, built by us) AND the optional
	// operator-supplied expression (untrusted — validated first).
	filter := buildBPFFilter(cap)
	if opf := strings.TrimSpace(cap.BPFFilter); opf != "" {
		if err := validateBPFFilter(opf, w.cfg.TcpdumpPath); err != nil {
			w.fail(ctx, cap.ID, "invalid bpf filter: "+err.Error())
			return
		}
		if filter != "" {
			filter = "(" + filter + ") and (" + opf + ")"
		} else {
			filter = opf
		}
	}

	outPath := w.cfg.TempDir + "/constellation-pcap-" + cap.ID + ".pcap"
	rollBase := w.cfg.TempDir + "/constellation-pcap-" + cap.ID
	rolling := cap.FileCount > 1
	defer func() {
		_ = os.Remove(outPath)
		if rolling {
			for _, m := range rollingFiles(rollBase) {
				_ = os.Remove(m)
			}
		}
	}()

	args := []string{"-i", iface, "-U", "-q"}
	if rolling {
		// Ring buffer: keep FileCount files of up to perMB each, total
		// clamped to the 100MB ceiling. Duration is bounded by the
		// context deadline (there is no -G self-stop in ring mode).
		fileCount := cap.FileCount
		if fileCount > maxPcapFiles {
			fileCount = maxPcapFiles
		}
		perMB := cap.FileSizeMB
		if perMB <= 0 {
			perMB = 10
		}
		if perMB*fileCount > maxPcapTotalMB {
			perMB = maxPcapTotalMB / fileCount
			if perMB < 1 {
				perMB = 1
			}
		}
		args = append(args, "-w", rollBase,
			"-C", fmt.Sprintf("%d", perMB), "-W", fmt.Sprintf("%d", fileCount))
	} else {
		args = append(args, "-w", outPath,
			"-G", fmt.Sprintf("%d", dur), "-W", "1")
	}
	if filter != "" {
		args = append(args, filter)
	}

	// Hard time cap = duration + 5s grace. In single-file mode tcpdump's
	// -G/-W self-stops at <duration>; in ring mode the context deadline is
	// the only stop. Cancel via SIGINT (not SIGKILL) so tcpdump flushes
	// and closes the pcap cleanly, then WaitDelay force-kills if it hangs.
	subCtx, cancel := context.WithTimeout(ctx, time.Duration(dur+5)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(subCtx, w.cfg.TcpdumpPath, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) }
	cmd.WaitDelay = 3 * time.Second
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()

	// In ring mode, merge the rolling files into outPath for the (single)
	// upload path, enforcing the 100MB ceiling.
	if rolling {
		if _, mErr := combinePcaps(rollingFiles(rollBase), outPath); mErr != nil {
			errMsg := "merge rolling pcaps: " + mErr.Error()
			if s := strings.TrimSpace(stderr.String()); s != "" {
				errMsg = errMsg + " | " + s
			}
			w.fail(ctx, cap.ID, errMsg)
			return
		}
	}

	// tcpdump exits non-zero when interrupted mid-capture. We treat any
	// output file with size > 0 as success regardless of exit code,
	// because that's what actually matters.
	fi, statErr := os.Stat(outPath)
	if statErr != nil || fi.Size() == 0 {
		errMsg := strings.TrimSpace(stderr.String())
		if err != nil {
			errMsg = errMsg + " | " + err.Error()
		}
		if errMsg == "" {
			errMsg = "tcpdump produced no output"
		}
		w.fail(ctx, cap.ID, errMsg)
		return
	}
	w.captured.Add(1)
	w.cfg.Logger.Info("pcap: capture complete",
		slog.String("id", cap.ID),
		slog.Int64("bytes", fi.Size()))

	if err := w.upload(ctx, cap.ID, outPath); err != nil {
		w.fail(ctx, cap.ID, "upload: "+err.Error())
		return
	}
	w.uploaded.Add(1)
}

// fail records a failure and reports it so the row doesn't hang in
// `running`.
func (w *PcapWorker) fail(ctx context.Context, id, msg string) {
	w.failed.Add(1)
	w.reportStatus(ctx, id, "failed", msg, 0)
}

// rollingFiles lists the ring-buffer files tcpdump wrote for base. With
// `-w <base> -W N`, tcpdump appends a numeric suffix (base0, base1, ...).
func rollingFiles(base string) []string {
	m, _ := filepath.Glob(base + "[0-9]*")
	sort.Strings(m)
	return m
}

// combinePcaps merges rolling ring-buffer pcap files into a single dst
// file. Every pcap file begins with a 24-byte global header followed by
// packet records; because all files come from one tcpdump invocation
// (identical link type + byte order), we keep the first file's header and
// append only the packet records of the rest. Total bytes are capped at
// the 100MB ceiling.
func combinePcaps(paths []string, dst string) (int64, error) {
	if len(paths) == 0 {
		return 0, fmt.Errorf("no capture files produced")
	}
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	const globalHeader = 24
	limit := int64(maxPcapTotalMB) << 20
	var total int64
	for i, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return total, err
		}
		if i > 0 {
			if _, err := f.Seek(globalHeader, io.SeekStart); err != nil {
				_ = f.Close()
				return total, err
			}
		}
		n, cErr := io.Copy(out, io.LimitReader(f, limit-total))
		_ = f.Close()
		total += n
		if cErr != nil {
			return total, cErr
		}
		if total >= limit {
			break
		}
	}
	return total, nil
}

// validIfaceName rejects anything that isn't a plausible Linux interface
// name (IFNAMSIZ is 16, i.e. 15 usable bytes; no whitespace or path
// separators). This is a trust-boundary check on operator-supplied input.
func validIfaceName(name string) bool {
	if name == "" || len(name) > 15 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_' || r == '@':
		default:
			return false
		}
	}
	return true
}

// validateBPFFilter is the trust boundary for the operator-supplied filter
// string. Two layers: (1) a strict character allowlist that rejects shell
// metacharacters and any control byte, so an injection attempt never
// reaches exec; (2) a dry `tcpdump -d <filter>` parse that compiles the
// expression (no interface opened, no privileges needed) — a non-zero
// exit means the filter is malformed. Passing filters are known-good
// pcap-filter(7) expressions.
func validateBPFFilter(filter, tcpdumpPath string) error {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return nil
	}
	if len(filter) > 1024 {
		return fmt.Errorf("filter too long (%d bytes, max 1024)", len(filter))
	}
	for _, r := range filter {
		if !isBPFRune(r) {
			return fmt.Errorf("illegal character %q in filter", r)
		}
	}
	if tcpdumpPath == "" {
		tcpdumpPath = "tcpdump"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, tcpdumpPath, "-d", filter).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tcpdump rejected filter: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// isBPFRune reports whether r may appear in a pcap-filter(7) expression.
// Allowed: alphanumerics, space/tab, and the punctuation the grammar
// actually uses — grouping (), byte-slice indexing [], arithmetic
// +-*/%, bitwise &|, and relational <>=!. Everything else (backtick,
// $, ;, quotes, backslash, newline, braces, ...) is a shell metacharacter
// and is rejected.
func isBPFRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z':
		return true
	case r >= 'A' && r <= 'Z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == ' ' || r == '\t':
		return true
	}
	return strings.ContainsRune(".:/()[]<>=!&|+-*%", r)
}

// buildBPFFilter assembles a tcpdump filter expression from the capture's
// 5-tuple. Each field that's set narrows the filter; missing fields are
// wildcards. The grammar is the same one tcpdump accepts on the CLI.
func buildBPFFilter(cap *pcapCaptureWire) string {
	parts := make([]string, 0, 4)
	if ip := strings.TrimSpace(cap.SrcIP); ip != "" {
		if net.ParseIP(ip) != nil {
			parts = append(parts, "host "+ip)
		}
	}
	if ip := strings.TrimSpace(cap.DstIP); ip != "" {
		if net.ParseIP(ip) != nil {
			parts = append(parts, "host "+ip)
		}
	}
	if cap.DstPort > 0 && cap.DstPort < 65536 {
		parts = append(parts, fmt.Sprintf("port %d", cap.DstPort))
	}
	switch strings.ToLower(cap.Protocol) {
	case "tcp":
		parts = append(parts, "tcp")
	case "udp":
		parts = append(parts, "udp")
	case "icmp":
		parts = append(parts, "icmp")
	}
	return strings.Join(parts, " and ")
}

// upload sends the .pcap as a multipart body to /runtime-pcap/{id}/upload.
// Note: our server's Upload handler accepts the raw bytes (not multipart);
// for compatibility we send the body directly with Content-Type set.
func (w *PcapWorker) upload(ctx context.Context, id, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > 100<<20 {
		return fmt.Errorf("pcap %d bytes exceeds 100MB cap", fi.Size())
	}

	// Use raw body upload to match server expectations (server reads from
	// r.Body via io.Copy). Multipart would add multipart-parse work without
	// benefit since we only carry one file.
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") +
		"/api/v1/runtime-pcap/" + id + "/upload"
	req, err := http.NewRequestWithContext(ctx, "POST", url, f)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	req.Header.Set("Content-Type", "application/vnd.tcpdump.pcap")
	req.ContentLength = fi.Size()
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("server %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// reportStatus POSTs a status change to /runtime-pcap/{id}/status. Used
// for the failure path; upload-success implicit-completes the row.
func (w *PcapWorker) reportStatus(ctx context.Context, id, status, errMsg string, packetCount int64) {
	body, _ := json.Marshal(map[string]any{
		"status":        status,
		"error_message": errMsg,
		"packet_count":  packetCount,
	})
	url := strings.TrimRight(w.cfg.APIBaseURL, "/") +
		"/api/v1/runtime-pcap/" + id + "/status"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := w.cfg.HTTPClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// PcapWorkerStats — for /metrics.
type PcapWorkerStats struct {
	Captured  uint64
	Uploaded  uint64
	Failed    uint64
	LastClaim int64
}

func (w *PcapWorker) Snapshot() PcapWorkerStats {
	return PcapWorkerStats{
		Captured:  w.captured.Load(),
		Uploaded:  w.uploaded.Load(),
		Failed:    w.failed.Load(),
		LastClaim: w.lastClaim.Load(),
	}
}

// Compile-time used-import check — keeps imports trimmed if the worker is
// refactored later. textproto + multipart are wired up for a future
// switch to multipart uploads if the server ever needs metadata fields.
var _ = textproto.MIMEHeader{}
var _ = multipart.NewWriter
