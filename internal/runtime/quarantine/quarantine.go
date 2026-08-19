// Package quarantine is the enforce-mode response orchestrator: when WAF, DLP, or
// the eBPF baseline drift detector raises a hard alert, this package
//
//	1. cordons the offending pod via a deny-all NetworkPolicy (pkg/netpolicy),
//	2. captures up to N seconds (or M bytes) of pcap on the pod's veth,
//	3. snapshots /proc/<pid>/{cmdline,environ,maps,status,fd} for the offending PID,
//	4. fetches the last 200 lines of every container log via the K8s API,
//	5. bundles all of the above into a deterministic tarball with a sha256 manifest,
//	   and returns the on-disk path plus the manifest digest.
//
// The package separates Plan (decide what to do) from Execute (do it) so callers can
// dry-run the response in monitor mode.
package quarantine

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Trigger describes why a workload is being quarantined.
type Trigger struct {
	Source   string // "waf" | "dlp" | "ebpf" | "baseline"
	Reason   string // human text, e.g. "SQLi attempt: CRS 942100"
	Severity string // info|warning|error|critical
	Match    string // the offending rule id / pattern id (string for portability)
}

// Target identifies the pod we're acting on.
type Target struct {
	Namespace   string
	Pod         string
	WorkloadID  string // <namespace>/<kind>/<name>
	ContainerID string
	PID         int    // best-effort; 0 if unknown
	Veth        string // host-side iface name; "" to skip pcap
}

// Options configures a Quarantine run.
type Options struct {
	// PCAPDuration is the upper bound on packet capture (default 10s).
	PCAPDuration time.Duration
	// PCAPMaxBytes caps the captured bytes (default 4 MiB).
	PCAPMaxBytes int64
	// LogLines is how many recent log lines per container to keep (default 200).
	LogLines int
	// OutputDir is where the snapshot tarball is written. Required.
	OutputDir string
	// Logger for slog.
	Logger *slog.Logger
	// DryRun, when true, performs all collection but skips the actual NetworkPolicy
	// cordon. Useful for monitor mode previews.
	DryRun bool
}

// Defaults returns a sane Options with required fields zeroed.
func Defaults() Options {
	return Options{
		PCAPDuration: 10 * time.Second,
		PCAPMaxBytes: 4 << 20,
		LogLines:     200,
		Logger:       slog.Default(),
	}
}

// Result is what Execute returns.
type Result struct {
	TarballPath  string    `json:"tarball_path"`
	ManifestHash string    `json:"manifest_sha256"`
	Bytes        int64     `json:"bytes"`
	Components   []string  `json:"components"`
	CapturedAt   time.Time `json:"captured_at"`
	NetPolicy    string    `json:"netpolicy_yaml,omitempty"` // applied yaml (empty in dry-run)
}

// CollectorSet is the seam every Execute calls go through. Production wires K8s,
// pcap, and procfs implementations; tests inject fakes.
type CollectorSet struct {
	// Cordon applies a deny-all NetworkPolicy. Returns the rendered YAML (for audit).
	Cordon func(ctx context.Context, t Target) (string, error)
	// PCAP captures up to maxBytes of traffic on veth for up to dur. Returns the pcap
	// bytes (libpcap savefile format).
	PCAP func(ctx context.Context, veth string, dur time.Duration, maxBytes int64) ([]byte, error)
	// Proc reads /proc/<pid>/{cmdline,environ,maps,status,fd}; returns a map of
	// relative filename → bytes.
	Proc func(ctx context.Context, pid int) (map[string][]byte, error)
	// Logs fetches last N lines per container; returns map of container → lines.
	Logs func(ctx context.Context, namespace, pod string, lines int) (map[string][]string, error)
}

// Quarantine is the executable orchestrator.
type Quarantine struct {
	opts       Options
	collectors CollectorSet
}

// New constructs a Quarantine. cols may have nil fields; missing collectors emit a
// log warning and are skipped (useful in early-build environments).
func New(opts Options, cols CollectorSet) (*Quarantine, error) {
	if opts.OutputDir == "" {
		return nil, errors.New("quarantine: OutputDir required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.PCAPDuration == 0 {
		opts.PCAPDuration = 10 * time.Second
	}
	if opts.PCAPMaxBytes == 0 {
		opts.PCAPMaxBytes = 4 << 20
	}
	if opts.LogLines == 0 {
		opts.LogLines = 200
	}
	if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
		return nil, fmt.Errorf("quarantine: mkdir output: %w", err)
	}
	return &Quarantine{opts: opts, collectors: cols}, nil
}

// Execute runs the response and writes the tarball. Returns the Result.
func (q *Quarantine) Execute(ctx context.Context, t Target, trig Trigger) (*Result, error) {
	now := time.Now().UTC()
	parts := map[string][]byte{}
	components := []string{}

	// 1. Cordon
	var netpolYAML string
	if !q.opts.DryRun && q.collectors.Cordon != nil {
		y, err := q.collectors.Cordon(ctx, t)
		if err != nil {
			q.opts.Logger.Warn("quarantine: cordon failed",
				slog.String("workload", t.WorkloadID), slog.String("err", err.Error()))
		} else {
			netpolYAML = y
			parts["netpolicy.yaml"] = []byte(y)
			components = append(components, "netpolicy")
		}
	}

	// 2. PCAP
	if q.collectors.PCAP != nil && t.Veth != "" {
		pcap, err := q.collectors.PCAP(ctx, t.Veth, q.opts.PCAPDuration, q.opts.PCAPMaxBytes)
		if err != nil {
			q.opts.Logger.Warn("quarantine: pcap failed", slog.String("err", err.Error()))
		} else {
			parts["capture.pcap"] = pcap
			components = append(components, "pcap")
		}
	}

	// 3. Procfs snapshot
	if q.collectors.Proc != nil && t.PID > 0 {
		files, err := q.collectors.Proc(ctx, t.PID)
		if err != nil {
			q.opts.Logger.Warn("quarantine: proc snapshot failed", slog.String("err", err.Error()))
		} else {
			for name, raw := range files {
				parts["proc/"+name] = raw
			}
			components = append(components, "proc")
		}
	}

	// 4. Logs
	if q.collectors.Logs != nil {
		logs, err := q.collectors.Logs(ctx, t.Namespace, t.Pod, q.opts.LogLines)
		if err != nil {
			q.opts.Logger.Warn("quarantine: logs failed", slog.String("err", err.Error()))
		} else {
			for c, lines := range logs {
				parts["logs/"+c+".log"] = []byte(strings.Join(lines, "\n"))
			}
			components = append(components, "logs")
		}
	}

	// 5. Manifest
	manifest := buildManifest(t, trig, now, parts)
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	parts["manifest.json"] = manifestBytes

	// 6. Tarball
	tarballPath := filepath.Join(q.opts.OutputDir,
		fmt.Sprintf("quarantine-%s-%d.tar.gz", sanitize(t.WorkloadID), now.UnixNano()))
	written, err := writeTarball(tarballPath, parts)
	if err != nil {
		return nil, fmt.Errorf("quarantine: write tarball: %w", err)
	}

	hash := manifest.SHA256
	return &Result{
		TarballPath:  tarballPath,
		ManifestHash: hash,
		Bytes:        written,
		Components:   components,
		CapturedAt:   now,
		NetPolicy:    netpolYAML,
	}, nil
}

// Manifest is the on-disk JSON describing the snapshot contents.
type Manifest struct {
	Kind       string            `json:"kind"`
	CapturedAt time.Time         `json:"captured_at"`
	Target     Target            `json:"target"`
	Trigger    Trigger           `json:"trigger"`
	Files      []FileEntry       `json:"files"`
	SHA256     string            `json:"sha256"`     // SHA-256 of (sorted file list || file hashes)
	Version    string            `json:"version"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// FileEntry is one entry inside the manifest.
type FileEntry struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

func buildManifest(t Target, trig Trigger, at time.Time, parts map[string][]byte) Manifest {
	names := make([]string, 0, len(parts))
	for n := range parts {
		if n == "manifest.json" {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	files := make([]FileEntry, 0, len(names))
	overall := sha256.New()
	for _, n := range names {
		sum := sha256.Sum256(parts[n])
		hex := hex.EncodeToString(sum[:])
		files = append(files, FileEntry{Name: n, Size: len(parts[n]), SHA256: hex})
		overall.Write([]byte(n))
		overall.Write(sum[:])
	}
	overallHex := hex.EncodeToString(overall.Sum(nil))
	return Manifest{
		Kind:       "ConstellationQuarantineSnapshot/v1",
		CapturedAt: at,
		Target:     t,
		Trigger:    trig,
		Files:      files,
		SHA256:     overallHex,
		Version:    "1",
	}
}

func writeTarball(path string, parts map[string][]byte) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	names := make([]string, 0, len(parts))
	for n := range parts {
		names = append(names, n)
	}
	sort.Strings(names)
	var bytesIn int64
	for _, n := range names {
		body := parts[n]
		hdr := &tar.Header{
			Name:    n,
			Size:    int64(len(body)),
			Mode:    0o600,
			ModTime: time.Now(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return 0, err
		}
		if _, err := tw.Write(body); err != nil {
			return 0, err
		}
		bytesIn += int64(len(body))
	}
	if err := tw.Close(); err != nil {
		return 0, err
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	info, err := f.Stat()
	if err != nil {
		return bytesIn, nil
	}
	return info.Size(), nil
}

func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

// Restore reads a tarball back into an in-memory map. Useful for the API layer
// when serving snapshots to the UI.
func Restore(path string) (map[string][]byte, *Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, nil, fmt.Errorf("quarantine: gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return nil, nil, err
		}
		out[hdr.Name] = body
	}
	var m Manifest
	if raw, ok := out["manifest.json"]; ok {
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, nil, fmt.Errorf("quarantine: manifest: %w", err)
		}
	}
	return out, &m, nil
}
