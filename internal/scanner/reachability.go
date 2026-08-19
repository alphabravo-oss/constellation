package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Go-binary reachability analysis.
//
// The multi-engine scanners (Trivy/Grype/VulnDB) match a Go module's *declared*
// version against advisory ranges. That tells us a vulnerable package is present
// in the binary, but not whether the vulnerable code is actually reachable from
// the program's entry points. govulncheck closes that gap: in binary mode it
// reads the symbol tables embedded in a Go binary and reports, per vulnerability,
// whether a vulnerable symbol is *called* (reachable) or merely imported.
//
// This pass is opt-in (ScanOptions.GoReachability). For each distinct Go binary
// referenced by a Go-ecosystem finding it runs `govulncheck -mode binary` with a
// hard per-binary cap (default 30s), then:
//   - sets Finding.Reachable=true for findings govulncheck proved reachable,
//   - sets Finding.Reachable=false for Go findings the binary contains but never
//     calls, and
//   - deprioritizes the unreachable Go findings in the result ordering so triage
//     surfaces the reachable ones first.
//
// It never *adds* or *removes* findings — govulncheck's vuln database differs
// from ours, so it is used purely as a reachability signal over the findings the
// canonical engines already produced. A binary govulncheck cannot analyze (no
// symbol table, missing binary, timeout) leaves Reachable nil for that binary's
// findings: unknown, not "unreachable".

// defaultGoReachabilityTimeout caps a single govulncheck binary-mode invocation.
// govulncheck binary mode is fast (it reads symbol tables, it does not type-check
// source), so 30s is generous; the cap exists to bound a pathological binary.
const defaultGoReachabilityTimeout = 30 * time.Second

// goReachabilityBinaryEcosystem is the ecosystem tag Syft assigns Go packages
// catalogued from a compiled binary (the go-module / go-binary cataloguers both
// normalize to "go").
const goReachabilityEcosystem = "go"

// reachabilityRunner runs govulncheck (or a test double) against a single binary
// path and returns its streamed JSON output. The default implementation shells
// out to the govulncheck CLI; tests inject a stub.
type reachabilityRunner func(ctx context.Context, binaryPath string) ([]byte, error)

// goReachabilityAnalyzer is the configurable entry point. The zero value uses the
// govulncheck CLI on PATH with the default timeout.
type goReachabilityAnalyzer struct {
	// run executes govulncheck binary mode. When nil, runGovulncheckBinary is used.
	run reachabilityRunner
	// timeout caps each binary analysis. When zero, defaultGoReachabilityTimeout.
	timeout time.Duration
	// resolvePath maps a finding's observed binary path (which for an image scan is
	// a path INSIDE the image) to a host-readable path govulncheck can open. When
	// nil, paths are used as-is (directory/serverless scans, tests). A path the
	// resolver cannot map (ok=false) is skipped, leaving that binary's findings at
	// Reachable=nil (unknown) rather than feeding govulncheck a path it cannot read.
	resolvePath func(string) (string, bool)
}

// analyze fills Reachable on Go-ecosystem findings using govulncheck binary mode,
// then deprioritizes unreachable Go findings. It mutates findings in place and
// returns the (re-ordered) slice. Non-Go findings are never touched.
func (a goReachabilityAnalyzer) analyze(ctx context.Context, findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	run := a.run
	if run == nil {
		run = runGovulncheckBinary
	}
	timeout := a.timeout
	if timeout <= 0 {
		timeout = defaultGoReachabilityTimeout
	}

	// Group the indexes of Go findings by the binary path they were observed in.
	// A single binary is analyzed once even if it carries many findings.
	byBinary := map[string][]int{}
	for i := range findings {
		if !isGoFinding(findings[i]) {
			continue
		}
		for _, path := range findingBinaryPaths(findings[i]) {
			hostPath := path
			if a.resolvePath != nil {
				resolved, ok := a.resolvePath(path)
				if !ok {
					// Not extractable to a host path (e.g. an image binary we could
					// not pull): leave this finding's reachability unknown.
					continue
				}
				hostPath = resolved
			}
			byBinary[hostPath] = append(byBinary[hostPath], i)
		}
	}
	if len(byBinary) == 0 {
		return findings
	}

	// Analyze each binary under its own timeout; a per-binary failure is
	// non-fatal and simply leaves that binary's findings at Reachable=nil.
	for path, idxs := range byBinary {
		select {
		case <-ctx.Done():
			return reorderByReachability(findings)
		default:
		}

		reach, err := analyzeBinary(ctx, run, timeout, path)
		if err != nil || reach == nil {
			continue
		}
		for _, i := range idxs {
			// A finding already proven reachable in one binary stays reachable.
			if boolValue(findings[i].Reachable) {
				continue
			}
			state, known := reach.lookup(findings[i])
			if !known {
				continue
			}
			findings[i].Reachable = boolPtr(state)
		}
	}

	return reorderByReachability(findings)
}

// analyzeBinary runs govulncheck against one binary and parses its result.
func analyzeBinary(ctx context.Context, run reachabilityRunner, timeout time.Duration, path string) (*reachabilityResult, error) {
	binCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := run(binCtx, path)
	if err != nil {
		return nil, err
	}
	return parseGovulncheckBinary(out), nil
}

// runGovulncheckBinary shells out to the govulncheck CLI in binary mode.
// `-mode binary` reads the binary's symbol tables; `-format json` streams the
// Message objects we parse. A missing binary on PATH is reported as an error so
// the caller treats reachability as unknown (it never fails the scan).
func runGovulncheckBinary(ctx context.Context, binaryPath string) ([]byte, error) {
	bin := "govulncheck"
	if _, err := exec.LookPath(bin); err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "-mode", "binary", "-format", "json", binaryPath)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// govulncheck exits non-zero when it finds vulnerabilities; that is expected
	// and stdout still holds the full JSON stream, so a non-nil run error is only
	// fatal when no JSON was produced.
	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return nil, err
	}
	return stdout.Bytes(), nil
}

// reachabilityResult maps a vulnerability identity to whether govulncheck proved
// a vulnerable symbol is called. Keys are uppercased vuln IDs: the OSV GO-id plus
// every alias (CVE-…, GHSA-…) so we can join against whichever ID our canonical
// engines recorded.
type reachabilityResult struct {
	// called is true when at least one symbol-level finding (a trace frame with a
	// function) referenced the id; present means the id appeared at all.
	called  map[string]bool
	present map[string]bool
}

func (r *reachabilityResult) lookup(f Finding) (state bool, known bool) {
	if r == nil {
		return false, false
	}
	for _, id := range findingVulnIDs(f) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		if r.called[id] {
			return true, true
		}
		if r.present[id] {
			known = true
		}
	}
	if known {
		// Present in the binary's vuln set but never reached a called frame.
		return false, true
	}
	return false, false
}

// govulncheck JSON message shapes. We define a minimal local copy rather than
// importing golang.org/x/vuln/internal/govulncheck (an internal package). Only
// the fields we read are declared; unknown fields are ignored.
type govulncheckMessage struct {
	OSV     *govulncheckOSV     `json:"osv,omitempty"`
	Finding *govulncheckFinding `json:"finding,omitempty"`
}

type govulncheckOSV struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases,omitempty"`
}

type govulncheckFinding struct {
	OSV   string              `json:"osv,omitempty"`
	Trace []*govulncheckFrame `json:"trace,omitempty"`
}

type govulncheckFrame struct {
	Function string `json:"function,omitempty"`
}

// parseGovulncheckBinary consumes a govulncheck `-format json` stream (a sequence
// of JSON objects) and returns the reachability verdict per vuln id.
func parseGovulncheckBinary(stream []byte) *reachabilityResult {
	res := &reachabilityResult{called: map[string]bool{}, present: map[string]bool{}}
	// Aliases per OSV id, learned from `osv` messages, so a called/present verdict
	// on the GO-id propagates to its CVE/GHSA aliases.
	aliases := map[string][]string{}

	dec := json.NewDecoder(bytes.NewReader(stream))
	for dec.More() {
		var msg govulncheckMessage
		if err := dec.Decode(&msg); err != nil {
			// Tolerate a truncated/garbled trailing record (e.g. killed by timeout)
			// while keeping everything parsed so far.
			break
		}
		switch {
		case msg.OSV != nil && msg.OSV.ID != "":
			id := strings.ToUpper(msg.OSV.ID)
			for _, alias := range msg.OSV.Aliases {
				if a := strings.ToUpper(strings.TrimSpace(alias)); a != "" {
					aliases[id] = append(aliases[id], a)
				}
			}
		case msg.Finding != nil && msg.Finding.OSV != "":
			id := strings.ToUpper(msg.Finding.OSV)
			res.present[id] = true
			if findingHasCalledSymbol(msg.Finding) {
				res.called[id] = true
			}
		}
	}

	// Propagate verdicts to aliases.
	for osvID, alist := range aliases {
		for _, alias := range alist {
			if res.present[osvID] {
				res.present[alias] = true
			}
			if res.called[osvID] {
				res.called[alias] = true
			}
		}
	}
	return res
}

// findingHasCalledSymbol reports whether a govulncheck finding represents a
// called (symbol-level) trace. In binary mode govulncheck emits a finding with a
// single trace frame; the frame carries a Function only when a vulnerable symbol
// is actually called. Module/package-level findings (imported-but-not-called)
// have no Function.
func findingHasCalledSymbol(f *govulncheckFinding) bool {
	for _, frame := range f.Trace {
		if frame != nil && strings.TrimSpace(frame.Function) != "" {
			return true
		}
	}
	return false
}

// reorderByReachability deprioritizes unreachable Go findings: it performs a
// stable partition that keeps reachable/unknown findings ahead of findings that
// govulncheck proved unreachable, without otherwise disturbing the engine's
// severity ordering.
func reorderByReachability(findings []Finding) []Finding {
	sort.SliceStable(findings, func(i, j int) bool {
		return reachabilityRank(findings[i]) < reachabilityRank(findings[j])
	})
	return findings
}

// reachabilityRank orders findings for triage: proven-unreachable Go findings
// sort last (rank 1); everything else keeps its place (rank 0). Only an explicit
// Reachable==false demotes a finding — nil (unknown) and true do not.
func reachabilityRank(f Finding) int {
	if f.Reachable != nil && !*f.Reachable {
		return 1
	}
	return 0
}

func isGoFinding(f Finding) bool {
	return strings.EqualFold(f.Package.Ecosystem, goReachabilityEcosystem)
}

// findingBinaryPaths returns the on-disk binary paths a Go finding was observed
// in, derived from the package's Syft locations. The real path is preferred (it
// resolves symlinks to the actual binary); access/path are fallbacks.
func findingBinaryPaths(f Finding) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	for _, loc := range f.Package.Locations {
		// A go-binary location's RealPath/Path is the executable itself.
		switch {
		case loc.RealPath != "":
			add(loc.RealPath)
		case loc.Path != "":
			add(loc.Path)
		case loc.AccessPath != "":
			add(loc.AccessPath)
		}
	}
	return out
}

// findingVulnIDs returns every identifier a finding may be known by: its primary
// vulnerability ID plus all aliases. Used to join govulncheck's OSV/CVE/GHSA ids
// against our findings regardless of which id the canonical engine recorded.
func findingVulnIDs(f Finding) []string {
	ids := make([]string, 0, len(f.Aliases)+1)
	if f.VulnerabilityID != "" {
		ids = append(ids, f.VulnerabilityID)
	}
	ids = append(ids, f.Aliases...)
	return ids
}

func boolValue(b *bool) bool { return b != nil && *b }
