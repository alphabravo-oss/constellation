// Package reachability implements static call-graph reachability analysis for the spec's
// FR-7 ("static analysis Go/Java/Python + runtime confirmation").
//
// Go reachability uses govulncheck in "source" mode — it constructs the import + call
// graph from the source modules and reports, per vuln, the call stack from package main
// down to the vuln symbol. We parse the OSV-flavored JSON output and produce
// ReachabilityVerdict per vulnerability.
//
// Java + Python reachability are queued (WALA / CodeQL / Jedi / Pyre — decided at P2 start
// per spec Open Questions section). The shape of the Verdict here is engine-agnostic so
// adding a `Verdict` from java/, python/ converges through the same risk-score boost.
package reachability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Verdict is one (module, vulnerability) reachability result.
type Verdict struct {
	// VulnerabilityID is the canonical id, e.g. CVE-2024-0001 or GHSA-….
	VulnerabilityID string `json:"vulnerability_id"`

	// Reachable is true when at least one source-call stack reaches the vuln symbol.
	Reachable bool `json:"reachable"`

	// Confidence is 1.0 when govulncheck reports a call stack, 0.5 when only an import
	// is detected (vuln symbol present but no observed call), 0 when the module imports
	// the dep transitively but no use is detected.
	Confidence float64 `json:"confidence"`

	// CallStack is the package.func chain reaching the vuln symbol. Empty for
	// import-only matches.
	CallStack []string `json:"call_stack,omitempty"`

	// Symbol is the vuln's `package.SymbolName` (e.g. "crypto/x509.Verify").
	Symbol string `json:"symbol,omitempty"`

	// Module is the dependency module path (e.g. "golang.org/x/net").
	Module string `json:"module,omitempty"`
}

// AnalyzeGo runs govulncheck against the Go module at modulePath and returns per-CVE
// reachability verdicts. modulePath is a filesystem directory containing go.mod (NOT a
// pre-built binary; we use -mode source to get reachability info).
func AnalyzeGo(ctx context.Context, modulePath string) ([]Verdict, error) {
	bin, err := exec.LookPath("govulncheck")
	if err != nil {
		return nil, fmt.Errorf("reachability: govulncheck not on PATH (install: go install golang.org/x/vuln/cmd/govulncheck@latest)")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, "-json", "-mode", "source", "./...")
	cmd.Dir = modulePath
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// govulncheck returns 3 when vulns are found, 0 when clean. Both are "success" for us.
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			// Exit code 3 = "vulnerabilities found"; that's not an error here.
			if exitErr.ExitCode() != 3 {
				return nil, fmt.Errorf("reachability: govulncheck: %w (stderr=%s)", err,
					strings.TrimSpace(stderr.String()))
			}
		} else {
			return nil, fmt.Errorf("reachability: govulncheck: %w", err)
		}
	}

	verdicts, err := parseGovulncheckJSON(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	return verdicts, nil
}

// parseGovulncheckJSON walks the streamed govulncheck JSON-Lines output.
//
// govulncheck emits a stream of typed messages; the two we care about are:
//
//	{"finding":{"osv":"GO-2024-…","trace":[{"function":"…","package":"…"}]}, ...}
//	{"osv":{"id":"GO-2024-…","aliases":["CVE-2024-…"], "affected":[{"package":{"name":"…"}}]}}
//
// Findings with a `trace` element carry a call stack → reachable. Findings without trace
// but matching the same OSV id mean "imported but not called" → not reachable.
func parseGovulncheckJSON(b []byte) ([]Verdict, error) {
	dec := json.NewDecoder(bytes.NewReader(b))

	osvByID := map[string]osvRecord{}
	traces := map[string][]string{}       // OSV id -> first call stack
	importsByOSV := map[string]struct{}{} // OSV ids that show up in any finding

	for dec.More() {
		var msg govulnMessage
		if err := dec.Decode(&msg); err != nil {
			return nil, fmt.Errorf("reachability: decode govulncheck json: %w", err)
		}
		if msg.OSV != nil {
			osvByID[msg.OSV.ID] = *msg.OSV
		}
		if msg.Finding != nil {
			importsByOSV[msg.Finding.OSV] = struct{}{}
			if len(msg.Finding.Trace) > 0 {
				stack := make([]string, 0, len(msg.Finding.Trace))
				for _, f := range msg.Finding.Trace {
					if f.Function != "" {
						stack = append(stack, f.Package+"."+f.Function)
					}
				}
				if _, ok := traces[msg.Finding.OSV]; !ok && len(stack) > 0 {
					traces[msg.Finding.OSV] = stack
				}
			}
		}
	}

	out := []Verdict{}
	for osvID := range importsByOSV {
		osv := osvByID[osvID]
		cve := pickCVE(osv.Aliases, osvID)
		v := Verdict{VulnerabilityID: cve, Symbol: pickSymbol(osv), Module: pickModule(osv)}
		if stack, ok := traces[osvID]; ok {
			v.Reachable = true
			v.Confidence = 1.0
			v.CallStack = stack
		} else {
			v.Reachable = false
			v.Confidence = 0.5
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VulnerabilityID < out[j].VulnerabilityID })
	return out, nil
}

// pickCVE prefers a CVE alias when present.
func pickCVE(aliases []string, fallback string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	if len(aliases) > 0 {
		return aliases[0]
	}
	return fallback
}

func pickSymbol(o osvRecord) string {
	for _, a := range o.Affected {
		for _, im := range a.EcosystemSpecific.Imports {
			for _, sym := range im.Symbols {
				return im.Path + "." + sym
			}
		}
	}
	return ""
}

func pickModule(o osvRecord) string {
	for _, a := range o.Affected {
		if a.Package.Name != "" {
			return a.Package.Name
		}
	}
	return ""
}

// MergeIntoFindings annotates an existing finding map (keyed by CVE id) with reachability
// info: callers can do this after a normal scan to light up the risk-score reachability
// boost without re-running govulncheck.
//
// Returns the count of findings annotated.
func MergeIntoFindings(verdicts []Verdict, set func(cve string, v Verdict)) int {
	n := 0
	for _, v := range verdicts {
		set(v.VulnerabilityID, v)
		n++
	}
	return n
}

// ErrNoModule is returned when AnalyzeGo is called against a path that's not a Go module.
var ErrNoModule = errors.New("reachability: path is not a Go module (no go.mod)")

// govulncheck JSON message envelope.
type govulnMessage struct {
	OSV     *osvRecord     `json:"osv,omitempty"`
	Finding *govulnFinding `json:"finding,omitempty"`
}

type govulnFinding struct {
	OSV   string         `json:"osv"`
	Trace []govulnFrame  `json:"trace"`
}

type govulnFrame struct {
	Function string `json:"function"`
	Package  string `json:"package"`
	Module   string `json:"module"`
}

type osvRecord struct {
	ID       string         `json:"id"`
	Aliases  []string       `json:"aliases"`
	Affected []osvAffected  `json:"affected"`
}

type osvAffected struct {
	Package           osvPackage           `json:"package"`
	EcosystemSpecific osvEcosystemSpecific `json:"ecosystem_specific"`
}

type osvPackage struct {
	Name string `json:"name"`
}

type osvEcosystemSpecific struct {
	Imports []osvImport `json:"imports"`
}

type osvImport struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}
