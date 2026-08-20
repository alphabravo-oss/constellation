package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// TrivyPackageMatcher matches an already-collected package inventory against
// Trivy's live vulnerability DB, mirroring GrypePackageMatcher. It gives the
// ScanPackages path (host / platform / node-local evidence scans — where there is
// no image to pull, so the Engines pipeline that runs the Trivy IMAGE scan never
// fires) a SECOND opinion: dedupe() merges Trivy's findings with Grype's by
// (cve, package), so a CVE both engines report is corroborated
// (engines=[grype,trivy]) and one only a single engine sees is still surfaced.
// Without this the node-local path ran Grype alone — every finding had one engine.
//
// It feeds Trivy the SAME synthesized CycloneDX SBOM the grype matcher builds
// (`trivy sbom`), so both match an identical package set — the only variable is
// each engine's advisory DB.
type TrivyPackageMatcher struct {
	Binary string
}

func (m *TrivyPackageMatcher) Name() string { return "trivy" }

func (m *TrivyPackageMatcher) MatchPackages(ctx context.Context, ref string, packages []Package, opts ScanOptions) (*EngineResult, error) {
	start := time.Now()
	bin := m.Binary
	if bin == "" {
		bin = "trivy"
	}
	if len(packages) == 0 {
		return &EngineResult{Engine: m.Name(), ImageRef: ref, Confidence: 0.85, Duration: time.Since(start)}, nil
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("trivy-matcher: binary not in PATH: %w", err)
	}

	sbom, err := cycloneDXFromPackages(packages)
	if err != nil {
		return nil, fmt.Errorf("trivy-matcher: build sbom: %w", err)
	}
	f, err := os.CreateTemp("", "constellation-trivy-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("trivy-matcher: temp file: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(sbom); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("trivy-matcher: write sbom: %w", err)
	}
	_ = f.Close()

	ctx, cancel := withTimeout(ctx, opts.Timeout, 10*time.Minute)
	defer cancel()

	args := []string{"sbom", "--format", "json", "--quiet", "--scanners", "vuln"}
	if scannerOfflineDB() {
		args = append(args, "--skip-db-update", "--skip-java-db-update")
	}
	args = append(args, f.Name())

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = registryEnv(opts)
	if err := cmd.Run(); err != nil {
		// Trivy exits nonzero when findings exist AND on error; the JSON body is
		// authoritative — only fail when it produced none.
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("trivy-matcher: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
		}
	}

	var doc trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("trivy-matcher: decode JSON: %w", err)
	}
	findings := findingsFromTrivyReport(doc, m.Name())
	return &EngineResult{
		Engine:     m.Name(),
		ImageRef:   ref,
		Findings:   findings,
		Confidence: 0.85,
		Raw:        stdout.Bytes(),
		Duration:   time.Since(start),
	}, nil
}
