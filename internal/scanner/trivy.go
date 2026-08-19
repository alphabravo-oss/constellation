package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TrivyEngine wraps the trivy CLI. Trivy is our secondary vulnerability matcher (paired
// with Grype) and a first-class IaC / secrets / misconfig engine.
type TrivyEngine struct {
	Binary string
}

func (t *TrivyEngine) Name() string { return "trivy" }

func (t *TrivyEngine) Scan(ctx context.Context, ref string, opts ScanOptions) (*EngineResult, error) {
	bin := t.Binary
	if bin == "" {
		bin = "trivy"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("trivy: binary not in PATH: %w", err)
	}

	start := time.Now()
	scanners := "vuln,secret"
	if opts.IncludeIaC {
		// `config` is Trivy's IaC / misconfiguration scanner (Dockerfile, k8s,
		// terraform, ...). Opt-in: only requested when ScanOptions.IncludeIaC is set.
		scanners = "vuln,secret,config"
	}
	args := []string{"image", "--format", "json", "--quiet", "--scanners", scanners}
	if opts.SBOMOnly {
		args = []string{"image", "--format", "cyclonedx", "--quiet"}
	}
	if opts.Insecure {
		args = append(args, "--insecure")
	}
	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}
	if scannerOfflineDB() {
		// Air-gapped: use only the pre-loaded local DB (operators mirror it, and
		// may point Trivy at an internal OCI registry via TRIVY_DB_REPOSITORY /
		// TRIVY_JAVA_DB_REPOSITORY, which Trivy reads from the environment).
		args = append(args, "--skip-db-update", "--skip-java-db-update")
	}
	args = append(args, ref)

	ctx, cancel := withTimeout(ctx, opts.Timeout, 10*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = registryEnv(opts)

	if err := cmd.Run(); err != nil {
		// Trivy returns nonzero when there are findings AND when there are errors; we treat
		// the JSON body as authoritative and only fail when JSON is missing.
		if len(stdout.Bytes()) == 0 {
			return nil, fmt.Errorf("trivy: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
		}
	}

	var doc trivyReport
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("trivy: decode JSON: %w", err)
	}

	findings := findingsFromTrivyReport(doc, t.Name())
	secrets := secretsFromTrivyReport(doc, t.Name())
	var misconfigs []MisconfigFinding
	if opts.IncludeIaC {
		misconfigs = misconfigsFromTrivyReport(doc, t.Name())
	}

	return &EngineResult{
		Engine:     t.Name(),
		ImageRef:   ref,
		Findings:   findings,
		Secrets:    secrets,
		Misconfigs: misconfigs,
		Confidence: 0.85,
		Duration:   time.Since(start),
	}, nil
}

func findingsFromTrivyReport(doc trivyReport, engineName string) []EngineFinding {
	if engineName == "" {
		engineName = "trivy"
	}
	findings := make([]EngineFinding, 0, 256)
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			refs := make([]string, 0, len(v.References)+1)
			if v.PrimaryURL != "" {
				refs = append(refs, v.PrimaryURL)
			}
			refs = append(refs, v.References...)

			ef := EngineFinding{
				Engine:          engineName,
				VulnerabilityID: v.VulnerabilityID,
				Severity:        strings.ToLower(v.Severity),
				CVSSBase:        pickCVSS(v.CVSS),
				CVSSVector:      pickVector(v.CVSS),
				Title:           firstNonEmpty(v.Title, v.VulnerabilityID),
				Description:     v.Description,
				References:      refs,
				Package: Package{
					Ecosystem: ecosystemFromTrivy(r.Type, r.Class),
					Name:      v.PkgName,
					Version:   v.InstalledVersion,
				},
				FixedVersion: v.FixedVersion,
				Published:    strings.TrimSpace(v.PublishedDate),
				Confidence:   0.85,
			}
			findings = append(findings, ef)
		}
	}
	return findings
}

func secretsFromTrivyReport(doc trivyReport, engineName string) []SecretFinding {
	if engineName == "" {
		engineName = "trivy"
	}
	secrets := make([]SecretFinding, 0, 32)
	for _, r := range doc.Results {
		target := strings.TrimSpace(r.Target)
		for _, s := range r.Secrets {
			match := strings.TrimSpace(s.Match)
			secrets = append(secrets, SecretFinding{
				Engine:        engineName,
				RuleID:        strings.TrimSpace(s.RuleID),
				Category:      strings.TrimSpace(s.Category),
				Severity:      strings.ToLower(strings.TrimSpace(s.Severity)),
				Title:         firstNonEmpty(strings.TrimSpace(s.Title), strings.TrimSpace(s.RuleID), "secret detected"),
				Target:        target,
				Path:          target,
				StartLine:     s.StartLine,
				EndLine:       s.EndLine,
				MatchSHA256:   secretMatchSHA256(match),
				MatchRedacted: redactSecretMatch(match),
			})
		}
	}
	return secrets
}

func misconfigsFromTrivyReport(doc trivyReport, engineName string) []MisconfigFinding {
	if engineName == "" {
		engineName = "trivy"
	}
	misconfigs := make([]MisconfigFinding, 0, 32)
	for _, r := range doc.Results {
		target := strings.TrimSpace(r.Target)
		for _, m := range r.Misconfigurations {
			// Only report actual failures; Trivy also emits PASS rows.
			if !strings.EqualFold(strings.TrimSpace(m.Status), "FAIL") {
				continue
			}
			ref := ""
			if len(m.References) > 0 {
				ref = m.References[0]
			}
			misconfigs = append(misconfigs, MisconfigFinding{
				Engine:      engineName,
				ID:          firstNonEmpty(strings.TrimSpace(m.AVDID), strings.TrimSpace(m.ID)),
				Severity:    strings.ToLower(strings.TrimSpace(m.Severity)),
				Title:       strings.TrimSpace(m.Title),
				Description: strings.TrimSpace(m.Description),
				Resolution:  strings.TrimSpace(m.Resolution),
				Target:      target,
				Type:        strings.ToLower(strings.TrimSpace(m.Type)),
				Message:     strings.TrimSpace(m.Message),
				Reference:   firstNonEmpty(strings.TrimSpace(m.PrimaryURL), strings.TrimSpace(ref)),
			})
		}
	}
	return misconfigs
}

// trivyReport captures the subset of trivy's JSON output we consume.
type trivyReport struct {
	ArtifactName string        `json:"ArtifactName"`
	ArtifactType string        `json:"ArtifactType"`
	Results      []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string               `json:"Target"`
	Class             string               `json:"Class"`
	Type              string               `json:"Type"`
	Vulnerabilities   []trivyVulnerability `json:"Vulnerabilities"`
	Secrets           []trivySecret        `json:"Secrets"`
	Misconfigurations []trivyMisconfig     `json:"Misconfigurations"`
}

type trivyMisconfig struct {
	ID          string   `json:"ID"`
	AVDID       string   `json:"AVDID"`
	Type        string   `json:"Type"`
	Title       string   `json:"Title"`
	Description string   `json:"Description"`
	Message     string   `json:"Message"`
	Resolution  string   `json:"Resolution"`
	Severity    string   `json:"Severity"`
	Status      string   `json:"Status"`
	PrimaryURL  string   `json:"PrimaryURL"`
	References  []string `json:"References"`
}

type trivyVulnerability struct {
	VulnerabilityID  string                    `json:"VulnerabilityID"`
	PkgName          string                    `json:"PkgName"`
	InstalledVersion string                    `json:"InstalledVersion"`
	FixedVersion     string                    `json:"FixedVersion"`
	Severity         string                    `json:"Severity"`
	Title            string                    `json:"Title"`
	Description      string                    `json:"Description"`
	PrimaryURL       string                    `json:"PrimaryURL"`
	References       []string                  `json:"References"`
	CVSS             map[string]trivyCVSSEntry `json:"CVSS"`
	// PublishedDate is the NVD/source disclosure date (RFC3339) trivy attaches to
	// the vulnerability; empty when trivy's DB has no publish date for it.
	PublishedDate string `json:"PublishedDate"`
}

type trivyCVSSEntry struct {
	V3Vector string  `json:"V3Vector,omitempty"`
	V3Score  float64 `json:"V3Score,omitempty"`
	V2Vector string  `json:"V2Vector,omitempty"`
	V2Score  float64 `json:"V2Score,omitempty"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
	Match     string `json:"Match"`
}

func pickCVSS(m map[string]trivyCVSSEntry) float64 {
	// Prefer NVD's CVSS v3; fall back to first available v3; then v2.
	if v, ok := m["nvd"]; ok && v.V3Score > 0 {
		return v.V3Score
	}
	for _, v := range m {
		if v.V3Score > 0 {
			return v.V3Score
		}
	}
	for _, v := range m {
		if v.V2Score > 0 {
			return v.V2Score
		}
	}
	return 0
}

func pickVector(m map[string]trivyCVSSEntry) string {
	if v, ok := m["nvd"]; ok && v.V3Vector != "" {
		return v.V3Vector
	}
	for _, v := range m {
		if v.V3Vector != "" {
			return v.V3Vector
		}
	}
	for _, v := range m {
		if v.V2Vector != "" {
			return v.V2Vector
		}
	}
	return ""
}

func ecosystemFromTrivy(typ, class string) string {
	if typ != "" {
		return strings.ToLower(typ)
	}
	return strings.ToLower(class)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func secretMatchSHA256(match string) string {
	if match == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(match))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func redactSecretMatch(match string) string {
	if match == "" {
		return ""
	}
	return fmt.Sprintf("[redacted:%d]", len(match))
}
