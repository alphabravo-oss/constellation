package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// GrypeEngine wraps the grype CLI. Grype is our reconciliation engine — when Trivy and
// Grype agree on a (CVE, pkg) pair the confidence boosts to ~0.95; disagreement drops the
// finding's overall confidence and is preserved in the audit payload.
type GrypeEngine struct {
	Binary string
}

func (g *GrypeEngine) Name() string { return "grype" }

func (g *GrypeEngine) Scan(ctx context.Context, ref string, opts ScanOptions) (*EngineResult, error) {
	bin := g.Binary
	if bin == "" {
		bin = "grype"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("grype: binary not in PATH: %w", err)
	}

	start := time.Now()
	args := []string{ref, "-o", "json", "-q"}
	if opts.Platform != "" {
		args = append(args, "--platform", opts.Platform)
	}

	ctx, cancel := withTimeout(ctx, opts.Timeout, 10*time.Minute)
	defer cancel()

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Env = grypeEnv(opts)

	if err := cmd.Run(); err != nil {
		if len(stdout.Bytes()) == 0 {
			return nil, fmt.Errorf("grype: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
		}
	}

	var doc grypeReport
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		return nil, fmt.Errorf("grype: decode JSON: %w", err)
	}

	findings := findingsFromGrypeReport(doc, g.Name())

	return &EngineResult{
		Engine:     g.Name(),
		ImageRef:   ref,
		Findings:   findings,
		Confidence: 0.85,
		Raw:        stdout.Bytes(),
		Duration:   time.Since(start),
	}, nil
}

func findingsFromGrypeReport(doc grypeReport, engineName string) []EngineFinding {
	if engineName == "" {
		engineName = "grype"
	}
	findings := make([]EngineFinding, 0, len(doc.Matches))
	for _, m := range doc.Matches {
		urls := make([]string, 0, len(m.Vulnerability.URLs)+1)
		if m.Vulnerability.DataSource != "" {
			urls = append(urls, m.Vulnerability.DataSource)
		}
		urls = append(urls, m.Vulnerability.URLs...)

		ef := EngineFinding{
			Engine:          engineName,
			VulnerabilityID: m.Vulnerability.ID,
			Aliases:         grypeAliases(m.Vulnerability.ID, m.RelatedVulnerabilities),
			Severity:        strings.ToLower(m.Vulnerability.Severity),
			Title:           firstNonEmpty(m.Vulnerability.Description, m.Vulnerability.ID),
			Description:     m.Vulnerability.Description,
			References:      urls,
			Package: Package{
				Ecosystem: strings.ToLower(m.Artifact.Type),
				Name:      m.Artifact.Name,
				Version:   m.Artifact.Version,
				Purl:      m.Artifact.PURL,
			},
			FixedVersion: firstFixed(m.Vulnerability.Fix.Versions),
			Published:    strings.TrimSpace(m.Vulnerability.Published),
			Confidence:   0.85,
		}
		// Keep the matched advisory scoring. Related identities inform deduplication,
		// without replacing this advisory's vulnerability fields.
		if len(m.Vulnerability.CVSS) > 0 {
			ef.CVSSBase, ef.CVSSVector = bestCVSS(m.Vulnerability.CVSS)
		}
		findings = append(findings, ef)
	}
	return findings
}

type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability          grypeVuln     `json:"vulnerability"`
	Artifact               grypeArtifact `json:"artifact"`
	RelatedVulnerabilities []grypeVuln   `json:"relatedVulnerabilities"`
}

var grypeAliasID = regexp.MustCompile(`^(CVE-[0-9]{4}-[0-9]{4,}|GO-[0-9]{4}-[0-9]+|GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})$`)

// Grype exposes database aliases and package CVE identities here. Only accept
// individual vulnerability identities here: vendor advisories can group multiple
// CVEs, and must not turn distinct vulnerabilities into one finding.
func grypeAliases(primary string, related []grypeVuln) []string {
	primary = strings.ToUpper(strings.TrimSpace(primary))
	if !grypeAliasID.MatchString(primary) {
		return nil
	}
	ids := []string{primary}
	for _, item := range related {
		id := strings.ToUpper(strings.TrimSpace(item.ID))
		if grypeAliasID.MatchString(id) {
			ids = mergeStrings(ids, []string{id})
		}
	}
	families := map[string]string{}
	for _, id := range ids {
		family, _, _ := strings.Cut(id, "-")
		if previous, exists := families[family]; exists && previous != id {
			return nil
		}
		families[family] = id
	}
	return ids[1:]
}

type grypeVuln struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
	URLs        []string    `json:"urls"`
	DataSource  string      `json:"dataSource"`
	CVSS        []grypeCVSS `json:"cvss"`
	Fix         grypeFix    `json:"fix"`
	// Published is the disclosure date carried in grype's vulnerability metadata.
	// Not every namespace/DB build populates it; left empty when absent.
	Published string `json:"published"`
}

type grypeCVSS struct {
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics grypeCVSSMetrics `json:"metrics"`
}

type grypeCVSSMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl"`
}

func firstFixed(versions []string) string {
	for _, v := range versions {
		if v != "" {
			return v
		}
	}
	return ""
}

func bestCVSS(scores []grypeCVSS) (float64, string) {
	bestScore := 0.0
	bestVector := ""
	for _, s := range scores {
		if s.Metrics.BaseScore > bestScore {
			bestScore = s.Metrics.BaseScore
			bestVector = s.Vector
		}
	}
	return bestScore, bestVector
}
