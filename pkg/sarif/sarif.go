// Package sarif converts Constellation findings to SARIF 2.1.0 JSON.
//
// SARIF (Static Analysis Results Interchange Format) is the OASIS standard supported by
// GitHub Code Scanning, Azure DevOps, Sonatype, Snyk, etc. Constellation emits SARIF for:
//
//   - constellationctl image-check --sarif <path>
//   - the GitHub Action / GitLab CI templates
//   - the /api/v1/findings.sarif export endpoint
//
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd02/sarif-v2.1.0-csprd02.html
package sarif

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/alphabravocompany/constellation/internal/scanner"
)

const (
	SchemaURI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
	Version   = "2.1.0"

	ToolName     = "Constellation"
	ToolURI      = "https://constellation.alphabravo.io"
	ToolFullName = "Constellation Container Security Platform"
)

// Doc is the root SARIF document.
type Doc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	FullName       string   `json:"fullName"`
	InformationURI string   `json:"informationUri"`
	Rules          []Rule   `json:"rules"`
}

type Rule struct {
	ID                   string                 `json:"id"`
	ShortDescription     Text                   `json:"shortDescription"`
	FullDescription      Text                   `json:"fullDescription"`
	HelpURI              string                 `json:"helpUri,omitempty"`
	DefaultConfiguration *RuleConfig            `json:"defaultConfiguration,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
}

type RuleConfig struct {
	Level string `json:"level"` // none|note|warning|error
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Text       `json:"message"`
	Locations []Location `json:"locations,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           *Region          `json:"region,omitempty"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine int `json:"startLine,omitempty"`
}

type Text struct {
	Text string `json:"text"`
}

// FromScanResult converts a scanner.ScanResult into a SARIF Doc. One rule per unique
// CVE (de-duplicating across packages) and one result per (CVE, package) pair.
func FromScanResult(version string, res *scanner.ScanResult) *Doc {
	rules := map[string]Rule{}
	results := make([]Result, 0, len(res.Findings))

	for _, f := range res.Findings {
		ruleID := f.VulnerabilityID
		if _, ok := rules[ruleID]; !ok {
			help := ""
			if len(f.References) > 0 {
				help = f.References[0]
			}
			rules[ruleID] = Rule{
				ID:               ruleID,
				ShortDescription: Text{Text: trim(f.Title, 240)},
				FullDescription:  Text{Text: trim(longest(f.Title, f.Description), 1200)},
				HelpURI:          help,
				DefaultConfiguration: &RuleConfig{
					Level: severityToLevel(f.Severity),
				},
				Properties: map[string]interface{}{
					"security-severity": fmt.Sprintf("%.1f", f.CVSSBase),
					"tags":              []string{"security", "vulnerability", f.Severity},
				},
			}
		}
		uri := fmt.Sprintf("pkg:%s/%s@%s", f.Package.Ecosystem, f.Package.Name, f.Package.Version)
		if f.Package.Purl != "" {
			uri = f.Package.Purl
		}
		msg := fmt.Sprintf("%s in %s %s", f.VulnerabilityID, f.Package.Name, f.Package.Version)
		if f.FixedVersion != "" {
			msg += fmt.Sprintf(" (fixed in %s)", f.FixedVersion)
		}
		results = append(results, Result{
			RuleID:  ruleID,
			Level:   severityToLevel(f.Severity),
			Message: Text{Text: msg},
			Locations: []Location{{
				PhysicalLocation: PhysicalLocation{
					ArtifactLocation: ArtifactLocation{URI: uri},
				},
			}},
			Properties: map[string]interface{}{
				"image":         res.ImageRef,
				"cvss_base":     f.CVSSBase,
				"kev_listed":    f.KEVListed,
				"epss":          f.EPSSProbability,
				"fixed_version": f.FixedVersion,
				"engines":       enginesToList(f.Engines),
			},
		})
	}

	// Sort rules for deterministic output (GitHub Code Scanning gets unhappy with non-stable ordering).
	ruleList := make([]Rule, 0, len(rules))
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	return &Doc{
		Schema:  SchemaURI,
		Version: Version,
		Runs: []Run{{
			Tool: Tool{Driver: Driver{
				Name:           ToolName,
				Version:        version,
				FullName:       ToolFullName,
				InformationURI: ToolURI,
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
}

// MarshalIndent serializes a Doc with deterministic 2-space indentation.
func MarshalIndent(d *Doc) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

func severityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	}
	return "none"
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func longest(a, b string) string {
	if len(b) > len(a) {
		return b
	}
	return a
}

func enginesToList(e []scanner.EngineProvenance) []string {
	names := make([]string, 0, len(e))
	for _, ep := range e {
		names = append(names, ep.Engine)
	}
	sort.Strings(names)
	return names
}
