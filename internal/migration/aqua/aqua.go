// Package aqua migrates an Aqua Security policy export.
//
// Aqua's REST API at /api/v2/policies returns Image Assurance Policies. Each carries a
// `policy_settings` block with control checks (e.g. block-high-cve, scan-coverage).
// We translate each control into a Constellation TargetPolicy with engine=
// constellation-builtin (the controls map to our scanner findings + admission engine).
package aqua

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type SourceExport struct {
	Policies []Policy `json:"policies"`
}

type Policy struct {
	ID            int            `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	Enabled       bool           `json:"enabled"`
	FailCICDOn    bool           `json:"fail_cicd_on"`
	BlockOn       []string       `json:"block_on"`
	Controls      PolicyControls `json:"controls"`
}

type PolicyControls struct {
	BlockHighVulns        bool `json:"block_high_vulns"`
	BlockCritical         bool `json:"block_critical_vulns"`
	ScanCoverage          int  `json:"scan_coverage_pct"`
	RequireMalwareScan    bool `json:"require_malware_scan"`
	RequireSensitiveData  bool `json:"require_sensitive_data_scan"`
}

type TargetPolicy struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Engine      string            `json:"engine"`
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	Mode        string            `json:"mode"`
	SpecYAML    string            `json:"spec_yaml"`
	Imported    map[string]string `json:"imported_from,omitempty"`
}

// Convert decodes an Aqua export and returns Constellation policies.
func Convert(raw []byte) ([]TargetPolicy, error) {
	if len(raw) == 0 {
		return nil, errors.New("aqua: empty export")
	}
	// Aqua exports as either {"policies":[...]} or top-level array.
	var doc SourceExport
	if err := json.Unmarshal(raw, &doc); err == nil && doc.Policies != nil {
		return convertAll(doc.Policies), nil
	}
	var arr []Policy
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("aqua: decode: %w", err)
	}
	return convertAll(arr), nil
}

func convertAll(in []Policy) []TargetPolicy {
	out := make([]TargetPolicy, 0, len(in))
	for _, p := range in {
		out = append(out, translate(p))
	}
	return out
}

func translate(p Policy) TargetPolicy {
	mode := "monitor"
	if p.FailCICDOn || (p.Controls.BlockCritical || p.Controls.BlockHighVulns) {
		mode = "enforce"
	}
	desc := []string{}
	if p.Controls.BlockCritical {
		desc = append(desc, "block on critical CVEs")
	}
	if p.Controls.BlockHighVulns {
		desc = append(desc, "block on high CVEs")
	}
	if p.Controls.RequireMalwareScan {
		desc = append(desc, "require malware scan")
	}
	if p.Controls.RequireSensitiveData {
		desc = append(desc, "require sensitive-data scan")
	}
	full := p.Description
	if len(desc) > 0 {
		full = full + " (" + strings.Join(desc, ", ") + ")"
	}
	return TargetPolicy{
		Name:        fmt.Sprintf("aqua-%d", p.ID),
		Description: full,
		Engine:      "constellation-builtin",
		Category:    "image-assurance",
		Enabled:     p.Enabled,
		Mode:        mode,
		SpecYAML:    emitYAML(p),
		Imported:    map[string]string{"source": "aqua", "source_id": fmt.Sprintf("%d", p.ID)},
	}
}

func emitYAML(p Policy) string {
	return fmt.Sprintf(`apiVersion: constellation.alphabravo.io/v1
kind: BuiltinRule
metadata:
  name: aqua-%d
  imported.from: aqua
  imported.id: "%d"
spec:
  kind: scan-finding-policy
  block_high_vulns: %v
  block_critical: %v
  require_malware_scan: %v
  scan_coverage_pct: %d
`, p.ID, p.ID, p.Controls.BlockHighVulns, p.Controls.BlockCritical,
		p.Controls.RequireMalwareScan, p.Controls.ScanCoverage)
}
