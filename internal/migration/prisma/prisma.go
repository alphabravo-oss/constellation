// Package prisma migrates a Palo Alto Prisma Cloud policy export (formerly Twistlock).
//
// Prisma exposes policies via /api/v1/policies. Compliance policies, runtime policies,
// and CNAPP rules each have their own shape. The simplest export is the compliance JSON
// dump, which we accept here. Other shapes will be added iteratively.
package prisma

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
	ID             string   `json:"policyId"`
	Name           string   `json:"name"`
	Type           string   `json:"policyType"` // config | network | iam | audit_event | data
	Severity       string   `json:"severity"`
	Enabled        bool     `json:"enabled"`
	Description    string   `json:"description"`
	Labels         []string `json:"labels"`
	ComplianceMeta []struct {
		StandardName string `json:"standardName"`
		SectionID    string `json:"sectionId"`
	} `json:"complianceMetadata"`
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

func Convert(raw []byte) ([]TargetPolicy, error) {
	if len(raw) == 0 {
		return nil, errors.New("prisma: empty export")
	}
	var doc SourceExport
	if err := json.Unmarshal(raw, &doc); err == nil && doc.Policies != nil {
		return convertAll(doc.Policies), nil
	}
	var arr []Policy
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil, fmt.Errorf("prisma: decode: %w", err)
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
	if strings.EqualFold(p.Severity, "high") || strings.EqualFold(p.Severity, "critical") {
		mode = "enforce"
	}
	frameworks := []string{}
	for _, c := range p.ComplianceMeta {
		frameworks = append(frameworks, c.StandardName+":"+c.SectionID)
	}
	return TargetPolicy{
		Name:        fmt.Sprintf("prisma-%s", slug(p.ID)),
		Description: p.Description,
		Engine:      "constellation-builtin",
		Category:    strings.ToLower(p.Type),
		Enabled:     p.Enabled,
		Mode:        mode,
		SpecYAML:    emitYAML(p, frameworks),
		Imported: map[string]string{
			"source":    "prisma",
			"source_id": p.ID,
			"name":      p.Name,
		},
	}
}

func emitYAML(p Policy, frameworks []string) string {
	return fmt.Sprintf(`apiVersion: constellation.alphabravo.io/v1
kind: BuiltinRule
metadata:
  name: prisma-%s
  imported.from: prisma
  imported.id: "%s"
spec:
  kind: %s
  severity: %s
  frameworks: [%s]
  labels: [%s]
`, slug(p.ID), p.ID, strings.ToLower(p.Type), p.Severity,
		strings.Join(frameworks, ", "), strings.Join(p.Labels, ", "))
}

func slug(s string) string {
	out := make([]byte, 0, len(s))
	prev := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			out = append(out, c)
			prev = false
		} else if c >= 'A' && c <= 'Z' {
			out = append(out, c+32)
			prev = false
		} else if !prev {
			out = append(out, '-')
			prev = true
		}
	}
	return strings.Trim(string(out), "-")
}
