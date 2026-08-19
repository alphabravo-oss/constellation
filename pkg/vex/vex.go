// Package vex emits Vulnerability-Exploitability eXchange statements in two formats:
//
//	OpenVEX 0.2.0       — https://openvex.dev/
//	CycloneDX 1.6 VEX   — CycloneDX subset with "vulnerabilities" + analysis state
//
// VEX is the standardized way to say "this CVE is in our SBOM but doesn't affect us
// because <reason>". Customers ship VEX alongside their SBOM so downstream consumers
// (and security scanners) can suppress noise that the producer has already triaged.
//
// Source of truth: Constellation's finding lifecycle.
//   open / triaged / in_progress  →  under_investigation
//   resolved                       →  fixed
//   suppressed                     →  not_affected (with justification)
//   accepted                       →  not_affected (with rationale)
//
// Output is stable JSON so downstream consumers can byte-compare across publications.
package vex

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Finding is the slice of Constellation's Finding shape this package needs. Keeping the
// dep surface narrow so pkg/vex doesn't import internal/scanner or the DB layer.
type Finding struct {
	VulnerabilityID string
	Lifecycle       string // open|triaged|in_progress|resolved|suppressed|accepted
	Rationale       string
	Approver        string
	Product         string // PURL or image ref
	Severity        string
	UpdatedAt       time.Time
}

// OpenVEX builds an OpenVEX 0.2.0 document from a slice of findings.
//
// Spec: https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md
func OpenVEX(author string, findings []Finding) map[string]interface{} {
	stmts := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		status, justification, response := lifecycleToOpenVEX(f.Lifecycle)
		stmt := map[string]interface{}{
			"vulnerability": map[string]string{
				"@id":  vulnURI(f.VulnerabilityID),
				"name": f.VulnerabilityID,
			},
			"products":  []map[string]string{{"@id": f.Product}},
			"status":    status,
			"timestamp": f.UpdatedAt.UTC().Format(time.RFC3339),
		}
		if justification != "" {
			stmt["justification"] = justification
		}
		if response != "" {
			stmt["impact_statement"] = response
		}
		if f.Rationale != "" {
			stmt["status_notes"] = f.Rationale
		}
		stmts = append(stmts, stmt)
	}

	now := time.Now().UTC()
	id := "https://openvex.dev/docs/constellation-" + sha1Short(author+now.Format(time.RFC3339))
	return map[string]interface{}{
		"@context":     "https://openvex.dev/ns/v0.2.0",
		"@id":          id,
		"author":       author,
		"role":         "Project Maintainer",
		"timestamp":    now.Format(time.RFC3339),
		"version":      1,
		"statements":   stmts,
		"tooling":      "Constellation OpenVEX emitter",
	}
}

// CycloneDXVEX builds a CycloneDX 1.6 VEX document. We use the "vulnerabilities-only"
// flavor — no components/services section — since the SBOM endpoint emits those
// separately. Consumers stitch the two together via the bom-ref.
//
// Spec: https://cyclonedx.org/docs/1.6/json/#vulnerabilities
func CycloneDXVEX(author string, findings []Finding) map[string]interface{} {
	vulns := make([]map[string]interface{}, 0, len(findings))
	for _, f := range findings {
		state, justification, response := lifecycleToCycloneDX(f.Lifecycle)
		v := map[string]interface{}{
			"id": f.VulnerabilityID,
			"source": map[string]string{
				"name": "Constellation Aggregator",
			},
			"updated": f.UpdatedAt.UTC().Format(time.RFC3339),
			"analysis": map[string]interface{}{
				"state":         state,
				"justification": justification,
				"response":      response,
				"detail":        f.Rationale,
			},
			"affects": []map[string]interface{}{{"ref": f.Product}},
		}
		if f.Approver != "" {
			v["credits"] = map[string]interface{}{
				"individuals": []map[string]string{{"name": f.Approver}},
			}
		}
		vulns = append(vulns, v)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	return map[string]interface{}{
		"$schema":      "http://cyclonedx.org/schema/bom-1.6.schema.json",
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"version":      1,
		"serialNumber": "urn:uuid:" + uuidV4(),
		"metadata": map[string]interface{}{
			"timestamp": now,
			"tools": []map[string]string{{"name": "Constellation", "vendor": "AlphaBravo"}},
			"authors": []map[string]string{{"name": author}},
		},
		"vulnerabilities": vulns,
	}
}

// lifecycleToOpenVEX maps Constellation lifecycle states to OpenVEX status + justification.
func lifecycleToOpenVEX(lifecycle string) (status, justification, response string) {
	switch strings.ToLower(lifecycle) {
	case "open", "triaged", "in_progress":
		return "under_investigation", "", ""
	case "resolved":
		return "fixed", "", "Patch deployed; finding closed."
	case "suppressed":
		return "not_affected", "vulnerable_code_not_in_execute_path", "Constellation marked as not exploitable in this product."
	case "accepted":
		return "affected", "", "Risk explicitly accepted by approver; mitigated by compensating controls."
	}
	return "under_investigation", "", ""
}

// lifecycleToCycloneDX maps to CycloneDX 1.6 analysis.state values.
func lifecycleToCycloneDX(lifecycle string) (state, justification, response string) {
	switch strings.ToLower(lifecycle) {
	case "open", "triaged", "in_progress":
		return "in_triage", "", ""
	case "resolved":
		return "resolved", "", "update"
	case "suppressed":
		return "not_affected", "code_not_present", "will_not_fix"
	case "accepted":
		return "exploitable", "", "rollback"
	}
	return "in_triage", "", ""
}

// vulnURI returns the canonical URI for a vulnerability id.
func vulnURI(id string) string {
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "https://nvd.nist.gov/vuln/detail/" + id
	case strings.HasPrefix(id, "GHSA-"):
		return "https://github.com/advisories/" + id
	case strings.HasPrefix(id, "GO-"):
		return "https://pkg.go.dev/vuln/" + id
	}
	return id
}

func sha1Short(s string) string {
	h := sha1.Sum([]byte(s))
	return hex.EncodeToString(h[:6])
}

// uuidV4 is a tiny UUID-shaped string for the CycloneDX serialNumber field — same approach
// as pkg/sbom (no crypto guarantee needed, just uniqueness).
func uuidV4() string {
	h := sha1.Sum([]byte(fmt.Sprintf("%d-vex", time.Now().UnixNano())))
	hex := hex.EncodeToString(h[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex[0:8], hex[8:12], "4"+hex[13:16], "8"+hex[17:20], hex[20:32])
}

// SortByCVE makes the output stable across publications (byte-comparable releases).
func SortByCVE(in []Finding) []Finding {
	out := append([]Finding(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].VulnerabilityID < out[j].VulnerabilityID })
	return out
}
