package compliance

// kube-bench JSON parser.
//
// kube-bench emits this shape (simplified):
//
//	{
//	  "Controls": [
//	    {"id":"1","text":"Master Node","tests":[
//	      {"section":"1.2","tests":[
//	        {"results":[{"test_number":"1.2.22","test_desc":"...","status":"FAIL","actual_value":"...","scored":true}]}
//	      ]}
//	    ]}
//	  ]
//	}
//
// We flatten to a slice of Check rows, one per (control_id, status), and use the kube-bench
// test_number as the CIS K8s control_id. The same row also expands into any cross-framework
// mappings declared in CoreMappings (if we have one indexed by internal-id "cis-k8s/<id>").

import (
	"encoding/json"
	"fmt"
	"strings"
)

// kbReport is the (partial) shape kube-bench emits.
type kbReport struct {
	Controls []struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Text    string `json:"text"`
		Tests   []struct {
			Section string `json:"section"`
			Desc    string `json:"desc"`
			Tests   []struct {
				Results []kbResult `json:"results"`
			} `json:"tests"`
			Results []kbResult `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
}

type kbResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Status      string `json:"status"`        // PASS | FAIL | WARN | INFO
	ActualValue string `json:"actual_value"`
	Scored      bool   `json:"scored"`
	Remediation string `json:"remediation"`
}

// ParseKubeBench turns kube-bench JSON into Constellation Check rows.
// Rows are tagged with the CIS profile version carried in the report (per-control
// version field, e.g. "eks-1.4.0" -> "cis-eks-1.4.0"), falling back to
// FrameworkCISK8s when absent. Cross-framework expansion happens via
// IngestKubeBench when the test_number matches a CoreMappings entry.
func ParseKubeBench(b []byte) ([]Check, error) {
	var doc kbReport
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("kube-bench parse: %w", err)
	}
	out := []Check{}
	for _, c := range doc.Controls {
		// kube-bench reports the benchmark id per Control (e.g. "cis-1.9",
		// "eks-1.4.0"). Each control's results inherit that profile so a mixed
		// report (master + node + managed addons) keeps the right framework tag.
		fw := normalizeBenchmarkFramework(c.Version)
		for _, section := range c.Tests {
			// kube-bench's schema is inconsistent — older versions put results at the section
			// level, newer ones nest one level deeper. We walk both layouts.
			for _, r := range section.Results {
				out = append(out, kbResultToCheck(r, fw))
			}
			for _, nested := range section.Tests {
				for _, r := range nested.Results {
					out = append(out, kbResultToCheck(r, fw))
				}
			}
		}
	}
	return out, nil
}

// IngestKubeBench parses + cross-framework-expands the kube-bench output. Returns the
// flattened set of compliance rows ready for COPY into compliance_checks.
func IngestKubeBench(b []byte) ([]Check, error) {
	return IngestKubeBenchProfile(b, "")
}

// IngestKubeBenchProfile is IngestKubeBench with an explicit benchmark-id override
// (e.g. from the runner's BENCH_VERSION / ?benchmark= query). When override is
// non-empty it wins over the per-control version in the report — useful when the
// report omits a benchmark id but the runner knows the distro it scanned. Empty
// override preserves the report-derived (and ultimately cis-k8s-1.9) tagging.
func IngestKubeBenchProfile(b []byte, override string) ([]Check, error) {
	checks, err := ParseKubeBench(b)
	if err != nil {
		return nil, err
	}
	if fw := normalizeBenchmarkOverride(override); fw != "" {
		for i := range checks {
			checks[i].Framework = fw
		}
	}
	out := make([]Check, 0, len(checks)*2)
	out = append(out, checks...)

	// Expand into cross-framework rows whenever the kube-bench test_number matches an
	// internal-id we've mapped. We look up by "k8s.<cleaned-test-number>" — admins can
	// extend the mapping table without recompiling.
	for _, ck := range checks {
		internal := internalIDForKBControl(ck.ControlID)
		if internal == "" {
			continue
		}
		evidence := ck.Evidence
		expanded := ExpandInternal(internal, ck.Status, evidence)
		// Skip the entry already in framework=FrameworkCISK8s (would duplicate).
		for _, e := range expanded {
			if e.Framework == FrameworkCISK8s {
				continue
			}
			out = append(out, e)
		}
	}
	return out, nil
}

func kbResultToCheck(r kbResult, framework string) Check {
	status := strings.ToLower(r.Status)
	switch status {
	case "pass":
	case "fail":
	case "warn":
		status = "manual"
	case "info":
		status = "not_applicable"
	default:
		status = "manual"
	}
	return Check{
		Framework: framework,
		ControlID: r.TestNumber,
		Title:     r.TestDesc,
		Status:    status,
		Severity:  severityForKBNumber(r.TestNumber),
		Evidence:  strings.TrimSpace(r.ActualValue),
	}
}

// normalizeBenchmarkFramework maps a kube-bench benchmark id (the per-Control
// "version" field) to a Constellation framework id. kube-bench reports ids like
// "cis-1.9", "eks-1.4.0", "gke-1.6.0", "aks-1.4.0", "k3s-cis-1.24", "rke2-cis-1.24".
// We normalize to a "cis-<distro>-<ver>" / "cis-k8s-<ver>" shape (matching
// NeuVector's cis-eks-1.4.0 / cis-gke-1.4.0 naming) and fall back to
// FrameworkCISK8s when the report carries no benchmark id (preserves prior
// behavior).
//
// ponytail: string-prefix mapping rather than a benchmark registry. Upgrade path
// is a lookup table / Framework descriptors per managed distro once the UI needs
// human names for each profile.
func normalizeBenchmarkFramework(version string) string {
	v := strings.ToLower(strings.TrimSpace(version))
	if v == "" {
		return FrameworkCISK8s
	}
	// Vanilla kube CIS reports as "cis-<ver>" (e.g. "cis-1.9", "cis-1.24").
	// Tag it as the canonical cis-k8s-<ver> so it lines up with FrameworkCISK8s.
	if rest := strings.TrimPrefix(v, "cis-"); rest != v {
		if isVersionToken(rest) {
			return "cis-k8s-" + rest
		}
		// e.g. "cis-eks-1.4.0" -> fall through with the cis- prefix stripped.
		v = rest
	}
	// Managed/distro benchmarks: eks-1.4.0, gke-1.6.0, aks-1.4.0, k3s-cis-1.24...
	return "cis-" + v
}

// normalizeBenchmarkOverride normalizes an explicit benchmark id (from the
// runner/query). Empty stays empty so callers treat it as "no override".
func normalizeBenchmarkOverride(override string) string {
	if strings.TrimSpace(override) == "" {
		return ""
	}
	return normalizeBenchmarkFramework(override)
}

// isVersionToken reports whether s looks like a bare version (digits and dots),
// i.e. the part after "cis-" is a version rather than a distro name.
func isVersionToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// severityForKBNumber maps the test number prefix to a severity. We tier:
//   1.1.x — control plane file perms          -> medium
//   1.2.x — API server flags                  -> high
//   1.3.x — controller-manager flags          -> high
//   1.4.x — scheduler flags                   -> medium
//   2.x   — etcd                              -> high
//   3.x   — control-plane configuration       -> high
//   4.x   — worker node                       -> medium
//   5.x   — policies (PSP/PSA/RBAC)           -> high
func severityForKBNumber(s string) string {
	if strings.HasPrefix(s, "1.2.") ||
		strings.HasPrefix(s, "1.3.") ||
		strings.HasPrefix(s, "2.") ||
		strings.HasPrefix(s, "3.") ||
		strings.HasPrefix(s, "5.") {
		return "high"
	}
	return "medium"
}

// internalIDForKBControl returns the Constellation internal-id matching a kube-bench
// control number, or empty if we don't have a cross-framework mapping. It is driven
// by the CoreMappings reverse index (frameworks.go), so the CIS K8s -> internal-id
// wiring lives in data: add a mapping there and the expansion follows automatically.
func internalIDForKBControl(id string) string {
	return InternalIDForCISK8s(id)
}
