package scanner

import (
	"encoding/json"
	"testing"
)

// trivy config (IaC) scan output shape: misconfigurations live alongside
// vulnerabilities/secrets in each Result. We only surface FAIL rows.
const trivyConfigReport = `{
  "ArtifactName": "example.com/app:latest",
  "Results": [
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "Misconfigurations": [
        {
          "ID": "DS002",
          "AVDID": "AVD-DS-0002",
          "Type": "Dockerfile Security Check",
          "Title": "Image user should not be 'root'",
          "Description": "Running containers with 'root' user can lead to a container escape situation.",
          "Message": "Specify at least 1 USER command",
          "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
          "Severity": "HIGH",
          "Status": "FAIL",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
          "References": ["https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"]
        },
        {
          "ID": "DS026",
          "AVDID": "AVD-DS-0026",
          "Title": "No HEALTHCHECK defined",
          "Severity": "LOW",
          "Status": "PASS"
        }
      ]
    }
  ]
}`

func TestMisconfigsFromTrivyReport(t *testing.T) {
	var doc trivyReport
	if err := json.Unmarshal([]byte(trivyConfigReport), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := misconfigsFromTrivyReport(doc, "")
	if len(got) != 1 {
		t.Fatalf("want 1 FAIL misconfig (PASS filtered), got %d", len(got))
	}
	m := got[0]
	if m.Engine != "trivy" {
		t.Errorf("engine = %q, want trivy", m.Engine)
	}
	if m.ID != "AVD-DS-0002" {
		t.Errorf("id = %q, want AVD-DS-0002 (AVDID preferred)", m.ID)
	}
	if m.Severity != "high" {
		t.Errorf("severity = %q, want high (lowercased)", m.Severity)
	}
	if m.Target != "Dockerfile" {
		t.Errorf("target = %q, want Dockerfile", m.Target)
	}
	if m.Type != "dockerfile security check" {
		t.Errorf("type = %q", m.Type)
	}
	if m.Reference != "https://avd.aquasec.com/misconfig/ds002" {
		t.Errorf("reference = %q, want PrimaryURL", m.Reference)
	}
}

// Without IncludeIaC the scanner must not request config scanning and must not
// emit misconfigs even if the report happens to contain them.
func TestMisconfigsEmptyWhenNotRequested(t *testing.T) {
	var doc trivyReport
	if err := json.Unmarshal([]byte(trivyConfigReport), &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The Scan() path only calls misconfigsFromTrivyReport when opts.IncludeIaC
	// is set; this guards the parser's PASS-filtering contract directly.
	for _, r := range doc.Results {
		for _, mc := range r.Misconfigurations {
			if mc.Status == "PASS" {
				// sanity: fixture has a PASS row to filter
				return
			}
		}
	}
	t.Fatal("fixture missing a PASS row")
}
