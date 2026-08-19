package compliance

import "testing"

const dockerBenchJSON = `{
  "tests": [
    {
      "id": "2",
      "desc": "Docker daemon configuration",
      "results": [
        {"id": "2.1", "desc": "Run the Docker daemon as a non-root rootless user if possible", "result": "WARN", "details": "rootful daemon"},
        {"id": "2.2", "desc": "Ensure network traffic is restricted between containers", "result": "PASS", "details": ""}
      ]
    },
    {
      "id": "1",
      "desc": "Host Configuration",
      "results": [
        {"id": "1.1.1", "desc": "Ensure a separate partition for containers has been created", "result": "INFO", "details": "manual"}
      ]
    }
  ]
}`

func TestParseDockerBench(t *testing.T) {
	checks, err := ParseDockerBench([]byte(dockerBenchJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(checks) != 3 {
		t.Fatalf("want 3 checks, got %d", len(checks))
	}
	for _, ck := range checks {
		if ck.Framework != FrameworkCISDocker {
			t.Errorf("control %s framework = %q, want %q", ck.ControlID, ck.Framework, FrameworkCISDocker)
		}
	}
	by := map[string]Check{}
	for _, ck := range checks {
		by[ck.ControlID] = ck
	}
	if by["2.1"].Status != "fail" {
		t.Errorf("2.1 status = %q, want fail (WARN)", by["2.1"].Status)
	}
	if by["2.1"].Severity != "high" {
		t.Errorf("2.1 severity = %q, want high (section 2.x)", by["2.1"].Severity)
	}
	if by["2.2"].Status != "pass" {
		t.Errorf("2.2 status = %q, want pass", by["2.2"].Status)
	}
	if by["1.1.1"].Status != "manual" {
		t.Errorf("1.1.1 status = %q, want manual (INFO)", by["1.1.1"].Status)
	}
	if by["1.1.1"].Severity != "medium" {
		t.Errorf("1.1.1 severity = %q, want medium (section 1.x)", by["1.1.1"].Severity)
	}
}
