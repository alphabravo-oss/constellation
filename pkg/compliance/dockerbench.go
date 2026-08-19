package compliance

// docker-bench-security JSON parser.
//
// docker-bench-security (`docker-bench-security.sh --json`) emits this shape
// (simplified):
//
//	{
//	  "tests": [
//	    {"id":"1","desc":"Host Configuration","results":[
//	      {"id":"1.1.1","desc":"Ensure a separate partition for containers has been created","result":"WARN","details":"..."}
//	    ]}
//	  ]
//	}
//
// We flatten to one Check row per result, keyed on the docker-bench check id as the
// CIS Docker control_id, landing every row in framework=FrameworkCISDocker. This is the
// host-level analogue of the kube-bench ingest path in kubebench.go.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// dbReport is the (partial) shape docker-bench-security emits with --json.
type dbReport struct {
	Tests []struct {
		ID      string     `json:"id"`
		Desc    string     `json:"desc"`
		Results []dbResult `json:"results"`
	} `json:"tests"`
}

type dbResult struct {
	ID      string `json:"id"`
	Desc    string `json:"desc"`
	Result  string `json:"result"` // PASS | WARN | INFO | NOTE
	Details string `json:"details"`
}

// ParseDockerBench turns docker-bench-security JSON into Constellation Check rows.
// All entries land in framework=FrameworkCISDocker.
func ParseDockerBench(b []byte) ([]Check, error) {
	var doc dbReport
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("docker-bench parse: %w", err)
	}
	out := []Check{}
	for _, t := range doc.Tests {
		for _, r := range t.Results {
			out = append(out, dbResultToCheck(r))
		}
	}
	return out, nil
}

func dbResultToCheck(r dbResult) Check {
	// docker-bench uses PASS/WARN/INFO/NOTE rather than kube-bench's PASS/FAIL.
	// WARN is a failed hardening control; INFO/NOTE are advisory/manual.
	status := "manual"
	switch strings.ToUpper(strings.TrimSpace(r.Result)) {
	case "PASS":
		status = "pass"
	case "WARN":
		status = "fail"
	case "INFO", "NOTE":
		status = "manual"
	}
	return Check{
		Framework: FrameworkCISDocker,
		ControlID: strings.TrimSpace(r.ID),
		Title:     strings.TrimSpace(r.Desc),
		Status:    status,
		Severity:  severityForDBNumber(r.ID),
		Evidence:  strings.TrimSpace(r.Details),
	}
}

// severityForDBNumber tiers CIS Docker sections by risk:
//
//	1.x — host configuration            -> medium
//	2.x — docker daemon configuration   -> high
//	3.x — daemon config files           -> medium
//	4.x — container images / build      -> high
//	5.x — container runtime             -> high
//	6.x — docker security operations    -> medium
//	7.x — docker swarm configuration    -> medium
func severityForDBNumber(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "2.") ||
		strings.HasPrefix(s, "4.") ||
		strings.HasPrefix(s, "5.") {
		return "high"
	}
	return "medium"
}
