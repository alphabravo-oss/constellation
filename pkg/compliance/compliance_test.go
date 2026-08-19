package compliance

import "testing"

func TestAllFrameworks_HasExpectedEntries(t *testing.T) {
	fws := AllFrameworks()
	wantIDs := map[string]bool{
		FrameworkCISK8s: true, FrameworkNIST80053: true, FrameworkPCIDSS4: true,
		FrameworkSOC2: true, FrameworkNIS2: true, FrameworkDORA: true, FrameworkISO27001: true,
	}
	got := map[string]bool{}
	for _, f := range fws {
		got[f.ID] = true
	}
	for id := range wantIDs {
		if !got[id] {
			t.Fatalf("framework %q missing from AllFrameworks()", id)
		}
	}
}

func TestExpandInternal_FansOutToFrameworks(t *testing.T) {
	out := ExpandInternal("k8s.api.audit-logging", "pass", "audit log = /var/log/audit.log")
	if len(out) < 4 {
		t.Fatalf("expected >= 4 cross-framework rows for audit-logging, got %d", len(out))
	}
	for _, c := range out {
		if c.Status != "pass" {
			t.Fatalf("status preserved: %q", c.Status)
		}
		if c.ControlID == "" {
			t.Fatalf("empty control id for framework %q", c.Framework)
		}
	}
}

func TestControlIDsByFramework(t *testing.T) {
	cis := ControlIDsByFramework(FrameworkCISK8s)
	if len(cis) == 0 {
		t.Fatal("expected at least one CIS K8s control mapped")
	}
	// Returned slice must be sorted + dedup'd.
	for i := 1; i < len(cis); i++ {
		if cis[i-1] >= cis[i] {
			t.Fatalf("not strictly sorted: %v", cis)
		}
	}
}

const kbSampleJSON = `
{
  "Controls": [{
    "id":"1","text":"Master Node","tests":[
      {"section":"1.2","desc":"API Server","results":[
        {"test_number":"1.2.22","test_desc":"Ensure audit policy file is set","status":"FAIL","actual_value":"--audit-policy-file not set","scored":true},
        {"test_number":"1.2.1","test_desc":"Ensure anonymous auth is disabled","status":"PASS","actual_value":"--anonymous-auth=false","scored":true}
      ]}
    ]
  }]
}`

func TestIngestKubeBench(t *testing.T) {
	checks, err := IngestKubeBench([]byte(kbSampleJSON))
	if err != nil {
		t.Fatal(err)
	}
	// Two CIS rows + cross-framework expansions for both controls.
	if len(checks) < 4 {
		t.Fatalf("expected >= 4 expanded checks, got %d", len(checks))
	}

	// Find the audit-logging fail in CIS.
	var found bool
	for _, c := range checks {
		if c.Framework == FrameworkCISK8s && c.ControlID == "1.2.22" && c.Status == "fail" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected CIS K8s 1.2.22 fail in output: %+v", checks)
	}

	// Find a NIST mapping derived from 1.2.22.
	for _, c := range checks {
		if c.Framework == FrameworkNIST80053 && c.ControlID == "AU-2" && c.Status == "fail" {
			return
		}
	}
	t.Fatalf("expected NIST AU-2 fail expanded from CIS 1.2.22")
}

// CMP-4: the CIS-K8s -> internal-id wiring is now data-driven from CoreMappings.
// A newly-mapped control (5.2.7 run-as-non-root) must expand into its NIST 800-190
// framework, and every one of the original 7 hard-coded controls must still expand.
const kbCMP4JSON = `
{
  "Controls": [{
    "id":"5","text":"Policies","tests":[
      {"section":"5.2","desc":"Pod Security","results":[
        {"test_number":"5.2.7","test_desc":"Minimize containers running as root","status":"FAIL","actual_value":"runAsNonRoot not set","scored":true}
      ]}
    ]
  }]
}`

func TestIngestKubeBench_DataDrivenCISMapping(t *testing.T) {
	checks, err := IngestKubeBench([]byte(kbCMP4JSON))
	if err != nil {
		t.Fatal(err)
	}
	// The newly-mapped 5.2.7 must expand beyond cis-k8s-1.9 into NIST 800-190.
	var nist bool
	for _, c := range checks {
		if c.Framework == FrameworkNIST800190 && c.ControlID == "4.5.1" && c.Status == "fail" {
			nist = true
		}
	}
	if !nist {
		t.Fatalf("expected 5.2.7 to expand into NIST 800-190 4.5.1: %+v", checks)
	}

	// Regression guard: the original 7 hard-coded controls must still resolve to an
	// internal id (and therefore still expand cross-framework).
	for ctrl, want := range map[string]string{
		"1.2.22": "k8s.api.audit-logging",
		"1.2.1":  "k8s.api.anonymous-auth",
		"1.2.31": "k8s.encryption-at-rest",
		"5.2.1":  "k8s.privileged-containers-forbidden",
		"5.2.4":  "k8s.host-network-forbidden",
		"5.1.3":  "k8s.rbac.no-wildcard-roles",
		"5.7.4":  "k8s.read-only-root-filesystem",
	} {
		if got := InternalIDForCISK8s(ctrl); got != want {
			t.Fatalf("original control %s: internal id = %q, want %q", ctrl, got, want)
		}
	}
}

// kbEKSJSON carries a per-Control "version" (eks-1.4.0) the way a real managed
// kube-bench run does. CMP-3: such rows must be tagged with the EKS CIS profile,
// not the hardcoded cis-k8s-1.9.
const kbEKSJSON = `
{
  "Controls": [{
    "id":"3","version":"eks-1.4.0","text":"Worker Node","tests":[
      {"section":"3.1","desc":"Kubelet","results":[
        {"test_number":"3.1.1","test_desc":"Ensure kubeconfig perms are 644","status":"FAIL","actual_value":"700","scored":true}
      ]}
    ]
  }]
}`

func TestIngestKubeBench_TagsBenchmarkVersionFromReport(t *testing.T) {
	checks, err := IngestKubeBench([]byte(kbEKSJSON))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range checks {
		if c.ControlID == "3.1.1" {
			found = true
			if c.Framework != "cis-eks-1.4.0" {
				t.Fatalf("framework = %q, want cis-eks-1.4.0 (must carry report benchmark version)", c.Framework)
			}
		}
	}
	if !found {
		t.Fatalf("expected control 3.1.1 in output: %+v", checks)
	}

	// No version in the report -> fall back to the default cis-k8s-1.9 (preserves
	// prior behavior).
	def, err := IngestKubeBench([]byte(kbSampleJSON))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range def {
		if c.ControlID == "1.2.22" && c.Framework != FrameworkCISK8s {
			t.Fatalf("absent version must fall back to %q, got %q", FrameworkCISK8s, c.Framework)
		}
	}

	// Explicit override (runner BENCH_VERSION / ?benchmark=) wins over the report.
	ov, err := IngestKubeBenchProfile([]byte(kbSampleJSON), "gke-1.6.0")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range ov {
		if c.ControlID == "1.2.22" && c.Framework != "cis-gke-1.6.0" {
			t.Fatalf("override must tag cis-gke-1.6.0, got %q", c.Framework)
		}
	}
}
