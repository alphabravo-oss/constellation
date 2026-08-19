package audit

import (
	"strings"
	"testing"
)

func TestControlIDsFor_EmptyAction(t *testing.T) {
	got := ControlIDsFor("")
	if got == nil {
		t.Fatal("ControlIDsFor must return non-nil even for empty input")
	}
	if len(got) != 0 {
		t.Errorf("empty action: want 0 mappings, got %d", len(got))
	}
}

func TestControlIDsFor_UnmappedAction(t *testing.T) {
	got := ControlIDsFor("totally.fictional.event")
	if len(got) != 0 {
		t.Errorf("unmapped action should return 0 mappings, got %d", len(got))
	}
}

// Login events are the single most heavily-audited control. If this
// regresses we've broken the federal baseline.
func TestControlIDsFor_AuthLoginCoversBaselines(t *testing.T) {
	got := ControlIDsFor("auth.login.local")
	want := []struct {
		fw Framework
		id string
	}{
		{FrameworkNIST80053, "AC-2"},
		{FrameworkNIST80053, "AC-7"},
		{FrameworkNIST80053, "AU-2"},
		{FrameworkNIST80053, "IA-2"},
		{FrameworkSOC2, "CC6.1"},
		{FrameworkPCIDSSv4, "8.2"},
		{FrameworkPCIDSSv4, "8.3"},
		{FrameworkPCIDSSv4, "10.2.1"},
		{FrameworkISO27001, "A.5.16"},
		{FrameworkISO27001, "A.8.5"},
	}
	for _, w := range want {
		found := false
		for _, m := range got {
			if m.Framework == w.fw && m.ControlID == w.id {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing mapping for auth.login.local: %s/%s", w.fw, w.id)
		}
	}
}

func TestControlIDsFor_StableOrder(t *testing.T) {
	got := ControlIDsFor("policy.update")
	for i := 1; i < len(got); i++ {
		a, b := got[i-1], got[i]
		if a.Framework > b.Framework {
			t.Fatalf("framework ordering broken at %d: %s > %s", i, a.Framework, b.Framework)
		}
		if a.Framework == b.Framework && a.ControlID > b.ControlID {
			t.Fatalf("control_id ordering broken at %d: %s > %s within %s", i, a.ControlID, b.ControlID, a.Framework)
		}
	}
}

func TestControlIDsFor_NoDuplicates(t *testing.T) {
	for _, action := range []string{
		"auth.login.oidc", "policy.create", "finding.suppress",
		"runtime.alert.exec", "backup.start", "scan-job.complete",
	} {
		got := ControlIDsFor(action)
		seen := make(map[string]bool)
		for _, m := range got {
			k := string(m.Framework) + "|" + m.ControlID
			if seen[k] {
				t.Errorf("duplicate mapping for action=%s: %s/%s", action, m.Framework, m.ControlID)
			}
			seen[k] = true
		}
	}
}

// Cross-cutting controls (AU-2 event logging, CM-3 change control) need
// to apply to multiple action families. Verify that.
func TestControlIDsFor_AU2AppearsAcrossFamilies(t *testing.T) {
	families := []string{
		"auth.login.local", "auth.logout",
		"policy.update", "finding.suppress",
		"runtime.alert.exec", "backup.start",
		"registry.create", "compliance.ingest", "federation.invite",
	}
	for _, a := range families {
		got := ControlIDsFor(a)
		found := false
		for _, m := range got {
			if m.Framework == FrameworkNIST80053 && m.ControlID == "AU-2" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AU-2 (Event Logging) should apply to %s but doesn't", a)
		}
	}
}

func TestActionsFor_RoundTrips(t *testing.T) {
	// AC-2 (Account Management) — should pull at least the auth.login and
	// the account-management rule (group./role_binding./service_account).
	got := ActionsFor(FrameworkNIST80053, "AC-2")
	wantContains := []string{"auth.login.", "group.create", "role_binding.create"}
	for _, w := range wantContains {
		hit := false
		for _, p := range got {
			if p == w {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("ActionsFor(nist, AC-2) missing prefix %q (got %v)", w, got)
		}
	}
}

func TestActionsFor_UnknownControl(t *testing.T) {
	got := ActionsFor(FrameworkNIST80053, "ZZ-99")
	if len(got) != 0 {
		t.Errorf("unknown control should return 0 prefixes, got %v", got)
	}
}

func TestAllControls_NonEmpty(t *testing.T) {
	all := AllControls()
	if len(all) < 20 {
		t.Fatalf("AllControls returned %d entries; mapping table looks suspiciously small", len(all))
	}
	// Sanity: every entry has a non-empty title.
	for _, m := range all {
		if m.Title == "" {
			t.Errorf("mapping %s/%s has empty title — auditors need these verbatim", m.Framework, m.ControlID)
		}
	}
}

func TestAllFrameworks_HasFour(t *testing.T) {
	fws := AllFrameworks()
	want := map[Framework]bool{
		FrameworkNIST80053: false,
		FrameworkSOC2:      false,
		FrameworkPCIDSSv4:  false,
		FrameworkISO27001:  false,
	}
	for _, fw := range fws {
		if _, ok := want[fw]; ok {
			want[fw] = true
		}
	}
	for fw, hit := range want {
		if !hit {
			t.Errorf("framework %s not in AllFrameworks: %v", fw, fws)
		}
	}
}

// The mapping table is the only place where the NIST/SOC2/PCI/ISO string
// constants are written. If anyone edits a Framework constant value, this
// test fails loudly — the strings appear in customer-facing audit exports.
func TestFrameworkConstants_HaveStablePublicNames(t *testing.T) {
	cases := map[Framework]string{
		FrameworkNIST80053: "nist-sp-800-53-r5",
		FrameworkSOC2:      "soc2-tsc-2017",
		FrameworkPCIDSSv4:  "pci-dss-v4.0",
		FrameworkISO27001:  "iso-27001-2022",
	}
	for fw, want := range cases {
		if string(fw) != want {
			t.Errorf("Framework constant changed: %q != %q (this is a customer-facing wire string)", fw, want)
		}
	}
}

func TestRulesCoverEveryDocumentedActionFamily(t *testing.T) {
	// A sanity check that every audit Action observed in the codebase
	// gets at least one mapping. If you add a new audit action and forget
	// to update compliance.go, this test catches it.
	knownActions := []string{
		"auth.login.local", "auth.login.oidc", "auth.logout",
		"group.create", "group.update", "group.delete",
		"role_binding.create", "role_binding.delete",
		"service_account.create",
		"settings.user.update", "settings.org.update",
		"policy.create", "policy.update", "policy.delete", "policy.bulk",
		"response_rule.update", "response_rule_v2.create",
		"vuln_profile.create", "dlp_sensor.create", "waf_group.create",
		"attestation_trust_policy.create", "attestation_trust_policy.update", "attestation_trust_policy.delete",
		"routing.yaml.update",
		"finding.suppress", "finding.accept_risk", "finding.comment", "finding.triage",
		"image.accept-risk", "image.accept-risk.revoke",
		"runtime.alert.exec", "runtime.alert.waf", "runtime.alert.dlp",
		"admission.deny", "baseline.transition", "file_profile.transition", "gitops.drift.detected",
		"component.crashloop",
		"receiver.create", "receiver.test_fire", "receiver.rotate_secret",
		"backup.start", "backup.complete", "backup.download", "backup.restore",
		"backup.verify", "backup.schedule.update",
		"registry.create", "registry.sync-now", "registry.test",
		"scan-job.enqueue", "scan-job.complete", "scan-job.fail",
		"attestation.verify",
		"cluster.cross-scan",
		"compliance.ingest", "compliance.schedule.create",
		"compliance.exemption.create", "compliance.exemption.revoke",
		"compliance.custom_framework.create",
		"cluster-init-bundle.read", "cluster-init-bundle.revoke",
		"federation.invite", "fed_member.add",
		"ai.query", "ai.tool",
		"quarantine.add", "quarantine.lift", "quarantine.auto",
	}
	for _, a := range knownActions {
		if got := ControlIDsFor(a); len(got) == 0 {
			t.Errorf("action %q has zero compliance mappings — add it to pkg/audit/compliance.go", a)
		}
	}
	_ = strings.Builder{} // satisfy import if test reduced
}
