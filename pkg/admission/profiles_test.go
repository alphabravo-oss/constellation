package admission

import "testing"

func TestBuiltInAdmissionProfiles(t *testing.T) {
	profiles := BuiltInAdmissionProfiles()
	if len(profiles) != 10 {
		t.Fatalf("profile count=%d want 10", len(profiles))
	}
	seen := map[string]bool{}
	last := ""
	for _, profile := range profiles {
		if profile.ID == "" || profile.Name == "" || profile.Description == "" {
			t.Fatalf("profile missing identity fields: %+v", profile)
		}
		if profile.ID < last {
			t.Fatalf("profiles are not sorted: %q before %q", profile.ID, last)
		}
		last = profile.ID
		if seen[profile.ID] {
			t.Fatalf("duplicate profile id %q", profile.ID)
		}
		seen[profile.ID] = true
		if profile.FailurePolicy != "Ignore" && profile.FailurePolicy != "Fail" {
			t.Fatalf("profile %s has invalid failure policy %q", profile.ID, profile.FailurePolicy)
		}
		if len(profile.Rules) == 0 {
			t.Fatalf("profile %s has no rules", profile.ID)
		}
		ruleNames := map[string]bool{}
		for _, rule := range profile.Rules {
			if rule.Name == "" || rule.Engine == "" || rule.Category == "" || rule.SpecYAML == "" {
				t.Fatalf("profile %s has incomplete rule: %+v", profile.ID, rule)
			}
			if rule.Mode != "monitor" && rule.Mode != "enforce" {
				t.Fatalf("profile %s rule %s has invalid mode %q", profile.ID, rule.Name, rule.Mode)
			}
			if ruleNames[rule.Name] {
				t.Fatalf("profile %s repeats rule %q", profile.ID, rule.Name)
			}
			ruleNames[rule.Name] = true
		}
	}
	for _, id := range []string{
		"pss-baseline",
		"pss-restricted",
		"basic-hardening",
		"strict-hardening",
		"image-provenance-required",
		"critical-vulnerabilities-blocked",
		"fixable-vulnerabilities-blocked",
		"secrets-misconfig-blocked",
		"privileged-workload-approval-required",
		"admission-exceptions",
	} {
		if !seen[id] {
			t.Fatalf("missing profile %q", id)
		}
	}
}

func TestAdmissionProfileBundleFor(t *testing.T) {
	profile, ok := BuiltInAdmissionProfile("strict-hardening")
	if !ok {
		t.Fatal("strict-hardening profile missing")
	}
	bundle := AdmissionProfileBundleFor(profile)
	if bundle.APIVersion != AdmissionProfileAPIVersion || bundle.Kind != AdmissionProfileKind {
		t.Fatalf("bad bundle identity: %+v", bundle)
	}
	if bundle.Profile.ID != "strict-hardening" {
		t.Fatalf("profile id=%q want strict-hardening", bundle.Profile.ID)
	}
}

func TestBuiltInAdmissionProfileDeprecatedAliases(t *testing.T) {
	cases := map[string]string{
		"baseline":   "basic-hardening",
		"restricted": "strict-hardening",
	}
	for alias, canonical := range cases {
		profile, ok := BuiltInAdmissionProfile(alias)
		if !ok {
			t.Fatalf("deprecated alias %q did not resolve", alias)
		}
		if profile.ID != canonical {
			t.Fatalf("alias %q resolved to %q want %q", alias, profile.ID, canonical)
		}
	}
}

func TestBuiltInAdmissionProfileUnknown(t *testing.T) {
	if _, ok := BuiltInAdmissionProfile("does-not-exist"); ok {
		t.Fatal("unknown profile should not resolve")
	}
}
