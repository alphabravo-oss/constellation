package neuvector

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/vulnprofile"
)

func TestRemainingCanonicalFixture(t *testing.T) {
	raw, err := os.ReadFile("testdata/remaining_families.yaml")
	if err != nil {
		t.Fatal(err)
	}
	manifestRaw, err := os.ReadFile("testdata/remaining_families.counts.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Source      map[string]int `json:"source"`
		Total       int            `json:"source_total"`
		Profiles    int            `json:"converted_vulnerability_profiles"`
		Registries  int            `json:"converted_registries"`
		Unsupported int            `json:"unsupported_diagnostics"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	counts, err := CountSourceObjects(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(counts.Map(), manifest.Source) || counts.Total() != manifest.Total {
		t.Fatalf("counts = %#v total=%d; manifest=%s", counts.Map(), counts.Total(), manifestRaw)
	}
	out, err := ConvertRemainingFamilies(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.VulnerabilityProfiles) != manifest.Profiles || len(out.Registries) != manifest.Registries || len(out.Unsupported) != manifest.Unsupported {
		t.Fatalf("unexpected converted counts: profiles=%d registries=%d unsupported=%d", len(out.VulnerabilityProfiles), len(out.Registries), len(out.Unsupported))
	}
	serialized, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "SECRET_") {
		t.Fatalf("secret leaked: %s", serialized)
	}
	registry := out.Registries[0]
	if registry.Kind != "generic-v2" || !registry.CredentialsRequired || len(registry.ImageGlobs) != 0 || registry.ImportedFrom["cadence"] != "manual" || registry.ImportedFrom["auth_kind"] != "none" {
		t.Fatalf("unsafe registry metadata: %+v", registry)
	}
	assertLegacyConvertersEmpty(t, raw)
}

func assertLegacyConvertersEmpty(t *testing.T, raw []byte) {
	t.Helper()
	if out, err := Convert(raw); err != nil || len(out) != 0 {
		t.Fatalf("policies = %+v, %v", out, err)
	}
	if out, err := ConvertFileProfiles(raw); err != nil || len(out) != 0 {
		t.Fatalf("files = %+v, %v", out, err)
	}
	if out, unsupported, err := ConvertProcessProfiles(raw); err != nil || len(out)+len(unsupported) != 0 {
		t.Fatalf("process = %+v, %+v, %v", out, unsupported, err)
	}
	if out, unsupported, err := ConvertGroups(raw); err != nil || len(out)+len(unsupported) != 0 {
		t.Fatalf("groups = %+v, %+v, %v", out, unsupported, err)
	}
	if out, unsupported, err := ConvertNetworkRules(raw); err != nil || len(out)+len(unsupported) != 0 {
		t.Fatalf("network = %+v, %+v, %v", out, unsupported, err)
	}
	if rules, bindings, unsupported, err := ConvertDPIRules(raw); err != nil || len(rules)+len(bindings)+len(unsupported) != 0 {
		t.Fatalf("DPI = %+v, %+v, %+v, %v", rules, bindings, unsupported, err)
	}
}

func TestVulnerabilityProfileMatcherParity(t *testing.T) {
	names := []string{"CVE-2026-1234", "CVE.2026+[literal]", "CVE-2026-*", "CVE-202[56]-*", "*", "cve-2025-*suffix"}
	ids := []string{"CVE-2026-1234", "cve-2026-1234", "CVE-2026-12345", "prefix-CVE-2026-1234-suffix", "CVE.2026+[literal]", "CVE-2025-1suffix", "unrelated", ""}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"vulnerability_profiles": []any{map[string]any{"name": "reviewed", "entries": []any{map[string]any{"name": name}}}}})
			out, err := ConvertRemainingFamilies(raw)
			if err != nil || len(out.VulnerabilityProfiles) != 1 || len(out.Unsupported) != 0 {
				t.Fatalf("conversion = %+v, %v", out, err)
			}
			profile := vulnprofile.Profile{Name: "reviewed", Active: true, Entries: out.VulnerabilityProfiles[0].Entries}
			for _, id := range ids {
				// NeuVector MakeVulnerabilityProfileFilter/filterOneVul:
				// EqualFold for literal names, unanchored regex only when '*' occurs.
				want := strings.EqualFold(name, id)
				if strings.Contains(name, "*") {
					want = regexp.MustCompile("(?i)" + strings.ReplaceAll(name, "*", ".*")).MatchString(id)
				}
				got := profile.Evaluate([]vulnprofile.CVE{{ID: id}})[0].Decision == vulnprofile.DecisionSuppressAccept
				if got != want {
					t.Errorf("name=%q id=%q suppression=%v want=%v", name, id, got, want)
				}
			}
		})
	}
}

func TestVulnerabilityRejectsWholeProfile(t *testing.T) {
	cases := map[string]string{
		"recent":             `{"name":"_RecentVuln","days":14}`,
		"recent_without_fix": `{"name":"_RecentVulnWithoutFix","days":14}`,
		"unknown_reserved":   `{"name":"_recent"}`,
		"domain":             `{"name":"CVE-2026-1","domains":["prod"]}`,
		"image_literal":      `{"name":"CVE-2026-1","images":["repo:tag"]}`,
		"image_wildcard":     `{"name":"CVE-2026-1","images":["team/*"]}`,
		"unknown_field":      `{"name":"CVE-2026-1","only_without_fix":true}`,
		"negative_days":      `{"name":"CVE-2026-1","days":-1}`,
		"days":               `{"name":"CVE-2026-1","days":2}`,
		"invalid_regex":      `{"name":"[*"}`,
		"empty_name":         `{"name":""}`,
		"secret_type_error":  `{"name":"CVE-2026-1","days":"SECRET_VALUE"}`,
	}
	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"vulnerability_profiles":[{"name":"test","entries":[{"name":"CVE-2026-1234"},` + bad + `]}]}`)
			out, err := ConvertRemainingFamilies(raw)
			if err != nil || len(out.VulnerabilityProfiles) != 0 || len(out.Unsupported) != 1 {
				t.Fatalf("partial/unsafe conversion: %+v %v", out, err)
			}
			encoded, _ := json.Marshal(out)
			if strings.Contains(string(encoded), "SECRET_VALUE") {
				t.Fatal("secret leaked")
			}
		})
	}
	for _, extra := range []string{`,"cfg_type":"federal"`, `,"domain_scope":{"namespaces":["prod"]}`, `,"unknown":true`} {
		out, err := ConvertRemainingFamilies([]byte(`{"profile":{"name":"test","entries":[]` + extra + `}}`))
		if err != nil || len(out.VulnerabilityProfiles) != 0 || len(out.Unsupported) != 1 {
			t.Fatalf("unknown profile semantics accepted: %+v %v", out, err)
		}
	}
}

func TestRemainingRESTAndCRDShapes(t *testing.T) {
	for _, raw := range []string{
		`{"profile":{"name":"test","entries":[]}}`,
		`{"profiles":[{"name":"test","entries":[]}]}`,
		`{"config":{"name":"test","entries":[]}}`,
		`{"vulnerability":{"profile":{"name":"test","entries":[]}}}`,
		`{"vulnerability":{"profiles":[{"name":"test","entries":[]}]}}`,
		`{"kind":"NvVulnerabilityProfileList","items":[{"kind":"NvVulnerabilityProfile","spec":{"profile":{"name":"test","entries":[]}}}]}`,
	} {
		out, err := ConvertRemainingFamilies([]byte(raw))
		if err != nil || len(out.VulnerabilityProfiles) != 1 || len(out.Unsupported) != 0 {
			t.Fatalf("shape %s: %+v %v", raw, out, err)
		}
		assertLegacyConvertersEmpty(t, []byte(raw))
		counts, err := CountSourceObjects([]byte(raw))
		if err != nil || counts.VulnerabilityProfiles != 1 || counts.Total() != 1 {
			t.Fatalf("shape counts %s: %+v %v", raw, counts, err)
		}
	}
}

func TestRegistryValidationAndSecretOmission(t *testing.T) {
	for _, endpoint := range []string{"http://registry.test", "https://user:SECRET_PASSWORD@registry.test", "https://registry.test?token=SECRET_TOKEN", "https://registry.test?", "https://registry.test#SECRET_FRAGMENT", "https://registry.test#", "https:///missing-host", "registry.test", "https://registry.test:bad", "https://registry.test\nSECRET_VALUE"} {
		raw, _ := json.Marshal(map[string]any{"registries": []any{map[string]any{"name": "test", "registry_type": "Docker Registry", "registry": endpoint}}})
		out, err := ConvertRemainingFamilies(raw)
		if err != nil || len(out.Registries) != 0 || len(out.Unsupported) != 1 {
			t.Fatalf("unsafe endpoint %q: %+v %v", endpoint, out, err)
		}
		encoded, _ := json.Marshal(out)
		if strings.Contains(string(encoded), "SECRET_") {
			t.Fatal("endpoint secret leaked")
		}
	}
	for _, kind := range []string{"Docker Registry", "Amazon ECR Registry", "Azure Container Registry", "Google Container Registry", "JFrog Artifactory", "OpenShift Registry", "Sonatype Nexus", "Gitlab", "IBM Cloud Container Registry", "Harbor Registry", "GitHub Container Registry", "quay"} {
		raw, _ := json.Marshal(map[string]any{"config": map[string]any{"name": "test", "registry_type": kind, "registry": "https://registry.test:443/v2", "integrations": map[string]any{"gitlab_private_token": "SECRET_TOKEN"}}})
		out, err := ConvertRemainingFamilies(raw)
		if err != nil || len(out.Registries) != 1 || !out.Registries[0].CredentialsRequired {
			t.Fatalf("kind %s: %+v %v", kind, out, err)
		}
		assertLegacyConvertersEmpty(t, raw)
		encoded, _ := json.Marshal(out)
		if strings.Contains(string(encoded), "SECRET_") {
			t.Fatal("nested credentials leaked")
		}
	}
}

func TestUnknownObjectsNeverBecomeLegacyPolicies(t *testing.T) {
	for _, raw := range []string{
		`SECRET_TOP_KEY: {name: SECRET_NAME, password: SECRET_VALUE}`,
		`kind: SECRET_KIND
metadata: {name: SECRET_NAME}
spec:
  target: {selector: {name: SECRET_GROUP}}
  process: [{name: SECRET_PROCESS, path: /bin/sh, action: allow}]
  file: [{filter: /etc/passwd, behavior: block_access}]
  ingress: [{selector: {name: SECRET_PEER}, ports: tcp/80, action: allow}]`,
		`kind: List
items:
  - kind: Secret
    metadata: {name: SECRET_NAME}
    spec: {process: [{name: SECRET_PROCESS, path: /bin/sh, action: allow}]}
SECRET_TOP_KEY: SECRET_VALUE`,
	} {
		out, err := ConvertRemainingFamilies([]byte(raw))
		if err != nil || len(out.Unsupported) == 0 {
			t.Fatalf("missing unsupported: %+v %v", out, err)
		}
		encoded, _ := json.Marshal(out)
		if strings.Contains(string(encoded), "SECRET_") {
			t.Fatalf("unknown value leaked: %s", encoded)
		}
		assertLegacyConvertersEmpty(t, []byte(raw))
	}
}

func TestParseErrorsRedactYAMLValues(t *testing.T) {
	converters := []struct {
		name string
		run  func([]byte) error
	}{
		{"policies", func(raw []byte) error { _, err := Convert(raw); return err }},
		{"files", func(raw []byte) error { _, err := ConvertFileProfiles(raw); return err }},
		{"process", func(raw []byte) error { _, _, err := ConvertProcessProfiles(raw); return err }},
		{"groups", func(raw []byte) error { _, _, err := ConvertGroups(raw); return err }},
		{"network", func(raw []byte) error { _, _, err := ConvertNetworkRules(raw); return err }},
		{"DPI", func(raw []byte) error { _, _, _, err := ConvertDPIRules(raw); return err }},
		{"counts", func(raw []byte) error { _, err := CountSourceObjects(raw); return err }},
		{"remaining", func(raw []byte) error { _, err := ConvertRemainingFamilies(raw); return err }},
	}
	for _, malformed := range []string{"SECRET_SCALAR", "value: [SECRET_UNCLOSED", "SECRET_KEY: one\nSECRET_KEY: two"} {
		for _, converter := range converters {
			t.Run(converter.name+fmt.Sprint(len(malformed)), func(t *testing.T) {
				err := converter.run([]byte(malformed))
				if err == nil || strings.Contains(err.Error(), "SECRET_") {
					t.Fatalf("expected redacted error, got %v", err)
				}
			})
		}
	}
	// Schema decoding errors used to include raw YAML scalar values.
	for _, converter := range converters[:len(converters)-1] {
		err := converter.run([]byte("rules: [{id: SECRET_ID}]"))
		if err == nil || strings.Contains(err.Error(), "SECRET_ID") {
			t.Fatalf("%s schema error: %v", converter.name, err)
		}
	}
}

func TestRemainingRejectsUnknownProfileEnvelopeSemantics(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"NvVulnerabilityProfile","spec":{"profile":{"name":"reviewed","entries":[{"name":"CVE-2026-1"}]},"domains":["SECRET_SCOPE"]}}`,
		`{"vulnerability":{"profile":{"name":"reviewed","entries":[{"name":"CVE-2026-1"}]},"domains":["SECRET_SCOPE"]}}`,
	} {
		converted, err := ConvertRemainingFamilies([]byte(raw))
		if err != nil || len(converted.VulnerabilityProfiles) != 0 || len(converted.Unsupported) != 1 {
			t.Fatalf("unsafe wrapper accepted: %+v %v", converted, err)
		}
		encoded, _ := json.Marshal(converted)
		if strings.Contains(string(encoded), "SECRET_SCOPE") {
			t.Fatal("unknown scope leaked")
		}
	}
	converted, err := ConvertRemainingFamilies([]byte(`{"SECRET_UNKNOWN_FAMILY":[]}`))
	if err != nil || len(converted.Unsupported) != 1 {
		t.Fatalf("unknown empty family silently disappeared: %+v %v", converted, err)
	}
}

func TestRemainingUnknownGenericEnvelopesAreRedacted(t *testing.T) {
	for _, raw := range []string{
		`{"config":{"name":"SECRET_AUTH_NAME","ldap":{"password":"SECRET_PASSWORD"}}}`,
		`{"configs":[{"name":"SECRET_AUTH_NAME","ldap":{"password":"SECRET_PASSWORD"}}]}`,
		`{"profile":{"name":"SECRET_COMPLIANCE_NAME","checks":["SECRET_CHECK"]}}`,
		`{"profiles":[{"name":"SECRET_COMPLIANCE_NAME","checks":["SECRET_CHECK"]}]}`,
	} {
		converted, err := ConvertRemainingFamilies([]byte(raw))
		if err != nil || len(converted.Unsupported) != 1 {
			t.Fatalf("unknown envelope disappeared: %+v %v", converted, err)
		}
		encoded, _ := json.Marshal(converted)
		if strings.Contains(string(encoded), "SECRET_") {
			t.Fatal("unknown envelope leaked source values")
		}
		assertLegacyConvertersEmpty(t, []byte(raw))
		counts, err := CountSourceObjects([]byte(raw))
		if err != nil || counts.Total() != 1 || counts.RemainingUnsupported != 1 {
			t.Fatalf("unknown envelope accounting=%+v error=%v", counts, err)
		}
	}
}
