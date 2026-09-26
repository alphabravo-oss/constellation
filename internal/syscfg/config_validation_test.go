package syscfg

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func requireSafeValidation(t *testing.T, err error, secret string) *ValidationError {
	t.Helper()
	var validation *ValidationError
	if !errors.As(err, &validation) {
		t.Fatalf("expected structured validation error, got %T", err)
	}
	encoded, marshalErr := json.Marshal(validation)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if secret != "" && (strings.Contains(err.Error(), secret) || strings.Contains(string(encoded), secret)) {
		t.Fatal("validation error exposed a rejected value")
	}
	if len(validation.Fields) == 0 {
		t.Fatal("validation error has no fields")
	}
	for _, field := range validation.Fields {
		if field.Code == "" || field.Message == "" {
			t.Fatal("validation error is missing a code or message")
		}
	}
	return validation
}

func TestConfigValidationAggregatesSafeFields(t *testing.T) {
	const secret = "secret-injected-value"
	c := Config{
		EgressProxy:             EgressProxy{HTTPSProxy: "http://user:" + secret + "@host/%zz"},
		CABundlePEM:             secret,
		ScannerDBRefreshMinutes: -1,
		SyslogSIEM: SyslogTarget{
			Host: "collector", Port: -1, Protocol: secret, Format: secret,
			MinLevel: secret, CACert: secret, ClientKey: secret,
		},
		SMTP:                     SMTPServer{Host: "mail", Port: -1},
		NetworkFlowRetentionDays: -1,
		EventsRetentionDays:      3651,
		ScanJobRetentionDays:     -1,
		AutoScanRescanHours:      -1,
	}
	validation := requireSafeValidation(t, c.Validate(), secret)
	want := []string{
		"egress_proxy.https_proxy", "ca_bundle_pem", "syslog_siem_target.port",
		"syslog_siem_target.protocol", "syslog_siem_target.format", "syslog_siem_target.min_level",
		"syslog_siem_target.ca_cert", "syslog_siem_target.client_cert", "scanner_db_refresh_minutes",
		"smtp.port", "smtp.from", "network_flow_retention_days", "events_retention_days",
		"scan_job_retention_days", "auto_scan_rescan_hours",
	}
	var got []string
	for _, field := range validation.Fields {
		got = append(got, field.Field)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fields = %v, want %v", got, want)
	}
	if again := requireSafeValidation(t, c.Validate(), secret); !reflect.DeepEqual(again.Fields, validation.Fields) {
		t.Fatal("validation ordering is unstable")
	}
}

func TestConfigPatchRejectsUnsafeShapes(t *testing.T) {
	const secret = "secret-injected-value"
	cases := []struct {
		name  string
		patch string
		field string
		code  string
	}{
		{"empty", "", "$", "invalid_json"},
		{"null root", "null", "$", "null_not_allowed"},
		{"array root", "[]", "$", "invalid_type"},
		{"string root", `"` + secret + `"`, "$", "invalid_type"},
		{"number root", "123", "$", "invalid_type"},
		{"boolean root", "false", "$", "invalid_type"},
		{"trailing object", `{} {"` + secret + `":1}`, "$", "invalid_json"},
		{"trailing null", "{} null", "$", "invalid_json"},
		{"trailing secret", "{} " + secret, "$", "invalid_json"},
		{"malformed", `{"` + secret, "$", "invalid_json"},
		{"unknown root", `{"` + secret + `":1}`, "$", "unknown_field"},
		{"unknown nested", `{"smtp":{"` + secret + `":"value"}}`, "$", "unknown_field"},
		{"case alias", `{"SMTP":{"host":"mail"}}`, "$", "unknown_field"},
		{"nested scalar", `{"smtp":"` + secret + `"}`, "smtp", "invalid_type"},
		{"null object", `{"smtp":null}`, "smtp", "null_not_allowed"},
		{"null field", `{"smtp":{"password":null}}`, "smtp.password", "null_not_allowed"},
		{"null boolean", `{"tls_verify":null}`, "tls_verify", "null_not_allowed"},
		{"null categories", `{"syslog_siem_target":{"categories":null}}`, "syslog_siem_target.categories", "null_not_allowed"},
		{"null category", `{"syslog_siem_target":{"categories":[null]}}`, "syslog_siem_target.categories", "null_not_allowed"},
		{"wrong category type", `{"syslog_siem_target":{"categories":[{"` + secret + `":1}]}}`, "syslog_siem_target.categories", "invalid_type"},
		{"wrong array type", `{"syslog_siem_target":{"categories":"` + secret + `"}}`, "syslog_siem_target.categories", "invalid_type"},
		{"wrong secret type", `{"nvd_api_key":{"` + secret + `":1}}`, "nvd_api_key", "invalid_type"},
		{"wrong integer type", `{"smtp":{"port":"` + secret + `"}}`, "smtp.port", "invalid_type"},
		{"integer overflow", `{"scanner_db_refresh_now":99999999999999999999999999999}`, "scanner_db_refresh_now", "invalid_type"},
		{"duplicate null", `{"tls_verify":null,"tls_verify":true}`, "tls_verify", "null_not_allowed"},
		{"secret proxy", `{"egress_proxy":{"https_proxy":"http://user:` + secret + `@host/%zz"}}`, "egress_proxy.https_proxy", "invalid_url"},
		{"secret enum", `{"syslog_siem_target":{"host":"collector","port":514,"protocol":"` + secret + `"}}`, "syslog_siem_target.protocol", "invalid_value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Default().ApplyPatch(json.RawMessage(tc.patch))
			validation := requireSafeValidation(t, err, secret)
			if len(validation.Fields) == 0 || validation.Fields[0].Field != tc.field || validation.Fields[0].Code != tc.code {
				t.Fatalf("fields = %+v, want %s/%s", validation.Fields, tc.field, tc.code)
			}
		})
	}
}

func TestConfigPatchAggregatesShapeErrors(t *testing.T) {
	_, err := Default().ApplyPatch(json.RawMessage(`{"smtp":{"port":null,"untrusted-secret":1},"tls_verify":"untrusted-secret"}`))
	validation := requireSafeValidation(t, err, "untrusted-secret")
	want := []string{"smtp.port", "$", "tls_verify"}
	var got []string
	for _, field := range validation.Fields {
		got = append(got, field.Field)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fields = %v, want %v", got, want)
	}
}

func TestConfigRedactsURLsFailClosed(t *testing.T) {
	const secret = "secret-injected-value"
	for _, raw := range []string{
		"https://user:" + secret + "@host/path",
		"https://host/path?api_key=" + secret,
		"https://host/path?" + secret + "=value",
		"https://host/path#token=" + secret,
		"https://host/path#" + secret,
		"https://user:" + secret + "@host/path?token=" + secret + "#" + secret,
		"https://user:" + secret + "@host/%zz",
		"https://host/?token=" + secret + "%zz",
		"https://host/?token=" + secret + ";bad=query",
		"https://user:" + secret + "@[invalid",
		"//user:" + secret + "@host",
		secret,
	} {
		c := Config{EgressProxy: EgressProxy{HTTPSProxy: raw}, NVDMirrorURL: raw}
		redacted := c.Redacted()
		for _, value := range []string{redacted.EgressProxy.HTTPSProxy, redacted.NVDMirrorURL} {
			if strings.Contains(value, secret) || value == raw {
				t.Fatal("URL secret was not redacted")
			}
			if !proxyUserinfoIsRedacted(value) {
				t.Fatal("redacted URL is not recognized for roundtrip preservation")
			}
			if redactProxyUserinfo(value) != value {
				t.Fatal("URL redaction is not idempotent")
			}
		}
		if c.EgressProxy.HTTPSProxy != raw || c.NVDMirrorURL != raw {
			t.Fatal("redaction mutated the original configuration")
		}
	}
}

func TestConfigRedactedRoundtripPreservesAllSecrets(t *testing.T) {
	for _, raw := range []string{
		"https://user:password@host/path", "https://host/path?api_key=secret",
		"https://host/path#secret", "https://user:password@host/path?token=secret#secret",
	} {
		base := Default()
		base.CABundlePEM = testCACert(t)
		base.EgressProxy.HTTPSProxy = raw
		base.NVDMirrorURL = raw
		base.NVDAPIKey = "nvd-secret"
		base.SMTP.Password = "smtp-secret"
		base.SyslogSIEM.ClientKey = "client-secret"
		patch, err := json.Marshal(base.Redacted())
		if err != nil {
			t.Fatal(err)
		}
		merged, err := base.ApplyPatch(patch)
		if err != nil {
			t.Fatalf("redacted roundtrip failed: %v", err)
		}
		before, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		after, err := json.Marshal(merged)
		if err != nil {
			t.Fatal(err)
		}
		if string(before) != string(after) {
			t.Fatal("redacted roundtrip changed a stored value")
		}
		cleared, err := base.ApplyPatch(json.RawMessage(`{"egress_proxy":{"https_proxy":""},"nvd_mirror_url":"","nvd_api_key":"","smtp":{"password":""},"syslog_siem_target":{"client_key":""},"ca_bundle_pem":""}`))
		if err != nil {
			t.Fatal(err)
		}
		if cleared.EgressProxy.HTTPSProxy != "" || cleared.NVDMirrorURL != "" || cleared.NVDAPIKey != "" || cleared.SMTP.Password != "" || cleared.SyslogSIEM.ClientKey != "" || cleared.CABundlePEM != "" {
			t.Fatal("explicit empty values did not clear secrets")
		}
	}
}

func TestConfigMalformedMirrorRoundtrip(t *testing.T) {
	base := Default()
	base.NVDMirrorURL = "https://user:secret@[invalid"
	patch, err := json.Marshal(base.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	merged, err := base.ApplyPatch(patch)
	if err != nil {
		t.Fatal(err)
	}
	if merged.NVDMirrorURL != base.NVDMirrorURL {
		t.Fatal("fully redacted mirror URL was not preserved")
	}
}

func TestConfigPatchDoesNotMutateOriginalCategories(t *testing.T) {
	for _, patch := range []string{
		`{"syslog_siem_target":{"categories":["changed"]}}`,
		`{"syslog_siem_target":{"categories":["changed"]},"auto_scan_rescan_hours":-1}`,
	} {
		base := Default()
		base.SyslogSIEM.Categories = []string{"original"}
		_, _ = base.ApplyPatch(json.RawMessage(patch))
		if !reflect.DeepEqual(base.SyslogSIEM.Categories, []string{"original"}) {
			t.Fatal("patch mutated the original configuration")
		}
	}
}
