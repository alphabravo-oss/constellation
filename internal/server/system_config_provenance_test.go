package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/syscfg"
)

func TestSystemConfig_ProvenanceAppliedReloadAndAudit(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://bootstrap-user:bootstrap-secret@proxy.test:3128")
	t.Setenv("CONSTELLATION_TLS_VERIFY", "true")
	srv, server, pool, signer, adminID, _, orgID := newSysConfigTestServer(t)
	ctx := context.Background()
	admin := issueFor(t, signer, adminID, orgID, 0)
	status, body := doJSON(t, http.MethodGet, server.URL+"/api/v1/system/config", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("GET status=%d body=%+v", status, body)
	}
	assertConfigSource(t, body, "tls_verify", "environment_bootstrap", false)
	assertConfigSource(t, body, "egress_proxy.https_proxy", "environment_bootstrap", true)
	assertConfigSource(t, body, "events_retention_days", "default", false)
	assertConfigApplied(t, body, body["revision"].(float64), "current")
	remote := syscfg.NewProvider(pool)
	_ = remote.Get(ctx, orgID)
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	patch := map[string]any{
		"tls_verify":            true,
		"events_retention_days": 0,
		"egress_proxy":          map[string]any{"https_proxy": proxy.URL},
		"nvd_api_key":           "nvd-secret-never-return",
	}
	status, body = doJSON(t, http.MethodPatch, server.URL+"/api/v1/system/config", admin, patch)
	if status != http.StatusOK {
		t.Fatalf("PATCH status=%d body=%+v", status, body)
	}
	assertConfigSource(t, body, "tls_verify", "database", false)
	assertConfigSource(t, body, "events_retention_days", "database", false)
	assertConfigSource(t, body, "nvd_api_key", "database", true)
	assertConfigSource(t, body, "scan_job_retention_days", "default", false)
	revision := int64(body["revision"].(float64))
	assertConfigApplied(t, body, float64(revision), "current")
	if remote.Applied(orgID, revision).Status != "behind" {
		t.Fatal("remote cache lag not exposed")
	}
	if remote.Refresh(ctx) != 1 || remote.Applied(orgID, revision).Status != "current" {
		t.Fatal("remote refresh did not apply new revision")
	}
	for _, provider := range []*syscfg.Provider{srv.syscfg, remote} {
		client := provider.HTTPClient(ctx, orgID, time.Second)
		response, err := client.Get("http://reload-config.invalid/test")
		client.CloseIdleConnections()
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("proxy status=%d", response.StatusCode)
		}
	}
	if proxyHits.Load() != 2 {
		t.Fatal("both provider clients must use reloaded proxy")
	}
	var before, after string
	if err := pool.QueryRow(ctx, `SELECT before::text, after::text FROM audit_events WHERE org_id=$1 AND action='system.config.update' ORDER BY id DESC LIMIT 1`, orgID).Scan(&before, &after); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"bootstrap-user", "bootstrap-secret", "nvd-secret-never-return"} {
		if strings.Contains(before+after, secret) {
			t.Fatalf("audit leaked secret %q", secret)
		}
	}
	if !strings.Contains(before+after, "REDACTED") {
		t.Fatal("audit must preserve redacted before/after snapshots")
	}
	status, body = doJSON(t, http.MethodGet, server.URL+"/api/v1/system/config", admin, nil)
	if status != http.StatusOK {
		t.Fatalf("GET after PATCH status=%d", status)
	}
	assertConfigSource(t, body, "events_retention_days", "database", false)
	assertConfigApplied(t, body, float64(revision), "current")
}

func TestSystemConfig_RedactedFieldErrorsDoNotMutateAndRBAC(t *testing.T) {
	_, server, pool, signer, adminID, auditorID, orgID := newSysConfigTestServer(t)
	admin := issueFor(t, signer, adminID, orgID, 0)
	_, initial := doJSON(t, http.MethodGet, server.URL+"/api/v1/system/config", admin, nil)
	cases := []struct{ name, patch, field string }{
		{"proxy", `{"egress_proxy":{"https_proxy":"ftp://private-user:private-secret@proxy.test"}}`, "egress_proxy.https_proxy"},
		{"enum", `{"syslog_siem_target":{"host":"collector.test","port":514,"protocol":"private-secret"}}`, "syslog_siem_target.protocol"},
		{"unknown", `{"private-secret":true}`, "$"},
		{"nested unknown", `{"smtp":{"private-secret":true}}`, "$"},
		{"type", `{"tls_verify":"private-secret"}`, "tls_verify"},
		{"null", `{"smtp":null}`, "smtp"},
		{"root null", `null`, "$"},
		{"trailing", `{} {"private-secret":true}`, "$"},
	}
	for _, testcase := range cases {
		t.Run(testcase.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPatch, server.URL+"/api/v1/system/config", strings.NewReader(testcase.patch))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer "+admin)
			request.Header.Set("Content-Type", "application/json")
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			payload, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.StatusCode, payload)
			}
			if strings.Contains(string(payload), "private-secret") || strings.Contains(string(payload), "private-user") {
				t.Fatalf("error leaked rejected values: %s", payload)
			}
			var body struct {
				Fields []syscfg.FieldError `json:"field_errors"`
			}
			if err := json.Unmarshal(payload, &body); err != nil || len(body.Fields) == 0 || body.Fields[0].Field != testcase.field {
				t.Fatalf("invalid field errors: %s (%v)", payload, err)
			}
		})
	}
	_, final := doJSON(t, http.MethodGet, server.URL+"/api/v1/system/config", admin, nil)
	if final["revision"] != initial["revision"] {
		t.Fatal("rejected mutation bumped revision")
	}
	var auditCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='system.config.update'`, orgID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("rejected mutation produced audit update: count=%d err=%v", auditCount, err)
	}
	auditor := issueFor(t, signer, auditorID, orgID, 0)
	for _, method := range []string{http.MethodGet, http.MethodPatch} {
		status, body := doJSON(t, method, server.URL+"/api/v1/system/config", auditor, map[string]any{"tls_verify": false})
		if status != http.StatusForbidden || body["provenance"] != nil || body["field_errors"] != nil {
			t.Fatalf("RBAC %s status=%d body=%+v", method, status, body)
		}
	}
}

func assertConfigSource(t *testing.T, body map[string]any, field, source string, redacted bool) {
	t.Helper()
	provenance, ok := body["provenance"].(map[string]any)
	if !ok {
		t.Fatalf("missing provenance: %+v", body)
	}
	entry, ok := provenance[field].(map[string]any)
	if !ok || entry["source"] != source || entry["redacted"] != redacted {
		t.Fatalf("%s provenance=%+v, want source=%s redacted=%v", field, entry, source, redacted)
	}
}

func assertConfigApplied(t *testing.T, body map[string]any, revision float64, status string) {
	t.Helper()
	applied, ok := body["applied"].(map[string]any)
	if !ok {
		t.Fatalf("missing applied: %+v", body)
	}
	provider, ok := applied["provider"].(map[string]any)
	if !ok || provider["revision"] != revision || provider["status"] != status || provider["scope"] != "serving_replica" || provider["component"] != "system_config_provider" {
		t.Fatalf("wrong applied provider: %+v", provider)
	}
}
