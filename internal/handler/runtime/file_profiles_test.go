package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestParseFileProfileFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		filter     string
		wantFilter string
		wantPath   string
		wantRegex  string
	}{
		{
			name:       "exact file",
			filter:     "/etc/passwd",
			wantFilter: "/etc/passwd",
			wantPath:   "/etc/passwd",
		},
		{
			name:       "wildcard file",
			filter:     "/usr/bin/*",
			wantFilter: "/usr/bin/*",
			wantPath:   "/usr/bin",
			wantRegex:  ".*",
		},
		{
			name:       "trailing directory",
			filter:     "/var/log/",
			wantFilter: "/var/log/*",
			wantPath:   "/var/log",
			wantRegex:  ".*",
		},
		{
			name:       "escaped dot",
			filter:     "/var/run/secrets/kubernetes.io/serviceaccount/*",
			wantFilter: "/var/run/secrets/kubernetes.io/serviceaccount/*",
			wantPath:   "/var/run/secrets/kubernetes\\.io/serviceaccount",
			wantRegex:  ".*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileProfileFilter(tt.filter)
			if err != nil {
				t.Fatalf("parseFileProfileFilter(%q): %v", tt.filter, err)
			}
			if got.Filter != tt.wantFilter || got.Path != tt.wantPath || got.Regex != tt.wantRegex {
				t.Fatalf("parseFileProfileFilter(%q) = %+v", tt.filter, got)
			}
		})
	}

	for _, filter := range []string{"relative/path", "/", "/etc/[passwd]", "/etc/../shadow", "/etc/./shadow"} {
		t.Run("reject "+filter, func(t *testing.T) {
			if got, err := parseFileProfileFilter(filter); err == nil {
				t.Fatalf("parseFileProfileFilter(%q) = %+v, want error", filter, got)
			}
		})
	}
}

func TestNormalizeFileProfileImportRequest(t *testing.T) {
	t.Parallel()

	raw := `{
	  "schema_version": "constellation-file-profile-v1",
	  "kind": "FileProfile",
	  "mode": "enforce",
		  "rules": [{
		    "filter": "/etc/passwd",
		    "path": "/tmp/stale",
		    "recursive": false,
		    "behavior": "deny",
		    "applications": ["cat", "cat", "sh"],
		    "enabled": false,
		    "description": "protect local account database"
		  }],
		  "exceptions": [{
		    "filter": "/etc/passwd",
		    "applications": ["rpm", "rpm"],
		    "description": "package manager reads passwd"
		  }]
		}`
	req, err := decodeFileProfileImportRequest(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mode, rules, exceptions, warnings, err := normalizeFileProfileImportRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if mode != fileProfileModeEnforce || len(rules) != 1 || len(exceptions) != 1 {
		t.Fatalf("mode/rules/exceptions = %s/%d/%d", mode, len(rules), len(exceptions))
	}
	rule := rules[0]
	if rule.Filter != "/etc/passwd" ||
		rule.Path != "/etc/passwd" ||
		rule.Regex != "" ||
		rule.Behavior != "block_access" ||
		rule.Enabled ||
		len(rule.Applications) != 2 ||
		rule.Applications[0] != "cat" ||
		rule.Applications[1] != "sh" {
		t.Fatalf("normalized rule = %+v", rule)
	}
	if len(warnings) == 0 || !strings.Contains(warnings[0], "path was re-derived") {
		t.Fatalf("warnings = %+v", warnings)
	}
	if exceptions[0].Filter != "/etc/passwd" || len(exceptions[0].Applications) != 1 || exceptions[0].Applications[0] != "rpm" {
		t.Fatalf("normalized exceptions = %+v", exceptions)
	}

	wrapper, err := decodeFileProfileImportRequest(strings.NewReader(`{"bundle":{"rules":[{"filter":"/tmp/*","behavior":"monitor_change"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	mode, rules, exceptions, _, err = normalizeFileProfileImportRequest(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if mode != fileProfileModeMonitor || len(rules) != 1 || len(exceptions) != 0 || rules[0].Filter != "/tmp/*" {
		t.Fatalf("wrapped import = mode:%s rules:%+v exceptions:%+v", mode, rules, exceptions)
	}
}

func TestFileProfilesSetModePersistsAcrossHandlers(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"deployments", "events", "pod_workload_links", "file_profile_states", "file_profile_transitions", "file_profile_rules", "file_profile_exceptions", "file_profile_watch_inventory"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	deploymentID := uuid.New()
	now := time.Now().UTC()
	workloadID := "default/api"
	podWorkloadID := "default/pod/api-7d9c"

	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'File Profile Test')`, orgID, "file-profile-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name, password_hash) VALUES ($1, $2, $3, 'Test User', 'x')`, userID, orgID, "file-profile@example.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'file-profile-cluster', 'k3s', 'connected')`, clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (
    id, org_id, cluster_id, namespace, name, kind, labels, first_seen_at, last_seen_at
) VALUES ($1, $2, $3, 'default', 'api', 'Deployment', '{"app":"api"}'::jsonb, $4, $4)`,
		deploymentID, orgID, clusterID, now); err != nil {
		t.Fatalf("deployment: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO pod_workload_links (
    org_id, cluster_id, namespace, pod_name, pod_uid, pod_workload_id,
    owner_kind, owner_name, owner_workload_id, deployment_id, last_seen_at
) VALUES (
    $1, $2, 'default', 'api-7d9c', 'pod-uid-api', $3,
    'Deployment', 'api', $4, $5, $6
)`, orgID, clusterID, podWorkloadID, workloadID, deploymentID, now); err != nil {
		t.Fatalf("pod workload link: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO events (
    org_id, cluster_id, node_id, kind, source, severity, verdict, workload_id, payload, at
) VALUES
    ($1, $2, 'test-node', 'file_open', 'runtime-agent', 'medium', 'alert', $3,
     '{"comm":"cat","path":"/var/run/secrets/kubernetes.io/serviceaccount/token","flags":0,"mode":0}'::jsonb, $4),
    ($1, $2, 'test-node', 'file_open', 'runtime-agent', 'medium', 'alert', 'default/pod/sibling',
     '{"comm":"cat","path":"/etc/shadow","flags":0,"mode":0}'::jsonb, $4)`,
		orgID, clusterID, podWorkloadID, now); err != nil {
		t.Fatalf("file event: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	body, _ := json.Marshal(map[string]string{"mode": "monitor", "reason": "validated observed file set"})
	rec := httptest.NewRecorder()
	req := baselineRequest(http.MethodPost, "/api/v1/runtime/file-profiles/default%2Fapi/mode?cluster_id="+clusterID.String(), workloadID, bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).SetMode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set mode status=%d body=%s", rec.Code, rec.Body.String())
	}

	recursive := true
	enabled := true
	body, _ = json.Marshal(map[string]any{
		"filter":       "/var/run/secrets/kubernetes.io/serviceaccount/*",
		"recursive":    recursive,
		"behavior":     "monitor_change",
		"applications": []string{"cat", "sh", "cat"},
		"enabled":      enabled,
		"description":  "watch projected service account tokens",
		"reason":       "add sensitive token file monitor",
	})
	rec = httptest.NewRecorder()
	req = fileProfileRuleRequest(http.MethodPost, "/api/v1/runtime/file-profiles/default%2Fapi/rules?cluster_id="+clusterID.String(), workloadID, "", bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).CreateRule(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rule status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created fileProfileRuleDTO
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Filter != "/var/run/secrets/kubernetes.io/serviceaccount/*" ||
		created.Path != "/var/run/secrets/kubernetes\\.io/serviceaccount" ||
		created.Regex != ".*" ||
		!created.Recursive ||
		created.Behavior != "monitor_change" ||
		len(created.Applications) != 2 {
		t.Fatalf("created rule = %+v", created)
	}

	body, _ = json.Marshal(map[string]any{
		"filter":       "/var/run/secrets/kubernetes.io/serviceaccount/*",
		"recursive":    recursive,
		"behavior":     "block_access",
		"applications": []string{"cat"},
		"enabled":      enabled,
		"description":  "block projected token reads by cat",
		"reason":       "enforce token file access",
	})
	rec = httptest.NewRecorder()
	req = fileProfileRuleRequest(http.MethodPut, "/api/v1/runtime/file-profiles/default%2Fapi/rules/"+created.ID+"?cluster_id="+clusterID.String(), workloadID, created.ID, bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).UpdateRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update rule status=%d body=%s", rec.Code, rec.Body.String())
	}

	body, _ = json.Marshal(map[string]any{
		"rule_id":      created.ID,
		"filter":       "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		"applications": []string{"sh", "sh"},
		"description":  "allow shell to read the CA bundle only",
		"reason":       "documented startup probe exception",
	})
	rec = httptest.NewRecorder()
	req = fileProfileExceptionRequest(http.MethodPost, "/api/v1/runtime/file-profiles/default%2Fapi/exceptions?cluster_id="+clusterID.String(), workloadID, "", bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).CreateException(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create exception status=%d body=%s", rec.Code, rec.Body.String())
	}
	var createdException fileProfileExceptionDTO
	if err := json.NewDecoder(rec.Body).Decode(&createdException); err != nil {
		t.Fatal(err)
	}
	if createdException.RuleID != created.ID ||
		createdException.Filter != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" ||
		createdException.Applications[0] != "sh" {
		t.Fatalf("created exception = %+v", createdException)
	}

	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodGet, "/api/v1/runtime/file-profiles/default%2Fapi/export?cluster_id="+clusterID.String(), workloadID, nil, orgID, userID)
	NewFileProfiles(d, nil).Export(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	var exported fileProfileExportBundle
	if err := json.NewDecoder(rec.Body).Decode(&exported); err != nil {
		t.Fatal(err)
	}
	if exported.SchemaVersion != fileProfileBundleSchemaVersion ||
		exported.WorkloadID != workloadID ||
		exported.Mode != "monitor" ||
		len(exported.Rules) != 1 ||
		exported.Rules[0].Behavior != "block_access" ||
		len(exported.Exceptions) != 1 ||
		exported.Exceptions[0].RuleID != created.ID {
		t.Fatalf("exported bundle = %+v", exported)
	}

	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodGet, "/api/v1/runtime/file-profiles/default%2Fapi?cluster_id="+clusterID.String(), workloadID, nil, orgID, userID)
	NewFileProfiles(d, nil).Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got fileProfileDetailDTO
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "monitor" || len(got.Transitions) != 1 || got.Transitions[0].Reason != "validated observed file set" {
		t.Fatalf("file profile detail = %+v", got)
	}
	if len(got.Files) != 1 || got.Files[0].Path != "/var/run/secrets/kubernetes.io/serviceaccount/token" || !got.Files[0].Sensitive {
		t.Fatalf("files = %+v", got.Files)
	}
	if got.SensitivePathCount != 1 || got.MonitoredAlerts24h != 1 {
		t.Fatalf("summary = %+v", got.fileProfileSummaryDTO)
	}
	if got.RuleCount != 1 ||
		len(got.Rules) != 1 ||
		got.Rules[0].Behavior != "block_access" ||
		got.Rules[0].Path != "/var/run/secrets/kubernetes\\.io/serviceaccount" ||
		got.Rules[0].Regex != ".*" ||
		got.Rules[0].Applications[0] != "cat" ||
		len(got.Exceptions) != 1 ||
		got.Exceptions[0].RuleID != created.ID {
		t.Fatalf("rules/exceptions = %+v / %+v", got.Rules, got.Exceptions)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/runtime/file-profile-rules:bundle?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{
		ID:    uuid.New(),
		OrgID: orgID,
		Name:  "agent-test",
	}))
	NewFileProfiles(d, nil).AgentRulesBundle(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("agent bundle status=%d body=%s", rec.Code, rec.Body.String())
	}
	var bundle fileProfileRuleBundleDTO
	if err := json.NewDecoder(rec.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.ClusterID != clusterID.String() ||
		len(bundle.Rules) != 1 ||
		bundle.Rules[0].WorkloadID != workloadID ||
		bundle.Rules[0].PodWorkloadIDs[0] != podWorkloadID ||
		bundle.Rules[0].Mode != "monitor" ||
		bundle.Rules[0].Behavior != "block_access" ||
		bundle.Rules[0].Applications[0] != "cat" ||
		len(bundle.Rules[0].Exceptions) != 1 ||
		bundle.Rules[0].Exceptions[0].ID != createdException.ID {
		t.Fatalf("agent bundle = %+v", bundle)
	}

	body, _ = json.Marshal(map[string]string{"mode": "enforce", "reason": "turn on token file protection"})
	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodPost, "/api/v1/runtime/file-profiles/default%2Fapi/mode?cluster_id="+clusterID.String(), workloadID, bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).SetMode(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("set enforce mode status=%d body=%s", rec.Code, rec.Body.String())
	}

	body, _ = json.Marshal(map[string]any{
		"cluster_id":         clusterID.String(),
		"node":               "node-a",
		"bundle_fingerprint": "fp-test",
		"rules": []map[string]any{{
			"id":                created.ID,
			"protect":           true,
			"enforcement_state": "enforced",
			"files_count":       1,
			"sensitive_count":   0,
			"files": []map[string]any{{
				"path":           "/var/run/secrets/kubernetes.io/serviceaccount/token",
				"container_id":   "abc123",
				"container_name": "api",
				"pod_name":       "api-7d9c",
				"pod_namespace":  "default",
			}},
		}},
	})
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/runtime/file-profile-watches:report", bytes.NewReader(body))
	req = req.WithContext(handler.WithRuntimeAgentToken(req.Context(), &handler.RuntimeAgentToken{
		ID:    uuid.New(),
		OrgID: orgID,
		Name:  "agent-test",
	}))
	NewFileProfiles(d, nil).ReportWatchInventory(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("watch report status=%d body=%s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodGet, "/api/v1/runtime/file-profiles/default%2Fapi?cluster_id="+clusterID.String(), workloadID, nil, orgID, userID)
	NewFileProfiles(d, nil).Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get after watch status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.WatchedFileCount != 1 ||
		len(got.WatchedFiles) != 1 ||
		got.WatchedFiles[0].FilesCount != 1 ||
		got.WatchedFiles[0].SensitiveCount != 1 ||
		!got.WatchedFiles[0].Protect ||
		got.WatchedFiles[0].EnforcementState != "enforced" {
		t.Fatalf("watched files = %+v", got.WatchedFiles)
	}

	body, _ = json.Marshal(map[string]string{"reason": "remove stale token monitor"})
	rec = httptest.NewRecorder()
	req = fileProfileRuleRequest(http.MethodDelete, "/api/v1/runtime/file-profiles/default%2Fapi/rules/"+created.ID+"?cluster_id="+clusterID.String(), workloadID, created.ID, bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).DeleteRule(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("delete rule status=%d body=%s", rec.Code, rec.Body.String())
	}

	body, _ = json.Marshal(map[string]any{
		"bundle":  exported,
		"replace": true,
		"reason":  "restore approved file profile bundle",
	})
	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodPost, "/api/v1/runtime/file-profiles/default%2Fapi:import?cluster_id="+clusterID.String(), workloadID, bytes.NewReader(body), orgID, userID)
	NewFileProfiles(d, nil).Import(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var imported fileProfileImportResponse
	if err := json.NewDecoder(rec.Body).Decode(&imported); err != nil {
		t.Fatal(err)
	}
	if imported.Imported != 1 || imported.Mode != "monitor" || imported.TargetWorkloadID != workloadID || len(imported.Rules) != 1 || len(imported.Exceptions) != 1 {
		t.Fatalf("imported response = %+v", imported)
	}

	rec = httptest.NewRecorder()
	req = baselineRequest(http.MethodGet, "/api/v1/runtime/file-profiles/default%2Fapi?cluster_id="+clusterID.String(), workloadID, nil, orgID, userID)
	NewFileProfiles(d, nil).Get(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("get after import status=%d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Mode != "monitor" || got.RuleCount != 1 || got.Rules[0].Behavior != "block_access" || len(got.Exceptions) != 1 || got.Exceptions[0].RuleID != got.Rules[0].ID {
		t.Fatalf("after import detail = %+v", got)
	}
}

func fileProfileRuleRequest(method, target, workloadID, ruleID string, body *bytes.Reader, orgID, userID uuid.UUID) *http.Request {
	req := baselineRequest(method, target, workloadID, body, orgID, userID)
	rctx := chi.RouteContext(req.Context())
	if ruleID != "" {
		rctx.URLParams.Add("rule_id", ruleID)
	}
	return req
}

func fileProfileExceptionRequest(method, target, workloadID, exceptionID string, body *bytes.Reader, orgID, userID uuid.UUID) *http.Request {
	req := baselineRequest(method, target, workloadID, body, orgID, userID)
	rctx := chi.RouteContext(req.Context())
	if exceptionID != "" {
		rctx.URLParams.Add("exception_id", exceptionID)
	}
	return req
}
