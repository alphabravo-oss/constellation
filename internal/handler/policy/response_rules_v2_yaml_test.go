package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

func responseRulesYAMLRequest(router http.Handler, method, path, body string, orgID, userID uuid.UUID) *httptest.ResponseRecorder {
	request := withSubj(httptest.NewRequest(method, path, strings.NewReader(body)), orgID, userID)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/yaml; charset=utf-8")
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func responseRulesYAMLFixture(scope, rules string) string {
	return "api_version: constellation.io/v1\nkind: ResponseRules\nscope: " + scope + "\nrules:\n" + rules
}

func TestResponseRulesV2YAMLImportAuditAttemptDoesNotBlockOrgLock(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := responseRuleV2Router(database, pool)
	fixture := responseRulesYAMLFixture("global", "  - name: deadline-rule\n    enabled: true\n    priority: 10\n    event_type: runtime\n    conditions: []\n    actions: []\n    workload_match: {}\n")
	contextWithDeadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request := withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2:import", strings.NewReader(fixture)).WithContext(contextWithDeadline), orgID, userID)
	request.Header.Set("Content-Type", "application/yaml")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if contextWithDeadline.Err() != nil || recorder.Code != http.StatusOK {
		t.Fatalf("nonempty import timed out or failed: deadline=%v status=%d body=%s", contextWithDeadline.Err(), recorder.Code, recorder.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM response_rules_v2 WHERE org_id=$1 AND name='deadline-rule'`, orgID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("imported count=%d err=%v", count, err)
	}
}

func TestResponseRulesV2YAMLExportImportScopedAndAudited(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ensureResponseRulesV2Table(t, pool)
	ensureResponseRulesV2ReceiversTable(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	if _, err := pool.Exec(context.Background(), `INSERT INTO receivers (org_id,name,kind,endpoint) VALUES ($1,'security-team','webhook','https://example.test/hook')`, orgID); err != nil {
		t.Fatal(err)
	}
	clusterID := seedResponseRuleV2Cluster(t, pool, orgID, "yaml-source")
	otherClusterID := seedResponseRuleV2Cluster(t, pool, orgID, "yaml-other")
	insertResponseRuleV2(t, pool, orgID, nil, "yaml-global", 10)
	clusterRuleID := insertResponseRuleV2(t, pool, orgID, clusterID, "yaml-cluster", 20)
	insertResponseRuleV2(t, pool, orgID, otherClusterID, "yaml-other", 30)
	if _, err := pool.Exec(context.Background(), `UPDATE response_rules_v2 SET actions=$1, workload_match=$2 WHERE id=$3`, `[ {"kind":"notify","target":"security-team","params":{"severity":"high"}} ]`, `{"namespace":"prod","labels":{"app":"api"}}`, clusterRuleID); err != nil {
		t.Fatal(err)
	}
	router := responseRuleV2Router(database, pool)

	path := "/api/v1/response-rules-v2:export?cluster_id=" + clusterID.String()
	blocked := responseRulesYAMLRequest(router, http.MethodGet, path, "", orgID, userID)
	if blocked.Code != http.StatusUnprocessableEntity || strings.Contains(blocked.Body.String(), "severity") || strings.Contains(blocked.Body.String(), "high") {
		t.Fatalf("action params export must fail closed, status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	if _, err := pool.Exec(context.Background(), `UPDATE response_rules_v2 SET actions=$1 WHERE id=$2`, `[ {"kind":"notify","target":"security-team","params":{"receiver":"security-team"}}, {"kind":"quarantine","params":{"isolate":"true"}} ]`, clusterRuleID); err != nil {
		t.Fatal(err)
	}
	exported := responseRulesYAMLRequest(router, http.MethodGet, path, "", orgID, userID)
	if exported.Code != http.StatusOK || !strings.HasPrefix(exported.Header().Get("Content-Type"), "application/yaml") {
		t.Fatalf("export status=%d content-type=%q body=%s", exported.Code, exported.Header().Get("Content-Type"), exported.Body.String())
	}
	var document responseRulesYAML
	if err := yaml.Unmarshal(exported.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document.Scope != "cluster" || len(document.Rules) != 1 || document.Rules[0].Name != "yaml-cluster" || document.Rules[0].Priority != 20 || len(document.Rules[0].Actions) != 2 || document.Rules[0].Actions[0].Target != "security-team" || document.Rules[0].Actions[0].Params["receiver"] != "security-team" || document.Rules[0].Actions[1].Params["isolate"] != "true" || document.Rules[0].WorkloadMatch.Namespace != "prod" || document.Rules[0].WorkloadMatch.Labels["app"] != "api" {
		t.Fatalf("cluster export: %+v", document)
	}
	if strings.Contains(exported.Body.String(), orgID.String()) || strings.Contains(exported.Body.String(), clusterID.String()) {
		t.Fatalf("export must not include tenant or cluster identifiers: %s", exported.Body.String())
	}
	global := responseRulesYAMLRequest(router, http.MethodGet, "/api/v1/response-rules-v2:export", "", orgID, userID)
	if global.Code != http.StatusOK || !strings.Contains(global.Body.String(), "yaml-global") || strings.Contains(global.Body.String(), "yaml-cluster") {
		t.Fatalf("global export status=%d body=%s", global.Code, global.Body.String())
	}

	targetOrgID, targetUserID := seedOrgUser(t, pool)
	if _, err := pool.Exec(context.Background(), `INSERT INTO receivers (org_id,name,kind,endpoint) VALUES ($1,'security-team','webhook','https://example.test/target')`, targetOrgID); err != nil {
		t.Fatal(err)
	}
	targetClusterID := seedResponseRuleV2Cluster(t, pool, targetOrgID, "yaml-target")
	importPath := "/api/v1/response-rules-v2:import?cluster_id=" + targetClusterID.String()
	imported := responseRulesYAMLRequest(router, http.MethodPost, importPath, exported.Body.String(), targetOrgID, targetUserID)
	if imported.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", imported.Code, imported.Body.String())
	}
	var result struct {
		Created           int   `json:"created"`
		AttemptAuditID    int64 `json:"audit_attempt_id"`
		CompletionAuditID int64 `json:"completion_audit_id"`
	}
	if err := json.Unmarshal(imported.Body.Bytes(), &result); err != nil || result.Created != 1 || result.AttemptAuditID == 0 || result.CompletionAuditID == 0 {
		t.Fatalf("import result=%+v err=%v", result, err)
	}
	var storedClusterID uuid.UUID
	var storedPriority int
	var storedActions, storedSelector []byte
	if err := pool.QueryRow(context.Background(), `SELECT cluster_id, priority, actions, workload_match FROM response_rules_v2 WHERE org_id=$1 AND name='yaml-cluster'`, targetOrgID).Scan(&storedClusterID, &storedPriority, &storedActions, &storedSelector); err != nil || storedClusterID != targetClusterID || storedPriority != 20 || !strings.Contains(string(storedActions), `"security-team"`) || !strings.Contains(string(storedSelector), `"prod"`) {
		t.Fatalf("import scope=%s priority=%d err=%v", storedClusterID, storedPriority, err)
	}
	var auditCount int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE id IN ($1,$2) AND org_id=$3 AND actor_id=$4 AND action IN ('response_rule_v2.import_attempt','response_rule_v2.import')`, result.AttemptAuditID, result.CompletionAuditID, targetOrgID, targetUserID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("audit count=%d err=%v", auditCount, err)
	}
	foreign := responseRulesYAMLRequest(router, http.MethodPost, "/api/v1/response-rules-v2:import?cluster_id="+clusterID.String(), exported.Body.String(), targetOrgID, targetUserID)
	if foreign.Code != http.StatusNotFound {
		t.Fatalf("foreign cluster import status=%d body=%s", foreign.Code, foreign.Body.String())
	}
	wrongScope := responseRulesYAMLRequest(router, http.MethodPost, "/api/v1/response-rules-v2:import", exported.Body.String(), targetOrgID, targetUserID)
	if wrongScope.Code != http.StatusBadRequest {
		t.Fatalf("wrong-scope import status=%d body=%s", wrongScope.Code, wrongScope.Body.String())
	}
	var sourceReceiverID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT id FROM receivers WHERE org_id=$1 AND name='security-team'`, orgID).Scan(&sourceReceiverID); err != nil {
		t.Fatal(err)
	}
	legacyActions := fmt.Sprintf(`[ {"kind":"notify","target":%q,"params":{"receiver":%q}} ]`, sourceReceiverID.String(), sourceReceiverID.String())
	if _, err := pool.Exec(context.Background(), `UPDATE response_rules_v2 SET actions=$1 WHERE id=$2`, legacyActions, clusterRuleID); err != nil {
		t.Fatal(err)
	}
	normalized := responseRulesYAMLRequest(router, http.MethodGet, path, "", orgID, userID)
	if normalized.Code != http.StatusOK || !strings.Contains(normalized.Body.String(), "security-team") || strings.Contains(normalized.Body.String(), sourceReceiverID.String()) {
		t.Fatalf("receiver ID export status=%d body=%s", normalized.Code, normalized.Body.String())
	}
	importByID := strings.ReplaceAll(exported.Body.String(), "security-team", sourceReceiverID.String())
	rejected := responseRulesYAMLRequest(router, http.MethodPost, importPath+"&on_conflict=replace", importByID, targetOrgID, targetUserID)
	if rejected.Code != http.StatusBadRequest {
		t.Fatalf("receiver ID import status=%d body=%s", rejected.Code, rejected.Body.String())
	}
}

func TestResponseRulesV2YAMLImportConflictsAndRollback(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := responseRuleV2Router(database, pool)
	path := "/api/v1/response-rules-v2:import"
	firstRule := "  - name: yaml-first\n    enabled: true\n    priority: 10\n    event_type: runtime\n    conditions: []\n    actions: []\n    workload_match: {}\n"
	secondRule := "  - name: yaml-second\n    enabled: true\n    priority: 20\n    event_type: runtime\n    conditions: []\n    actions: []\n    workload_match: {}\n"
	fixture := responseRulesYAMLFixture("global", firstRule+secondRule)
	response := responseRulesYAMLRequest(router, http.MethodPost, path, fixture, orgID, userID)
	if response.Code != http.StatusOK {
		t.Fatalf("first import status=%d body=%s", response.Code, response.Body.String())
	}
	response = responseRulesYAMLRequest(router, http.MethodPost, path, fixture, orgID, userID)
	if response.Code != http.StatusConflict {
		t.Fatalf("default conflict status=%d body=%s", response.Code, response.Body.String())
	}
	response = responseRulesYAMLRequest(router, http.MethodPost, path+"?on_conflict=skip", fixture, orgID, userID)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"skipped":2`) {
		t.Fatalf("skip status=%d body=%s", response.Code, response.Body.String())
	}
	updated := strings.Replace(fixture, "priority: 10", "priority: 40", 1)
	updated = strings.Replace(updated, "  - name: yaml-second\n", "  - name: yaml-second\n    on_conflict: skip\n", 1)
	response = responseRulesYAMLRequest(router, http.MethodPost, path+"?on_conflict=replace", updated, orgID, userID)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"replaced":1`) || !strings.Contains(response.Body.String(), `"skipped":1`) {
		t.Fatalf("replace status=%d body=%s", response.Code, response.Body.String())
	}
	var priority int
	if err := pool.QueryRow(context.Background(), `SELECT priority FROM response_rules_v2 WHERE org_id=$1 AND name='yaml-first'`, orgID).Scan(&priority); err != nil || priority != 40 {
		t.Fatalf("replaced priority=%d err=%v", priority, err)
	}

	atomic := responseRulesYAMLFixture("global", strings.Replace(firstRule, "yaml-first", "yaml-new", 1)+secondRule)
	response = responseRulesYAMLRequest(router, http.MethodPost, path, atomic, orgID, userID)
	if response.Code != http.StatusConflict {
		t.Fatalf("atomic conflict status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM response_rules_v2 WHERE org_id=$1 AND name='yaml-new'`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial import count=%d err=%v", count, err)
	}
	clusterID := seedResponseRuleV2Cluster(t, pool, orgID, "yaml-conflict")
	otherScope := responseRulesYAMLFixture("cluster", strings.Replace(firstRule, "yaml-first", "yaml-second", 1))
	response = responseRulesYAMLRequest(router, http.MethodPost, path+"?cluster_id="+clusterID.String()+"&on_conflict=replace", otherScope, orgID, userID)
	if response.Code != http.StatusConflict {
		t.Fatalf("cross-scope conflict status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestResponseRulesV2YAMLRejectsUnsafeDocumentsAndAuditUnavailable(t *testing.T) {
	base := responseRulesYAMLFixture("global", "  - name: valid\n    priority: 10\n    event_type: runtime\n    conditions: []\n    actions: []\n")
	for name, document := range map[string]string{
		"unknown field":         strings.Replace(base, "    priority: 10", "    unknown: value\n    priority: 10", 1),
		"duplicate key":         strings.Replace(base, "    priority: 10", "    priority: 10\n    priority: 20", 1),
		"alias":                 strings.Replace(base, "    conditions: []\n    actions: []", "    conditions: &empty []\n    actions: *empty", 1),
		"anchor":                strings.Replace(base, "    conditions: []", "    conditions: &empty []", 1),
		"multi document":        base + "---\nkind: ResponseRules\n",
		"empty second document": base + "---\n",
		"oversize":              strings.Repeat("x", 1<<20+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeResponseRulesYAML(strings.NewReader(document)); err == nil {
				t.Fatal("accepted unsafe YAML")
			}
		})
	}
	if _, err := decodeResponseRulesYAML(strings.NewReader(base)); err != nil {
		t.Fatalf("valid YAML: %v", err)
	}
	if err := validateResponseRulesYAML(responseRulesYAML{APIVersion: "constellation.io/v1", Kind: "ResponseRules", Scope: "global", Rules: []responseRuleYAMLRule{{Name: "bad", Priority: 10, EventType: "nonsense"}}}, "global", "error"); err == nil {
		t.Fatal("invalid event type accepted")
	}
	secretParams := strings.Replace(base, "    actions: []", "    actions:\n      - kind: notify\n        target: security-team\n        params:\n          token: should-never-be-portable", 1)
	secretDocument, err := decodeResponseRulesYAML(strings.NewReader(secretParams))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateResponseRulesYAML(secretDocument, "global", "error"); err == nil {
		t.Fatal("action params accepted in portable YAML")
	}
	if _, err := decodeResponseRulesYAML(strings.NewReader("\n")); err == nil {
		t.Fatal("empty YAML accepted")
	}

	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	ensureResponseRulesV2Table(t, pool)
	orgID, userID := seedOrgUser(t, pool)
	router := chi.NewRouter()
	router.Post("/api/v1/response-rules-v2:import", NewResponseRulesV2(database, nil).ImportYAML)
	response := responseRulesYAMLRequest(router, http.MethodPost, "/api/v1/response-rules-v2:import", base, orgID, userID)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit unavailable status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM response_rules_v2 WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("audit unavailable persisted %d rules: %v", count, err)
	}
	request := withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2:import", strings.NewReader(base)), orgID, userID)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-YAML media type status=%d body=%s", response.Code, response.Body.String())
	}
	request = withSubj(httptest.NewRequest(http.MethodPost, "/api/v1/response-rules-v2:import", strings.NewReader(base)), orgID, userID)
	request.Header.Set("Content-Type", "application/yaml; charset=iso-8859-1")
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-UTF-8 media type status=%d body=%s", response.Code, response.Body.String())
	}
}
