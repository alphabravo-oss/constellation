package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestNetworkRulesPortableExportImportAuthoredOverrides(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	sourceClusterID := uuid.New()
	targetClusterID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Rules Portable Test')`,
		orgID, "network-rules-portable-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Network Rules Portable User')`,
		userID, orgID, "network-rules-portable-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, state)
VALUES ($1, $2, 'source-cluster', 'connected'),
       ($3, $2, 'target-cluster', 'connected')`,
		sourceClusterID, orgID, targetClusterID); err != nil {
		t.Fatalf("clusters: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO network_rule_overrides
  (org_id, cluster_id, from_ep, to_ep, ports, applications, action, disable, comment, priority, cfg_type, updated_by)
VALUES ($1, $2, 'prod/api', 'prod/db', 'tcp/5432', ARRAY['postgres','postgres'], 'deny', false, 'block direct db', 42, 'user_created', $3)`,
		orgID, sourceClusterID, userID); err != nil {
		t.Fatalf("override: %v", err)
	}

	router := chi.NewRouter()
	h := NewNetwork(d).WithAudit(audit.New(pool))
	router.Get("/clusters/{id}/network-rules:export", h.ExportNetworkRules)
	router.Post("/clusters/{id}/network-rules:import", h.ImportNetworkRules)

	req := httptest.NewRequest(http.MethodGet, "/clusters/"+sourceClusterID.String()+"/network-rules:export", nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export status: %d %s", rec.Code, rec.Body.String())
	}
	exported := rec.Body.String()
	if !strings.Contains(exported, "NetworkRuleBundle") || !strings.Contains(exported, "prod/api") || !strings.Contains(exported, "block direct db") {
		t.Fatalf("exported bundle missing rule: %s", exported)
	}

	req = httptest.NewRequest(http.MethodPost, "/clusters/"+targetClusterID.String()+"/network-rules:import", strings.NewReader(exported))
	req.Header.Set("Content-Type", "application/x-yaml")
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status: %d %s", rec.Code, rec.Body.String())
	}
	var importResp struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&importResp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if importResp.Created != 1 || importResp.Updated != 0 {
		t.Fatalf("import response = %+v", importResp)
	}
	var ports, action, comment, cfgType string
	var apps []string
	var priority int
	if err := pool.QueryRow(ctx, `
SELECT ports, applications, action, comment, priority, cfg_type
  FROM network_rule_overrides
 WHERE org_id=$1 AND cluster_id=$2 AND from_ep='prod/api' AND to_ep='prod/db'`,
		orgID, targetClusterID).Scan(&ports, &apps, &action, &comment, &priority, &cfgType); err != nil {
		t.Fatalf("imported override: %v", err)
	}
	if ports != "tcp/5432" || action != "deny" || comment != "block direct db" || priority != 42 || cfgType != "user_created" {
		t.Fatalf("imported row ports=%s action=%s comment=%s priority=%d cfg=%s", ports, action, comment, priority, cfgType)
	}
	if len(apps) != 1 || apps[0] != "postgres" {
		t.Fatalf("apps = %+v, want deduped postgres", apps)
	}
}

func TestNetworkRulesPortableImportBoundaryAndPerRuleErrors(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Network Rules Boundary Test')`,
		orgID, "network-rules-boundary-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Network Rules Boundary User')`,
		userID, orgID, "network-rules-boundary-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'boundary-cluster', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}

	router := chi.NewRouter()
	router.Post("/clusters/{id}/network-rules:import", NewNetwork(d).WithAudit(audit.New(pool)).ImportNetworkRules)
	importRules := func(contentType, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/clusters/"+clusterID.String()+"/network-rules:import", strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}
	validBundle := "apiVersion: constellation/v1\nkind: NetworkRuleBundle\nrules:\n  - from: prod/api\n    to: prod/db\n"
	for _, tc := range []struct {
		name, contentType, body, errorText string
		status                             int
	}{
		{"missing content type", "", validBundle, "Content-Type must be application/x-yaml", http.StatusUnsupportedMediaType},
		{"JSON content type", "application/json", validBundle, "Content-Type must be application/x-yaml", http.StatusUnsupportedMediaType},
		{"malformed content type", "application/x-yaml; charset=", validBundle, "Content-Type must be application/x-yaml", http.StatusUnsupportedMediaType},
		{"missing apiVersion", "application/x-yaml", strings.Replace(validBundle, "apiVersion: constellation/v1\n", "", 1), "apiVersion must be constellation/v1", http.StatusBadRequest},
		{"wrong apiVersion", "application/x-yaml", strings.Replace(validBundle, "constellation/v1", "constellation/v2", 1), "apiVersion must be constellation/v1", http.StatusBadRequest},
		{"missing kind", "application/x-yaml", strings.Replace(validBundle, "kind: NetworkRuleBundle\n", "", 1), "kind must be NetworkRuleBundle", http.StatusBadRequest},
		{"wrong kind", "application/x-yaml", strings.Replace(validBundle, "NetworkRuleBundle", "OtherBundle", 1), "kind must be NetworkRuleBundle", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := importRules(tc.contentType, tc.body)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.errorText) {
				t.Fatalf("import status=%d body=%s, want %d with %q", rec.Code, rec.Body.String(), tc.status, tc.errorText)
			}
			var count int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&count); err != nil {
				t.Fatalf("count rules: %v", err)
			}
			if count != 0 {
				t.Fatalf("invalid import wrote %d rules", count)
			}
		})
	}
	foreignOrgID, foreignClusterID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Foreign Network Rules Org')`, foreignOrgID, "foreign-network-rules-"+foreignOrgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, foreignOrgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, foreignClusterID, foreignOrgID, "foreign-network-rules-"+foreignClusterID.String()); err != nil {
		t.Fatal(err)
	}
	foreignRequest := httptest.NewRequest(http.MethodPost, "/clusters/"+foreignClusterID.String()+"/network-rules:import", strings.NewReader(validBundle))
	foreignRequest.Header.Set("Content-Type", "application/x-yaml")
	foreignRequest = foreignRequest.WithContext(authctx.WithSubject(foreignRequest.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	foreignResponse := httptest.NewRecorder()
	router.ServeHTTP(foreignResponse, foreignRequest)
	if foreignResponse.Code != http.StatusNotFound {
		t.Fatalf("foreign cluster import status=%d body=%s", foreignResponse.Code, foreignResponse.Body.String())
	}
	var foreignRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, foreignClusterID).Scan(&foreignRows); err != nil || foreignRows != 0 {
		t.Fatalf("foreign cluster rules=%d err=%v", foreignRows, err)
	}
	noAuditRouter := chi.NewRouter()
	noAuditRouter.Post("/clusters/{id}/network-rules:import", NewNetwork(d).ImportNetworkRules)
	noAuditRequest := httptest.NewRequest(http.MethodPost, "/clusters/"+clusterID.String()+"/network-rules:import", strings.NewReader(validBundle))
	noAuditRequest.Header.Set("Content-Type", "application/x-yaml")
	noAuditRequest = noAuditRequest.WithContext(authctx.WithSubject(noAuditRequest.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	noAuditResponse := httptest.NewRecorder()
	noAuditRouter.ServeHTTP(noAuditResponse, noAuditRequest)
	if noAuditResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("audit-free import status=%d body=%s", noAuditResponse.Code, noAuditResponse.Body.String())
	}
	var unauditedRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&unauditedRows); err != nil || unauditedRows != 0 {
		t.Fatalf("unaudited import wrote %d rules, err=%v", unauditedRows, err)
	}

	rec := importRules("application/x-yaml; charset=utf-8", "apiVersion: constellation/v1\nkind: NetworkRuleBundle\nrules:\n  - from: ''\n    to: prod/db\n  - from: prod/api\n    to: prod/db\n")
	if rec.Code != http.StatusOK {
		t.Fatalf("mixed import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode mixed import: %v", err)
	}
	if response.Created != 1 || response.Updated != 0 || len(response.Results) != 2 ||
		response.Results[0].Status != "error" || response.Results[0].Error != "from and to are required" ||
		response.Results[1].Status != "created" {
		t.Fatalf("mixed import response = %+v", response)
	}
	var auditAttempts int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='network_rule.import_attempt' AND target_id=$2`, orgID, clusterID.String()).Scan(&auditAttempts); err != nil || auditAttempts != 1 {
		t.Fatalf("import audit attempts=%d err=%v", auditAttempts, err)
	}
}

func portableImportFixture(t *testing.T) (*db.DB, func(string) *httptest.ResponseRecorder, uuid.UUID, uuid.UUID) {
	t.Helper()
	database := openTestDB(t)
	orgID, userID, clusterID := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,$2)`, orgID, "portable-import-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
		database.Close()
	})
	if _, err := database.Pool().Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Portable Import User')`, userID, orgID, userID.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "portable-import-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/clusters/{id}/network-rules:import", NewNetwork(database).WithAudit(audit.New(database.Pool())).ImportNetworkRules)
	request := func(bundle string) *httptest.ResponseRecorder {
		httpRequest := httptest.NewRequest(http.MethodPost, "/clusters/"+clusterID.String()+"/network-rules:import", strings.NewReader(bundle))
		httpRequest.Header.Set("Content-Type", "application/x-yaml")
		httpRequest = httpRequest.WithContext(authctx.WithSubject(httpRequest.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httpRequest)
		return response
	}
	return database, request, orgID, clusterID
}

func TestNetworkRulesPortableImportCompletionFailureRollsBackWrites(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "create"
		if existing {
			name = "update"
		}
		t.Run(name, func(t *testing.T) {
			database, importRules, orgID, clusterID := portableImportFixture(t)
			ctx := context.Background()
			if existing {
				if _, err := database.Pool().Exec(ctx, `INSERT INTO network_rule_overrides (org_id, cluster_id, from_ep, to_ep, action, priority) VALUES ($1,$2,'prod/api','prod/db','allow',1000)`, orgID, clusterID); err != nil {
					t.Fatal(err)
				}
			}
			const constraint = "test_portable_import_completion_guard"
			statement := fmt.Sprintf(`ALTER TABLE audit_events ADD CONSTRAINT %s CHECK (NOT (org_id='%s' AND action='network_rule.import')) NOT VALID`, constraint, orgID)
			if _, err := database.Pool().Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = database.Pool().Exec(context.Background(), `ALTER TABLE audit_events DROP CONSTRAINT `+constraint)
			})
			response := importRules("apiVersion: constellation/v1\nkind: NetworkRuleBundle\nrules:\n  - from: prod/api\n    to: prod/db\n    action: deny\n    priority: 5\n")
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("completion failure status=%d body=%s", response.Code, response.Body.String())
			}
			var count, attempts, completions int
			if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if err := database.Pool().QueryRow(ctx, `SELECT count(*) FILTER (WHERE action='network_rule.import_attempt'), count(*) FILTER (WHERE action='network_rule.import') FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, clusterID.String()).Scan(&attempts, &completions); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if existing {
				wantCount = 1
				var action string
				var priority int
				if err := database.Pool().QueryRow(ctx, `SELECT action, priority FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2 AND from_ep='prod/api'`, orgID, clusterID).Scan(&action, &priority); err != nil || action != "allow" || priority != 1000 {
					t.Fatalf("updated row survived rollback: action=%s priority=%d err=%v", action, priority, err)
				}
			}
			if count != wantCount || attempts != 1 || completions != 0 {
				t.Fatalf("count=%d attempts=%d completions=%d", count, attempts, completions)
			}
		})
	}
}

func TestNetworkRulesPortableImportAttemptFailurePreventsWrites(t *testing.T) {
	database, importRules, orgID, clusterID := portableImportFixture(t)
	ctx := context.Background()
	const constraint = "test_portable_import_attempt_guard"
	statement := fmt.Sprintf(`ALTER TABLE audit_events ADD CONSTRAINT %s CHECK (NOT (org_id='%s' AND action='network_rule.import_attempt')) NOT VALID`, constraint, orgID)
	if _, err := database.Pool().Exec(ctx, statement); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = database.Pool().Exec(context.Background(), `ALTER TABLE audit_events DROP CONSTRAINT `+constraint)
	})
	response := importRules("apiVersion: constellation/v1\nkind: NetworkRuleBundle\nrules:\n  - from: prod/api\n    to: prod/db\n")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("attempt failure status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := database.Pool().QueryRow(ctx, `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rules=%d err=%v", count, err)
	}
}

func TestNetworkRulesPortableImportKeepsPerRowErrors(t *testing.T) {
	database, importRules, orgID, clusterID := portableImportFixture(t)
	response := importRules("apiVersion: constellation/v1\nkind: NetworkRuleBundle\nrules:\n  - from: prod/bad\n    to: prod/db\n    priority: 2147483648\n  - from: prod/good\n    to: prod/db\n    priority: 7\n")
	if response.Code != http.StatusOK {
		t.Fatalf("mixed import status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
		Results []struct {
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"results"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Created != 1 || result.Updated != 0 || len(result.Results) != 2 || result.Results[0].Status != "error" || result.Results[0].Error == "" || result.Results[1].Status != "created" {
		t.Fatalf("mixed import result=%+v", result)
	}
	var count, completions int
	if err := database.Pool().QueryRow(context.Background(), `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("rules=%d err=%v", count, err)
	}
	if err := database.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='network_rule.import'`, orgID, clusterID.String()).Scan(&completions); err != nil || completions != 1 {
		t.Fatalf("completions=%d err=%v", completions, err)
	}
}

func TestNetworkRulesPortableImportSerializesConcurrentWrites(t *testing.T) {
	database, importRules, orgID, clusterID := portableImportFixture(t)
	const imports = 4
	responses := make(chan *httptest.ResponseRecorder, imports)
	var group sync.WaitGroup
	for index := 0; index < imports; index++ {
		group.Add(1)
		go func(priority int) {
			defer group.Done()
			bundle := fmt.Sprintf("apiVersion: constellation/v1\nkind: NetworkRuleBundle\nrules:\n  - from: prod/api\n    to: prod/db\n    priority: %d\n", priority)
			responses <- importRules(bundle)
		}(index + 1)
	}
	group.Wait()
	close(responses)
	created, updated := 0, 0
	for response := range responses {
		if response.Code != http.StatusOK {
			t.Fatalf("concurrent import status=%d body=%s", response.Code, response.Body.String())
		}
		var result struct {
			Created int `json:"created"`
			Updated int `json:"updated"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		created += result.Created
		updated += result.Updated
	}
	var rules, attempts, completions int
	if err := database.Pool().QueryRow(context.Background(), `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if err := database.Pool().QueryRow(context.Background(), `SELECT count(*) FILTER (WHERE action='network_rule.import_attempt'), count(*) FILTER (WHERE action='network_rule.import') FROM audit_events WHERE org_id=$1 AND target_id=$2`, orgID, clusterID.String()).Scan(&attempts, &completions); err != nil {
		t.Fatal(err)
	}
	if created != 1 || updated != imports-1 || rules != 1 || attempts != imports || completions != imports {
		t.Fatalf("created=%d updated=%d rules=%d attempts=%d completions=%d", created, updated, rules, attempts, completions)
	}
	if broken, err := audit.VerifyChain(context.Background(), database.Pool()); err != nil || broken != nil {
		t.Fatalf("audit chain break=%v err=%v", broken, err)
	}
}
