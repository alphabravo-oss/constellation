package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestGroupsUsageMapsConcreteReferencesAndBlocksDelete(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	groupID := uuid.New()
	dlpID := uuid.New()
	groupName := "nv.api-" + groupID.String()[:8]

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Group Usage Test')`,
		orgID, "group-usage-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Group Usage User')`,
		userID, orgID, "group-usage-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'usage-cluster', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, $3, $4, 'ground', '[{"key":"namespace","op":"eq","value":"prod"}]'::jsonb, '["prod/api","prod/web"]'::jsonb, 'monitor', 'protect')`,
		groupID, orgID, clusterID, groupName); err != nil {
		t.Fatalf("group: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode, comment)
VALUES ($1, $2, $3, 'nv.db', '[{"protocol":"tcp","port":5432}]'::jsonb, 'protect', 'postgres edge')`,
		orgID, clusterID, groupName); err != nil {
		t.Fatalf("edge: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO dlp_sensors (id, org_id, cluster_id, name, cfg_type, rules)
VALUES ($1, $2, $3, 'pci sensor', 'user', '[{"name":"cc","pattern":"4[0-9]{12}","action":"block"}]'::jsonb)`,
		dlpID, orgID, clusterID); err != nil {
		t.Fatalf("sensor: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO group_dpi_sensor_bindings (org_id, group_id, sensor_kind, sensor_id, created_by)
VALUES ($1, $2, 'dlp', $3, $4)`,
		orgID, groupID, dlpID, userID); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, event_type, conditions, actions, workload_match, created_by)
VALUES ($1, $2, 'api response', '', true, 'runtime',
        '[{"type":"level","value":"high"}]'::jsonb,
        '[{"kind":"suppress-log"}]'::jsonb,
        $3::jsonb, $4)`,
		orgID, clusterID, `{"group":"`+groupName+`"}`, userID); err != nil {
		t.Fatalf("response rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO policies (org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, $2, 'api admission', '', 'constellation-admission', 'admission', $3, true, 'enforce')`,
		orgID, clusterID, `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: api-admission
spec:
  match:
    kinds: [Pod]
    groups: [`+groupName+`]
  conditions:
    any:
      - field: spec.containers[*].securityContext.privileged
        equals: true
  action: deny
`); err != nil {
		t.Fatalf("admission rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO process_baseline_states (org_id, cluster_id, workload_id, namespace, name, mode, created_by, updated_by)
VALUES ($1, $2, 'prod/api', 'prod', 'api', 'monitor', $3, $3)`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("process baseline state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO process_profile_rules (org_id, cluster_id, workload_id, name, path, action, proc_user, created_by, updated_by)
VALUES ($1, $2, 'prod/api', 'nginx', '/usr/sbin/nginx', 'allow', 'root', $3, $3)`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("process profile rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO file_profile_states (org_id, cluster_id, workload_id, namespace, name, mode, created_by, updated_by)
VALUES ($1, $2, 'prod/api', 'prod', 'api', 'enforce', $3, $3)`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("file profile state: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO file_profile_rules (org_id, cluster_id, workload_id, filter, path, behavior, created_by, updated_by)
VALUES ($1, $2, 'prod/api', 'app-config', '/etc/app', 'monitor_change', $3, $3)`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("file profile rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO file_profile_exceptions (org_id, cluster_id, workload_id, filter, path, applications, created_by, updated_by)
VALUES ($1, $2, 'prod/web', 'log-writer', '/var/log/app.log', ARRAY['logger'], $3, $3)`,
		orgID, clusterID, userID); err != nil {
		t.Fatalf("file profile exception: %v", err)
	}

	h := NewGroups(d, audit.New(pool))
	router := chi.NewRouter()
	router.Get("/groups/{id}/usage", h.Usage)
	router.Put("/groups/{id}", h.Update)
	router.Delete("/groups/{id}", h.Delete)

	req := httptest.NewRequest(http.MethodGet, "/groups/"+groupID.String()+"/usage?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("usage status: %d %s", w.Code, w.Body.String())
	}
	var usage groupUsageDTO
	if err := json.NewDecoder(w.Body).Decode(&usage); err != nil {
		t.Fatalf("decode usage: %v", err)
	}
	if usage.GroupName != groupName {
		t.Fatalf("group name = %q, want %q", usage.GroupName, groupName)
	}
	if usage.Summary.TotalReferences != 9 || usage.Summary.BlockingReferences != 4 || !usage.Summary.DeleteBlocked {
		t.Fatalf("summary = %+v", usage.Summary)
	}
	if usage.Summary.NetworkRules != 1 || usage.Summary.DPISensorBindings != 1 || usage.Summary.ResponseRules != 1 || usage.Summary.AdmissionRules != 1 || usage.Summary.MemberTargets != 2 ||
		usage.Summary.ProcessProfiles != 2 || usage.Summary.FileProfiles != 3 || usage.Summary.DerivedReferences != 5 {
		t.Fatalf("reference counts = %+v", usage.Summary)
	}
	if len(usage.References) != 9 {
		t.Fatalf("references = %+v", usage.References)
	}
	for _, kind := range []string{"response-rule-v2", "admission-rule", "process-baseline-state", "process-profile-rule", "file-profile-state", "file-profile-rule", "file-profile-exception"} {
		if !hasUsageKind(usage.References, kind) {
			t.Fatalf("references omitted %s: %+v", kind, usage.References)
		}
	}
	if !hasCoverageStatus(usage.Coverage, "Process profiles", "derived") ||
		!hasCoverageStatus(usage.Coverage, "File profiles and exceptions", "derived") ||
		!hasCoverageStatus(usage.Coverage, "Response rules", "covered") ||
		!hasCoverageStatus(usage.Coverage, "Admission", "covered") {
		t.Fatalf("coverage omitted not-modeled families: %+v", usage.Coverage)
	}

	updateReq := httptest.NewRequest(http.MethodPut, "/groups/"+groupID.String()+"?cluster_id="+clusterID.String(), strings.NewReader(`{
  "name":"`+groupName+`-renamed",
  "kind":"ground",
  "comment":"rename while referenced",
  "criteria":[{"key":"namespace","op":"eq","value":"prod"}],
  "members":[],
  "learned_from":"",
  "cfg_type":"user",
  "policy_mode":"monitor",
  "profile_mode":"protect"
}`))
	updateReq = updateReq.WithContext(WithSubject(updateReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	updateRec := httptest.NewRecorder()
	router.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusConflict {
		t.Fatalf("update referenced group status: %d %s", updateRec.Code, updateRec.Body.String())
	}
	var updateConflict map[string]any
	if err := json.NewDecoder(updateRec.Body).Decode(&updateConflict); err != nil {
		t.Fatalf("decode update conflict: %v", err)
	}
	if updateConflict["blocking_references"].(float64) != 4 || !jsonArrayContains(updateConflict["changed_fields"], "name") {
		t.Fatalf("update conflict = %+v", updateConflict)
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/groups/"+groupID.String(), nil)
	delReq = delReq.WithContext(WithSubject(delReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	delRec := httptest.NewRecorder()
	router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusConflict {
		t.Fatalf("delete referenced group status: %d %s", delRec.Code, delRec.Body.String())
	}
	var conflict map[string]any
	if err := json.NewDecoder(delRec.Body).Decode(&conflict); err != nil {
		t.Fatalf("decode conflict: %v", err)
	}
	if conflict["blocking_references"].(float64) != 4 {
		t.Fatalf("blocking references = %+v", conflict)
	}

	if _, err := pool.Exec(ctx, `DELETE FROM group_dpi_sensor_bindings WHERE group_id = $1`, groupID); err != nil {
		t.Fatalf("clear bindings: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_rule_edges WHERE org_id = $1 AND (from_group = $2 OR to_group = $2)`, orgID, groupName); err != nil {
		t.Fatalf("clear edges: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM response_rules_v2 WHERE org_id = $1 AND workload_match->>'group' = $2`, orgID, groupName); err != nil {
		t.Fatalf("clear response rule: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM policies WHERE org_id = $1 AND engine = 'constellation-admission'`, orgID); err != nil {
		t.Fatalf("clear admission rule: %v", err)
	}
	delReq = httptest.NewRequest(http.MethodDelete, "/groups/"+groupID.String(), nil)
	delReq = delReq.WithContext(WithSubject(delReq.Context(), Subject{UserID: userID, OrgID: orgID}))
	delRec = httptest.NewRecorder()
	router.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("delete unreferenced group status: %d %s", delRec.Code, delRec.Body.String())
	}
}

func TestOrgWideGroupReferencesCannotBeHiddenByClusterFilter(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, userID, firstClusterID, secondClusterID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	groupName := "org-wide-" + groupID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Group Scope Test')`, []any{orgID, "group-scope-" + orgID.String()}},
		{`INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Group Scope User')`, []any{userID, orgID, "group-scope-" + userID.String() + "@example.com"}},
		{`INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'scope-first', 'connected')`, []any{firstClusterID, orgID}},
		{`INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'scope-second', 'connected')`, []any{secondClusterID, orgID}},
		{`INSERT INTO groups (id, org_id, name, kind, criteria, members, policy_mode, profile_mode) VALUES ($1, $2, $3, 'ground', '[]'::jsonb, '[]'::jsonb, 'monitor', 'monitor')`, []any{groupID, orgID, groupName}},
		{`INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode, comment) VALUES ($1, $2, $3, 'peer', '[]'::jsonb, 'monitor', 'other cluster')`, []any{orgID, secondClusterID, groupName}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatalf("seed group scope: %v", err)
		}
	}

	handler := NewGroups(database, audit.New(pool))
	router := chi.NewRouter()
	router.Get("/groups/{id}/usage", handler.Usage)
	router.Put("/groups/{id}", handler.Update)
	router.Delete("/groups/{id}", handler.Delete)
	request := func(method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}
	path := "/groups/" + groupID.String()
	usage := request(http.MethodGet, path+"/usage?cluster_id="+firstClusterID.String(), "")
	if usage.Code != http.StatusOK {
		t.Fatalf("filtered usage status=%d body=%s", usage.Code, usage.Body.String())
	}
	var result groupUsageDTO
	if err := json.NewDecoder(usage.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Summary.BlockingReferences != 1 || len(result.References) != 1 || result.References[0].ClusterID != secondClusterID.String() {
		t.Fatalf("org-wide group omitted other-cluster reference: %+v", result)
	}

	updateBody := `{"name":"` + groupName + `-renamed","kind":"ground","criteria":[],"members":[],"policy_mode":"monitor","profile_mode":"monitor"}`
	updated := request(http.MethodPut, path+"?cluster_id="+firstClusterID.String(), updateBody)
	if updated.Code != http.StatusConflict {
		t.Fatalf("filtered update status=%d body=%s, want 409", updated.Code, updated.Body.String())
	}
	deleted := request(http.MethodDelete, path, "")
	if deleted.Code != http.StatusConflict {
		t.Fatalf("delete status=%d body=%s, want 409", deleted.Code, deleted.Body.String())
	}
	var storedName string
	if err := pool.QueryRow(ctx, `SELECT name FROM groups WHERE id=$1`, groupID).Scan(&storedName); err != nil || storedName != groupName {
		t.Fatalf("guard changed group name=%q err=%v", storedName, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_rule_edges WHERE org_id=$1 AND cluster_id=$2`, orgID, secondClusterID); err != nil {
		t.Fatal(err)
	}
	updated = request(http.MethodPut, path+"?cluster_id="+firstClusterID.String(), updateBody)
	if updated.Code != http.StatusOK {
		t.Fatalf("unreferenced update status=%d body=%s", updated.Code, updated.Body.String())
	}
}

func TestGroupMutationWaitsForConcurrentReferenceWrite(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		for _, referenceKind := range []string{"network", "dpi", "response", "admission"} {
			t.Run(method+"/"+referenceKind, func(t *testing.T) {
				database := openTestDB(t)
				t.Cleanup(database.Close)
				ctx := context.Background()
				pool := database.Pool()
				orgID, userID, clusterID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
				groupName := "concurrent-" + groupID.String()[:8]
				t.Cleanup(func() {
					_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
				})
				for _, statement := range []struct {
					query string
					args  []any
				}{
					{`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Concurrent Group Test')`, []any{orgID, "concurrent-group-" + orgID.String()}},
					{`INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Concurrent Group User')`, []any{userID, orgID, "concurrent-group-" + userID.String() + "@example.com"}},
					{`INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'concurrent-cluster', 'connected')`, []any{clusterID, orgID}},
					{`INSERT INTO groups (id, org_id, name, kind, criteria, members, policy_mode, profile_mode) VALUES ($1, $2, $3, 'ground', '[]'::jsonb, '[]'::jsonb, 'monitor', 'monitor')`, []any{groupID, orgID, groupName}},
				} {
					if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
						t.Fatal(err)
					}
				}
				writer, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Rollback(ctx)
				var referenceQuery string
				var referenceArgs []any
				switch referenceKind {
				case "network":
					referenceQuery = `
INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode)
VALUES ($1, $2, $3, 'peer', '[]'::jsonb, 'monitor')`
					referenceArgs = []any{orgID, clusterID, groupName}
				case "dpi":
					referenceQuery = `INSERT INTO group_dpi_sensor_bindings (org_id, group_id, sensor_kind, sensor_id) VALUES ($1, $2, 'dlp', $3)`
					referenceArgs = []any{orgID, groupID, uuid.New()}
				case "response":
					referenceQuery = `INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, event_type, conditions, actions, workload_match)
VALUES ($1, $2, 'concurrent response', '', true, 'runtime', '[]'::jsonb, '[]'::jsonb, $3::jsonb)`
					referenceArgs = []any{orgID, clusterID, `{"group":"` + groupName + `"}`}
				case "admission":
					referenceQuery = `INSERT INTO policies (org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode)
VALUES ($1, $2, 'concurrent admission', '', 'constellation-admission', 'admission', $3, true, 'enforce')`
					referenceArgs = []any{orgID, clusterID, "spec:\n  match:\n    groups: [" + groupName + "]\n"}
				}
				if _, err := writer.Exec(ctx, referenceQuery, referenceArgs...); err != nil {
					t.Fatal(err)
				}
				handler := NewGroups(database, audit.New(pool))
				router := chi.NewRouter()
				router.Put("/groups/{id}", handler.Update)
				router.Delete("/groups/{id}", handler.Delete)
				body := ""
				if method == http.MethodPut {
					body = `{"name":"` + groupName + `-renamed","kind":"ground","criteria":[],"policy_mode":"monitor","profile_mode":"monitor"}`
				}
				request := httptest.NewRequest(method, "/groups/"+groupID.String(), strings.NewReader(body))
				request = request.WithContext(WithSubject(request.Context(), Subject{UserID: userID, OrgID: orgID}))
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					response := httptest.NewRecorder()
					router.ServeHTTP(response, request)
					result <- response
				}()
				select {
				case response := <-result:
					t.Fatalf("mutation completed before reference commit: %d %s", response.Code, response.Body.String())
				case <-time.After(120 * time.Millisecond):
				}
				if err := writer.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				select {
				case response := <-result:
					if response.Code != http.StatusConflict {
						t.Fatalf("mutation status=%d body=%s, want 409", response.Code, response.Body.String())
					}
				case <-time.After(5 * time.Second):
					t.Fatal("group mutation did not finish after reference commit")
				}
				var storedName string
				if err := pool.QueryRow(ctx, `SELECT name FROM groups WHERE id=$1`, groupID).Scan(&storedName); err != nil || storedName != groupName {
					t.Fatalf("group changed despite reference: name=%q err=%v", storedName, err)
				}
			})
		}
	}
}

func TestGroupDeleteWaitsForOrgDeletionBeforeTakingReferenceLocks(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Delete Lock Test')`, []any{orgID, "delete-lock-" + orgID.String()}},
		{`INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Delete Lock User')`, []any{userID, orgID, "delete-lock-" + userID.String() + "@example.com"}},
		{`INSERT INTO groups (id, org_id, name, kind, criteria, members, policy_mode, profile_mode) VALUES ($1, $2, $3, 'ground', '[]'::jsonb, '[]'::jsonb, 'monitor', 'monitor')`, []any{groupID, orgID, "delete-lock-" + groupID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	orgDeletion, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer orgDeletion.Rollback(ctx)
	if _, err := orgDeletion.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, orgID); err != nil {
		t.Fatal(err)
	}
	handler := NewGroups(database, audit.New(pool))
	router := chi.NewRouter()
	router.Delete("/groups/{id}", handler.Delete)
	request := httptest.NewRequest(http.MethodDelete, "/groups/"+groupID.String(), nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{UserID: userID, OrgID: orgID}))
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		result <- response
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case response := <-result:
			t.Fatalf("group delete completed while org deletion was uncommitted: %d %s", response.Code, response.Body.String())
		default:
		}
		var waiting int
		if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM pg_stat_activity
 WHERE pid <> pg_backend_pid()
   AND datname = current_database()
   AND query LIKE 'SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE%'
   AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("group delete did not wait on the org row")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := orgDeletion.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-result:
		if response.Code != http.StatusNoContent {
			t.Fatalf("group delete after org rollback status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("group delete did not finish after org rollback")
	}
}

func TestGroupDeleteReleasesPartialReferenceLocksWhileRetrying(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Reference Lock Test')`, []any{orgID, "reference-lock-" + orgID.String()}},
		{`INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Reference Lock User')`, []any{userID, orgID, "reference-lock-" + userID.String() + "@example.com"}},
		{`INSERT INTO groups (id, org_id, name, kind, criteria, members, policy_mode, profile_mode) VALUES ($1, $2, $3, 'ground', '[]'::jsonb, '[]'::jsonb, 'monitor', 'monitor')`, []any{groupID, orgID, "reference-lock-" + groupID.String()}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(ctx)
	if _, err := blocker.Exec(ctx, `LOCK TABLE group_dpi_sensor_bindings IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	handler := NewGroups(database, audit.New(pool))
	router := chi.NewRouter()
	router.Delete("/groups/{id}", handler.Delete)
	request := httptest.NewRequest(http.MethodDelete, "/groups/"+groupID.String(), nil)
	request = request.WithContext(WithSubject(request.Context(), Subject{UserID: userID, OrgID: orgID}))
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		result <- response
	}()
	select {
	case response := <-result:
		t.Fatalf("group delete completed while reference table was locked: %d %s", response.Code, response.Body.String())
	case <-time.After(100 * time.Millisecond):
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := blocker.Exec(ctx, `SAVEPOINT lock_attempt`); err != nil {
			t.Fatal(err)
		}
		_, err := blocker.Exec(ctx, `LOCK TABLE group_rule_edges IN ROW EXCLUSIVE MODE NOWAIT`)
		if err == nil {
			break
		}
		if _, rollbackErr := blocker.Exec(ctx, `ROLLBACK TO SAVEPOINT lock_attempt`); rollbackErr != nil {
			t.Fatal(rollbackErr)
		}
		if time.Now().After(deadline) {
			t.Fatalf("group mutation retained a partial table lock: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-result:
		if response.Code != http.StatusNoContent {
			t.Fatalf("group delete after lock release status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("group delete did not finish after lock release")
	}
}

func TestGroupsListIncludesMembershipPreview(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	groupID := uuid.New()
	groupName := "nv.membership-" + groupID.String()[:8]

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Group Membership Test')`,
		orgID, "group-membership-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Group Membership User')`,
		userID, orgID, "group-membership-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'membership-cluster', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	older := time.Date(2026, 8, 24, 1, 0, 0, 0, time.UTC)
	newer := older.Add(30 * time.Minute)
	if _, err := pool.Exec(ctx, `
INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels, last_seen_at)
VALUES ($1, $2, 'prod', 'api', 'Deployment', '{"app":"api"}'::jsonb, $3),
       ($1, $2, 'prod', 'worker', 'Deployment', '{"app":"worker"}'::jsonb, $4)`,
		orgID, clusterID, older, newer); err != nil {
		t.Fatalf("deployments: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, policy_mode, profile_mode)
VALUES ($1, $2, $3, $4, 'ground', '[{"key":"namespace","op":"eq","value":"prod"}]'::jsonb, '["prod/api","prod/worker"]'::jsonb, 'monitor', 'protect')`,
		groupID, orgID, clusterID, groupName); err != nil {
		t.Fatalf("group: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/groups?cluster_id="+clusterID.String(), nil)
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	w := httptest.NewRecorder()
	NewGroups(d, nil).List(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list status: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Groups []groupDTO `json:"groups"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode groups: %v", err)
	}
	if len(resp.Groups) != 1 {
		t.Fatalf("groups = %+v", resp.Groups)
	}
	got := resp.Groups[0].Membership
	if got.CriteriaCount != 1 || got.MemberCount != 2 || got.PolicyMode != "monitor" || got.ProfileMode != "protect" {
		t.Fatalf("membership counts/modes = %+v", got)
	}
	if got.LastMatchedMember != "prod/worker" || got.LastMatchedAt == nil || !got.LastMatchedAt.Equal(newer) {
		t.Fatalf("last matched = %+v, want prod/worker at %s", got, newer)
	}
}

func hasCoverageStatus(rows []groupUsageCoverageDTO, family, status string) bool {
	for _, row := range rows {
		if row.Family == family && row.Status == status {
			return true
		}
	}
	return false
}

func hasUsageKind(rows []groupUsageReferenceDTO, kind string) bool {
	for _, row := range rows {
		if row.Kind == kind {
			return true
		}
	}
	return false
}

func jsonArrayContains(value any, needle string) bool {
	rows, ok := value.([]any)
	if !ok {
		return false
	}
	for _, row := range rows {
		if row == needle {
			return true
		}
	}
	return false
}
