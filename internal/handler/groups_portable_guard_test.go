package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGroupImportCannotChangeReferencedCriteria(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	orgID, userID, clusterID, otherClusterID, groupID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	groupName := "portable-" + groupID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Portable Group')`, []any{orgID, "portable-" + orgID.String()}},
		{`INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Portable User')`, []any{userID, orgID, "portable-" + userID.String() + "@example.com"}},
		{`INSERT INTO clusters (id, org_id, name, state) VALUES ($1,$2,$3,'connected')`, []any{clusterID, orgID, "portable-" + clusterID.String()}},
		{`INSERT INTO clusters (id, org_id, name, state) VALUES ($1,$2,$3,'connected')`, []any{otherClusterID, orgID, "portable-" + otherClusterID.String()}},
		{`INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members) VALUES ($1,$2,$3,$4,'ground',$5::jsonb,'[]'::jsonb)`, []any{groupID, orgID, clusterID, groupName, `[ {"key":"namespace","op":"eq","value":"before"} ]`}},
		{`INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode) VALUES ($1,$2,$3,'external','[]'::jsonb,'monitor')`, []any{orgID, clusterID, groupName}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewGroups(database, nil)
	importGroup := func(value, comment string, scope ...uuid.UUID) (int, map[string]any) {
		t.Helper()
		bundle := groupBundle{APIVersion: "constellation/v1", Kind: "GroupBundle", Groups: []portableGroup{{
			Name: groupName, Kind: "ground", Comment: comment,
			Criteria: []portableGroupCriterion{{Key: "namespace", Op: "eq", Value: value}},
		}}}
		body, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		query := "?cluster_id=" + clusterID.String()
		if len(scope) > 0 {
			if scope[0] == uuid.Nil {
				query = ""
			} else {
				query = "?cluster_id=" + scope[0].String()
			}
		}
		request := httptest.NewRequest(http.MethodPost, "/groups:import"+query, strings.NewReader(string(body)))
		request = request.WithContext(WithSubject(request.Context(), Subject{UserID: userID, OrgID: orgID}))
		response := httptest.NewRecorder()
		handler.Import(response, request)
		var result map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return response.Code, result
	}
	for _, scope := range []uuid.UUID{uuid.Nil, otherClusterID} {
		if code, result := importGroup("after", "wrong scope", scope); code != http.StatusOK || result["updated"] != float64(0) || result["results"].([]any)[0].(map[string]any)["status"] != "error" {
			t.Fatalf("out-of-scope import: scope=%s code=%d result=%v", scope, code, result)
		}
	}
	if code, result := importGroup("after", "blocked"); code != http.StatusOK || result["updated"] != float64(0) || result["results"].([]any)[0].(map[string]any)["status"] != "error" {
		t.Fatalf("referenced criteria import: code=%d result=%v", code, result)
	}
	var savedCriteria []byte
	if err := pool.QueryRow(ctx, `SELECT criteria FROM groups WHERE id=$1`, groupID).Scan(&savedCriteria); err != nil || !strings.Contains(string(savedCriteria), "before") {
		t.Fatalf("criteria changed despite rejection: %s err=%v", savedCriteria, err)
	}
	if code, result := importGroup("before", "allowed comment"); code != http.StatusOK || result["updated"] != float64(1) {
		t.Fatalf("comment-only import: code=%d result=%v", code, result)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_rule_edges WHERE org_id=$1 AND from_group=$2`, orgID, groupName); err != nil {
		t.Fatal(err)
	}
	writer, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err := writer.Exec(ctx, `INSERT INTO group_rule_edges (org_id, cluster_id, from_group, to_group, ports, mode) VALUES ($1,$2,$3,'external','[]'::jsonb,'monitor')`, orgID, clusterID, groupName); err != nil {
		t.Fatal(err)
	}
	resultCh := make(chan map[string]any, 1)
	go func() {
		_, result := importGroup("after", "blocked by in-flight edge")
		resultCh <- result
	}()
	select {
	case result := <-resultCh:
		t.Fatalf("import completed before edge writer committed: %v", result)
	case <-time.After(120 * time.Millisecond):
	}
	if err := writer.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-resultCh:
		if result["updated"] != float64(0) || result["results"].([]any)[0].(map[string]any)["status"] != "error" {
			t.Fatalf("import after edge commit: %v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("import did not finish after edge writer committed")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM group_rule_edges WHERE org_id=$1 AND from_group=$2`, orgID, groupName); err != nil {
		t.Fatal(err)
	}
	if code, result := importGroup("after", "allowed criteria"); code != http.StatusOK || result["updated"] != float64(1) {
		t.Fatalf("unreferenced criteria import: code=%d result=%v", code, result)
	}
}

func TestGroupImportRollsBackFailedProfilePropagation(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	ctx := context.Background()
	orgID, userID, clusterID := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Portable Atomic')`, orgID, "portable-atomic-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Portable Atomic User')`, userID, orgID, "portable-atomic-"+userID.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "portable-atomic-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES ($1,$2,'default','a','Deployment','{}'), ($1,$2,'default','b','Deployment','{}')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	constraint := "portable_atomic_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE process_baseline_states DROP CONSTRAINT IF EXISTS `+constraint)
	})
	if _, err := pool.Exec(ctx, `ALTER TABLE process_baseline_states ADD CONSTRAINT `+constraint+` CHECK (NOT (org_id='`+orgID.String()+`'::uuid AND workload_id='default/b' AND mode='enforce')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	handler := NewGroups(database, nil)
	importMode := func(mode string) map[string]any {
		t.Helper()
		bundle := groupBundle{APIVersion: "constellation/v1", Kind: "GroupBundle", Groups: []portableGroup{{
			Name: "portable-atomic", Kind: "ground", PolicyMode: "monitor", ProfileMode: mode,
			Criteria: []portableGroupCriterion{{Key: "namespace", Op: "eq", Value: "default"}},
		}}}
		encoded, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/groups:import?cluster_id="+clusterID.String(), strings.NewReader(string(encoded)))
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: orgID, UserID: userID}))
		response := httptest.NewRecorder()
		handler.Import(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("import status=%d body=%s", response.Code, response.Body.String())
		}
		var result map[string]any
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	if result := importMode("protect"); result["created"] != float64(0) {
		t.Fatalf("failed create counted as success: %+v", result)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name='portable-atomic'`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial imported group=%d err=%v", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial create baselines=%d err=%v", count, err)
	}
	if result := importMode("monitor"); result["created"] != float64(1) {
		t.Fatalf("monitor create: %+v", result)
	}
	if result := importMode("protect"); result["updated"] != float64(0) {
		t.Fatalf("failed update counted as success: %+v", result)
	}
	var mode string
	if err := pool.QueryRow(ctx, `SELECT profile_mode FROM groups WHERE org_id=$1 AND name='portable-atomic'`, orgID).Scan(&mode); err != nil || mode != "monitor" {
		t.Fatalf("group mode after failed update=%q err=%v", mode, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1 AND mode='enforce'`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial update baselines=%d err=%v", count, err)
	}
}
