package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestCreateAdmissionRuleRejectsClusterGroupWithoutClusterScope(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	pool := database.Pool()
	orgID, userID := seedOrgUser(t, pool)
	clusterID := seedResponseRuleV2Cluster(t, pool, orgID, "admission-scope")
	for _, group := range []struct {
		name      string
		clusterID any
	}{
		{"admission-global", nil},
		{"admission-cluster", clusterID},
	} {
		if _, err := pool.Exec(context.Background(), `INSERT INTO groups (org_id, cluster_id, name, kind) VALUES ($1,$2,$3,'ground')`,
			orgID, group.clusterID, group.name); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewPolicies(database, nil, nil)
	for _, test := range []struct {
		name       string
		group      string
		query      string
		wantStatus int
	}{
		{"reject-cluster", "admission-cluster", "", http.StatusBadRequest},
		{"accept-global", "admission-global", "", http.StatusCreated},
		{"accept-cluster", "admission-cluster", "?cluster_id=" + clusterID.String(), http.StatusCreated},
	} {
		body, err := json.Marshal(map[string]any{
			"name": test.name, "mode": "monitor", "group": test.group,
			"criteria": []map[string]string{{"key": "disallow_latest_tag", "value": "true"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/policies/admission/rules"+test.query, strings.NewReader(string(body)))
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		response := httptest.NewRecorder()
		handler.CreateAdmissionRule(response, request)
		if response.Code != test.wantStatus {
			t.Fatalf("%s status=%d body=%s", test.name, response.Code, response.Body.String())
		}
	}
}

func TestCreateAdmissionRuleRejectsGroupRenamedDuringWrite(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, userID, groupID := uuid.New(), uuid.New(), uuid.New()
	oldName := "admission-race-" + groupID.String()[:8]
	newName := oldName + "-new"
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	for _, statement := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Admission Group Race')`, []any{orgID, "admission-race-" + orgID.String()}},
		{`INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Admission Group User')`, []any{userID, orgID, "admission-race-" + userID.String() + "@example.com"}},
		{`INSERT INTO groups (id, org_id, name, kind, criteria, members, policy_mode, profile_mode) VALUES ($1, $2, $3, 'ground', '[]'::jsonb, '[]'::jsonb, 'monitor', 'monitor')`, []any{groupID, orgID, oldName}},
	} {
		if _, err := pool.Exec(ctx, statement.query, statement.args...); err != nil {
			t.Fatal(err)
		}
	}
	mutation, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer mutation.Rollback(ctx)
	if _, err := mutation.Exec(ctx, `LOCK TABLE policies IN SHARE MODE`); err != nil {
		t.Fatal(err)
	}
	if _, err := mutation.Exec(ctx, `UPDATE groups SET name=$1 WHERE id=$2`, newName, groupID); err != nil {
		t.Fatal(err)
	}
	handler := NewPolicies(database, nil, nil)
	requestRule := func(name, groupName string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"name": name, "mode": "monitor", "group": groupName,
			"criteria": []map[string]string{{"key": "disallow_latest_tag", "value": "true"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/policies/admission/rules", strings.NewReader(string(body)))
		request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
		response := httptest.NewRecorder()
		handler.CreateAdmissionRule(response, request)
		return response
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- requestRule("old group rule", oldName)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case response := <-result:
			t.Fatalf("rule write completed before group rename committed: %d %s", response.Code, response.Body.String())
		default:
		}
		var waiting int
		if err := pool.QueryRow(ctx, `
SELECT COUNT(*) FROM pg_stat_activity
 WHERE pid <> pg_backend_pid()
   AND datname = current_database()
   AND query LIKE 'LOCK TABLE policies IN ROW EXCLUSIVE MODE%'
   AND wait_event_type = 'Lock'`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("admission rule writer did not wait for policy-table mutation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := mutation.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-result:
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "group not found") {
			t.Fatalf("old group rule status=%d body=%s", response.Code, response.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("admission rule writer did not finish after rename")
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND name='old group rule'`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("old group rule persisted: count=%d err=%v", count, err)
	}
	response := requestRule("new group rule", newName)
	if response.Code != http.StatusCreated {
		t.Fatalf("new group rule status=%d body=%s", response.Code, response.Body.String())
	}
}
