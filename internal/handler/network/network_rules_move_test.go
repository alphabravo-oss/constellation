package network

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func moveRuleFixture(t *testing.T) (*db.DB, uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	orgID, userID, clusterID := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	if _, err := database.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,$2)`, orgID, "move-rule-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = database.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })
	if _, err := database.Pool().Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,$4)`, userID, orgID, userID.String()+"@example.com", "move-rule"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "move-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Pool().Exec(ctx, `INSERT INTO network_rule_overrides (org_id, cluster_id, from_ep, to_ep, priority) VALUES ($1,$2,'default/top','default/db',1000),($1,$2,'default/lower','default/db',1010)`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	return database, orgID, userID, clusterID
}

func moveRuleRequest(database *db.DB, orgID, userID, clusterID uuid.UUID, from string, withAudit bool) *httptest.ResponseRecorder {
	handler := NewNetwork(database)
	if withAudit {
		handler.WithAudit(audit.New(database.Pool()))
	}
	router := chi.NewRouter()
	router.Post("/clusters/{id}/network-rules:move-top", handler.MoveNetworkRuleToTop)
	request := httptest.NewRequest(http.MethodPost, "/clusters/"+clusterID.String()+"/network-rules:move-top", strings.NewReader(`{"from":"`+from+`","to":"default/db"}`))
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: userID}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestMoveNetworkRuleToTopAuditsAndChangesExistingRule(t *testing.T) {
	database, orgID, userID, clusterID := moveRuleFixture(t)
	response := moveRuleRequest(database, orgID, userID, clusterID, "default/lower", true)
	if response.Code != http.StatusOK {
		t.Fatalf("move status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Priority                int   `json:"priority"`
		AuditAttemptID          int64 `json:"audit_attempt_id"`
		CompletionAuditID       int64 `json:"completion_audit_id"`
		CompletionAuditRecorded bool  `json:"completion_audit_recorded"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Priority != 990 || result.AuditAttemptID < 1 || result.CompletionAuditID < 1 || !result.CompletionAuditRecorded {
		t.Fatalf("move result=%+v", result)
	}
	var priority, auditRows int
	if err := database.Pool().QueryRow(context.Background(), `SELECT priority FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2 AND from_ep='default/lower'`, orgID, clusterID).Scan(&priority); err != nil || priority != 990 {
		t.Fatalf("priority=%d err=%v", priority, err)
	}
	if err := database.Pool().QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action IN ('network_rule.move_top_attempt','network_rule.move_top')`, orgID, clusterID.String()+"/default/lower/default/db").Scan(&auditRows); err != nil || auditRows != 2 {
		t.Fatalf("audit rows=%d err=%v", auditRows, err)
	}
}

func TestMoveNetworkRuleToTopRejectsMissingScopeRuleAndAudit(t *testing.T) {
	database, orgID, userID, clusterID := moveRuleFixture(t)
	for _, test := range []struct {
		name      string
		clusterID uuid.UUID
		from      string
		withAudit bool
		status    int
	}{
		{"missing rule", clusterID, "default/missing", true, http.StatusNotFound},
		{"foreign cluster", uuid.New(), "default/lower", true, http.StatusNotFound},
		{"audit absent", clusterID, "default/lower", false, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := moveRuleRequest(database, orgID, userID, test.clusterID, test.from, test.withAudit)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	var count, priority int
	if err := database.Pool().QueryRow(context.Background(), `SELECT count(*) FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("rule count=%d err=%v", count, err)
	}
	if err := database.Pool().QueryRow(context.Background(), `SELECT priority FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2 AND from_ep='default/lower'`, orgID, clusterID).Scan(&priority); err != nil || priority != 1010 {
		t.Fatalf("priority=%d err=%v", priority, err)
	}
}

func TestMoveNetworkRuleToTopSerializesConcurrentMoves(t *testing.T) {
	database, orgID, userID, clusterID := moveRuleFixture(t)
	var group sync.WaitGroup
	statuses := make(chan int, 2)
	for _, from := range []string{"default/top", "default/lower"} {
		group.Add(1)
		go func() {
			defer group.Done()
			statuses <- moveRuleRequest(database, orgID, userID, clusterID, from, true).Code
		}()
	}
	group.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent move status=%d", status)
		}
	}
	rows, err := database.Pool().Query(context.Background(), `SELECT priority FROM network_rule_overrides WHERE org_id=$1 AND cluster_id=$2 ORDER BY priority`, orgID, clusterID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	priorities := []int{}
	for rows.Next() {
		var priority int
		if err := rows.Scan(&priority); err != nil {
			t.Fatal(err)
		}
		priorities = append(priorities, priority)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(priorities) != 2 || priorities[0] != 980 || priorities[1] != 990 {
		t.Fatalf("concurrent priorities=%v", priorities)
	}
}

func TestNetworkRulesPreservesNegativePrecedence(t *testing.T) {
	database, orgID, userID, clusterID := moveRuleFixture(t)
	if _, err := database.Pool().Exec(context.Background(), `UPDATE network_rule_overrides SET priority=-10 WHERE org_id=$1 AND cluster_id=$2 AND from_ep='default/lower'`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	handler := NewNetwork(database)
	router := chi.NewRouter()
	router.Get("/clusters/{id}/network-rules", handler.NetworkRules)
	request := httptest.NewRequest(http.MethodGet, "/clusters/"+clusterID.String()+"/network-rules", nil)
	request = request.WithContext(authctx.WithSubject(request.Context(), authctx.Subject{OrgID: orgID, UserID: userID}))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Rules []struct {
			From     string `json:"from"`
			Priority int64  `json:"priority"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Rules) != 2 || result.Rules[0].From != "default/lower" || result.Rules[0].Priority != -10 {
		t.Fatalf("negative precedence list=%+v", result.Rules)
	}
}
