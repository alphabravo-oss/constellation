package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestGroupCreateAndUpdateRollBackFailedProfilePropagation(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID, clusterID, userID := uuid.New(), uuid.New(), uuid.New()
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID) })
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Atomic Group Mode')`, orgID, "atomic-group-mode-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1,$2,$3,'Atomic Group User')`, userID, orgID, "atomic-group-mode-"+userID.String()+"@example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1,$2,$3)`, clusterID, orgID, "atomic-group-mode-"+clusterID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments (org_id, cluster_id, namespace, name, kind, labels) VALUES ($1,$2,'default','a','Deployment','{}'), ($1,$2,'default','b','Deployment','{}')`, orgID, clusterID); err != nil {
		t.Fatal(err)
	}
	constraint := "atomic_group_mode_" + orgID.String()[:8]
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `ALTER TABLE process_baseline_states DROP CONSTRAINT IF EXISTS `+constraint)
	})
	if _, err := pool.Exec(ctx, `ALTER TABLE process_baseline_states ADD CONSTRAINT `+constraint+` CHECK (NOT (org_id='`+orgID.String()+`'::uuid AND workload_id='default/b' AND mode='enforce')) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	handler := NewGroups(database, audit.New(pool))
	create := func(name, mode string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/groups?cluster_id="+clusterID.String(), strings.NewReader(`{"name":"`+name+`","kind":"ground","criteria":[{"key":"namespace","op":"eq","value":"default"}],"cfg_type":"user","policy_mode":"monitor","profile_mode":"`+mode+`"}`))
		request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: orgID, UserID: userID}))
		response := httptest.NewRecorder()
		handler.Create(response, request)
		return response
	}
	if response := create("atomic-failed", "protect"); response.Code != http.StatusInternalServerError {
		t.Fatalf("failed create status=%d body=%s", response.Code, response.Body.String())
	}
	var groups, baselines int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM groups WHERE org_id=$1 AND name='atomic-failed'`, orgID).Scan(&groups); err != nil || groups != 0 {
		t.Fatalf("partial group=%d err=%v", groups, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1`, orgID).Scan(&baselines); err != nil || baselines != 0 {
		t.Fatalf("partial create baselines=%d err=%v", baselines, err)
	}
	if response := create("atomic-update", "monitor"); response.Code != http.StatusCreated {
		t.Fatalf("setup create status=%d body=%s", response.Code, response.Body.String())
	}
	var groupID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM groups WHERE org_id=$1 AND name='atomic-update'`, orgID).Scan(&groupID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/groups/"+groupID.String()+"?cluster_id="+clusterID.String(), strings.NewReader(`{"name":"atomic-update","kind":"ground","criteria":[{"key":"namespace","op":"eq","value":"default"}],"cfg_type":"user","policy_mode":"monitor","profile_mode":"protect"}`))
	request = request.WithContext(WithSubject(request.Context(), Subject{OrgID: orgID, UserID: userID}))
	response := httptest.NewRecorder()
	router := chi.NewRouter()
	router.Put("/groups/{id}", handler.Update)
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("failed update status=%d body=%s", response.Code, response.Body.String())
	}
	var mode string
	if err := pool.QueryRow(ctx, `SELECT profile_mode FROM groups WHERE id=$1`, groupID).Scan(&mode); err != nil || mode != "monitor" {
		t.Fatalf("group profile mode=%q err=%v", mode, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM process_baseline_states WHERE org_id=$1 AND mode='enforce'`, orgID).Scan(&baselines); err != nil || baselines != 0 {
		t.Fatalf("partial update baselines=%d err=%v", baselines, err)
	}
}
