package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func TestGroupsPromoteSupportsExplicitModeChangeAndProfilePropagation(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	policyGroupID := uuid.New()
	profileGroupID := uuid.New()
	learnedGroupID := uuid.New()

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Group Promote Test')`,
		orgID, "group-promote-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Group Promote User')`,
		userID, orgID, "group-promote-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name, state) VALUES ($1, $2, 'promote-cluster', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO groups (id, org_id, cluster_id, name, kind, criteria, members, cfg_type, policy_mode, profile_mode)
VALUES ($1, $2, $4, 'nv.promote-policy', 'ground', '[]'::jsonb, '[]'::jsonb, 'user', 'discover', 'monitor'),
       ($3, $2, $4, 'nv.demote-profile', 'ground', '[]'::jsonb, '["prod/api"]'::jsonb, 'user', 'monitor', 'protect'),
       ($5, $2, $4, 'nv.learned-profile', 'learned', '[]'::jsonb, '["prod/worker"]'::jsonb, 'learned', 'monitor', 'protect')`,
		policyGroupID, orgID, profileGroupID, clusterID, learnedGroupID); err != nil {
		t.Fatalf("groups: %v", err)
	}

	h := NewGroups(d, audit.New(pool))
	router := chi.NewRouter()
	router.Post("/groups:promote", h.Promote)

	req := httptest.NewRequest(http.MethodPost, "/groups:promote?cluster_id="+clusterID.String(),
		strings.NewReader(`{"dimension":"policy","from":"discover"}`))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy promote status: %d %s", rec.Code, rec.Body.String())
	}
	var legacyResp struct {
		From     string `json:"from"`
		To       string `json:"to"`
		Changed  int    `json:"changed"`
		Promoted int    `json:"promoted"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&legacyResp); err != nil {
		t.Fatalf("decode legacy promote: %v", err)
	}
	if legacyResp.From != "discover" || legacyResp.To != "monitor" || legacyResp.Changed != 1 || legacyResp.Promoted != 1 {
		t.Fatalf("legacy promote response = %+v", legacyResp)
	}

	req = httptest.NewRequest(http.MethodPost, "/groups:promote?cluster_id="+clusterID.String(),
		strings.NewReader(`{"dimension":"profile","from":"protect","to":"monitor"}`))
	req = req.WithContext(WithSubject(req.Context(), Subject{UserID: userID, OrgID: orgID}))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit mode status: %d %s", rec.Code, rec.Body.String())
	}
	var explicitResp struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Changed int    `json:"changed"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&explicitResp); err != nil {
		t.Fatalf("decode explicit mode: %v", err)
	}
	if explicitResp.From != "protect" || explicitResp.To != "monitor" || explicitResp.Changed != 1 {
		t.Fatalf("explicit mode response = %+v", explicitResp)
	}

	var policyMode, profileMode, learnedProfileMode string
	if err := pool.QueryRow(ctx, `SELECT policy_mode FROM groups WHERE id=$1`, policyGroupID).Scan(&policyMode); err != nil {
		t.Fatalf("policy mode: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT profile_mode FROM groups WHERE id=$1`, profileGroupID).Scan(&profileMode); err != nil {
		t.Fatalf("profile mode: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT profile_mode FROM groups WHERE id=$1`, learnedGroupID).Scan(&learnedProfileMode); err != nil {
		t.Fatalf("learned profile mode: %v", err)
	}
	if policyMode != "monitor" || profileMode != "monitor" || learnedProfileMode != "protect" {
		t.Fatalf("modes policy=%s profile=%s learned=%s", policyMode, profileMode, learnedProfileMode)
	}
	var baselineMode string
	if err := pool.QueryRow(ctx, `
SELECT mode
  FROM process_baseline_states
 WHERE org_id=$1 AND cluster_id=$2 AND workload_id='prod/api'`, orgID, clusterID).Scan(&baselineMode); err != nil {
		t.Fatalf("baseline mode: %v", err)
	}
	if baselineMode != "monitor" {
		t.Fatalf("baseline mode = %s, want monitor", baselineMode)
	}
}
