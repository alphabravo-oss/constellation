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

	"github.com/alphabravocompany/constellation/pkg/audit"
)

func bulkGroupRequest(t *testing.T, policies *Policies, orgID, userID uuid.UUID, path string, operations ...bulkPolicyOp) *httptest.ResponseRecorder {
	t.Helper()
	request, response := rawPolicyRequest(t, http.MethodPost, path, bulkPolicyRequest{Operations: operations}, orgID, userID, uuid.Nil)
	policies.Bulk(response, request)
	return response
}

func bulkCreateGroupPolicy(name string, selectors ...string) bulkPolicyOp {
	body, _ := json.Marshal(createPolicyBody{Name: name, Engine: "constellation-admission", Category: "admission", SpecYAML: rawAdmissionSpec(selectors...)})
	return bulkPolicyOp{Op: "create", Body: body}
}

func bulkUpdateGroupPolicy(id uuid.UUID, spec string) bulkPolicyOp {
	body, _ := json.Marshal(updatePolicyBody{SpecYAML: &spec})
	return bulkPolicyOp{Op: "update", ID: &id, Body: body}
}

func TestBulkAdmissionPolicyCreateScopesGroupsAndRollsBack(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	orgID, userID := seedOrgUser(t, pool)
	otherOrgID, _ := seedOrgUser(t, pool)
	clusterID := seedRawPolicyCluster(t, pool, orgID)
	otherClusterID := seedRawPolicyCluster(t, pool, orgID)
	foreignClusterID := seedRawPolicyCluster(t, pool, otherOrgID)
	globalID := seedRawPolicyGroup(t, pool, orgID, nil, "bulk-global-"+uuid.NewString())
	clusterGroup := "bulk-cluster-" + uuid.NewString()
	seedRawPolicyGroup(t, pool, orgID, clusterID, clusterGroup)
	otherGroup := "bulk-other-" + uuid.NewString()
	seedRawPolicyGroup(t, pool, orgID, otherClusterID, otherGroup)
	foreignGroup := "bulk-foreign-" + uuid.NewString()
	seedRawPolicyGroup(t, pool, otherOrgID, nil, foreignGroup)
	policies := NewPolicies(database, audit.New(pool), nil)
	for _, test := range []struct {
		name, path, selector string
		status               int
	}{
		{"global-id", "/policies/bulk", globalID.String(), http.StatusOK},
		{"cluster-unscoped", "/policies/bulk", clusterGroup, http.StatusBadRequest},
		{"cluster-scoped", "/policies/bulk?cluster_id=" + clusterID.String(), clusterGroup, http.StatusOK},
		{"other-cluster", "/policies/bulk?cluster_id=" + clusterID.String(), otherGroup, http.StatusBadRequest},
		{"foreign-org", "/policies/bulk", foreignGroup, http.StatusBadRequest},
		{"missing", "/policies/bulk", "not-a-group", http.StatusBadRequest},
		{"foreign-cluster", "/policies/bulk?cluster_id=" + foreignClusterID.String(), globalID.String(), http.StatusBadRequest},
		{"invalid-cluster", "/policies/bulk?cluster_id=invalid", globalID.String(), http.StatusBadRequest},
	} {
		response := bulkGroupRequest(t, policies, orgID, userID, test.path, bulkCreateGroupPolicy(test.name, test.selector))
		if response.Code != test.status {
			t.Errorf("%s: status=%d body=%s", test.name, response.Code, response.Body.String())
		}
	}
	response := bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk",
		bulkCreateGroupPolicy("bulk-rollback-"+uuid.NewString(), globalID.String()),
		bulkCreateGroupPolicy("bulk-missing-"+uuid.NewString(), "not-a-group"))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("batch rollback: status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM policies WHERE org_id=$1 AND name LIKE 'bulk-rollback-%'`, orgID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("batch partially persisted: count=%d err=%v", count, err)
	}
	var storedClusterID uuid.UUID
	if err := pool.QueryRow(context.Background(), `SELECT cluster_id FROM policies WHERE org_id=$1 AND name='cluster-scoped'`, orgID).Scan(&storedClusterID); err != nil || storedClusterID != clusterID {
		t.Fatalf("cluster scope not stored: id=%s err=%v", storedClusterID, err)
	}
}

func TestBulkAdmissionPolicyUpdateValidatesResultingGroups(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	pool := database.Pool()
	orgID, userID := seedOrgUser(t, pool)
	clusterID := seedRawPolicyCluster(t, pool, orgID)
	groupName := "bulk-update-" + uuid.NewString()
	seedRawPolicyGroup(t, pool, orgID, clusterID, groupName)
	policies := NewPolicies(database, audit.New(pool), nil)
	response := bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk?cluster_id="+clusterID.String(), bulkCreateGroupPolicy("bulk-target-"+uuid.NewString(), groupName))
	if response.Code != http.StatusOK {
		t.Fatalf("create: status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Results []struct {
			ID uuid.UUID `json:"id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || len(result.Results) != 1 {
		t.Fatalf("create response=%s err=%v", response.Body.String(), err)
	}
	policyID := result.Results[0].ID
	response = bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkUpdateGroupPolicy(policyID, rawAdmissionSpec("missing")))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid update: status=%d body=%s", response.Code, response.Body.String())
	}
	otherOrgID, otherUserID := seedOrgUser(t, pool)
	otherPolicy := bulkGroupRequest(t, policies, otherOrgID, otherUserID, "/policies/bulk", bulkCreateGroupPolicy("bulk-foreign-policy-"+uuid.NewString()))
	if otherPolicy.Code != http.StatusOK {
		t.Fatalf("foreign create: status=%d body=%s", otherPolicy.Code, otherPolicy.Body.String())
	}
	var otherResult struct {
		Results []struct {
			ID uuid.UUID `json:"id"`
		} `json:"results"`
	}
	if err := json.Unmarshal(otherPolicy.Body.Bytes(), &otherResult); err != nil || len(otherResult.Results) != 1 {
		t.Fatalf("foreign create response=%s err=%v", otherPolicy.Body.String(), err)
	}
	response = bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkUpdateGroupPolicy(otherResult.Results[0].ID, rawAdmissionSpec(groupName)))
	if response.Code != http.StatusNotFound {
		t.Fatalf("foreign policy update: status=%d body=%s", response.Code, response.Body.String())
	}
	response = bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkUpdateGroupPolicy(policyID, rawAdmissionSpec(groupName)))
	if response.Code != http.StatusOK {
		t.Fatalf("existing cluster scope: status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := pool.Exec(context.Background(), `UPDATE policies SET spec_yaml=$2 WHERE id=$1`, policyID, rawAdmissionSpec("missing")); err != nil {
		t.Fatal(err)
	}
	response = bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkPolicyOp{Op: "enable", ID: &policyID})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("dangling selector enable: status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestBulkAdmissionPolicyCreateWaitsForGroupMutation(t *testing.T) {
	for _, operation := range []string{"create", "update"} {
		for _, mutationKind := range []string{"rename", "delete"} {
			t.Run(operation+"-"+mutationKind, func(t *testing.T) {
				database := openTestDB(t)
				defer database.Close()
				pool := database.Pool()
				orgID, userID := seedOrgUser(t, pool)
				groupName := "bulk-race-" + uuid.NewString()
				groupID := seedRawPolicyGroup(t, pool, orgID, nil, groupName)
				policies := NewPolicies(database, nil, nil)
				var policyID uuid.UUID
				if operation == "update" {
					response := bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkCreateGroupPolicy("bulk-race-existing-"+uuid.NewString()))
					if response.Code != http.StatusOK {
						t.Fatalf("seed policy: status=%d body=%s", response.Code, response.Body.String())
					}
					var result struct {
						Results []struct {
							ID uuid.UUID `json:"id"`
						} `json:"results"`
					}
					if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || len(result.Results) != 1 {
						t.Fatalf("seed response=%s err=%v", response.Body.String(), err)
					}
					policyID = result.Results[0].ID
				}
				mutation, err := pool.Begin(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer mutation.Rollback(context.Background())
				if _, err := mutation.Exec(context.Background(), `LOCK TABLE policies IN SHARE MODE`); err != nil {
					t.Fatal(err)
				}
				if mutationKind == "rename" {
					_, err = mutation.Exec(context.Background(), `UPDATE groups SET name=$2 WHERE id=$1`, groupID, groupName+"-new")
				} else {
					_, err = mutation.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, groupID)
				}
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					if operation == "create" {
						result <- bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkCreateGroupPolicy("bulk-race-target-"+uuid.NewString(), groupName))
					} else {
						result <- bulkGroupRequest(t, policies, orgID, userID, "/policies/bulk", bulkUpdateGroupPolicy(policyID, rawAdmissionSpec(groupName)))
					}
				}()
				deadline := time.Now().Add(5 * time.Second)
				for {
					select {
					case response := <-result:
						t.Fatalf("completed before mutation committed: %d %s", response.Code, response.Body.String())
					default:
					}
					var waiting int
					if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'LOCK TABLE policies IN ROW EXCLUSIVE MODE%' AND wait_event_type='Lock'`).Scan(&waiting); err != nil {
						t.Fatal(err)
					}
					if waiting > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("bulk writer did not wait")
					}
					time.Sleep(10 * time.Millisecond)
				}
				if err := mutation.Commit(context.Background()); err != nil {
					t.Fatal(err)
				}
				select {
				case response := <-result:
					if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "group not found") {
						t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
					}
				case <-time.After(5 * time.Second):
					t.Fatal("bulk writer did not finish")
				}
			})
		}
	}
}
