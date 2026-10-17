package runtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
)

func TestRuntimePolicyBindingsExactOwnedPodGenerations(t *testing.T) {
	database, token, policies := seedRuntimePolicyBindingFixture(t)
	org, cluster := policies[0].OrgID, policies[0].ClusterID
	ctx, pool := t.Context(), database.Pool()
	bindings, err := loadRuntimePolicyBindings(ctx, pool, org, cluster, policies)
	if err != nil {
		t.Fatal(err)
	}
	assertRuntimePolicyBindings(t, policies, bindings)
	// A changed or removed source policy cannot turn an incomplete read into a full bundle.
	stale := *policies[0]
	stale.Version++
	if _, err := loadRuntimePolicyBindings(ctx, pool, org, cluster, []*RuntimePolicy{&stale}); err == nil {
		t.Fatal("changed source version accepted")
	}
	foreign := *policies[0]
	foreign.ID = uuid.New()
	if _, err := loadRuntimePolicyBindings(ctx, pool, org, cluster, []*RuntimePolicy{&foreign}); err == nil {
		t.Fatal("missing source policy accepted")
	}
	assertRuntimePolicyBundleProtocol(t, database, token, cluster)

}

func seedRuntimePolicyBindingFixture(t *testing.T) (*db.DB, *handler.RuntimeAgentToken, []*RuntimePolicy) {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx, pool := t.Context(), database.Pool()
	org, cluster, otherOrg, otherCluster := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	token := seedBoundRuntimeAgentScope(t, database, org, cluster)
	_ = seedBoundRuntimeAgentScope(t, database, otherOrg, otherCluster)
	sibling := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'sibling')`, sibling, org); err != nil {
		t.Fatal(err)
	}
	owners := map[string]uuid.UUID{}
	for _, fixture := range []struct{ name, kind string }{{"api", "Deployment"}, {"shared", "Deployment"}, {"shared", "StatefulSet"}} {
		id := uuid.New()
		if _, err := pool.Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind)VALUES($1,$2,$3,'custom',$4,$5)`, id, org, cluster, fixture.name, fixture.kind); err != nil {
			t.Fatal(err)
		}
		owners[fixture.name+fixture.kind] = id
	}
	insertLink := func(linkOrg, linkCluster uuid.UUID, namespace, pod, uid, owner, kind string, deployment uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO pod_workload_links(org_id,cluster_id,namespace,pod_name,pod_uid,pod_workload_id,owner_kind,owner_name,owner_workload_id,deployment_id)VALUES($1,$2,$3,$4,$5,$3||'/pod/'||$4,$6,$7,$3||'/'||$7,$8)`, linkOrg, linkCluster, namespace, pod, uid, kind, owner, deployment); err != nil {
			t.Fatal(err)
		}
	}
	owner := owners["apiDeployment"]
	insertLink(org, cluster, "custom", "api-abc", "uid-old", "api", "Deployment", owner)
	insertLink(org, cluster, "custom", "api-abc", "uid-current", "api", "Deployment", owner)
	insertLink(org, cluster, "custom", "prefix-only", "uid-prefix", "api-other", "Deployment", owner)
	insertLink(org, cluster, "other", "wrong-ns", "uid-namespace", "api", "Deployment", owner)
	insertLink(otherOrg, cluster, "custom", "foreign", "uid-foreign", "api", "Deployment", owner)
	insertLink(org, sibling, "custom", "other-cluster", "uid-cluster", "api", "Deployment", owner)
	insertLink(org, cluster, "custom", "shared-pod", "uid-shared", "shared", "Deployment", owners["sharedDeployment"])
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM runtime_policies WHERE org_id=$1`, org) })
	policies := []*RuntimePolicy{}
	store := NewRuntimePolicyStore(database, nil)
	for _, workload := range []string{"custom/api", "custom/shared", "custom/missing", "custom/pod/api-abc"} {
		policy := &RuntimePolicy{OrgID: org, ClusterID: cluster, Namespace: "custom", Workload: workload, Name: "scoped", Mode: PolicyModeEnforce, DefAction: 2, ApplyDir: 3, Rules: json.RawMessage("[]")}
		id, err := store.Insert(ctx, policy, "scope-test")
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := store.Get(ctx, org, id)
		if err != nil {
			t.Fatal(err)
		}
		policies = append(policies, loaded)
	}

	return database, token, policies
}

func assertRuntimePolicyBindings(t *testing.T, policies []*RuntimePolicy, bindings map[uuid.UUID]runtimePolicyBindings) {
	t.Helper()
	for _, index := range []int{0, 3} {
		binding := bindings[policies[index].ID]
		if binding.Status != "resolved" || len(binding.Pods) != 2 {
			t.Fatalf("workload %s bindings=%+v", policies[index].Workload, binding)
		}
		for _, pod := range binding.Pods {
			if pod.Namespace != "custom" || pod.PodName != "api-abc" || (pod.PodUID != "uid-old" && pod.PodUID != "uid-current") {
				t.Fatalf("borrowed binding=%+v", pod)
			}
		}
	}
	if binding := bindings[policies[1].ID]; binding.Status != "ambiguous" || len(binding.Pods) != 0 {
		t.Fatalf("ambiguous owner=%+v", binding)
	}
	if binding := bindings[policies[2].ID]; binding.Status != "unresolved" || binding.Pods == nil || len(binding.Pods) != 0 {
		t.Fatalf("missing owner=%+v", binding)
	}

}

func assertRuntimePolicyBundleProtocol(t *testing.T, database *db.DB, token *handler.RuntimeAgentToken, cluster uuid.UUID) {
	t.Helper()
	ctx := t.Context()
	request := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/runtime/policies:bundle?protocol=2&cluster_id="+cluster.String(), nil)
	request = request.WithContext(handler.WithRuntimeAgentToken(ctx, token))
	response := httptest.NewRecorder()
	NewRuntimePoliciesHTTP(database, nil).AgentPolicyBundle(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("bundle %d: %s", response.Code, response.Body.String())
	}
	legacy := httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/v1/runtime/policies:bundle?cluster_id="+cluster.String(), nil)
	legacy = legacy.WithContext(handler.WithRuntimeAgentToken(ctx, token))
	legacyResponse := httptest.NewRecorder()
	NewRuntimePoliciesHTTP(database, nil).AgentPolicyBundle(legacyResponse, legacy)
	if legacyResponse.Code != http.StatusUpgradeRequired {
		t.Fatalf("unqualified legacy bundle status=%d", legacyResponse.Code)
	}
	var bundle agentRuntimePolicyBundle
	if err := json.Unmarshal(response.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.ProtocolVersion != 2 || bundle.ClusterID != cluster || !bundle.SourceComplete || len(bundle.Policies) != 4 {
		t.Fatalf("incomplete envelope=%+v", bundle)
	}
	for _, policy := range bundle.Policies {
		if policy.Namespace != "custom" || policy.PodBindings == nil {
			t.Fatalf("incomplete identity=%+v", policy)
		}
	}
}
