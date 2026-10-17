package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestDPWireIdentityBoundaries(t *testing.T) {
	for _, id := range []int64{-1, math.MinInt64, int64(math.MaxUint32) + 1, int64(math.MaxUint32) + 8, math.MaxInt64} {
		if _, err := networkPolicyWireID(id); err == nil {
			t.Fatalf("network ID wrapped %d", id)
		}
		if _, err := signatureWireID(id); err == nil {
			t.Fatalf("signature ID wrapped %d", id)
		}
	}
	for _, id := range []int64{1, 9001, math.MaxUint32} {
		network, err := networkPolicyWireID(id)
		if err != nil || int64(network) != id {
			t.Fatalf("network ID changed %d", id)
		}
		signature, err := signatureWireID(id)
		if err != nil || int64(signature) != id {
			t.Fatalf("signature ID changed %d", id)
		}
	}
	if id, err := networkPolicyWireID(0); err != nil || id != 0 {
		t.Fatal("legacy zero network ID must remain unstamped")
	}
	if _, err := signatureWireID(0); err == nil {
		t.Fatal("unassigned signature identity accepted")
	}
}
func TestPolicyMergeNeverAliasesLargeIDAndPreservesLegacyZero(t *testing.T) {
	for _, id := range []int64{0, 7, math.MaxUint32} {
		source := runtimePolicyWire{DPPolicyID: id, Mode: "enforce", Rules: []*dp.PolicyRule{{ID: 13, Action: dp.PolicyActionDeny}}}
		merged := buildMergedWorkloadPolicy([]runtimePolicyWire{source}, nil)
		expected := int64(13)
		if id > 0 {
			expected = id
		}
		if merged == nil || len(merged.Rules) != 1 || int64(merged.Rules[0].ID) != expected || merged.Rules[0].Action != dp.PolicyActionDeny {
			t.Fatalf("identity/enforcement changed %+v", merged)
		}
	}
	for _, id := range []int64{-1, int64(math.MaxUint32) + 1, int64(math.MaxUint32) + 8} {
		if merged := buildMergedWorkloadPolicy([]runtimePolicyWire{{DPPolicyID: 7, Mode: "enforce"}, {DPPolicyID: id, Mode: "enforce", Rules: []*dp.PolicyRule{{Action: dp.PolicyActionDeny}}}}, nil); merged != nil {
			t.Fatal("published partially valid policy bundle")
		}
	}
}
func TestNetworkBundleInvalidIdentityPreservesLastGoodResolverAndRIDs(t *testing.T) {
	policy := scopedPolicyFixture("a", "a-1", "uid-a", 7, "enforce")
	policy.Rules[0].Fqdn = "retained.example.test"
	worker, dataplane, payload := scopedPolicyHarness(t, policy)
	worker.SyncOnce(t.Context())
	confirmed := worker.confirmed[scopedMACA]
	for _, id := range []int64{-1, int64(math.MaxUint32) + 1, int64(math.MaxUint32) + 8} {
		invalid := scopedPolicyFixture("b", "b-1", "uid-b", id, "enforce")
		storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(policy, invalid))
		before := worker.Snapshot()
		worker.SyncOnce(t.Context())
		after := worker.Snapshot()
		if after.Errors != before.Errors+1 || after.Pushes != before.Pushes || after.Deletes != before.Deletes || worker.confirmed[scopedMACA].Source != confirmed.Source || !reflect.DeepEqual(loadPolicyRIDs(), []uint32{7}) || !reflect.DeepEqual(dataplane.allowed, []string{"retained.example.test"}) {
			t.Fatal("invalid bundle altered confirmed scope")
		}
	}
	policy.DPPolicyID = 0
	storeScopedPolicyPayload(t, payload, scopedPolicyEnvelope(policy))
	if policies, err := worker.fetch(t.Context()); err != nil || len(policies) != 1 || policies[0].DPPolicyID != 0 {
		t.Fatal("legacy zero wire identity rejected in scoped protocol", err)
	}
}
func TestSignatureBundleRejectsInvalidIDsBeforePublishingPIISet(t *testing.T) {
	saved := validatedThreatIDs.Load()
	t.Cleanup(func() { validatedThreatIDs.Store(saved) })
	valid := dlpRuleWire{DPRuleID: 9001, Name: "builtin-dlp-federal-pii", Mode: "monitor", Patterns: []string{"fixture"}}
	setValidatedThreatIDs([]dlpRuleWire{valid})
	confirmed := validatedThreatIDs.Load()
	var payload atomic.Value
	payload.Store(`{"rules":[]}`)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/runtime/dlp-rules:bundle" || r.URL.Query().Get("cluster_id") != "selected-cluster" {
			t.Error("wrong signature bundle scope")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload.Load().(string)))
	}))
	defer server.Close()
	worker := NewDLPSyncWorker(DLPSyncConfig{APIBaseURL: server.URL, ClusterID: "selected-cluster", DPSup: dp.New(dp.Options{})})
	worker.appliedSig = "last-known-good"
	for _, id := range []int64{-1, 0, int64(math.MaxUint32) + 1, int64(math.MaxUint32) + 9002, math.MaxInt64} {
		invalid := valid
		invalid.DPRuleID = id
		body, err := json.Marshal(map[string]any{"rules": []dlpRuleWire{valid, invalid}})
		if err != nil {
			t.Fatal(err)
		}
		payload.Store(string(body))
		bundle, err := worker.fetch(context.Background())
		if err == nil || bundle.rules != nil {
			t.Fatal("malformed signature bundle accepted")
		}
		setValidatedThreatIDs([]dlpRuleWire{valid, invalid})
		if validatedThreatIDs.Load() != confirmed || worker.appliedSig != "last-known-good" {
			t.Fatal("invalid identities changed confirmed PII/signature state")
		}
		if plan := planDLPPushes([]dlpRuleWire{valid, invalid}, []string{"aa:bb:cc:dd:ee:ff"}, true); plan != nil {
			t.Fatal("invalid DLP ID produced partial plan")
		}
		if rules := userWAFRules([]dlpRuleWire{valid, invalid}, true); rules != nil {
			t.Fatal("invalid WAF ID produced partial plan")
		}
	}
}
func TestSignatureMaxIdentityKeepsExistingDLPAndWAFMapping(t *testing.T) {
	rule := dlpRuleWire{DPRuleID: math.MaxUint32, Name: "federal-pii-boundary", Mode: "enforce", Patterns: []string{"fixture"}}
	plan := planDLPPushes([]dlpRuleWire{rule}, []string{"aa:bb:cc:dd:ee:ff"}, false)
	if len(plan) != 1 || len(plan[0].rules) != 1 || plan[0].rules[0].ID != dp.DLPSigID(math.MaxUint32) || plan[0].rules[0].Mode != "monitor" {
		t.Fatal("valid signature wire mapping or default monitor gate changed")
	}
	waf := userWAFRules([]dlpRuleWire{rule}, false)
	if len(waf) != 1 || waf[0].ID != dp.UserWAFSigID(math.MaxUint32) || waf[0].Mode != "monitor" {
		t.Fatal("valid WAF wire mapping or default monitor gate changed")
	}
	saved := validatedThreatIDs.Load()
	t.Cleanup(func() { validatedThreatIDs.Store(saved) })
	setValidatedThreatIDs([]dlpRuleWire{rule})
	if _, ok := (*validatedThreatIDs.Load())[dp.DLPSigID(math.MaxUint32)]; !ok {
		t.Fatal("PII signature set lost max uint32 identity")
	}
}
