package main

import (
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/runtime"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/group"
)

// TestGroupBindingScopeMACs_MatchingPodScoped is the NET-43 agent core: a locally
// tapped pod that matches a WAF-bound group's selector has its MAC opted into WAF,
// while a non-matching pod is left unscoped.
func TestGroupBindingScopeMACs_MatchingPodScoped(t *testing.T) {
	webGroup := uuid.New()
	wafSensor := uuid.New()

	bindings := []runtime.GroupSensorBinding{
		{GroupID: webGroup, Kind: runtime.SensorKindWAF, SensorID: wafSensor},
	}
	groups := []runtime.BoundGroupDef{
		{ID: webGroup, Name: "web", Criteria: []group.Criterion{
			{Key: "namespace", Value: "shop", Op: group.OpEq},
			{Key: "label.app", Value: "web", Op: group.OpEq},
		}},
	}
	pods := []dp.PodTapMeta{
		// matches: namespace shop + app=web
		{MAC: "aa:aa:aa:aa:aa:aa", Namespace: "shop", PodName: "web-1", Labels: map[string]string{"app": "web"}},
		// non-match: wrong namespace
		{MAC: "bb:bb:bb:bb:bb:bb", Namespace: "other", PodName: "web-2", Labels: map[string]string{"app": "web"}},
		// non-match: wrong label
		{MAC: "cc:cc:cc:cc:cc:cc", Namespace: "shop", PodName: "api-1", Labels: map[string]string{"app": "api"}},
	}

	wafMACs, dlpMACs := groupBindingScopeMACs(bindings, groups, pods, "clusterX")

	if !wafMACs["aa:aa:aa:aa:aa:aa"] {
		t.Fatalf("matching pod not WAF-scoped: %v", wafMACs)
	}
	if wafMACs["bb:bb:bb:bb:bb:bb"] || wafMACs["cc:cc:cc:cc:cc:cc"] {
		t.Fatalf("non-matching pod scoped: %v", wafMACs)
	}
	if len(dlpMACs) != 0 {
		t.Fatalf("a WAF binding must not opt any MAC into DLP: %v", dlpMACs)
	}
}

// TestGroupBindingScopeMACs_KindRouting: a DLP-bound group opts matched MACs into
// DLP (not WAF), and cluster criteria are honoured.
func TestGroupBindingScopeMACs_KindRoutingAndCluster(t *testing.T) {
	g := uuid.New()
	sensor := uuid.New()
	bindings := []runtime.GroupSensorBinding{{GroupID: g, Kind: runtime.SensorKindDLP, SensorID: sensor}}
	groups := []runtime.BoundGroupDef{
		{ID: g, Name: "payments", Criteria: []group.Criterion{
			{Key: "cluster", Value: "prod", Op: group.OpEq},
			{Key: "namespace", Value: "payments", Op: group.OpEq},
		}},
	}
	pods := []dp.PodTapMeta{
		{MAC: "11:11:11:11:11:11", Namespace: "payments", PodName: "pay-1"},
	}

	// Wrong cluster → no match.
	waf, dlp := groupBindingScopeMACs(bindings, groups, pods, "staging")
	if len(waf)+len(dlp) != 0 {
		t.Fatalf("cluster mismatch should scope nothing: waf=%v dlp=%v", waf, dlp)
	}
	// Right cluster → DLP-scoped, not WAF.
	waf, dlp = groupBindingScopeMACs(bindings, groups, pods, "prod")
	if !dlp["11:11:11:11:11:11"] {
		t.Fatalf("matching pod not DLP-scoped: %v", dlp)
	}
	if len(waf) != 0 {
		t.Fatalf("DLP binding must not opt into WAF: %v", waf)
	}
}

// TestGroupBindingScopeMACs_NoBindingsOrGroups: with no bindings, no groups, or no
// pods the resolver is a no-op (empty, non-nil maps).
func TestGroupBindingScopeMACs_Empty(t *testing.T) {
	g := uuid.New()
	b := []runtime.GroupSensorBinding{{GroupID: g, Kind: runtime.SensorKindWAF, SensorID: uuid.New()}}
	defs := []runtime.BoundGroupDef{{ID: g, Criteria: []group.Criterion{{Key: "namespace", Value: "x", Op: group.OpEq}}}}
	pods := []dp.PodTapMeta{{MAC: "aa", Namespace: "x", PodName: "p"}}

	for _, tc := range []struct {
		name string
		b    []runtime.GroupSensorBinding
		d    []runtime.BoundGroupDef
		p    []dp.PodTapMeta
	}{
		{"no bindings", nil, defs, pods},
		{"no groups", b, nil, pods},
		{"no pods", b, defs, nil},
	} {
		waf, dlp := groupBindingScopeMACs(tc.b, tc.d, tc.p, "c")
		if len(waf) != 0 || len(dlp) != 0 {
			t.Fatalf("%s: expected no scope, got waf=%v dlp=%v", tc.name, waf, dlp)
		}
	}
}
