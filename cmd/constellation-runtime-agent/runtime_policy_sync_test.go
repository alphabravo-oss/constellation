package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

func TestBuildMergedWorkloadPolicy(t *testing.T) {
	policies := []runtimePolicyWire{
		{
			Workload: "default/api", Mode: "enforce", DPPolicyID: 11, DefAction: dp.PolicyActionDeny,
			Rules: []*dp.PolicyRule{
				{DstIP: net.ParseIP("10.0.0.1"), Port: 443, IPProto: 6, Action: dp.PolicyActionDeny},
			},
		},
		{
			Workload: "default/web", Mode: "monitor", DPPolicyID: 22, DefAction: dp.PolicyActionAllow,
			Rules: []*dp.PolicyRule{
				{DstIP: net.ParseIP("10.0.0.2"), Port: 80, IPProto: 6, Action: dp.PolicyActionDeny},
				{Fqdn: "api.example.com", Action: dp.PolicyActionAllow},
			},
		},
		{
			Workload: "default/old", Mode: "disabled", DPPolicyID: 33, DefAction: dp.PolicyActionDeny,
			Rules: []*dp.PolicyRule{
				{DstIP: net.ParseIP("10.0.0.3"), Action: dp.PolicyActionDeny},
			},
		},
	}

	merged := buildMergedWorkloadPolicy(policies, []string{"aa:bb:cc:dd:ee:ff"})

	if got := len(merged.Rules); got != 3 {
		t.Fatalf("merged rules = %d, want 3 (disabled policy must contribute none)", got)
	}
	// enforce policy keeps deny, stamped with its dp_policy_id.
	if merged.Rules[0].Action != dp.PolicyActionDeny || merged.Rules[0].ID != 11 {
		t.Fatalf("enforce rule = %+v", merged.Rules[0])
	}
	// monitor policy demotes deny → violate.
	if merged.Rules[1].Action != dp.PolicyActionViolate || merged.Rules[1].ID != 22 {
		t.Fatalf("monitor deny should demote to violate, got %+v", merged.Rules[1])
	}
	// non-deny rule under monitor is untouched (still stamped).
	if merged.Rules[2].Action != dp.PolicyActionAllow || merged.Rules[2].Fqdn != "api.example.com" {
		t.Fatalf("monitor allow rule = %+v", merged.Rules[2])
	}
	if merged.DefAction != dp.PolicyActionDeny || merged.ApplyDir != dp.ApplyDirBoth {
		t.Fatalf("merged defaults = def %d dir %d", merged.DefAction, merged.ApplyDir)
	}
	// Source rules must not be mutated (we copy before mapping).
	if policies[1].Rules[0].Action != dp.PolicyActionDeny {
		t.Fatalf("source rule was mutated: %+v", policies[1].Rules[0])
	}

	// FQDN allow-set must surface the FQDN-anchored rule for SetAllowedFqdns.
	allow := dp.FqdnAllowSet(merged)
	if len(allow) != 1 || allow[0] != "api.example.com" {
		t.Fatalf("fqdn allow-set = %v", allow)
	}
}

func TestMergedDefaultAction(t *testing.T) {
	tests := []struct {
		name     string
		policies []runtimePolicyWire
		want     uint8
	}{
		{
			name:     "legacy omitted def_action is allow",
			policies: []runtimePolicyWire{{Mode: "enforce"}},
			want:     dp.PolicyActionAllow,
		},
		{
			name:     "disabled deny ignored",
			policies: []runtimePolicyWire{{Mode: "disabled", DefAction: dp.PolicyActionDeny}},
			want:     dp.PolicyActionAllow,
		},
		{
			name:     "monitor deny alerts without blocking",
			policies: []runtimePolicyWire{{Mode: "monitor", DefAction: dp.PolicyActionDeny}},
			want:     dp.PolicyActionViolate,
		},
		{
			name: "enforce deny wins over monitor",
			policies: []runtimePolicyWire{
				{Mode: "monitor", DefAction: dp.PolicyActionDeny},
				{Mode: "enforce", DefAction: dp.PolicyActionDeny},
			},
			want: dp.PolicyActionDeny,
		},
		{
			name:     "learn preserved over allow",
			policies: []runtimePolicyWire{{Mode: "enforce", DefAction: dp.PolicyActionLearn}},
			want:     dp.PolicyActionLearn,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergedDefaultAction(tt.policies); got != tt.want {
				t.Fatalf("mergedDefaultAction = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFingerprintWorkloadPolicyChanges(t *testing.T) {
	base := buildMergedWorkloadPolicy([]runtimePolicyWire{{
		Workload: "w", Mode: "enforce", DPPolicyID: 1,
		Rules: []*dp.PolicyRule{{DstIP: net.ParseIP("10.0.0.1"), Port: 443, Action: dp.PolicyActionDeny}},
	}}, []string{"mac-1"})

	same := buildMergedWorkloadPolicy([]runtimePolicyWire{{
		Workload: "w", Mode: "enforce", DPPolicyID: 1,
		Rules: []*dp.PolicyRule{{DstIP: net.ParseIP("10.0.0.1"), Port: 443, Action: dp.PolicyActionDeny}},
	}}, []string{"mac-1"})

	if fingerprintWorkloadPolicy(base) != fingerprintWorkloadPolicy(same) {
		t.Fatalf("identical policies should fingerprint equal")
	}

	// Adding a MAC (new pod tapped) must change the fingerprint → re-push.
	withMAC := buildMergedWorkloadPolicy([]runtimePolicyWire{{
		Workload: "w", Mode: "enforce", DPPolicyID: 1,
		Rules: []*dp.PolicyRule{{DstIP: net.ParseIP("10.0.0.1"), Port: 443, Action: dp.PolicyActionDeny}},
	}}, []string{"mac-1", "mac-2"})
	if fingerprintWorkloadPolicy(base) == fingerprintWorkloadPolicy(withMAC) {
		t.Fatalf("MAC scope change must alter fingerprint")
	}

	// Mode change (deny → violate) must change the fingerprint.
	monitor := buildMergedWorkloadPolicy([]runtimePolicyWire{{
		Workload: "w", Mode: "monitor", DPPolicyID: 1,
		Rules: []*dp.PolicyRule{{DstIP: net.ParseIP("10.0.0.1"), Port: 443, Action: dp.PolicyActionDeny}},
	}}, []string{"mac-1"})
	if fingerprintWorkloadPolicy(base) == fingerprintWorkloadPolicy(monitor) {
		t.Fatalf("action change must alter fingerprint")
	}
}

func TestRuntimePolicySyncFetch(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path + "?" + r.URL.RawQuery
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policies":[{"workload":"default/api","mode":"enforce","dp_policy_id":7,"rules":[{"dip":"10.0.0.5","port":443,"proto":6,"action":7}]}]}`))
	}))
	defer srv.Close()

	w := NewRuntimePolicySyncWorker(RuntimePolicySyncConfig{
		APIBaseURL: srv.URL, Token: "tok", ClusterID: "c1",
		DPSup: dp.New(dp.Options{}),
	})
	policies, err := w.fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotPath != "/api/v1/runtime/policies:bundle?cluster_id=c1" {
		t.Fatalf("unexpected path: %q", gotPath)
	}
	if len(policies) != 1 || policies[0].DPPolicyID != 7 || len(policies[0].Rules) != 1 {
		t.Fatalf("decoded policies = %+v", policies)
	}
	if policies[0].Rules[0].Action != dp.PolicyActionDeny || policies[0].Rules[0].DstIP.String() != "10.0.0.5" {
		t.Fatalf("decoded rule = %+v", policies[0].Rules[0])
	}
}

// TestRuntimePolicySyncSetsAllowedFqdns verifies SyncOnce drives the FQDN
// allow-set into the resolver (the production caller of SetAllowedFqdns). The
// supervisor is unstarted so PushPolicy is a no-op error path, but SetAllowedFqdns
// operates on the resolver directly.
func TestRuntimePolicySyncSetsAllowedFqdns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"policies":[{"workload":"default/api","mode":"enforce","dp_policy_id":7,"rules":[{"fqdn":"allowed.example.com","action":2}]}]}`))
	}))
	defer srv.Close()

	sup := dp.New(dp.Options{})
	w := NewRuntimePolicySyncWorker(RuntimePolicySyncConfig{
		APIBaseURL: srv.URL, Token: "tok", ClusterID: "c1", DPSup: sup,
	})
	w.SyncOnce(context.Background())

	// After sync, the resolver should accept observations for the allowed name.
	msgs := sup.Fqdns().Observe("allowed.example.com", []dp.ResolvedIP{{IP: net.ParseIP("1.2.3.4"), TTL: 60}}, time.Now())
	if len(msgs) == 0 {
		t.Fatalf("allowed.example.com should be in the allow-set after sync")
	}
	if other := sup.Fqdns().Observe("not-allowed.example.com", []dp.ResolvedIP{{IP: net.ParseIP("1.2.3.4"), TTL: 60}}, time.Now()); len(other) != 0 {
		t.Fatalf("unrelated name must not be allowed")
	}
}
