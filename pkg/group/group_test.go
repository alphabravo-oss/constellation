package group

import (
	"testing"
	"time"
)

func TestGroup_Matches(t *testing.T) {
	g := &Group{Name: "g", Kind: KindGround, Criteria: []Criterion{
		{Key: "namespace", Value: "prod", Op: OpEq},
		{Key: "label.app", Value: "api", Op: OpEq},
	}}
	wl := &Workload{Namespace: "prod", Labels: map[string]string{"app": "api"}}
	if !g.Matches(wl) {
		t.Fatal("expected match")
	}
	wl2 := &Workload{Namespace: "prod", Labels: map[string]string{"app": "web"}}
	if g.Matches(wl2) {
		t.Fatal("expected no match")
	}
}

func TestGroup_ComputeMembers(t *testing.T) {
	g := &Group{Name: "g", Kind: KindGround, Criteria: []Criterion{
		{Key: "namespace", Value: "prod", Op: OpEq},
	}}
	wls := []Workload{
		{ID: "prod/api", Namespace: "prod"},
		{ID: "dev/api", Namespace: "dev"},
		{ID: "prod/web", Namespace: "prod"},
	}
	got := g.ComputeMembers(wls)
	if len(got) != 2 || got[0] != "prod/api" || got[1] != "prod/web" {
		t.Fatalf("expected sorted [prod/api prod/web], got %v", got)
	}
	// No criteria -> Matches is false -> no members.
	if m := (&Group{Name: "empty", Kind: KindGround}).ComputeMembers(wls); len(m) != 0 {
		t.Fatalf("expected no members for criteria-less group, got %v", m)
	}
}

func TestGroup_Validate_Modes(t *testing.T) {
	g := &Group{Name: "g", Kind: KindGround}
	if err := g.Validate(); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if g.PolicyMode != ModeMonitor || g.ProfileMode != ModeMonitor {
		t.Fatalf("empty modes should default to monitor, got %s/%s", g.PolicyMode, g.ProfileMode)
	}
	bad := &Group{Name: "g", Kind: KindGround, PolicyMode: Mode("enforce")}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected invalid policy_mode error")
	}
}

func TestGroup_Matches_RegexAndContains(t *testing.T) {
	g := &Group{Name: "g", Kind: KindGround, Criteria: []Criterion{
		{Key: "label.tier", Value: "front.*", Op: OpRegex},
		{Key: "label.env", Value: "prod", Op: OpContains},
	}}
	wl := &Workload{Labels: map[string]string{"tier": "frontend-v2", "env": "us-prod-1"}}
	if !g.Matches(wl) {
		t.Fatal("expected match")
	}
}

func TestLearnFromObservations(t *testing.T) {
	now := time.Now()
	obs := []Observation{
		{At: now, Workload: Workload{ID: "a", Cluster: "c1", Namespace: "payments", Labels: map[string]string{"app": "api"}}},
		{At: now, Workload: Workload{ID: "b", Cluster: "c1", Namespace: "payments", Labels: map[string]string{"app": "api"}}},
		{At: now, Workload: Workload{ID: "c", Cluster: "c1", Namespace: "payments", Labels: map[string]string{"app": "web"}}},
		{At: now.Add(-time.Hour), Workload: Workload{ID: "d", Cluster: "c2", Namespace: "dev", Labels: map[string]string{"app": "x"}}},
	}
	got := LearnFromObservations(obs, 24*time.Hour, 2)
	if len(got) != 1 {
		t.Fatalf("expected 1 learned group, got %d", len(got))
	}
	if got[0].Kind != KindLearned {
		t.Fatalf("expected learned kind, got %s", got[0].Kind)
	}
	if len(got[0].Members) != 3 {
		t.Fatalf("expected 3 members, got %v", got[0].Members)
	}
}

// TestLearnFromObservations_PerService pins the P0-05 granularity fix: when the
// Service field is set the learner emits one learned group PER (namespace, service)
// — matching NeuVector's nv.<service> — instead of collapsing every service in a
// namespace into one namespace-wide group. Fails before the Service-bucketing change
// (both services land in a single "payments" group).
func TestLearnFromObservations_PerService(t *testing.T) {
	now := time.Now()
	obs := []Observation{
		{At: now, Workload: Workload{ID: "payments/api", Cluster: "c1", Namespace: "payments", Service: "api", Labels: map[string]string{"app": "api"}}},
		{At: now, Workload: Workload{ID: "payments/web", Cluster: "c1", Namespace: "payments", Service: "web", Labels: map[string]string{"app": "web"}}},
	}
	got := LearnFromObservations(obs, 0, 1)
	if len(got) != 2 {
		t.Fatalf("expected one learned group per service (2), got %d: %+v", len(got), got)
	}
	if got[0].Name != "learned-c1-payments-api" || got[1].Name != "learned-c1-payments-web" {
		t.Fatalf("unexpected group names: %q, %q", got[0].Name, got[1].Name)
	}
	if got[0].LearnedFrom != "api" || got[1].LearnedFrom != "web" {
		t.Fatalf("expected learned_from=service, got %q, %q", got[0].LearnedFrom, got[1].LearnedFrom)
	}
	for _, g := range got {
		if g.Kind != KindLearned || g.CfgType != "learned" {
			t.Fatalf("expected learned kind/cfg_type, got %s/%s", g.Kind, g.CfgType)
		}
		// Criteria must anchor on namespace + the service's dominant label so the
		// group actually selects that service's workloads.
		if len(g.Criteria) != 2 || g.Criteria[0].Key != "namespace" || g.Criteria[0].Value != "payments" {
			t.Fatalf("expected namespace criterion, got %+v", g.Criteria)
		}
	}
}

func TestGroup_Validate(t *testing.T) {
	cases := []struct {
		g    Group
		want bool
	}{
		{Group{Name: "", Kind: KindGround}, true},
		{Group{Name: "x", Kind: "bogus"}, true},
		{Group{Name: "x", Kind: KindGround, Criteria: []Criterion{{Key: "k", Value: "[bad", Op: OpRegex}}}, true},
		{Group{Name: "x", Kind: KindGround, Criteria: []Criterion{{Key: "k", Value: "v", Op: "wat"}}}, true},
		{Group{Name: "x", Kind: KindGround, Criteria: []Criterion{{Key: "k", Value: "v", Op: OpEq}}}, false},
	}
	for i, c := range cases {
		if err := c.g.Validate(); (err != nil) != c.want {
			t.Errorf("case %d: gotErr=%v want=%v", i, err, c.want)
		}
	}
}

func TestGroup_MembersChanged(t *testing.T) {
	// The stale-membership scenario the reconcile closes: a group authored when
	// only prod/api existed; a new replica prod/web now matches the criteria.
	g := &Group{Name: "g", Kind: KindGround, Members: []string{"prod/api"},
		Criteria: []Criterion{{Key: "namespace", Value: "prod", Op: OpEq}}}
	wls := []Workload{
		{ID: "prod/api", Namespace: "prod"},
		{ID: "prod/web", Namespace: "prod"}, // new member, no group write happened
		{ID: "dev/api", Namespace: "dev"},
	}
	newMembers := g.ComputeMembers(wls)
	if !g.MembersChanged(newMembers) {
		t.Fatalf("expected membership change for new replica prod/web; members=%v", newMembers)
	}
	if len(newMembers) != 2 || newMembers[0] != "prod/api" || newMembers[1] != "prod/web" {
		t.Fatalf("expected [prod/api prod/web], got %v", newMembers)
	}

	// Idempotent: recompute over the same set (any order) is not a change.
	g.Members = []string{"prod/web", "prod/api"}
	if g.MembersChanged(g.ComputeMembers(wls)) {
		t.Fatal("expected no change when membership is already current")
	}

	// Removal is also a change (workload prod/api scaled to zero).
	g.Members = []string{"prod/api", "prod/web"}
	if !g.MembersChanged([]string{"prod/web"}) {
		t.Fatal("expected change when a member is removed")
	}
}
