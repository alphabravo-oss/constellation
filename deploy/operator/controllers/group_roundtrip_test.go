package controllers

import (
	"reflect"
	"testing"

	"github.com/google/uuid"

	cv1alpha1 "github.com/alphabravocompany/constellation/deploy/operator/api/v1alpha1"
	"github.com/alphabravocompany/constellation/deploy/operator/policydb"
	"github.com/alphabravocompany/constellation/pkg/group"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

// TestExportRoundTrip_Group proves the GitOps loop closes for workload groups: a stored row
// exported to a CR (policydb.GroupCR) and fed back through the reconciler's mapping (mapGroup)
// reproduces the identical row. Export then `kubectl apply` is lossless.
func TestExportRoundTrip_Group(t *testing.T) {
	org := uuid.New()
	want := policydb.GroupRow{
		OrgID:   org,
		Name:    "frontend",
		Kind:    "ground",
		Comment: "web tier",
		Criteria: []group.Criterion{
			{Key: "namespace", Value: "web", Op: group.OpEq},
			{Key: "label.app", Value: "nginx", Op: group.OpContains},
		},
		PolicyMode:  "monitor",
		ProfileMode: "protect",
	}

	cr := policydb.GroupCR(want)
	if cr.APIVersion != policydb.APIVersion || cr.Kind != policydb.KindGroup {
		t.Fatalf("CR TypeMeta = %s/%s, want %s/%s", cr.APIVersion, cr.Kind, policydb.APIVersion, policydb.KindGroup)
	}
	if cr.Name != want.Name {
		t.Fatalf("CR metadata.name = %q, want %q", cr.Name, want.Name)
	}

	got, err := mapGroup(cr)
	if err != nil {
		t.Fatalf("mapGroup: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestMapGroup_Defaults asserts the safety defaults: an empty kind becomes "ground" and empty
// modes become "monitor" (observe, never block) — the reconciler must never author a blocking
// group implicitly.
func TestMapGroup_Defaults(t *testing.T) {
	cr := &cv1alpha1.ConstellationGroup{}
	cr.Name = "svc"
	cr.Spec.OrgID = uuid.New().String()
	cr.Spec.Criteria = []cv1alpha1.GroupCriterion{{Key: "namespace", Value: "prod"}}

	got, err := mapGroup(cr)
	if err != nil {
		t.Fatalf("mapGroup: %v", err)
	}
	if got.Kind != "ground" {
		t.Fatalf("default kind = %q, want ground", got.Kind)
	}
	if got.PolicyMode != "monitor" || got.ProfileMode != "monitor" {
		t.Fatalf("default modes = %q/%q, want monitor/monitor", got.PolicyMode, got.ProfileMode)
	}
}

// TestMapGroup_RejectsBadOrg proves a non-UUID orgID is a permanent (spec) error so the
// reconciler records InvalidSpec rather than writing a row.
func TestMapGroup_RejectsBadOrg(t *testing.T) {
	cr := &cv1alpha1.ConstellationGroup{}
	cr.Name = "svc"
	cr.Spec.OrgID = "not-a-uuid"
	if _, err := mapGroup(cr); err == nil {
		t.Fatal("mapGroup accepted a non-UUID orgID, want error")
	}
}

// TestExportRoundTrip_NetworkRule proves the GitOps loop closes for group→group edges: a stored
// row exported to a CR (policydb.NetworkRuleCR) and fed back through mapNetworkRule reproduces the
// identical row (the synthesised metadata.name is not part of the reconcile identity).
func TestExportRoundTrip_NetworkRule(t *testing.T) {
	org := uuid.New()
	cluster := uuid.New()
	want := policydb.NetworkRuleRow{
		OrgID:     org,
		ClusterID: cluster,
		FromGroup: "frontend",
		ToGroup:   "backend",
		Ports: []netpolicy.PortSpec{
			{Protocol: "TCP", Port: 5432},
		},
		Mode:    "protect",
		Comment: "db access",
	}

	cr := policydb.NetworkRuleCR(want)
	if cr.APIVersion != policydb.APIVersion || cr.Kind != policydb.KindNetworkRule {
		t.Fatalf("CR TypeMeta = %s/%s, want %s/%s", cr.APIVersion, cr.Kind, policydb.APIVersion, policydb.KindNetworkRule)
	}
	if cr.Name == "" {
		t.Fatal("CR metadata.name is empty; edges must get a synthesised handle")
	}

	got, err := mapNetworkRule(cr)
	if err != nil {
		t.Fatalf("mapNetworkRule: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestMapNetworkRule_Defaults asserts the safety default: an empty mode becomes "monitor" so a
// freshly authored edge never enforces a default-deny until explicitly promoted to protect.
func TestMapNetworkRule_Defaults(t *testing.T) {
	cr := &cv1alpha1.ConstellationNetworkRule{}
	cr.Spec.OrgID = uuid.New().String()
	cr.Spec.ClusterID = uuid.New().String()
	cr.Spec.FromGroup = "a"
	cr.Spec.ToGroup = "b"

	got, err := mapNetworkRule(cr)
	if err != nil {
		t.Fatalf("mapNetworkRule: %v", err)
	}
	if got.Mode != "monitor" {
		t.Fatalf("default mode = %q, want monitor", got.Mode)
	}
}

// TestMapNetworkRule_RejectsMissingGroups proves an edge missing from/to is a spec error.
func TestMapNetworkRule_RejectsMissingGroups(t *testing.T) {
	cr := &cv1alpha1.ConstellationNetworkRule{}
	cr.Spec.OrgID = uuid.New().String()
	cr.Spec.ClusterID = uuid.New().String()
	cr.Spec.FromGroup = "a"
	// ToGroup intentionally empty.
	if _, err := mapNetworkRule(cr); err == nil {
		t.Fatal("mapNetworkRule accepted an edge with no toGroup, want error")
	}
}
