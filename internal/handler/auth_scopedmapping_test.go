package handler

import (
	"testing"

	"github.com/google/uuid"
)

// TestBuildScopedMapping is a pure (no DB/HTTP) test of the P0-10 CRUD create validation: it pins
// the invariants that make the sso_role_mappings write path safe — a known role, a required group,
// a parseable cluster, and (crucially) that a namespace grant MUST carry a cluster so it can later
// be materialized into a scope_namespace role_assignments row rather than silently over-granting.
func TestBuildScopedMapping(t *testing.T) {
	orgID := uuid.New()
	serverID := uuid.New()
	clusterID := uuid.New()

	t.Run("cluster+namespace grant is accepted and mapped", func(t *testing.T) {
		m, err := buildScopedMapping(orgID, serverID, scopedMappingBody{
			Group:     "  Okta-SecAdmins  ",
			Role:      "SecurityAdmin",
			ClusterID: clusterID.String(),
			Namespace: "prod",
		}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.Group != "Okta-SecAdmins" {
			t.Fatalf("group not trimmed: %q", m.Group)
		}
		if m.ClusterID == nil || *m.ClusterID != clusterID {
			t.Fatalf("cluster id = %v, want %v", m.ClusterID, clusterID)
		}
		if m.Namespace != "prod" {
			t.Fatalf("namespace = %q, want prod", m.Namespace)
		}
		if m.OrgID != orgID || m.AuthServerID != serverID {
			t.Fatalf("scope ids not propagated: %+v", m)
		}
	})

	t.Run("org-wide (no cluster, no namespace) grant is accepted", func(t *testing.T) {
		m, err := buildScopedMapping(orgID, serverID, scopedMappingBody{Group: "auditors", Role: "Auditor"}, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.ClusterID != nil {
			t.Fatalf("cluster id should be nil for org-wide grant, got %v", m.ClusterID)
		}
	})

	t.Run("namespace with no cluster is rejected", func(t *testing.T) {
		if _, err := buildScopedMapping(orgID, serverID, scopedMappingBody{
			Group: "auditors", Role: "Auditor", Namespace: "prod",
		}, nil); err == nil {
			t.Fatal("expected error for namespace without cluster_id, got nil")
		}
	})

	t.Run("unknown role is rejected", func(t *testing.T) {
		if _, err := buildScopedMapping(orgID, serverID, scopedMappingBody{
			Group: "auditors", Role: "NotARole", ClusterID: clusterID.String(),
		}, nil); err == nil {
			t.Fatal("expected error for unknown role, got nil")
		}
	})

	t.Run("empty group is rejected", func(t *testing.T) {
		if _, err := buildScopedMapping(orgID, serverID, scopedMappingBody{Group: "   ", Role: "Auditor"}, nil); err == nil {
			t.Fatal("expected error for empty group, got nil")
		}
	})

	t.Run("unparseable cluster_id is rejected", func(t *testing.T) {
		if _, err := buildScopedMapping(orgID, serverID, scopedMappingBody{
			Group: "auditors", Role: "Auditor", ClusterID: "not-a-uuid",
		}, nil); err == nil {
			t.Fatal("expected error for invalid cluster_id, got nil")
		}
	})
}
