package handler

import (
	"testing"

	"github.com/google/uuid"
)

// TestDeriveBindingScopes is the P0-11 regression guard: a role binding's requested scopes must
// be mirrored faithfully into the enforced role_assignments rows, and unrepresentable scopes
// must be REFUSED rather than silently widened to org-wide.
func TestDeriveBindingScopes(t *testing.T) {
	c1 := uuid.New().String()
	c2 := uuid.New().String()
	p1 := uuid.New().String()

	t.Run("empty scopes grant org-wide", func(t *testing.T) {
		rows, err := deriveBindingScopes(nil)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(rows) != 1 || rows[0].ClusterID != nil || rows[0].ProjectID != nil {
			t.Fatalf("want single org-wide row, got %+v", rows)
		}
	})

	t.Run("explicit org scope grants org-wide", func(t *testing.T) {
		rows, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "org"}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(rows) != 1 || rows[0].ClusterID != nil {
			t.Fatalf("want single org-wide row, got %+v", rows)
		}
	})

	t.Run("cluster scope maps to cluster rows only", func(t *testing.T) {
		rows, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "cluster", Values: []string{c1, c2}}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("want 2 rows, got %d", len(rows))
		}
		for _, r := range rows {
			if r.ClusterID == nil || r.ProjectID != nil {
				t.Fatalf("cluster row must set only ClusterID, got %+v", r)
			}
		}
		if rows[0].ClusterID.String() != c1 || rows[1].ClusterID.String() != c2 {
			t.Fatalf("cluster ids not preserved: %v %v", rows[0].ClusterID, rows[1].ClusterID)
		}
	})

	t.Run("project scope maps to project rows only", func(t *testing.T) {
		rows, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "project", Values: []string{p1}}})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(rows) != 1 || rows[0].ProjectID == nil || rows[0].ClusterID != nil {
			t.Fatalf("want single project row, got %+v", rows)
		}
	})

	t.Run("org scope supersedes narrower rows", func(t *testing.T) {
		rows, err := deriveBindingScopes([]accessControlScopeDTO{
			{Kind: "cluster", Values: []string{c1}},
			{Kind: "org"},
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(rows) != 1 || rows[0].ClusterID != nil {
			t.Fatalf("org scope must collapse to a single org-wide row, got %+v", rows)
		}
	})

	t.Run("namespace scope is refused, not widened", func(t *testing.T) {
		if _, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "namespace", Values: []string{"kube-system"}}}); err == nil {
			t.Fatalf("namespace scope must be rejected (would otherwise over-grant to cluster/org)")
		}
	})

	t.Run("unknown kind is rejected", func(t *testing.T) {
		if _, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "galaxy", Values: []string{"x"}}}); err == nil {
			t.Fatalf("unknown scope kind must be rejected")
		}
	})

	t.Run("invalid cluster id is rejected", func(t *testing.T) {
		if _, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "cluster", Values: []string{"not-a-uuid"}}}); err == nil {
			t.Fatalf("invalid cluster id must be rejected")
		}
	})

	t.Run("cluster scope with no values is rejected", func(t *testing.T) {
		if _, err := deriveBindingScopes([]accessControlScopeDTO{{Kind: "cluster"}}); err == nil {
			t.Fatalf("cluster scope with no ids must be rejected")
		}
	})
}
