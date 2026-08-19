package server

import (
	"testing"

	"github.com/google/uuid"
)

// TestClusterScopeFromPattern guards the P0-09 route→scope derivation: only routes on the
// /clusters/{id} subtree carry a cluster scope, and only when {id} is a valid UUID.
func TestClusterScopeFromPattern(t *testing.T) {
	cid := uuid.New()

	cases := []struct {
		name    string
		pattern string
		idParam string
		want    *uuid.UUID
	}{
		{"cluster detail route", "/api/v1/clusters/{id}", cid.String(), &cid},
		{"cluster subresource route", "/api/v1/clusters/{id}/nodes", cid.String(), &cid},
		{"federation proxy cluster route", "/api/v1/federation/clusters/{id}/*", cid.String(), &cid},
		{"non-cluster route with id param", "/api/v1/findings/{id}", cid.String(), nil},
		{"registries route", "/api/v1/registries/{id}", cid.String(), nil},
		{"org-wide route no id", "/api/v1/findings", "", nil},
		{"cluster route but empty id", "/api/v1/clusters/{id}", "", nil},
		{"cluster route but bad uuid", "/api/v1/clusters/{id}", "not-a-uuid", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := clusterScopeFromPattern(tc.pattern, tc.idParam)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("want nil, got %v", got)
			case tc.want != nil && got == nil:
				t.Fatalf("want %v, got nil", tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("want %v, got %v", *tc.want, *got)
			}
		})
	}
}
