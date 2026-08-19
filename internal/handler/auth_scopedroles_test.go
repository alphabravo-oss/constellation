package handler

import (
	"context"
	"testing"

	authpkg "github.com/alphabravocompany/constellation/internal/auth"
	"github.com/google/uuid"
)

// TestReconcileJITRoles_MaterializesClusterScopedGrants exercises the A2/P0-10 seam: reconcileJITRoles
// must materialize an identity's CLUSTER-scoped SSO grants into scope_cluster_id-bearing
// role_assignments rows (additive), dedup them on a re-login, and materialize a namespace-bearing
// grant as a row that carries scope_namespace (P0-10) so it grants exactly that namespace and never
// silently widens to a whole-cluster grant.
func TestReconcileJITRoles_MaterializesClusterScopedGrants(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	if _, err := pool.Exec(ctx,
		`INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scoped Org')`,
		orgID, "scoped-org-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Bob')`,
		userID, orgID, "bob-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, $3)`,
		clusterID, orgID, "cluster-"+clusterID.String()); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}

	scoped := []authpkg.ScopedRole{
		// Cluster-scoped grant -> materialized as a whole-cluster row (scope_namespace '').
		{Role: "Auditor", Scope: authpkg.RoleScope{ClusterID: clusterID.String()}},
		// Namespace-bearing grant -> materialized as a scope_namespace row (P0-10), NOT widened.
		{Role: "SecurityAdmin", Scope: authpkg.RoleScope{ClusterID: clusterID.String(), Namespace: "prod"}},
		// Namespace with no cluster -> no anchor to materialize against; skipped.
		{Role: "Auditor", Scope: authpkg.RoleScope{Namespace: "prod"}},
		// Org-scope grant -> handled by the org-scope idpRoles path, not the scoped writer.
		{Role: "GlobalAdmin", Scope: authpkg.RoleScope{}},
	}

	if _, err := reconcileJITRoles(ctx, d, userID, orgID, []string{"GlobalAdmin"}, scoped); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Count cluster rows for a (role, namespace): the Auditor whole-cluster grant lands with ns '';
	// the SecurityAdmin namespace grant lands with ns 'prod' (not '' — it must not widen the cluster).
	countClusterRole := func(role, ns string) int {
		var n int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM role_assignments
			  WHERE user_id = $1 AND role = $2 AND scope_cluster_id = $3 AND scope_namespace = $4
			    AND scope_project_id IS NULL`,
			userID, role, clusterID, ns).Scan(&n); err != nil {
			t.Fatalf("count %s@%q: %v", role, ns, err)
		}
		return n
	}
	if got := countClusterRole("Auditor", ""); got != 1 {
		t.Fatalf("whole-cluster Auditor rows = %d, want 1", got)
	}
	if got := countClusterRole("SecurityAdmin", "prod"); got != 1 {
		t.Fatalf("namespace-scoped SecurityAdmin@prod rows = %d, want 1", got)
	}
	if got := countClusterRole("SecurityAdmin", ""); got != 0 {
		t.Fatalf("namespace-bearing SecurityAdmin widened to %d whole-cluster rows, want 0", got)
	}
	// The org-scope GlobalAdmin grant landed as an org-scope row.
	var orgRoleN int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM role_assignments
		  WHERE user_id = $1 AND role = 'GlobalAdmin' AND scope_org_id = $2
		    AND scope_cluster_id IS NULL AND scope_project_id IS NULL`,
		userID, orgID).Scan(&orgRoleN); err != nil {
		t.Fatalf("count org GlobalAdmin: %v", err)
	}
	if orgRoleN != 1 {
		t.Fatalf("org-scope GlobalAdmin rows = %d, want 1", orgRoleN)
	}

	// Re-login: the scoped materialization must be idempotent (dedup, no duplicate cluster row).
	if _, err := reconcileJITRoles(ctx, d, userID, orgID, []string{"GlobalAdmin"}, scoped); err != nil {
		t.Fatalf("reconcile (2nd): %v", err)
	}
	if got := countClusterRole("Auditor", ""); got != 1 {
		t.Fatalf("after re-login whole-cluster Auditor rows = %d, want 1 (dedup)", got)
	}
	if got := countClusterRole("SecurityAdmin", "prod"); got != 1 {
		t.Fatalf("after re-login namespace-scoped SecurityAdmin@prod rows = %d, want 1 (dedup)", got)
	}
}
