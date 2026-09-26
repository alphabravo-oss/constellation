package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestResolveAgentClusterIDRejectsConflictingBundles(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID := uuid.New()
	clusterA, clusterB := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "agent-bundle-scope-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO clusters (id, org_id, name) VALUES ($1, $2, 'a'), ($3, $2, 'b')`, clusterA, orgID, clusterB); err != nil {
		t.Fatal(err)
	}
	_, tokenID, err := IssueRuntimeAgentToken(ctx, pool, orgID, "agent-bundle-scope-"+uuid.NewString(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	token := &RuntimeAgentToken{ID: tokenID, OrgID: orgID}
	insertBundle := func(clusterID uuid.UUID) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO cluster_init_bundles (org_id, cluster_id, name, expires_at, runtime_agent_token_id, kek_fingerprint, contents_encrypted) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour', $4, 'test-kek', '\x00'::bytea)`, orgID, clusterID, "agent-bundle-scope-"+uuid.NewString(), tokenID); err != nil {
			t.Fatal(err)
		}
	}
	insertBundle(clusterA)
	if got, err := ResolveAgentClusterID(ctx, database, token); err != nil || got == nil || *got != clusterA {
		t.Fatalf("single bundle cluster=%v error=%v", got, err)
	}
	insertBundle(clusterB)
	if got, err := ResolveAgentClusterID(ctx, database, token); got != nil || !errors.Is(err, ErrAgentClusterScope) {
		t.Fatalf("conflicting bundles cluster=%v error=%v", got, err)
	}
}
