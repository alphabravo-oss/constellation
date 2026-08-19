package compliance

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
)

// openTestDB mirrors the package-internal helper in internal/handler; each
// sub-package owns its own copy so its tests are self-contained. Skips when no
// test database is reachable.
func openTestDB(t *testing.T) *db.DB {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	d, err := db.Connect(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	return d
}

// ensureNetworkPolicyLifecycleTables is a per-package test-helper copy (the
// canonical definition lives with the netpolicy domain tests in
// internal/handler/netpolicy). Each Go package owns its own test helpers; the
// network-policy lifecycle DDL is needed here because the compliance-evidence
// integration test overlays network-policy state.
func ensureNetworkPolicyLifecycleTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
CREATE TABLE IF NOT EXISTS network_policy_lifecycle_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL,
    current_mode TEXT NOT NULL,
    target_mode TEXT,
    approval_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    preview_yaml TEXT NOT NULL DEFAULT '',
    preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb,
    diff JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_available BOOLEAN NOT NULL DEFAULT FALSE,
    rollback_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
    audit_trail JSONB NOT NULL DEFAULT '[]'::jsonb,
    applied_ref TEXT,
    rollback_ref TEXT,
    candidate_hash TEXT,
    last_applied_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload)
);
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS candidate_hash TEXT;
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE network_policy_lifecycle_states
    ADD COLUMN IF NOT EXISTS mode_since TIMESTAMPTZ NOT NULL DEFAULT NOW();
ALTER TABLE network_policy_lifecycle_states
    DROP CONSTRAINT IF EXISTS network_policy_lifecycle_states_org_id_workload_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_lifecycle_org_cluster_workload
    ON network_policy_lifecycle_states(org_id, cluster_id, workload);
CREATE TABLE IF NOT EXISTS network_policy_lifecycle_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL,
    action TEXT NOT NULL,
    previous_mode TEXT NOT NULL,
    next_mode TEXT NOT NULL,
    reason TEXT NOT NULL,
    preview_yaml TEXT NOT NULL DEFAULT '',
    preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb,
    preview_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
    diff JSONB NOT NULL DEFAULT '{}'::jsonb,
    rollback_ref TEXT,
    idempotency_key TEXT,
    candidate_hash TEXT,
    actor_id UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS candidate_hash TEXT;
ALTER TABLE network_policy_lifecycle_actions
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_actions_idempotency
    ON network_policy_lifecycle_actions(org_id, cluster_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS network_policy_rollback_refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL,
    rollback_ref TEXT NOT NULL,
    previous_mode TEXT NOT NULL,
    restore_mode TEXT NOT NULL,
    preview_yaml TEXT NOT NULL DEFAULT '',
    preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb,
    preview_refs JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, rollback_ref)
);
ALTER TABLE network_policy_rollback_refs
    ADD COLUMN IF NOT EXISTS cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE;
ALTER TABLE network_policy_rollback_refs
    ADD COLUMN IF NOT EXISTS preview_manifests JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE network_policy_rollback_refs
    DROP CONSTRAINT IF EXISTS network_policy_rollback_refs_org_id_rollback_ref_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_network_policy_rollback_refs_org_cluster_ref
    ON network_policy_rollback_refs(org_id, cluster_id, rollback_ref);
CREATE TABLE IF NOT EXISTS network_policy_apply_status (
    org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    flavor TEXT NOT NULL,
    resource_ref TEXT NOT NULL DEFAULT '',
    desired_mode TEXT NOT NULL DEFAULT '',
    approval_status TEXT NOT NULL DEFAULT '',
    last_action TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    candidate_hash TEXT,
    applied_ref TEXT,
    rollback_ref TEXT,
    last_applied_at TIMESTAMPTZ,
    last_deleted_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id, workload, flavor)
);
`)
	if err != nil {
		t.Fatalf("network policy lifecycle tables: %v", err)
	}
}
