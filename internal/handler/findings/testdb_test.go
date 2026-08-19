package findings

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
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

// ensureScanObjectTables mirrors the package-internal helper in
// internal/handler; each sub-package owns its own test-helper copy.
func ensureScanObjectTables(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"scan_targets", "scan_evidence", "cluster_platform_facts"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}
}

// createScanObjectOrg mirrors the package-internal helper in internal/handler;
// copied verbatim so the moved VulnDB-rescan test is self-contained.
func createScanObjectOrg(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (uuid.UUID, uuid.UUID, uuid.UUID) {
	t.Helper()
	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name)
VALUES ($1, $2, $3)`, orgID, "scan-object-"+suffix+"-"+orgID.String(), "Scan Object "+suffix); err != nil {
		t.Fatalf("org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name, password_hash)
VALUES ($1, $2, $3, 'Test User', 'x')`, userID, orgID, "scan-object-"+suffix+"@example.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state, last_heartbeat_at)
VALUES ($1, $2, $3, 'k3s', 'connected', NOW())`, clusterID, orgID, "scan-object-"+suffix+"-"+clusterID.String()); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	return orgID, userID, clusterID
}

// insertScanObjectTarget mirrors the package-internal helper in
// internal/handler; copied verbatim for the moved test.
func insertScanObjectTarget(t *testing.T, ctx context.Context, pool *pgxpool.Pool, orgID, clusterID uuid.UUID, targetType, targetRef, sourceType, metadata string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	targetID := uuid.New()
	evidenceID := uuid.New()
	inventoryHash := "sha256:" + uuid.NewString()
	if err := pool.QueryRow(ctx, `
INSERT INTO scan_targets (
    id, org_id, cluster_id, type, ref, source_type, source_ref, inventory_hash, metadata
) VALUES (
    $1, $2, $3, $4, $5, $6, $5, $7, $8::jsonb
) RETURNING id`, targetID, orgID, clusterID, targetType, targetRef, sourceType, inventoryHash, metadata).Scan(&targetID); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if err := pool.QueryRow(ctx, `
INSERT INTO scan_evidence (
    id, org_id, scan_target_id, cluster_id, target_type, target_ref,
    source_type, source_ref, evidence_type, inventory_hash, package_count, payload, observed_at
) VALUES (
    $1, $2, $3, $4, $5, $6,
    $7, $6, 'package-inventory', $8, 1,
    '{"packages":[{"name":"openssl","version":"3.0.13","ecosystem":"deb","namespace_kind":"os","namespace_name":"ubuntu"}]}'::jsonb,
    NOW()
) RETURNING id`, evidenceID, orgID, targetID, clusterID, targetType, targetRef, sourceType, inventoryHash).Scan(&evidenceID); err != nil {
		t.Fatalf("scan evidence: %v", err)
	}
	return targetID, evidenceID
}

// platformTargetRef mirrors the package-internal helper in internal/handler
// (platform_facts.go) for the moved test.
func platformTargetRef(clusterID uuid.UUID) string {
	return "cluster:" + clusterID.String()
}
