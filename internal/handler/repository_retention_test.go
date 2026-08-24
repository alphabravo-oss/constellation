package handler

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRepositoryScanRetentionPrunesOldRepositoryTarget(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	requireRepositoryRetentionSchema(t, d.Pool())

	ctx := context.Background()
	pool := d.Pool()
	resetRepositoryRetentionState(t, pool)
	orgID := createRepositoryRetentionOrg(t, pool, "prune")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	now := time.Date(2000, 1, 4, 12, 0, 0, 0, time.UTC)
	targetID := createRepositoryRetentionFixture(t, pool, orgID, "github.com/acme/prune", now.Add(-72*time.Hour), "completed")

	out, err := PruneRepositoryScansOnce(ctx, pool, RepositoryScanRetentionConfig{
		Enabled:   true,
		MaxAge:    24 * time.Hour,
		BatchSize: 10,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !out.LockAcquired || out.Candidates != 1 || out.PrunedTargets != 1 || out.DeletedFindings != 1 || out.DeletedAssets != 1 {
		t.Fatalf("retention result = %+v", out)
	}
	assertRepositoryTargetGone(t, pool, targetID)
}

func TestRepositoryScanRetentionSkipsActiveJobs(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	requireRepositoryRetentionSchema(t, d.Pool())

	ctx := context.Background()
	pool := d.Pool()
	resetRepositoryRetentionState(t, pool)
	orgID := createRepositoryRetentionOrg(t, pool, "active")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	now := time.Date(2000, 1, 4, 12, 0, 0, 0, time.UTC)
	targetID := createRepositoryRetentionFixture(t, pool, orgID, "github.com/acme/active", now.Add(-72*time.Hour), "pending")

	out, err := PruneRepositoryScansOnce(ctx, pool, RepositoryScanRetentionConfig{
		Enabled:   true,
		MaxAge:    24 * time.Hour,
		BatchSize: 10,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Candidates != 0 || out.PrunedTargets != 0 {
		t.Fatalf("active target should not prune: %+v", out)
	}
	assertRepositoryTargetExists(t, pool, targetID)
}

func TestRepositoryScanRetentionSkipsAttestationVerificationHistory(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	requireRepositoryRetentionSchema(t, d.Pool())

	ctx := context.Background()
	pool := d.Pool()
	resetRepositoryRetentionState(t, pool)
	orgID := createRepositoryRetentionOrg(t, pool, "verified")

	now := time.Date(2000, 1, 4, 12, 0, 0, 0, time.UTC)
	targetID := createRepositoryRetentionFixture(t, pool, orgID, "github.com/acme/verified", now.Add(-72*time.Hour), "completed")
	attestationID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_result_attestations (
    id, org_id, scan_target_id, target_type, target_ref, source_type,
    subject_kind, subject_ref, subject_digest, predicate_type, format,
    payload, payload_sha256, verification_status, trusted, observed_at
) VALUES (
    $1, $2, $3, 'repository', 'github.com/acme/verified', 'repository',
    'image', 'ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'https://slsa.dev/provenance/v1', 'in-toto',
    '{}'::jsonb, 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'untrusted', false, $4
)`, attestationID, orgID, targetID, now.Add(-72*time.Hour)); err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_attestation_verifications (
    org_id, attestation_id, status, trusted, reason, subject_ref, subject_digest,
    predicate_type, payload_sha256, auto_verified
) VALUES (
    $1, $2, 'untrusted', false, 'fixture', 'ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'https://slsa.dev/provenance/v1', 'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    true
)`, orgID, attestationID); err != nil {
		t.Fatalf("verification: %v", err)
	}

	out, err := PruneRepositoryScansOnce(ctx, pool, RepositoryScanRetentionConfig{
		Enabled:   true,
		MaxAge:    24 * time.Hour,
		BatchSize: 10,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Candidates != 0 || out.PrunedTargets != 0 {
		t.Fatalf("verified target should not prune: %+v", out)
	}
	assertRepositoryTargetExists(t, pool, targetID)
}

func requireRepositoryRetentionSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{
		"scan_targets",
		"scan_jobs",
		"scan_evidence",
		"assets",
		"findings",
		"scan_result_attestations",
		"scan_attestation_verifications",
	} {
		var regclass string
		if err := pool.QueryRow(context.Background(), `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}
}

func resetRepositoryRetentionState(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `
DELETE FROM findings
 WHERE target_type = 'repository'
    OR scan_target_id IN (SELECT id FROM scan_targets WHERE type = 'repository')`); err != nil {
		t.Fatalf("reset repository findings: %v", err)
	}
	if _, err := pool.Exec(ctx, `
DELETE FROM assets
 WHERE kind = 'repository'
   AND (digest LIKE 'scan-target:%' OR labels->>'target_type' = 'repository')`); err != nil {
		t.Fatalf("reset repository assets: %v", err)
	}
	if _, err := pool.Exec(ctx, `
DELETE FROM scan_targets st
 WHERE st.type = 'repository'
   AND NOT EXISTS (
        SELECT 1
          FROM scan_result_attestations sra
          JOIN scan_attestation_verifications sav
            ON sav.org_id = sra.org_id
           AND sav.attestation_id = sra.id
         WHERE sra.scan_target_id = st.id
   )`); err != nil {
		t.Fatalf("reset repository targets: %v", err)
	}
}

func createRepositoryRetentionOrg(t *testing.T, pool *pgxpool.Pool, suffix string) uuid.UUID {
	t.Helper()
	orgID := uuid.New()
	if _, err := pool.Exec(context.Background(), `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $3)`,
		orgID, "repository-retention-"+suffix+"-"+orgID.String(), "Repository Retention "+suffix); err != nil {
		t.Fatalf("org: %v", err)
	}
	return orgID
}

func createRepositoryRetentionFixture(t *testing.T, pool *pgxpool.Pool, orgID uuid.UUID, ref string, observedAt time.Time, jobStatus string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	targetID := uuid.New()
	assetID := uuid.New()
	jobID := uuid.New()
	evidenceID := uuid.New()
	findingID := uuid.New()
	metadata := map[string]string{"repository_ref": ref, "repository_url": "https://" + ref}
	metadataRaw, _ := json.Marshal(metadata)
	labelsRaw, _ := json.Marshal(map[string]string{"scan_target_id": targetID.String(), "target_type": "repository"})

	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (
    id, org_id, type, ref, source_type, source_ref, metadata, inventory_hash,
    first_seen_at, last_seen_at
) VALUES ($1, $2, 'repository', $3, 'repository', $4, $5::jsonb, $6, $7, $7)`,
		targetID, orgID, ref, ref+"@main", string(metadataRaw), "inv-"+targetID.String(), observedAt); err != nil {
		t.Fatalf("scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (
    id, org_id, target_id, status, package_count, finding_count, requested_at, finished_at
) VALUES ($1, $2, $3, $4, 1, 1, $5::timestamptz, CASE WHEN $4 = 'completed' THEN $5::timestamptz ELSE NULL END)`,
		jobID, orgID, targetID, jobStatus, observedAt); err != nil {
		t.Fatalf("scan job: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_evidence (
    id, org_id, scan_target_id, target_type, target_ref, source_type, source_ref,
    evidence_type, inventory_hash, package_count, payload, observed_at
) VALUES ($1, $2, $3, 'repository', $4, 'repository', $5, 'package-inventory', $6, 1, '{"packages":[]}'::jsonb, $7)`,
		evidenceID, orgID, targetID, ref, ref+"@main", "inv-"+targetID.String(), observedAt); err != nil {
		t.Fatalf("scan evidence: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO assets (id, org_id, kind, name, digest, labels, criticality, first_seen_at, last_seen_at)
VALUES ($1, $2, 'repository', $3, $4, $5::jsonb, 'medium', $6, $6)`,
		assetID, orgID, ref, "scan-target:"+targetID.String(), string(labelsRaw), observedAt); err != nil {
		t.Fatalf("asset: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO findings (
    id, org_id, asset_id, kind, external_id, title, severity, risk_score,
    lifecycle, detail_json, first_seen_at, last_seen_at, scan_target_id,
    target_type, target_ref, source_type
) VALUES ($1, $2, $3, 'vulnerability', 'CVE-2099-RETENTION', 'retention fixture',
    'high', 80, 'open', '{}'::jsonb, $4, $4, $5, 'repository', $6, 'repository')`,
		findingID, orgID, assetID, observedAt, targetID, ref); err != nil {
		t.Fatalf("finding: %v", err)
	}
	return targetID
}

func assertRepositoryTargetGone(t *testing.T, pool *pgxpool.Pool, targetID uuid.UUID) {
	t.Helper()
	if countRepositoryRetentionRows(t, pool, "scan_targets", targetID) != 0 ||
		countRepositoryRetentionRows(t, pool, "scan_jobs", targetID) != 0 ||
		countRepositoryRetentionRows(t, pool, "scan_evidence", targetID) != 0 ||
		countRepositoryRetentionRows(t, pool, "findings", targetID) != 0 ||
		countRepositoryRetentionRows(t, pool, "assets", targetID) != 0 {
		t.Fatalf("repository target %s still has retained rows", targetID)
	}
}

func assertRepositoryTargetExists(t *testing.T, pool *pgxpool.Pool, targetID uuid.UUID) {
	t.Helper()
	if countRepositoryRetentionRows(t, pool, "scan_targets", targetID) != 1 {
		t.Fatalf("repository target %s was pruned", targetID)
	}
}

func countRepositoryRetentionRows(t *testing.T, pool *pgxpool.Pool, table string, targetID uuid.UUID) int {
	t.Helper()
	var count int
	var err error
	switch table {
	case "scan_targets":
		err = pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM scan_targets WHERE id = $1`, targetID).Scan(&count)
	case "scan_jobs":
		err = pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM scan_jobs WHERE target_id = $1`, targetID).Scan(&count)
	case "scan_evidence":
		err = pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM scan_evidence WHERE scan_target_id = $1`, targetID).Scan(&count)
	case "findings":
		err = pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM findings WHERE scan_target_id = $1`, targetID).Scan(&count)
	case "assets":
		err = pool.QueryRow(context.Background(), `SELECT COUNT(*)::int FROM assets WHERE digest = $1`, "scan-target:"+targetID.String()).Scan(&count)
	default:
		t.Fatalf("unknown table %s", table)
	}
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}
