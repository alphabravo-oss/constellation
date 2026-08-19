package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/registry"
	"github.com/google/uuid"
)

func TestRegistryScanPolicyNormalizeUsesLegacyGlobs(t *testing.T) {
	policy := normalizeRegistryScanPolicy(nil, []string{"ghcr.io/acme/*", "docker.io/acme/api"})
	if got := len(policy.IncludeRepos); got != 2 {
		t.Fatalf("include len=%d want 2: %+v", got, policy)
	}
	if policy.TagSelection != "all" {
		t.Fatalf("tag selection=%q want all", policy.TagSelection)
	}
	if policy.BlockPromotionThreshold != "critical" {
		t.Fatalf("threshold=%q want critical", policy.BlockPromotionThreshold)
	}
}

func TestRegistryScanPolicyFiltering(t *testing.T) {
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	policy := normalizeRegistryScanPolicy(&registryScanPolicy{
		IncludeRepos: []string{"ghcr.io/acme/*"},
		ExcludeRepos: []string{"*/experimental-*"},
		MaxAge:       "48h",
	}, nil)
	images := []registry.Image{
		{Repository: "ghcr.io/acme/api", PushedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		{Repository: "ghcr.io/acme/experimental-api", PushedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)},
		{Repository: "ghcr.io/acme/old", PushedAt: now.Add(-72 * time.Hour).Format(time.RFC3339)},
		{Repository: "docker.io/acme/api", PushedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)},
	}
	filtered := filterImagesByScanPolicy(images, policy, now)
	if len(filtered) != 1 || filtered[0].Repository != "ghcr.io/acme/api" {
		t.Fatalf("filtered=%+v, want only ghcr.io/acme/api", filtered)
	}
}

func TestRegistryScanPolicySelectLatestTag(t *testing.T) {
	policy := normalizeRegistryScanPolicy(&registryScanPolicy{TagSelection: "latest"}, nil)
	if got := selectRegistryTags([]string{"1.0.0", "latest", "2.0.0"}, policy); len(got) != 1 || got[0] != "latest" {
		t.Fatalf("latest tags=%v, want latest", got)
	}
	if got := selectRegistryTags([]string{"1.0.0", "2.0.0"}, policy); len(got) != 1 || got[0] != "2.0.0" {
		t.Fatalf("fallback latest tags=%v, want lexical highest", got)
	}
}

func TestRegistryPolicyHashStableForGlobOrder(t *testing.T) {
	a := normalizeRegistryScanPolicy(&registryScanPolicy{IncludeRepos: []string{"b/*", "a/*"}}, nil)
	b := normalizeRegistryScanPolicy(&registryScanPolicy{IncludeRepos: []string{"a/*", "b/*"}}, nil)
	if registryPolicyHash(a) != registryPolicyHash(b) {
		t.Fatalf("policy hash changed for equivalent include order")
	}
}

func TestDigestFromResolvedRef(t *testing.T) {
	if got := digestFromResolvedRef("ghcr.io/acme/api@sha256:abc"); got != "sha256:abc" {
		t.Fatalf("digest=%q want sha256:abc", got)
	}
	if got := digestFromResolvedRef("ghcr.io/acme/api:latest"); got != "" {
		t.Fatalf("unexpected digest=%q", got)
	}
}

func TestRegistryScanRequeuesWhenVulnDBBundleChanges(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}

	registryID := uuid.New()
	repo := "ghcr.io/acme/vulndb-requeue-" + strings.ReplaceAll(registryID.String(), "-", "")
	if _, err := pool.Exec(ctx, `
INSERT INTO registries (id, org_id, name, kind, endpoint, auth_kind)
VALUES ($1, $2, $3, 'ghcr', 'ghcr.io', 'none')`,
		registryID, orgID, "vulndb-requeue-"+registryID.String()); err != nil {
		t.Fatalf("insert registry: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM scan_targets WHERE registry_id = $1`, registryID)
		_, _ = pool.Exec(ctx, `DELETE FROM registry_images WHERE registry_id = $1`, registryID)
		_, _ = pool.Exec(ctx, `DELETE FROM registries WHERE id = $1`, registryID)
	})

	policy := normalizeRegistryScanPolicy(&registryScanPolicy{
		IncludeRepos:   []string{repo},
		TagSelection:   "latest",
		RescanInterval: "",
	}, nil)
	policyHash := registryPolicyHash(policy)
	images := []registry.Image{{Repository: repo, Tags: []string{"latest"}}}
	conn := fixedDigestConnector{digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}

	jobs, err := upsertImagesAndEnqueue(ctx, pool, orgID, registryID, images, conn, policy, policyHash, "bundle-a")
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if jobs != 1 {
		t.Fatalf("first jobs=%d want 1", jobs)
	}

	jobs, err = upsertImagesAndEnqueue(ctx, pool, orgID, registryID, images, conn, policy, policyHash, "bundle-a")
	if err != nil {
		t.Fatalf("same bundle upsert: %v", err)
	}
	if jobs != 0 {
		t.Fatalf("same bundle jobs=%d want 0", jobs)
	}

	jobs, err = upsertImagesAndEnqueue(ctx, pool, orgID, registryID, images, conn, policy, policyHash, "bundle-b")
	if err != nil {
		t.Fatalf("new bundle upsert: %v", err)
	}
	if jobs != 1 {
		t.Fatalf("new bundle jobs=%d want 1", jobs)
	}

	rows, err := pool.Query(ctx, `
SELECT vulndb_bundle_version, enqueue_reason
  FROM scan_jobs sj
  JOIN scan_targets st ON st.id = sj.target_id
 WHERE st.registry_id = $1
 ORDER BY sj.requested_at`, registryID)
	if err != nil {
		t.Fatalf("query scan jobs: %v", err)
	}
	defer rows.Close()

	got := map[string]string{}
	for rows.Next() {
		var bundleVersion, reason string
		if err := rows.Scan(&bundleVersion, &reason); err != nil {
			t.Fatalf("scan row: %v", err)
		}
		got[bundleVersion] = reason
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("scan jobs=%v, want bundle-a and bundle-b", got)
	}
	if got["bundle-a"] != "digest-policy-or-vulndb-changed" || got["bundle-b"] != "digest-policy-or-vulndb-changed" {
		t.Fatalf("enqueue reasons=%v, want digest-policy-or-vulndb-changed for both bundles", got)
	}
}

type fixedDigestConnector struct {
	digest string
}

func (c fixedDigestConnector) Name() string {
	return "fixed"
}

func (c fixedDigestConnector) ListImages(context.Context) ([]registry.Image, error) {
	return nil, nil
}

func (c fixedDigestConnector) ResolveDigest(_ context.Context, ref string) (string, error) {
	return ref + "@" + c.digest, nil
}
