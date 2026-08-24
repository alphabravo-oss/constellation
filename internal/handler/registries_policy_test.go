package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/registry"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/go-chi/chi/v5"
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

func TestRegistryScanPolicyLimitsReposAndTagsDeterministically(t *testing.T) {
	policy := normalizeRegistryScanPolicy(&registryScanPolicy{
		IncludeRepos: []string{"ghcr.io/acme/*"},
		RepoLimit:    2,
		TagLimit:     2,
	}, nil)
	images := []registry.Image{
		{Repository: "ghcr.io/acme/z"},
		{Repository: "ghcr.io/acme/a"},
		{Repository: "ghcr.io/acme/m"},
		{Repository: "docker.io/acme/out"},
	}
	filtered := filterImagesByScanPolicy(images, policy, time.Now())
	if len(filtered) != 2 || filtered[0].Repository != "ghcr.io/acme/a" || filtered[1].Repository != "ghcr.io/acme/m" {
		t.Fatalf("filtered=%+v, want deterministic first two acme repos", filtered)
	}

	tags := selectRegistryTags([]string{"1.0.0", "2.0.0", "3.0.0"}, policy)
	if len(tags) != 2 || tags[0] != "2.0.0" || tags[1] != "3.0.0" {
		t.Fatalf("tags=%v, want highest two tags", tags)
	}
}

func TestRegistryScanPolicyRejectsInvalidNVFields(t *testing.T) {
	tests := []struct {
		name   string
		policy registryScanPolicy
	}{
		{name: "negative repo limit", policy: registryScanPolicy{RepoLimit: -1}},
		{name: "negative tag limit", policy: registryScanPolicy{TagLimit: -1}},
		{name: "bad custom interval", policy: registryScanPolicy{CustomInterval: "soon"}},
		{name: "bad cron", policy: registryScanPolicy{Cron: "not valid"}},
		{name: "custom and cron", policy: registryScanPolicy{CustomInterval: "12h", Cron: "0 2 * * *"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRegistryScanPolicy(tt.policy); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRegistryCadenceAcceptsCustomDurationAndCron(t *testing.T) {
	for _, cadence := range []string{"auto", "12h", "cron:0 2 * * *"} {
		if !validRegistryCadence(cadence) {
			t.Fatalf("cadence %q should be valid", cadence)
		}
	}
	for _, cadence := range []string{"", "custom", "cron:not valid", "-1h"} {
		if validRegistryCadence(cadence) {
			t.Fatalf("cadence %q should be invalid", cadence)
		}
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

func TestRegistryCancelActiveScansCancelsOnlyActiveJobsForRegistry(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()

	orgID := uuid.New()
	userID := uuid.New()
	registryID := uuid.New()
	otherRegistryID := uuid.New()
	targetID := uuid.New()
	otherTargetID := uuid.New()
	pendingJobID := uuid.New()
	runningJobID := uuid.New()
	pausedJobID := uuid.New()
	completedJobID := uuid.New()
	failedJobID := uuid.New()
	otherRegistryJobID := uuid.New()
	orgName := "registry-cancel-" + strings.ReplaceAll(orgID.String(), "-", "")

	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Registry Cancel Test')`, orgID, orgName); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Registry Cancel User')`,
		userID, orgID, "registry-cancel-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM scan_jobs WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM scan_targets WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM registries WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE org_id = $1`, orgID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	if _, err := pool.Exec(ctx, `
INSERT INTO registries (id, org_id, name, kind, endpoint, auth_kind)
VALUES ($1, $2, 'primary-registry', 'ghcr', 'ghcr.io', 'none'),
       ($3, $2, 'other-registry', 'ghcr', 'ghcr.io/other', 'none')`,
		registryID, orgID, otherRegistryID); err != nil {
		t.Fatalf("insert registries: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, source_ref, image_ref, registry_id)
VALUES ($1, $2, 'image', 'ghcr.io/acme/api:latest', 'registry', 'ghcr.io/acme/api', 'ghcr.io/acme/api:latest', $3),
       ($4, $2, 'image', 'ghcr.io/other/api:latest', 'registry', 'ghcr.io/other/api', 'ghcr.io/other/api:latest', $5)`,
		targetID, orgID, registryID, otherTargetID, otherRegistryID); err != nil {
		t.Fatalf("insert scan targets: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_jobs (id, org_id, target_id, status, requested_at, claimed_at, lease_expires_at, finished_at)
VALUES ($1, $2, $3, 'pending', NOW() - INTERVAL '5 minutes', NULL, NULL, NULL),
       ($4, $2, $3, 'running', NOW() - INTERVAL '4 minutes', NOW() - INTERVAL '3 minutes', NOW() + INTERVAL '10 minutes', NULL),
       ($5, $2, $3, 'paused', NOW() - INTERVAL '3 minutes', NULL, NULL, NULL),
       ($6, $2, $3, 'completed', NOW() - INTERVAL '2 minutes', NULL, NULL, NOW() - INTERVAL '1 minute'),
       ($7, $2, $3, 'failed', NOW() - INTERVAL '2 minutes', NULL, NULL, NOW() - INTERVAL '1 minute'),
       ($8, $2, $9, 'running', NOW() - INTERVAL '4 minutes', NOW() - INTERVAL '3 minutes', NOW() + INTERVAL '10 minutes', NULL)`,
		pendingJobID, orgID, targetID, runningJobID, pausedJobID, completedJobID, failedJobID, otherRegistryJobID, otherTargetID); err != nil {
		t.Fatalf("insert scan jobs: %v", err)
	}

	h := NewRegistries(d, audit.New(pool))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/registries/"+registryID.String()+"/cancel-scans", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", registryID.String())
	req = req.WithContext(WithSubject(context.WithValue(req.Context(), chi.RouteCtxKey, rctx), Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()
	h.CancelActiveScans(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("cancel status: %d body: %s", rec.Code, rec.Body.String())
	}
	var res registryCancelScansResponse
	if err := json.NewDecoder(rec.Body).Decode(&res); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if res.RegistryID != registryID.String() || res.Canceled != 3 || res.ActiveRemaining != 0 {
		t.Fatalf("cancel response = %+v, want registry=%s canceled=3 remaining=0", res, registryID)
	}

	wantStatuses := map[uuid.UUID]string{
		pendingJobID:       "canceled",
		runningJobID:       "canceled",
		pausedJobID:        "canceled",
		completedJobID:     "completed",
		failedJobID:        "failed",
		otherRegistryJobID: "running",
	}
	for jobID, want := range wantStatuses {
		var got string
		if err := pool.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE id = $1`, jobID).Scan(&got); err != nil {
			t.Fatalf("query status for %s: %v", jobID, err)
		}
		if got != want {
			t.Fatalf("job %s status=%s want %s", jobID, got, want)
		}
	}

	var runningLease *time.Time
	if err := pool.QueryRow(ctx, `SELECT lease_expires_at FROM scan_jobs WHERE id = $1`, runningJobID).Scan(&runningLease); err != nil {
		t.Fatalf("query running lease: %v", err)
	}
	if runningLease != nil {
		t.Fatalf("canceled running job kept lease_expires_at=%v", runningLease)
	}

	var auditCount int
	if err := pool.QueryRow(ctx, `
SELECT COUNT(*)::int FROM audit_events
 WHERE org_id = $1 AND actor_id = $2 AND action = 'registry.scans.cancel' AND target_id = $3`,
		orgID, userID, registryID.String()).Scan(&auditCount); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("audit count=%d want 1", auditCount)
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
