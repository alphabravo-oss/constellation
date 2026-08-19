package admissionevidence

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

func TestAdmissionEvidenceImagesIncludesAllPodContainerTypes(t *testing.T) {
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.36"}},
		Containers:     []corev1.Container{{Name: "app", Image: "ghcr.io/acme/app:1.0"}},
		EphemeralContainers: []corev1.EphemeralContainer{{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: "debug", Image: "ubuntu:24.04"},
		}},
	}}
	got := admissionEvidenceImages(pod)
	if len(got) != 3 {
		t.Fatalf("image count = %d", len(got))
	}
	if got[0].Role != "init" || got[1].Role != "container" || got[2].Role != "ephemeral" {
		t.Fatalf("roles = %+v", got)
	}
}

func TestImageRefCandidatesAddsDockerAndDigestForms(t *testing.T) {
	busybox := imageRefCandidates(admission.ParseReqImageName("busybox"))
	wantBusybox := []string{"busybox", "docker.io/library/busybox:latest", "busybox:latest", "docker.io/busybox:latest"}
	if !reflect.DeepEqual(busybox, wantBusybox) {
		t.Fatalf("busybox candidates = %#v", busybox)
	}

	digest := imageRefCandidates(admission.ParseReqImageName("ghcr.io/acme/app@sha256:abc"))
	wantDigest := []string{"ghcr.io/acme/app@sha256:abc"}
	if !reflect.DeepEqual(digest, wantDigest) {
		t.Fatalf("digest candidates = %#v", digest)
	}
}

func TestEvidenceGateSeverityAndKindMapping(t *testing.T) {
	vuln := admission.EvidenceGate{Type: "vulnerability", MaxAllowedSeverity: "high"}
	if got := minimumSeverityRankForGate(vuln); got != 4 {
		t.Fatalf("critical-only rank = %d", got)
	}
	misconfig := admission.EvidenceGate{Type: "finding", FindingKinds: []string{"misconfiguration"}, MinimumSeverity: "critical"}
	if got := findingKindsForGate(misconfig); !reflect.DeepEqual(got, []string{"misconfiguration", "iac", "cloud-config", "compliance"}) {
		t.Fatalf("misconfiguration kinds = %#v", got)
	}
	if got := minimumSeverityRankForGate(misconfig); got != 4 {
		t.Fatalf("misconfiguration min rank = %d", got)
	}
	secret := admission.EvidenceGate{Type: "finding", FindingKinds: []string{"secret"}, MinimumConfidence: "high"}
	if got := confidenceRank(secret.MinimumConfidence); got != 3 {
		t.Fatalf("secret confidence rank = %d", got)
	}
}

func TestFindEvidenceHitFailsClosedForNonVulnerabilityKinds(t *testing.T) {
	// image_scan_findings persists only vulnerability findings, so a
	// misconfiguration/iac/cloud-config/compliance gate cannot be evaluated and
	// must fail closed (return an error the caller turns into a deny) rather than
	// silently match zero rows. The guard runs before any DB access, so a
	// pool-less Source is sufficient.
	src := &Source{orgID: uuid.New()}
	gate := admission.EvidenceGate{Type: "finding", FindingKinds: []string{"misconfiguration"}}
	image := admissionEvidenceImageFor("app", "container", "ghcr.io/acme/app:1.0")
	if _, found, err := src.findEvidenceHit(context.Background(), gate, image); err == nil {
		t.Fatalf("expected fail-closed error for non-vulnerability gate, got found=%v err=nil", found)
	}

	// A vulnerability gate still passes the guard (and would proceed to query the
	// DB, so we only assert the guard does not reject it by checking the error is
	// not the fail-closed kind-evaluation error). Use a recover-free path: the nil
	// pool would panic on Query, so instead assert the guard alone via kinds.
	vuln := admission.EvidenceGate{Type: "vulnerability", MaxAllowedSeverity: "high"}
	if kinds := findingKindsForGate(vuln); !reflect.DeepEqual(kinds, []string{"vulnerability"}) {
		t.Fatalf("vulnerability gate kinds = %#v", kinds)
	}
}

func TestArtifactGateFromFindingGate(t *testing.T) {
	secretGate, ok := artifactGateFromFindingGate(admission.EvidenceGate{
		Type:              "finding",
		FindingKinds:      []string{"secret"},
		MinimumConfidence: "high",
	})
	if !ok {
		t.Fatal("secret finding gate should map to artifact gate")
	}
	if secretGate.Type != "artifact" || secretGate.Artifact != "secret" || secretGate.MinimumSeverity != "high" {
		t.Fatalf("secret artifact gate = %+v", secretGate)
	}

	fileRiskGate, ok := artifactGateFromFindingGate(admission.EvidenceGate{
		Type:         "finding",
		FindingKinds: []string{"file-risk", "setuid", "device-node"},
	})
	if !ok {
		t.Fatal("file risk finding gate should map to artifact gate")
	}
	if fileRiskGate.Artifact != "file-risk" || !reflect.DeepEqual(fileRiskGate.RiskTypes, []string{"setuid", "device-node"}) {
		t.Fatalf("file risk artifact gate = %+v", fileRiskGate)
	}

	signatureGate, ok := artifactGateFromFindingGate(admission.EvidenceGate{
		Type:         "finding",
		FindingKinds: []string{"signature"},
	})
	if !ok {
		t.Fatal("signature finding gate should map to artifact gate")
	}
	if signatureGate.Artifact != "signature" || !signatureGate.RequireTrustedSignature {
		t.Fatalf("signature artifact gate = %+v", signatureGate)
	}
}

func TestFormatAdmissionArtifactHits(t *testing.T) {
	image := admissionEvidenceImage{Container: "app", Raw: "ghcr.io/acme/app@sha256:abc"}
	secret := formatAdmissionEvidenceHit(admission.Rule{}, admission.EvidenceGate{Type: "artifact"}, image, admissionEvidenceHit{
		Kind: "secret", Severity: "high", ExternalID: "aws-access-key", Title: "AWS access key", Path: "/app/config.env", Count: 2,
	})
	if !strings.Contains(secret, "2 secret finding(s)") || !strings.Contains(secret, "/app/config.env") {
		t.Fatalf("secret message = %q", secret)
	}
	fileRisk := formatAdmissionEvidenceHit(admission.Rule{}, admission.EvidenceGate{Type: "artifact"}, image, admissionEvidenceHit{
		Kind: "file-risk", Severity: "medium", Title: "setuid root executable", Path: "/usr/bin/helper", Count: 1,
	})
	if !strings.Contains(fileRisk, "1 file-risk finding(s)") || !strings.Contains(fileRisk, "/usr/bin/helper") {
		t.Fatalf("file-risk message = %q", fileRisk)
	}
	signature := formatAdmissionEvidenceHit(admission.Rule{}, admission.EvidenceGate{Type: "artifact"}, image, admissionEvidenceHit{
		Kind: "signature", Status: "unsigned", Title: "cosign verification failed",
	})
	if !strings.Contains(signature, `signature status "unsigned"`) {
		t.Fatalf("signature message = %q", signature)
	}
	identity := formatAdmissionEvidenceHit(admission.Rule{}, admission.EvidenceGate{Type: "artifact"}, image, admissionEvidenceHit{
		Kind: "signature", Status: "identity-not-allowed", Identity: "repo@example.com", Title: "repo@example.com",
	})
	if !strings.Contains(identity, `signature verifier identity "repo@example.com"`) {
		t.Fatalf("identity message = %q", identity)
	}
}

func TestAdmissionEvidenceArtifactsFromPostgres(t *testing.T) {
	ctx := context.Background()
	pool := openAdmissionTestPool(t)
	defer pool.Close()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	var regclass string
	if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.image_scan_artifacts')::text, '')`).Scan(&regclass); err != nil || regclass == "" {
		t.Skipf("skipping: image_scan_artifacts migration not applied (%v)", err)
	}

	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1"
	ref := "ghcr.io/acme/admission-artifact@" + digest
	resultID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, digest)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, digest)
	})

	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash, package_count, finding_count
) VALUES ($1,$2,$3,$3,'ghcr.io/acme/admission-artifact',$4,'linux/amd64','default','bundle-test','sha256:bundle',4,0)`,
		resultID, orgID, ref, digest); err != nil {
		t.Fatalf("insert image scan result: %v", err)
	}
	insertArtifact := func(artifactType, format, payload string, count int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_artifacts (
  org_id, image_scan_result_id, artifact_type, format, payload, sha256, package_count
) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
			orgID, resultID, artifactType, format, payload, "sha256:"+artifactType, count); err != nil {
			t.Fatalf("insert %s artifact: %v", artifactType, err)
		}
	}
	insertArtifact("secret-scan", "constellation-image-secrets-v1", `{
  "schema_version":"constellation.image-secrets.v1",
  "secret_count":1,
  "secrets":[{"rule_id":"aws-access-key-id","title":"AWS access key","severity":"high","path":"/app/.env"}]
}`, 1)
	insertArtifact("file-risk", "constellation-image-file-risk-v1", `{
  "schema_version":"constellation.image-file-risk.v1",
  "file_risk_count":1,
  "findings":[{"path":"/usr/bin/helper","severity":"medium","reason":"setuid executable","risk_types":["setuid"]}]
}`, 1)
	insertArtifact("signature-scan", "constellation-image-signature-v1", `{
  "schema_version":"constellation.image-signature.v1",
  "status":"untrusted",
  "signed":true,
  "trusted":false,
  "signature":{"identity":"repo@example.com","reason":"issuer mismatch"}
}`, 1)

	source := New(pool, orgID)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "artifact-gated", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: ref,
		}}},
	}

	for _, tc := range []struct {
		name   string
		gate   admission.EvidenceGate
		expect string
	}{
		{
			name:   "secret",
			gate:   admission.EvidenceGate{Type: "artifact", Artifact: "secret", MinimumSeverity: "high"},
			expect: "secret finding(s)",
		},
		{
			name:   "file risk",
			gate:   admission.EvidenceGate{Type: "artifact", Artifact: "file-risk", MinimumSeverity: "medium", RiskTypes: []string{"setuid"}},
			expect: "file-risk finding(s)",
		},
		{
			name:   "signature",
			gate:   admission.EvidenceGate{Type: "artifact", Artifact: "signature", RequireTrustedSignature: true},
			expect: `signature status "untrusted"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, hit, err := source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{tc.gate}}}, pod)
			if err != nil {
				t.Fatal(err)
			}
			if !hit || !strings.Contains(reason, tc.expect) {
				t.Fatalf("hit=%v reason=%q want substring %q", hit, reason, tc.expect)
			}
			_, hit, details, err := source.EvaluateAdmissionEvidenceWithDetails(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{tc.gate}}}, pod)
			if err != nil {
				t.Fatal(err)
			}
			if !hit || len(details) != 1 || details[0].ScanResult == nil || details[0].ScanResult.ID != resultID.String() {
				t.Fatalf("details hit=%v details=%+v", hit, details)
			}
			if details[0].Artifact == nil || details[0].Artifact.Type == "" || details[0].Artifact.ID == "" {
				t.Fatalf("artifact detail missing: %+v", details[0])
			}
			if tc.name == "file risk" && !reflect.DeepEqual(details[0].Artifact.RiskTypes, []string{"setuid"}) {
				t.Fatalf("file risk detail risk types = %+v", details[0].Artifact.RiskTypes)
			}
		})
	}

	t.Run("signature identity allowed", func(t *testing.T) {
		reason, hit, err := source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{{
			Type:                      "artifact",
			Artifact:                  "signature",
			RequireVerifierIdentity:   true,
			AllowedVerifierIdentities: []string{"repo@example.com"},
		}}}}, pod)
		if err != nil {
			t.Fatal(err)
		}
		if hit {
			t.Fatalf("allowed identity should not hit: %q", reason)
		}
	})

	t.Run("signature identity denied", func(t *testing.T) {
		reason, hit, err := source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{{
			Type:                      "artifact",
			Artifact:                  "signature",
			RequireVerifierIdentity:   true,
			AllowedVerifierIdentities: []string{"security@example.com"},
		}}}}, pod)
		if err != nil {
			t.Fatal(err)
		}
		if !hit || !strings.Contains(reason, "signature verifier identity") {
			t.Fatalf("hit=%v reason=%q", hit, reason)
		}
	})
}

func TestAdmissionEvidenceScanQualityGatesFromPostgres(t *testing.T) {
	ctx := context.Background()
	pool := openAdmissionTestPool(t)
	defer pool.Close()

	for _, table := range []string{"scan_targets", "image_scan_results", "image_scan_findings", "scan_result_attestations", "scan_attestation_trust_policies"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Admission Evidence Test')`, orgID, "admission-evidence-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})

	digest := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"
	ref := "ghcr.io/acme/admission-quality@" + digest
	targetID := uuid.New()
	resultID := uuid.New()
	trustPolicyID := uuid.New()
	_, _ = pool.Exec(ctx, `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, digest)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM image_scan_results WHERE org_id = $1 AND image_digest = $2`, orgID, digest)
	})

	if _, err := pool.Exec(ctx, `
INSERT INTO scan_targets (id, org_id, type, ref, source_type, source_ref, image_ref)
VALUES ($1,$2,'image',$3,'repository','github.com/acme/admission-quality@abcdef',$3)`,
		targetID, orgID, ref); err != nil {
		t.Fatalf("insert scan target: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_attestation_trust_policies (
  id, org_id, name, enabled, auto_verify, subject_kind, source_types,
  predicate_types, allowed_identities, allowed_issuers
) VALUES (
  $1,$2,'Admission quality trust',true,true,'image',ARRAY['repository']::text[],
  ARRAY['https://slsa.dev/provenance/v1']::text[],
  ARRAY['repo:acme/admission-quality:ref:refs/heads/main']::text[],
  ARRAY['https://token.actions.githubusercontent.com']::text[]
)`, trustPolicyID, orgID); err != nil {
		t.Fatalf("insert trust policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash, package_count, finding_count,
  source_type, source_ref, scan_target_id, last_scanned_at, updated_at
) VALUES ($1,$2,$3,$3,'ghcr.io/acme/admission-quality',$4,'linux/amd64','default','bundle-test','sha256:bundle',4,1,'repository','github.com/acme/admission-quality@abcdef',$5,NOW(),NOW())`,
		resultID, orgID, ref, digest, targetID); err != nil {
		t.Fatalf("insert image scan result: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
  org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score,
  canonical_engine, engines, package_ecosystem, package_name, package_version, fixed_version, detail_json
) VALUES (
  $1,$2,'cve-quality','CVE-2026-QUALITY','fixable vuln','high',92,
  'vulndb','[]'::jsonb,'deb','openssl','3.0.0','3.0.2','{"confidence":"high"}'::jsonb
)`, orgID, resultID); err != nil {
		t.Fatalf("insert image finding: %v", err)
	}

	source := New(pool, orgID)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "quality-gated", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: ref,
		}}},
	}
	gate := admission.EvidenceGate{
		Type:                    "vulnerability",
		MaxAllowedSeverity:      "medium",
		RequireKnownScanResult:  true,
		MaxScanAgeSeconds:       int64((24 * time.Hour) / time.Second),
		RequireVulnDBBundle:     true,
		AllowedSourceTypes:      []string{"repository"},
		RequireDigestMatch:      true,
		AllowedCanonicalEngines: []string{"vulndb"},
		RequireFixAvailable:     true,
	}
	reason, hit, err := source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "CVE-2026-QUALITY") {
		t.Fatalf("canonical fixable vuln gate hit=%v reason=%q", hit, reason)
	}
	_, hit, details, err := source.EvaluateAdmissionEvidenceWithDetails(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || len(details) != 1 || details[0].ScanResult == nil || details[0].Finding == nil {
		t.Fatalf("vulnerability details hit=%v details=%+v", hit, details)
	}
	if details[0].Kind != "image-finding" ||
		details[0].ScanResult.ID != resultID.String() ||
		details[0].ScanResult.SourceType != "repository" ||
		details[0].ScanResult.SourceRef != "github.com/acme/admission-quality@abcdef" ||
		details[0].ScanResult.VulnDBBundleVersion != "bundle-test" ||
		details[0].Finding.ExternalID != "CVE-2026-QUALITY" ||
		details[0].Finding.CanonicalEngine != "vulndb" ||
		details[0].Finding.PackageName != "openssl" ||
		details[0].Finding.FixedVersion != "3.0.2" {
		t.Fatalf("unexpected vulnerability details: %+v", details[0])
	}

	attestationGate := admission.EvidenceGate{
		RequireKnownScanResult:       true,
		AllowedSourceTypes:           []string{"repository"},
		RequireDigestMatch:           true,
		RequireTrustedAttestation:    true,
		AttestationPredicateTypes:    []string{"https://slsa.dev/provenance/v1"},
		AllowedAttestationIdentities: []string{"repo:acme/admission-quality:ref:refs/heads/main"},
		AllowedAttestationIssuers:    []string{"https://token.actions.githubusercontent.com"},
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{attestationGate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "no trusted repository/CI attestation") {
		t.Fatalf("missing attestation hit=%v reason=%q", hit, reason)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO scan_result_attestations (
  org_id, scan_target_id, image_scan_result_id,
  target_type, target_ref, source_type, source_ref,
  subject_kind, subject_ref, subject_digest,
  predicate_type, format, payload, payload_sha256,
  verification_status, trusted, signer_identity, signer_issuer, verified_at, observed_at, metadata, trust_policy_id, verification_reason
) VALUES (
  $1,$2,$3,
  'image',$4,'repository','github.com/acme/admission-quality@abcdef',
  'image',$4,$5,
  'https://slsa.dev/provenance/v1','in-toto-statement-v1',
  '{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://slsa.dev/provenance/v1","subject":[{"name":"ghcr.io/acme/admission-quality","digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2"}}],"predicate":{}}'::jsonb,
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'trusted', true, 'repo:acme/admission-quality:ref:refs/heads/main', 'https://token.actions.githubusercontent.com', NOW(), NOW(), '{}'::jsonb, $6, 'attestation trusted'
)`, orgID, targetID, resultID, ref, digest, trustPolicyID); err != nil {
		t.Fatalf("insert trusted attestation: %v", err)
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{attestationGate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Fatalf("trusted attestation gate should pass: %q", reason)
	}
	attestationGate.AllowedAttestationIdentities = []string{"repo:other/app:ref:refs/heads/main"}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{attestationGate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "no trusted repository/CI attestation") {
		t.Fatalf("wrong attestation identity hit=%v reason=%q", hit, reason)
	}
	attestationGate.AllowedAttestationIdentities = []string{"repo:acme/admission-quality:ref:refs/heads/main"}
	if _, err := pool.Exec(ctx, `UPDATE scan_attestation_trust_policies SET enabled = false WHERE org_id = $1 AND id = $2`, orgID, trustPolicyID); err != nil {
		t.Fatalf("disable trust policy: %v", err)
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{attestationGate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "no trusted repository/CI attestation") {
		t.Fatalf("disabled attestation policy hit=%v reason=%q", hit, reason)
	}
	if _, err := pool.Exec(ctx, `UPDATE scan_attestation_trust_policies SET enabled = true WHERE org_id = $1 AND id = $2`, orgID, trustPolicyID); err != nil {
		t.Fatalf("restore trust policy: %v", err)
	}

	tagOnlyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "quality-gated-tag", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "ghcr.io/acme/admission-quality:latest",
		}}},
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, tagOnlyPod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "not digest-pinned") {
		t.Fatalf("digest-required hit=%v reason=%q", hit, reason)
	}

	if _, err := pool.Exec(ctx, `UPDATE image_scan_results SET source_type = 'manual', source_ref = 'manual-source', last_scanned_at = NOW(), updated_at = NOW() WHERE org_id = $1 AND id = $2`, orgID, resultID); err != nil {
		t.Fatalf("manual source: %v", err)
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "allowed source types") {
		t.Fatalf("source-required hit=%v reason=%q", hit, reason)
	}
	if _, err := pool.Exec(ctx, `UPDATE image_scan_results SET source_type = 'repository', source_ref = 'github.com/acme/admission-quality@abcdef', last_scanned_at = NOW(), updated_at = NOW() WHERE org_id = $1 AND id = $2`, orgID, resultID); err != nil {
		t.Fatalf("restore source: %v", err)
	}

	gate.AllowedCanonicalEngines = []string{"grype"}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Fatalf("non-canonical engine should not hit: %q", reason)
	}

	gate.AllowedCanonicalEngines = []string{"vulndb"}
	if _, err := pool.Exec(ctx, `UPDATE image_scan_findings SET fixed_version = NULL WHERE org_id = $1 AND image_scan_result_id = $2`, orgID, resultID); err != nil {
		t.Fatalf("clear fixed version: %v", err)
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if hit {
		t.Fatalf("non-fixable vuln should not hit fixable gate: %q", reason)
	}

	if _, err := pool.Exec(ctx, `UPDATE image_scan_findings SET fixed_version = '3.0.2' WHERE org_id = $1 AND image_scan_result_id = $2`, orgID, resultID); err != nil {
		t.Fatalf("restore fixed version: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE image_scan_results SET last_scanned_at = NOW() - INTERVAL '48 hours', updated_at = NOW() - INTERVAL '48 hours' WHERE org_id = $1 AND id = $2`, orgID, resultID); err != nil {
		t.Fatalf("stale scan: %v", err)
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "scan result is stale") {
		t.Fatalf("stale scan hit=%v reason=%q", hit, reason)
	}
	_, hit, details, err = source.EvaluateAdmissionEvidenceWithDetails(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || len(details) != 1 || details[0].Kind != "image-scan-result" || details[0].ScanResult == nil || details[0].ScanResult.ID != resultID.String() {
		t.Fatalf("stale scan details hit=%v details=%+v", hit, details)
	}

	if _, err := pool.Exec(ctx, `UPDATE image_scan_results SET last_scanned_at = NOW(), updated_at = NOW(), vulndb_bundle_version = '', vulndb_bundle_hash = '' WHERE org_id = $1 AND id = $2`, orgID, resultID); err != nil {
		t.Fatalf("clear bundle provenance: %v", err)
	}
	reason, hit, err = source.EvaluateAdmissionEvidence(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}, pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "no VulnDB bundle provenance") {
		t.Fatalf("missing bundle hit=%v reason=%q", hit, reason)
	}

	missingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "missing-scan", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "ghcr.io/acme/missing@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3",
		}}},
	}
	missingGate := admission.EvidenceGate{RequireKnownScanResult: true}
	reason, hit, details, err = source.EvaluateAdmissionEvidenceWithDetails(ctx, admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{missingGate}}}, missingPod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "no known Constellation scan result") || len(details) != 1 || details[0].Kind != "missing-image-scan-result" {
		t.Fatalf("missing scan details hit=%v reason=%q details=%+v", hit, reason, details)
	}
}

func openAdmissionTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	if url == "" {
		url = "postgres://test:test@localhost:15433/constellation_test?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	return pool
}

// TestAdmissionEvidenceCVEScoreGateFromPostgres verifies the CVE-score gate
// (ADM-2): findings whose detail_json->'cvss_base' is >= the threshold are
// counted (distinct external_id), and the gate denies when the count exceeds
// MaxCVEsAtOrAboveScore. DB-backed; auto-skips if the test DB is unreachable.
func TestAdmissionEvidenceCVEScoreGateFromPostgres(t *testing.T) {
	ctx := context.Background()
	pool := openAdmissionTestPool(t)
	defer pool.Close()

	for _, table := range []string{"image_scan_results", "image_scan_findings"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'CVE Score Gate Test')`, orgID, "adm2-score-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	digest := "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc2"
	ref := "ghcr.io/acme/adm2-score@" + digest
	resultID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, package_count, finding_count, last_scanned_at, updated_at
) VALUES ($1,$2,$3,$3,'ghcr.io/acme/adm2-score',$4,'linux/amd64','default',4,3,NOW(),NOW())`,
		resultID, orgID, ref, digest); err != nil {
		t.Fatalf("insert image scan result: %v", err)
	}

	// Three CVEs at/above score 7.0, one below — only the three count.
	findings := []struct {
		ext  string
		sev  string
		cvss float64
	}{
		{"CVE-2026-AAAA", "critical", 9.8},
		{"CVE-2026-BBBB", "high", 7.5},
		{"CVE-2026-CCCC", "high", 7.0},
		{"CVE-2026-DDDD", "medium", 5.0},
	}
	for i, f := range findings {
		if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
  org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score,
  canonical_engine, engines, detail_json
) VALUES ($1,$2,$3,$4,'vuln',$5,0,'vulndb','[]'::jsonb, jsonb_build_object('cvss_base', $6::numeric))`,
			orgID, resultID, "k"+itoaTest(i), f.ext, f.sev, f.cvss); err != nil {
			t.Fatalf("insert finding %d: %v", i, err)
		}
	}

	source := New(pool, orgID)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "score-gated", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: ref}}},
	}
	rule := func(max int, score float64) admission.Rule {
		m := max
		return admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{{
			Type:                  "vulnerability",
			MaxCVEsAtOrAboveScore: &m,
			MinCVEScore:           score,
		}}}}
	}

	// 3 CVEs >= 7.0, allow at most 2 -> deny.
	reason, hit, err := source.EvaluateAdmissionEvidence(ctx, rule(2, 7.0), pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "CVSS score >= 7") {
		t.Fatalf("score gate should deny (3 >= 7.0, allow 2): hit=%v reason=%q", hit, reason)
	}
	// Allow at most 3 -> pass.
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, rule(3, 7.0), pod); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Fatalf("score gate should pass when count == allowed (3 >= 7.0, allow 3)")
	}
}

// TestAdmissionEvidenceDeniedCVEAndGraceFromPostgres verifies A3 (named-CVE deny
// list) and A4 (publish-age grace window): a denied CVE id blocks admission
// regardless of severity, and the grace window excludes freshly-published CVEs
// from both the named-deny and count paths. DB-backed; auto-skips if the test DB
// is unreachable.
func TestAdmissionEvidenceDeniedCVEAndGraceFromPostgres(t *testing.T) {
	ctx := context.Background()
	pool := openAdmissionTestPool(t)
	defer pool.Close()

	for _, table := range []string{"image_scan_results", "image_scan_findings"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Denied CVE Gate Test')`, orgID, "adm-cve-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	digest := "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd1"
	ref := "ghcr.io/acme/adm-cve@" + digest
	resultID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, package_count, finding_count, last_scanned_at, updated_at
) VALUES ($1,$2,$3,$3,'ghcr.io/acme/adm-cve',$4,'linux/amd64','default',4,3,NOW(),NOW())`,
		resultID, orgID, ref, digest); err != nil {
		t.Fatalf("insert image scan result: %v", err)
	}

	// Two low-severity CVEs: one published long ago, one published today. A
	// severity gate would ignore both; the named-deny list must still block.
	insertFinding := func(key, ext, sev, published string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
  org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score,
  canonical_engine, engines, detail_json
) VALUES ($1,$2,$3,$4,'vuln',$5,0,'vulndb','[]'::jsonb,
  CASE WHEN $6::text = '' THEN '{}'::jsonb ELSE jsonb_build_object('published', $6::text) END)`,
			orgID, resultID, key, ext, sev, published); err != nil {
			t.Fatalf("insert finding %s: %v", ext, err)
		}
	}
	insertFinding("k-old", "CVE-2020-0001", "low", "2020-01-01T00:00:00Z")
	insertFinding("k-new", "CVE-2026-9999", "high", time.Now().UTC().Format("2006-01-02T15:04:05Z"))

	source := New(pool, orgID)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "cve-gated", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: ref}}},
	}
	vulnRule := func(gate admission.EvidenceGate) admission.Rule {
		gate.Type = "vulnerability"
		return admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}
	}

	// A3: a named-denied low-severity CVE blocks regardless of severity.
	reason, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{DeniedCVEs: []string{"cve-2020-0001"}}), pod)
	if err != nil {
		t.Fatal(err)
	}
	if !hit || !strings.Contains(reason, "denied CVE CVE-2020-0001") {
		t.Fatalf("named-CVE deny should hit: hit=%v reason=%q", hit, reason)
	}

	// A3 miss: a CVE that is not present does not block.
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{DeniedCVEs: []string{"CVE-2000-0000"}}), pod); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Fatal("absent CVE must not block")
	}

	// A4: the freshly-published denied CVE is excluded by a 30-day grace window.
	graceDays := 30
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{DeniedCVEs: []string{"CVE-2026-9999"}, CVEGraceDays: &graceDays}), pod); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Fatal("freshly-published denied CVE must be excluded by the grace window")
	}
	// Without a grace window the same denied CVE blocks.
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{DeniedCVEs: []string{"CVE-2026-9999"}}), pod); err != nil {
		t.Fatal(err)
	} else if !hit {
		t.Fatal("freshly-published denied CVE must block without a grace window")
	}

	// A4 on the count path: 1 high CVE total, but it is fresh. With a 30-day
	// grace window it is not counted, so maxHighCount=0 passes; without grace it
	// exceeds the threshold and denies.
	zero := 0
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxHighCVEs: &zero, CVEGraceDays: &graceDays}), pod); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Fatal("fresh high CVE must be excluded from the count by the grace window")
	}
	if reason, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxHighCVEs: &zero}), pod); err != nil {
		t.Fatal(err)
	} else if !hit || !strings.Contains(reason, "high CVEs") {
		t.Fatalf("high CVE must be counted without grace window: hit=%v reason=%q", hit, reason)
	}
}

func itoaTest(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
