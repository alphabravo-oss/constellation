package admissionevidence

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

// ADM-29: cveMediumCount and the per-severity with-fix count thresholds are
// evaluated against the image's distinct-CVE counts. DB-backed; skips when the
// test Postgres is unreachable, mirroring the other *FromPostgres tests.
func TestAdmissionEvidenceCVEGranularityCountsFromPostgres(t *testing.T) {
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
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'CVE Granularity Test')`, orgID, "adm-gran-"+orgID.String()); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID) })

	digest := "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1"
	ref := "ghcr.io/acme/adm-gran@" + digest
	resultID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, package_count, finding_count, last_scanned_at, updated_at
) VALUES ($1,$2,$3,$3,'ghcr.io/acme/adm-gran',$4,'linux/amd64','default',5,5,NOW(),NOW())`,
		resultID, orgID, ref, digest); err != nil {
		t.Fatalf("insert image scan result: %v", err)
	}

	// key, ext, severity, fixedVersion ("" = no fix available)
	insertFinding := func(key, ext, sev, fixed string) {
		t.Helper()
		if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
  org_id, image_scan_result_id, finding_key, external_id, title, severity, risk_score,
  canonical_engine, engines, fixed_version, detail_json
) VALUES ($1,$2,$3,$4,'vuln',$5,0,'vulndb','[]'::jsonb,$6,'{}'::jsonb)`,
			orgID, resultID, key, ext, sev, fixed); err != nil {
			t.Fatalf("insert finding %s: %v", ext, err)
		}
	}
	// 2 medium; 1 critical with a fix; 1 high with a fix, 1 high without a fix.
	insertFinding("m1", "CVE-2026-1001", "medium", "")
	insertFinding("m2", "CVE-2026-1002", "medium", "1.2.3")
	insertFinding("c1", "CVE-2026-2001", "critical", "9.9.9")
	insertFinding("h1", "CVE-2026-3001", "high", "4.5.6")
	insertFinding("h2", "CVE-2026-3002", "high", "")

	source := New(pool, orgID)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "gran", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: ref}}},
	}
	vulnRule := func(gate admission.EvidenceGate) admission.Rule {
		gate.Type = "vulnerability"
		return admission.Rule{Conditions: admission.RuleConditions{EvidenceGates: []admission.EvidenceGate{gate}}}
	}
	ptr := func(n int) *int { return &n }

	// cveMediumCount: 2 mediums present; allow at most 1 → deny.
	if reason, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxMediumCVEs: ptr(1)}), pod); err != nil {
		t.Fatal(err)
	} else if !hit || !strings.Contains(reason, "medium CVEs") {
		t.Fatalf("2 mediums over a max of 1 must deny: hit=%v reason=%q", hit, reason)
	}
	// allow at most 2 → pass.
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxMediumCVEs: ptr(2)}), pod); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Fatal("2 mediums within a max of 2 must pass")
	}

	// cveCriticalWithFixCount: 1 fixable critical; allow 0 → deny.
	if reason, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxCriticalWithFixCVEs: ptr(0)}), pod); err != nil {
		t.Fatal(err)
	} else if !hit || !strings.Contains(reason, "fixable critical CVEs") {
		t.Fatalf("1 fixable critical over a max of 0 must deny: hit=%v reason=%q", hit, reason)
	}

	// cveHighWithFixCount: only 1 of the 2 highs has a fix; allow 1 → pass,
	// allow 0 → deny (the fix-less high is excluded from the with-fix count).
	if _, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxHighWithFixCVEs: ptr(1)}), pod); err != nil {
		t.Fatal(err)
	} else if hit {
		t.Fatal("1 fixable high within a max of 1 must pass")
	}
	if reason, hit, err := source.EvaluateAdmissionEvidence(ctx, vulnRule(admission.EvidenceGate{MaxHighWithFixCVEs: ptr(0)}), pod); err != nil {
		t.Fatal(err)
	} else if !hit || !strings.Contains(reason, "fixable high CVEs") {
		t.Fatalf("1 fixable high over a max of 0 must deny: hit=%v reason=%q", hit, reason)
	}
}
