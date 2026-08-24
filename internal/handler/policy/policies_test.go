package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/admission"
)

func TestPolicies_SimulateWithoutStorageUsesNoSynthesizedPolicies(t *testing.T) {
	body := []byte(`{"manifest":"apiVersion: v1\nkind: Pod\nmetadata:\n  name: privileged-debug\n  namespace: default\nspec:\n  containers:\n    - name: shell\n      image: busybox:latest\n      securityContext:\n        privileged: true\n        runAsUser: 0\n"}`)
	w := httptest.NewRecorder()

	NewPolicies(nil, nil, nil).Simulate(w, httptest.NewRequest(http.MethodPost, "/api/v1/policies/simulate", bytes.NewReader(body)))

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got admissionSimulationResponseDTO
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != "allow" || got.EnforcementMode != "none" {
		t.Fatalf("unexpected decision: %+v", got)
	}
	if !got.Workload.Privileged || !got.Workload.LatestTag || !got.Workload.UnsignedImage {
		t.Fatalf("workload signals missing: %+v", got.Workload)
	}
	if len(got.Matches) != 0 {
		t.Fatalf("expected no synthesized policy matches, got %+v", got.Matches)
	}
	if !got.AdmissionReview.DryRun || got.AdmissionReview.PersistsDecision || got.AdmissionReview.SendsWebhook {
		t.Fatalf("simulation must remain dry-run: %+v", got.AdmissionReview)
	}
	if got.AdmissionReview.ReviewedAt == "" || got.AdmissionReview.Source != "pasted manifest" {
		t.Fatalf("missing review metadata: %+v", got.AdmissionReview)
	}
	if len(got.Guardrails) == 0 || len(got.ClusterResources) != 0 {
		t.Fatalf("unexpected guardrails/resources: %+v", got)
	}
}

func TestPolicies_SimulateRejectsClusterResourceSamplesWithoutManifest(t *testing.T) {
	body := []byte(`{"cluster_resource_id":"missing-resource"}`)
	w := httptest.NewRecorder()

	NewPolicies(nil, nil, nil).Simulate(w, httptest.NewRequest(http.MethodPost, "/api/v1/policies/simulate", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestPolicies_SimulateEvaluatesStoredCriticalVulnerabilityEvidence(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := context.Background()
	pool := d.Pool()
	for _, table := range []string{"policies", "policy_decisions", "image_scan_results", "image_scan_findings"} {
		var regclass string
		if err := pool.QueryRow(ctx, `SELECT COALESCE(to_regclass('public.' || $1)::text, '')`, table).Scan(&regclass); err != nil || regclass == "" {
			t.Skipf("skipping: %s migration not applied (%v)", table, err)
		}
	}

	orgID := uuid.New()
	userID := uuid.New()
	clusterID := uuid.New()
	policyID := uuid.New()
	resultID := uuid.New()
	digest := "sha256:simulatorcritical000000000000000000000000000000000000000000000001"
	imageRef := "ghcr.io/acme/simulator@" + digest

	if _, err := pool.Exec(ctx, `
INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Policy Simulator Evidence Test')`,
		orgID, "policy-sim-"+orgID.String()); err != nil {
		t.Fatalf("org: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id = $1`, orgID)
	})
	if _, err := pool.Exec(ctx, `
INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Policy Simulator User')`,
		userID, orgID, "policy-sim-"+userID.String()+"@example.com"); err != nil {
		t.Fatalf("user: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO clusters (id, org_id, name, distro, state) VALUES ($1, $2, 'local', 'k3s', 'connected')`,
		clusterID, orgID); err != nil {
		t.Fatalf("cluster: %v", err)
	}
	specYAML := `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: block-critical-vulns
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 24h
    requireVulnDBBundle: true
    canonicalEngines: ["vulndb"]
  vulnerability:
    maxAllowedSeverity: high
    requireKnownScanResult: true
    requireFixAvailable: true
  action: deny
`
	if _, err := pool.Exec(ctx, `
INSERT INTO policies (id, org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode, version)
VALUES ($1, $2, $3, 'block-critical-vulns', 'block critical image CVEs', 'constellation-admission', 'vulnerability-gating', $4, TRUE, 'enforce', 1)`,
		policyID, orgID, clusterID, specYAML); err != nil {
		t.Fatalf("policy: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_results (
  id, org_id, image_ref, image_ref_normalized, image_repository, image_digest,
  platform, scanner_profile, vulndb_bundle_version, vulndb_bundle_hash, package_count, finding_count,
  last_scanned_at, updated_at
) VALUES ($1, $2, $3, $3, 'ghcr.io/acme/simulator', $4, 'linux/amd64', 'default',
          'fixture-20260614', 'sha256:fixture-bundle', 8, 1, NOW(), NOW())`,
		resultID, orgID, imageRef, digest); err != nil {
		t.Fatalf("image scan result: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO image_scan_findings (
  org_id, image_scan_result_id, finding_key, external_id, title, description,
  severity, risk_score, canonical_engine, engines, package_ecosystem, package_name,
  package_version, fixed_version, detail_json
) VALUES ($1, $2, 'fixture:CVE-2026-SIMULATOR', 'CVE-2026-SIMULATOR', 'critical openssl vuln',
          'critical openssl vuln', 'critical', 97, 'vulndb', '[]'::jsonb,
          'deb', 'openssl', '3.0.0', '3.0.2', '{"confidence":"high"}'::jsonb)`,
		orgID, resultID); err != nil {
		t.Fatalf("image scan finding: %v", err)
	}

	var decisionsBefore int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policy_decisions WHERE org_id = $1`, orgID).Scan(&decisionsBefore); err != nil {
		t.Fatalf("count decisions before: %v", err)
	}
	rawBody, _ := json.Marshal(map[string]string{"manifest": `apiVersion: v1
kind: Pod
metadata:
  name: simulator
  namespace: default
spec:
  containers:
    - name: app
      image: ` + imageRef + `
`})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/simulate?cluster_id="+clusterID.String(), bytes.NewReader(rawBody))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: userID, OrgID: orgID}))
	rec := httptest.NewRecorder()

	NewPolicies(d, nil, nil).Simulate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var got admissionSimulationResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Decision != "deny" || got.EnforcementMode != "enforce" || len(got.Matches) != 1 {
		t.Fatalf("unexpected simulator response: %+v", got)
	}
	if got.Matches[0].PolicyID != policyID.String() || !strings.Contains(got.Matches[0].Reason, "CVE-2026-SIMULATOR") {
		t.Fatalf("evidence-backed match missing CVE details: %+v", got.Matches[0])
	}
	if len(got.Matches[0].EvidenceDetails) != 1 {
		t.Fatalf("expected one evidence detail, got %+v", got.Matches[0].EvidenceDetails)
	}
	detail := got.Matches[0].EvidenceDetails[0]
	if detail.Kind != "image-finding" ||
		detail.ScanResult == nil ||
		detail.ScanResult.ID != resultID.String() ||
		!strings.Contains(detail.Href, "/clusters/"+clusterID.String()+"/images/"+resultID.String()) ||
		detail.ScanResult.VulnDBBundleVersion != "fixture-20260614" ||
		detail.ScanResult.PackageCount != 8 ||
		detail.ScanResult.FindingCount != 1 ||
		detail.Finding == nil ||
		detail.Finding.ExternalID != "CVE-2026-SIMULATOR" ||
		detail.Finding.Severity != "critical" ||
		detail.Finding.CanonicalEngine != "vulndb" ||
		detail.Finding.PackageName != "openssl" ||
		detail.Finding.PackageVersion != "3.0.0" ||
		detail.Finding.FixedVersion != "3.0.2" ||
		detail.Image.Ref != imageRef ||
		detail.Image.Digest != digest {
		t.Fatalf("unexpected evidence detail: %+v", detail)
	}
	if !got.AdmissionReview.DryRun || got.AdmissionReview.PersistsDecision || got.AdmissionReview.SendsWebhook {
		t.Fatalf("simulation must remain dry-run: %+v", got.AdmissionReview)
	}
	var decisionsAfter int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM policy_decisions WHERE org_id = $1`, orgID).Scan(&decisionsAfter); err != nil {
		t.Fatalf("count decisions after: %v", err)
	}
	if decisionsAfter != decisionsBefore {
		t.Fatalf("simulation wrote policy decisions: before=%d after=%d", decisionsBefore, decisionsAfter)
	}
}

func TestPolicies_AdmissionProfilesListAndExport(t *testing.T) {
	h := NewPolicies(nil, nil, nil)
	list := httptest.NewRecorder()
	h.AdmissionProfiles(list, httptest.NewRequest(http.MethodGet, "/api/v1/policies/admission-profiles", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", list.Code, list.Body.String())
	}
	var listed struct {
		Profiles []struct {
			ID string `json:"id"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Profiles) != 10 {
		t.Fatalf("profile count=%d want 10", len(listed.Profiles))
	}

	exportReq := httptest.NewRequest(http.MethodGet, "/api/v1/policies/admission-profiles/strict-hardening/export", nil)
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("profile", "strict-hardening")
	exportReq = exportReq.WithContext(context.WithValue(exportReq.Context(), chi.RouteCtxKey, routeCtx))
	export := httptest.NewRecorder()
	h.ExportAdmissionProfile(export, exportReq)
	if export.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", export.Code, export.Body.String())
	}
	var bundle struct {
		Kind    string `json:"kind"`
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(export.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Kind != "AdmissionProfileBundle" || bundle.Profile.ID != "strict-hardening" {
		t.Fatalf("unexpected bundle: %+v", bundle)
	}
}

func TestPolicies_ImportAdmissionProfileDryRun(t *testing.T) {
	body := []byte(`{"profile_id":"strict-hardening","mode":"monitor","enabled":false,"dry_run":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/admission-profiles:import", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: uuid.New(), OrgID: uuid.New()}))
	w := httptest.NewRecorder()

	NewPolicies(nil, nil, nil).ImportAdmissionProfile(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got admissionProfileImportResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.DryRun || got.ProfileID != "strict-hardening" || got.Imported != 0 || len(got.Policies) == 0 {
		t.Fatalf("unexpected dry-run response: %+v", got)
	}
	for _, policy := range got.Policies {
		if policy.Mode != "monitor" || policy.Enabled {
			t.Fatalf("override not applied to policy: %+v", policy)
		}
		if !strings.HasPrefix(policy.PolicyName, "strict-hardening/") {
			t.Fatalf("policy name should be profile-prefixed: %+v", policy)
		}
	}
}

func TestPolicies_ImportAdmissionProfileRejectsUnknownProfile(t *testing.T) {
	body := []byte(`{"profile_id":"missing","dry_run":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/admission-profiles:import", bytes.NewReader(body))
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{UserID: uuid.New(), OrgID: uuid.New()}))
	w := httptest.NewRecorder()

	NewPolicies(nil, nil, nil).ImportAdmissionProfile(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestAdmissionProfileImportAcceptsDirectBundle(t *testing.T) {
	profile, ok := admission.BuiltInAdmissionProfile("basic-hardening")
	if !ok {
		t.Fatal("basic-hardening profile missing")
	}
	raw, err := json.Marshal(admission.AdmissionProfileBundleFor(profile))
	if err != nil {
		t.Fatal(err)
	}
	req, err := decodeAdmissionProfileImportRequest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := resolveAdmissionProfileImportBundle(req)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Profile.ID != "basic-hardening" {
		t.Fatalf("profile=%q want basic-hardening", bundle.Profile.ID)
	}
}

func TestAdmissionProfileImportRejectsOversizedRuleSet(t *testing.T) {
	profile, ok := admission.BuiltInAdmissionProfile("basic-hardening")
	if !ok {
		t.Fatal("basic-hardening profile missing")
	}
	profile.Rules = make([]admission.AdmissionProfileRule, 201)
	for i := range profile.Rules {
		profile.Rules[i] = admission.AdmissionProfileRule{
			Name: "rule", Engine: "constellation-admission", Category: "admission", Mode: "monitor", Enabled: true, SpecYAML: "kind: AdmissionRule\n",
		}
	}
	err := validateAdmissionProfileBundle(admission.AdmissionProfileBundleFor(profile))
	if err == nil || !strings.Contains(err.Error(), "no more than 200 rules") {
		t.Fatalf("expected max-rules error, got %v", err)
	}
}

func TestParseAdmissionWorkloadIncludesEphemeralContainers(t *testing.T) {
	got, err := parseAdmissionWorkload(`apiVersion: v1
kind: Pod
metadata:
  name: debug-target
spec:
  containers:
    - name: app
      image: ghcr.io/acme/app@sha256:111
  ephemeralContainers:
    - name: debugger
      image: busybox:latest
      targetContainerName: app
      securityContext:
        privileged: true
        runAsUser: 0
`)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Privileged || !got.RunAsRoot || !got.LatestTag || !got.UnsignedImage {
		t.Fatalf("ephemeral container signals missing: %+v", got)
	}
	if len(got.Images) != 2 || got.Images[1] != "busybox:latest" {
		t.Fatalf("expected ephemeral image to be captured, got %+v", got.Images)
	}
}

func TestParseAdmissionWorkloadRequiresEveryImagePinnedWhenNoSignatureAnnotation(t *testing.T) {
	got, err := parseAdmissionWorkload(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: mixed-images
spec:
  template:
    spec:
      containers:
        - name: pinned
          image: ghcr.io/acme/pinned@sha256:111
        - name: mutable
          image: ghcr.io/acme/mutable:1.0
`)
	if err != nil {
		t.Fatal(err)
	}
	if !got.UnsignedImage {
		t.Fatalf("one digest-pinned image must not mark the whole workload signed: %+v", got)
	}
}

func TestParseAdmissionWorkloadHonorsTemplateSignatureAnnotation(t *testing.T) {
	got, err := parseAdmissionWorkload(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: signed-template
spec:
  template:
    metadata:
      annotations:
        cosign.sigstore.dev/signature: verified
    spec:
      containers:
        - name: app
          image: ghcr.io/acme/app:1.0
`)
	if err != nil {
		t.Fatal(err)
	}
	if got.UnsignedImage {
		t.Fatalf("pod-template signature annotation should satisfy image provenance: %+v", got)
	}
}

func TestEvaluateAdmissionPoliciesDeniesExplicitPrivilegedUnsignedPolicy(t *testing.T) {
	manifest := `apiVersion: v1
kind: Pod
metadata:
  name: privileged-debug
  namespace: default
spec:
  containers:
    - name: shell
      image: busybox:latest
      securityContext:
        privileged: true
        runAsUser: 0
`
	workload := admissionSimulationWorkloadDTO{
		Kind: "Pod", Name: "privileged-debug", Namespace: "default",
		Images: []string{"busybox:latest"}, Privileged: true, RunAsRoot: true, LatestTag: true, UnsignedImage: true,
	}
	matches := evaluateAdmissionPolicies(context.Background(), workload, manifest, []policyDTO{
		{
			ID: uuid.New(), Name: "block-unsigned-images", Engine: "constellation-admission",
			Category: "signature-verification", Enabled: true, Mode: "enforce",
			SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
spec:
  match:
    kinds: ["Pod"]
  provenance:
    requireSignatureAnnotation: constellation.dev/signature
  action: deny
`,
		},
		{
			ID: uuid.New(), Name: "deny-privileged-workloads", Engine: "constellation-admission",
			Category: "admission", Enabled: true, Mode: "enforce",
			SpecYAML: `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
spec:
  match:
    kinds: ["Pod"]
  conditions:
    any:
      - field: spec.containers[*].securityContext.privileged
        equals: true
  action: deny
`,
		},
	}, nil, nil, nil)
	decision, mode := admissionDecision(matches)
	if decision != "deny" || mode != "enforce" || len(matches) != 2 {
		t.Fatalf("unexpected explicit policy result: decision=%s mode=%s matches=%+v", decision, mode, matches)
	}
}
