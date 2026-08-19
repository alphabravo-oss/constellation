package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestRuleFromYAMLParsesSupportedBuiltInProfileRules(t *testing.T) {
	for _, profileID := range []string{"basic-hardening", "strict-hardening", "image-provenance-required", "privileged-workload-approval-required"} {
		profile, ok := BuiltInAdmissionProfile(profileID)
		if !ok {
			t.Fatalf("profile %q missing", profileID)
		}
		for _, profileRule := range profile.Rules {
			t.Run(profileID+"/"+profileRule.Name, func(t *testing.T) {
				rule, supported, err := RuleFromYAML(profileID+"/"+profileRule.Name, profileRule.Name, profileRule.Description, profileRule.Mode, profileRule.SpecYAML)
				if err != nil {
					t.Fatal(err)
				}
				if !supported {
					t.Fatalf("expected supported rule")
				}
				if rule.ID == "" || rule.Mode != profileRule.Mode || len(rule.Kinds) == 0 {
					t.Fatalf("bad parsed rule: %+v", rule)
				}
			})
		}
	}
}

func TestRuleFromYAMLParsesFindingBackedProfileRules(t *testing.T) {
	for _, profileID := range []string{"critical-vulnerabilities-blocked", "fixable-vulnerabilities-blocked", "secrets-misconfig-blocked"} {
		profile, ok := BuiltInAdmissionProfile(profileID)
		if !ok {
			t.Fatalf("profile %q missing", profileID)
		}
		for _, profileRule := range profile.Rules {
			t.Run(profileID+"/"+profileRule.Name, func(t *testing.T) {
				rule, supported, err := RuleFromYAML(profileRule.Name, profileRule.Name, profileRule.Description, profileRule.Mode, profileRule.SpecYAML)
				if err != nil {
					t.Fatal(err)
				}
				if !supported {
					t.Fatalf("finding-backed rule should parse as an evidence gate")
				}
				if len(rule.Conditions.EvidenceGates) == 0 {
					t.Fatalf("missing evidence gates: %+v", rule)
				}
			})
		}
	}
}

func TestRuleFromYAMLParsesImageArtifactGates(t *testing.T) {
	rule, supported, err := RuleFromYAML("artifact-gates", "artifact-gates", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: artifact-gates
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 12h
    requireVulnDBBundle: true
    canonicalEngines: ["vulndb"]
  imageArtifacts:
    secrets:
      maxAllowed: 0
      minimumSeverity: high
    fileRisks:
      maxAllowed: 1
      minimumSeverity: medium
      riskTypes: ["setuid", "device-node", "setuid"]
    signature:
      requireKnownScanResult: true
      requireTrusted: true
      requireVerifierIdentity: true
      allowedStatuses: ["trusted"]
      allowedIdentities: ["repo@example.com"]
  action: deny
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("image artifact gates should be supported")
	}
	if len(rule.Conditions.EvidenceGates) != 3 {
		t.Fatalf("evidence gates = %+v", rule.Conditions.EvidenceGates)
	}
	secret := rule.Conditions.EvidenceGates[0]
	if secret.Type != "artifact" || secret.Artifact != "secret" || secret.MaxAllowedCount != 0 || secret.MinimumSeverity != "high" ||
		secret.MaxScanAgeSeconds != 43200 || !secret.RequireVulnDBBundle || len(secret.AllowedCanonicalEngines) != 1 || secret.AllowedCanonicalEngines[0] != "vulndb" {
		t.Fatalf("secret gate = %+v", secret)
	}
	fileRisk := rule.Conditions.EvidenceGates[1]
	if fileRisk.Artifact != "file-risk" || fileRisk.MaxAllowedCount != 1 || fileRisk.MinimumSeverity != "medium" {
		t.Fatalf("file risk gate = %+v", fileRisk)
	}
	if len(fileRisk.RiskTypes) != 2 || fileRisk.RiskTypes[0] != "setuid" || fileRisk.RiskTypes[1] != "device-node" {
		t.Fatalf("file risk types = %+v", fileRisk.RiskTypes)
	}
	signature := rule.Conditions.EvidenceGates[2]
	if signature.Artifact != "signature" || !signature.RequireKnownScanResult || !signature.RequireTrustedSignature || !signature.RequireVerifierIdentity {
		t.Fatalf("signature gate = %+v", signature)
	}
	if len(signature.AllowedSignatureStatuses) != 1 || signature.AllowedSignatureStatuses[0] != "trusted" {
		t.Fatalf("signature statuses = %+v", signature.AllowedSignatureStatuses)
	}
	if len(signature.AllowedVerifierIdentities) != 1 || signature.AllowedVerifierIdentities[0] != "repo@example.com" {
		t.Fatalf("signature identities = %+v", signature.AllowedVerifierIdentities)
	}
}

func TestRuleFromYAMLParsesVulnerabilityEvidenceQualityGates(t *testing.T) {
	rule, supported, err := RuleFromYAML("vuln-evidence", "vuln-evidence", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: vuln-evidence
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: 48h
    requireVulnDBBundle: true
    sourceTypes: ["repository", "repository"]
    requireDigestMatch: true
    requireTrustedAttestation: true
    attestationPredicateTypes: ["https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v1"]
    allowedAttestationIdentities: ["repo:acme/app:ref:refs/heads/main"]
    allowedAttestationIssuers: ["https://token.actions.githubusercontent.com"]
    canonicalEngine: vulndb
  vulnerability:
    maxAllowedSeverity: medium
    requireKnownScanResult: true
    honorActiveExceptions: true
    requireFixAvailable: true
  action: deny
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported || len(rule.Conditions.EvidenceGates) != 1 {
		t.Fatalf("supported=%v gates=%+v", supported, rule.Conditions.EvidenceGates)
	}
	gate := rule.Conditions.EvidenceGates[0]
	if gate.Type != "vulnerability" ||
		gate.MaxScanAgeSeconds != 172800 ||
		!gate.RequireVulnDBBundle ||
		!gate.RequireKnownScanResult ||
		!gate.RequireDigestMatch ||
		!gate.RequireTrustedAttestation ||
		!gate.HonorActiveExceptions ||
		!gate.RequireFixAvailable ||
		len(gate.AllowedSourceTypes) != 1 ||
		gate.AllowedSourceTypes[0] != "repository" ||
		len(gate.AttestationPredicateTypes) != 1 ||
		gate.AttestationPredicateTypes[0] != "https://slsa.dev/provenance/v1" ||
		len(gate.AllowedAttestationIdentities) != 1 ||
		gate.AllowedAttestationIdentities[0] != "repo:acme/app:ref:refs/heads/main" ||
		len(gate.AllowedAttestationIssuers) != 1 ||
		gate.AllowedAttestationIssuers[0] != "https://token.actions.githubusercontent.com" ||
		len(gate.AllowedCanonicalEngines) != 1 ||
		gate.AllowedCanonicalEngines[0] != "vulndb" {
		t.Fatalf("vulnerability evidence gate = %+v", gate)
	}
}

func TestRuleFromYAMLRejectsInvalidScanEvidenceDuration(t *testing.T) {
	_, supported, err := RuleFromYAML("bad-duration", "bad-duration", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: bad-duration
spec:
  match:
    kinds: ["Pod"]
  scanEvidence:
    maxAge: soon
  vulnerability:
    maxAllowedSeverity: high
  action: deny
`)
	if err == nil || supported {
		t.Fatalf("expected invalid duration error, supported=%v err=%v", supported, err)
	}
}

func TestEvaluate_ProfileRuleRequiresNonRoot(t *testing.T) {
	rule := mustProfileRule(t, "strict-hardening", "require-non-root")
	zero := int64(0)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "root-user"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "alpine:3.18",
			SecurityContext: &corev1.SecurityContext{RunAsUser: &zero},
		}}},
	}
	resp := (&PolicyEngine{Rules: []Rule{rule}}).Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("runAsUser=0 should be denied")
	}
}

func TestEvaluate_ProfileRuleDisallowsLatestAndImplicitTags(t *testing.T) {
	rule := mustProfileRule(t, "strict-hardening", "disallow-latest-tag")
	engine := &PolicyEngine{Rules: []Rule{rule}}
	for _, image := range []string{"busybox:latest", "busybox"} {
		t.Run(image, func(t *testing.T) {
			pod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "mutable-image"},
				Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "app", Image: image,
				}}},
			}
			resp := engine.Evaluate(context.Background(), reviewFor(pod))
			if resp.Allowed {
				t.Fatalf("%s should be denied", image)
			}
		})
	}
}

func TestEvaluate_ProfileRuleRequiresDigest(t *testing.T) {
	rule := mustProfileRule(t, "image-provenance-required", "require-digest-pinned-images")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "tagged-image"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "ghcr.io/acme/app:1.0",
		}}},
	}
	resp := (&PolicyEngine{Rules: []Rule{rule}}).Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("tag-only image should be denied")
	}
}

func TestEvaluate_ProfileRuleAllowsOnlyConfiguredRegistries(t *testing.T) {
	rule, supported, err := RuleFromYAML("allow-registry", "allow-registry", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
metadata:
  name: allow-registry
spec:
  match:
    kinds: ["Pod"]
  images:
    allowedRegistries: ["registry.corp/"]
  action: deny
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("allowedRegistries should be supported")
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "external-image"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "docker.io/library/nginx:1.25",
		}}},
	}
	resp := (&PolicyEngine{Rules: []Rule{rule}}).Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("non-allowlisted registry should be denied")
	}
	pod.Spec.Containers[0].Image = "registry.corp/app:1.0"
	if resp := (&PolicyEngine{Rules: []Rule{rule}}).Evaluate(context.Background(), reviewFor(pod)); !resp.Allowed {
		t.Fatalf("allowlisted registry should be allowed: %+v", resp.Result)
	}
}

func TestEvaluate_ProfileRuleRequiresPrivilegedApproval(t *testing.T) {
	rule := mustProfileRule(t, "privileged-workload-approval-required", "require-approval-for-privileged-workloads")
	t1 := true
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "approved-debug"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "debug", Image: "busybox:1.36",
			SecurityContext: &corev1.SecurityContext{Privileged: &t1},
		}}},
	}
	engine := &PolicyEngine{Rules: []Rule{rule}}
	if resp := engine.Evaluate(context.Background(), reviewFor(pod)); resp.Allowed {
		t.Fatalf("privileged pod without approval should be denied")
	}
	pod.Annotations = map[string]string{"constellation.alphabravo.io/privileged-approval": "approved"}
	if resp := engine.Evaluate(context.Background(), reviewFor(pod)); !resp.Allowed {
		t.Fatalf("approved privileged pod should be allowed: %+v", resp.Result)
	}
}

func TestEvaluate_EvidenceGateUsesEvidenceSource(t *testing.T) {
	rule := mustProfileRule(t, "critical-vulnerabilities-blocked", "block-critical-vulnerabilities")
	engine := &PolicyEngine{
		Rules:    []Rule{rule},
		Evidence: fakeEvidenceSource{reason: `image "repo/app:1.0" has critical vulnerability CVE-2026-0001`},
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "vulnerable"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "repo/app:1.0",
		}}},
	}
	resp := engine.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatal("evidence-backed gate should deny when source reports a hit")
	}
	if resp.Result == nil || resp.Result.Message == "" {
		t.Fatalf("missing deny reason: %+v", resp)
	}
}

func TestEvaluate_EvidenceGateEmitsDenyEventEvidenceDetails(t *testing.T) {
	rule := mustProfileRule(t, "critical-vulnerabilities-blocked", "block-critical-vulnerabilities")
	got := make(chan DenyEvent, 1)
	engine := &PolicyEngine{
		Rules: []Rule{rule},
		Evidence: fakeDetailedEvidenceSource{
			reason: `image "repo/app:1.0" has critical vulnerability CVE-2026-0001`,
			details: []EvidenceDetail{{
				Kind:  "image-finding",
				Label: "CVE-2026-0001",
				Image: EvidenceImageDetail{Container: "app", Ref: "repo/app:1.0"},
				ScanResult: &EvidenceScanResultDetail{
					ID:                  "33333333-3333-3333-3333-333333333333",
					ImageRef:            "repo/app:1.0",
					VulnDBBundleVersion: "bundle-20260614",
					VulnDBBundleHash:    "sha256:bundle",
					PackageCount:        4,
					FindingCount:        1,
				},
				Finding: &EvidenceFindingDetail{
					ID:              "44444444-4444-4444-4444-444444444444",
					ExternalID:      "CVE-2026-0001",
					Severity:        "critical",
					CanonicalEngine: "vulndb",
					PackageName:     "openssl",
					FixedVersion:    "3.0.2",
				},
			}},
		},
		OnDeny: func(_ context.Context, ev DenyEvent) { got <- ev },
	}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "vulnerable", Namespace: "default"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "repo/app:1.0",
		}}},
	}
	resp := engine.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatal("evidence-backed gate should deny when source reports a hit")
	}
	select {
	case ev := <-got:
		if ev.RuleID != rule.ID || ev.Reason == "" {
			t.Fatalf("bad deny event: %+v", ev)
		}
		if len(ev.EvidenceDetails) != 1 || ev.EvidenceDetails[0].Finding == nil || ev.EvidenceDetails[0].Finding.ExternalID != "CVE-2026-0001" {
			t.Fatalf("missing evidence details: %+v", ev.EvidenceDetails)
		}
		if ev.EvidenceDetails[0].ScanResult == nil || ev.EvidenceDetails[0].ScanResult.VulnDBBundleVersion != "bundle-20260614" {
			t.Fatalf("missing scan result detail: %+v", ev.EvidenceDetails[0])
		}
	case <-time.After(time.Second):
		t.Fatal("OnDeny hook was not invoked")
	}
}

func TestEvaluate_EvidenceGateFailsClosedWhenSourceUnavailableOrErrors(t *testing.T) {
	rule := mustProfileRule(t, "critical-vulnerabilities-blocked", "block-critical-vulnerabilities")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "vulnerable"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "app", Image: "repo/app:1.0",
		}}},
	}
	if resp := (&PolicyEngine{Rules: []Rule{rule}}).Evaluate(context.Background(), reviewFor(pod)); resp.Allowed {
		t.Fatal("evidence gate should fail closed when no evidence source is configured")
	}
	engine := &PolicyEngine{Rules: []Rule{rule}, Evidence: fakeEvidenceSource{err: errors.New("db down")}}
	if resp := engine.Evaluate(context.Background(), reviewFor(pod)); resp.Allowed {
		t.Fatal("evidence gate should fail closed on evidence lookup error")
	}
}

func mustProfileRule(t *testing.T, profileID, ruleName string) Rule {
	t.Helper()
	profile, ok := BuiltInAdmissionProfile(profileID)
	if !ok {
		t.Fatalf("profile %q missing", profileID)
	}
	for _, profileRule := range profile.Rules {
		if profileRule.Name != ruleName {
			continue
		}
		rule, supported, err := RuleFromYAML(profileID+"/"+profileRule.Name, profileRule.Name, profileRule.Description, profileRule.Mode, profileRule.SpecYAML)
		if err != nil {
			t.Fatal(err)
		}
		if !supported {
			t.Fatalf("profile rule %s/%s is unsupported", profileID, ruleName)
		}
		return rule
	}
	t.Fatalf("rule %s/%s missing", profileID, ruleName)
	return Rule{}
}

type fakeEvidenceSource struct {
	reason string
	err    error
}

func (f fakeEvidenceSource) EvaluateAdmissionEvidence(_ context.Context, _ Rule, _ *corev1.Pod) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	if f.reason != "" {
		return f.reason, true, nil
	}
	return "", false, nil
}

type fakeDetailedEvidenceSource struct {
	reason  string
	details []EvidenceDetail
	err     error
}

func (f fakeDetailedEvidenceSource) EvaluateAdmissionEvidence(ctx context.Context, rule Rule, pod *corev1.Pod) (string, bool, error) {
	reason, hit, _, err := f.EvaluateAdmissionEvidenceWithDetails(ctx, rule, pod)
	return reason, hit, err
}

func (f fakeDetailedEvidenceSource) EvaluateAdmissionEvidenceWithDetails(_ context.Context, _ Rule, _ *corev1.Pod) (string, bool, []EvidenceDetail, error) {
	if f.err != nil {
		return "", false, nil, f.err
	}
	if f.reason != "" {
		return f.reason, true, append([]EvidenceDetail(nil), f.details...), nil
	}
	return "", false, nil, nil
}
