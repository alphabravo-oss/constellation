package admission

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// envSecretEngine builds a single-rule engine that denies env-var secrets (ADM-2).
func envSecretEngine() *PolicyEngine {
	deny := true
	return &PolicyEngine{Rules: []Rule{{
		ID: "deny-env-secrets", Title: "Deny env-var secrets",
		Mode: "enforce", Kinds: []string{"Pod"},
		Conditions: RuleConditions{DenyEnvVarSecrets: &deny},
	}}}
}

func TestEvaluate_DeniesEnvVarSecret(t *testing.T) {
	e := envSecretEngine()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "leaky"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", Image: "alpine:3.18",
				Env: []corev1.EnvVar{
					{Name: "REGION", Value: "us-east-1"},
					{Name: "AWS_ACCESS_KEY_ID", Value: "AKIAIOSFODNN7EXAMPLE"},
				},
			}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if resp.Allowed {
		t.Fatalf("pod with AWS-key-shaped env literal must be denied")
	}
	if resp.Result == nil || !strings.Contains(resp.Result.Message, "secret-like") {
		t.Fatalf("expected secret-like denial message, got %+v", resp.Result)
	}
}

func TestEvaluate_AllowsEnvVarSecretRef(t *testing.T) {
	e := envSecretEngine()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "clean"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "c", Image: "alpine:3.18",
				Env: []corev1.EnvVar{
					{Name: "REGION", Value: "us-east-1"},
					// valueFrom is the safe injection path — must NOT be flagged.
					{Name: "AWS_ACCESS_KEY_ID", ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{Name: "aws"},
							Key:                  "id",
						},
					}},
				},
			}},
		},
	}
	resp := e.Evaluate(context.Background(), reviewFor(pod))
	if !resp.Allowed {
		t.Fatalf("pod using secretKeyRef (no literal) must be allowed, got %+v", resp.Result)
	}
}

func TestRuleFromYAMLParsesEnvVarSecretGate(t *testing.T) {
	rule, supported, err := RuleFromYAML("env-secrets", "env-secrets", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
spec:
  containers:
    denyEnvVarSecrets: true
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("env-var-secret rule should be supported by the local evaluator")
	}
	if rule.Conditions.DenyEnvVarSecrets == nil || !*rule.Conditions.DenyEnvVarSecrets {
		t.Fatalf("DenyEnvVarSecrets = %v (want true)", rule.Conditions.DenyEnvVarSecrets)
	}
}

func TestRuleFromYAMLParsesCVEScoreGate(t *testing.T) {
	rule, supported, err := RuleFromYAML("cve-score", "cve-score", "", "enforce", `apiVersion: constellation.alphabravo.io/v1alpha1
kind: AdmissionRule
spec:
  vulnerability:
    maxCveScoreCount: 3
    cveScore: 7.0
`)
	if err != nil {
		t.Fatal(err)
	}
	if !supported {
		t.Fatal("cve-score gate rule should be supported")
	}
	if len(rule.Conditions.EvidenceGates) != 1 {
		t.Fatalf("gates = %+v", rule.Conditions.EvidenceGates)
	}
	g := rule.Conditions.EvidenceGates[0]
	if g.MaxCVEsAtOrAboveScore == nil || *g.MaxCVEsAtOrAboveScore != 3 {
		t.Fatalf("maxCVEsAtOrAboveScore = %v (want 3)", g.MaxCVEsAtOrAboveScore)
	}
	if g.MinCVEScore != 7.0 {
		t.Fatalf("minCVEScore = %v (want 7.0)", g.MinCVEScore)
	}
}
