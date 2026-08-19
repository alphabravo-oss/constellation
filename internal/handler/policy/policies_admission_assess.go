package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/alphabravocompany/constellation/internal/admissionevidence"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	constadmission "github.com/alphabravocompany/constellation/pkg/admission"
)

// admissionAssessRequest is a dry-run admission probe for a single image. It
// mirrors NeuVector's POST /v1/assess/admission/rule: submit a candidate image
// (plus optional namespace/pod labels) and get back which admission rules would
// deny it and why, without deploying anything.
type admissionAssessRequest struct {
	Image     string            `json:"image"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type admissionAssessResponseDTO struct {
	Image           string                        `json:"image"`
	Namespace       string                        `json:"namespace"`
	Decision        string                        `json:"decision"`
	EnforcementMode string                        `json:"enforcement_mode"`
	Matches         []admissionSimulationMatchDTO `json:"matches"`
}

// Assess evaluates a single candidate image against the current org/cluster
// admission ruleset using the same matcher the webhook runs, and returns the
// per-rule deny/warn verdicts (empty = admitted). It never writes
// policy_decisions or calls a webhook — it is a pure dry-run.
func (p *Policies) Assess(w http.ResponseWriter, r *http.Request) {
	var req admissionAssessRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "bad request")
		return
	}
	image := strings.TrimSpace(req.Image)
	if image == "" {
		jsonError(w, http.StatusBadRequest, "image required")
		return
	}
	namespace := strings.TrimSpace(req.Namespace)
	if namespace == "" {
		namespace = "default"
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	policies, err := p.simulationPolicies(r.Context(), subj.OrgID, clusterArg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var evidence constadmission.EvidenceSource
	if p.db != nil {
		evidence = admissionevidence.New(p.db.Pool(), subj.OrgID)
	}
	matches, err := assessImageMatches(r.Context(), image, namespace, req.Labels, policies, evidence, clusterArg)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	decision, mode := admissionDecision(matches)
	httpx.WriteJSON(w, http.StatusOK, admissionAssessResponseDTO{
		Image:           image,
		Namespace:       namespace,
		Decision:        decision,
		EnforcementMode: mode,
		Matches:         matches,
	})
}

// assessImageMatches synthesizes a minimal single-container Pod for the image and
// runs it through the existing admission matcher (evaluateAdmissionPolicies), so
// assess and the live webhook share one evaluation path. Factored out of the
// handler so it can be exercised without a DB by injecting a fake evidence source.
func assessImageMatches(ctx context.Context, image, namespace string, labels map[string]string, policies []policyDTO, evidence constadmission.EvidenceSource, clusterArg any) ([]admissionSimulationMatchDTO, error) {
	manifest, err := assessPodManifest(image, namespace, labels)
	if err != nil {
		return nil, err
	}
	workload, err := parseAdmissionWorkload(manifest)
	if err != nil {
		return nil, err
	}
	return evaluateAdmissionPolicies(ctx, workload, manifest, policies, evidence, clusterArg), nil
}

// assessPodManifest builds a JSON Pod manifest wrapping a single container that
// runs the candidate image. JSON is valid YAML, so the manifest feeds the same
// parseAdmissionWorkload / pod-extraction path the manifest-based Simulate uses.
func assessPodManifest(image, namespace string, labels map[string]string) (string, error) {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "assess",
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "assessed", Image: image}},
		},
	}
	raw, err := json.Marshal(pod)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
