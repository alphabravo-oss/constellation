package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/alphabravocompany/constellation/internal/admissionevidence"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	constadmission "github.com/alphabravocompany/constellation/pkg/admission"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/notify"
)

type Policies struct {
	db         *db.DB
	auditLog   *audit.Logger
	dispatcher *notify.Dispatcher
}

// NewPolicies constructs the Policies handler. dispatcher may be nil — when nil, the
// CRUD path still works but no outbound notification fires on create/update.
func NewPolicies(database *db.DB, auditLog *audit.Logger, dispatcher *notify.Dispatcher) *Policies {
	return &Policies{db: database, auditLog: auditLog, dispatcher: dispatcher}
}

type policyDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Engine      string    `json:"engine"`
	Category    string    `json:"category"`
	Enabled     bool      `json:"enabled"`
	Mode        string    `json:"mode"`
	Version     int       `json:"version"`
	SpecYAML    string    `json:"spec_yaml"`
	// HitCount is how many times this rule has denied admission (derived from the
	// audit trail). Populated only by List; 0 means the rule is dead (never hit).
	HitCount int `json:"hit_count"`
}

func (p *Policies) List(w http.ResponseWriter, r *http.Request) {
	subj, _ := authctx.SubjectFrom(r.Context())
	category := r.URL.Query().Get("category")
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rows, err := p.db.Pool().Query(r.Context(),
		`SELECT id, name, COALESCE(description,''), engine, category, enabled, mode, version, spec_yaml
           FROM policies
          WHERE org_id = $1
            AND ($2::text = '' OR category = $2)
            AND ($3::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $3)
          ORDER BY category, name`,
		subj.OrgID, category, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := make([]policyDTO, 0)
	for rows.Next() {
		var d policyDTO
		if err := rows.Scan(&d.ID, &d.Name, &d.Description, &d.Engine, &d.Category,
			&d.Enabled, &d.Mode, &d.Version, &d.SpecYAML); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out = append(out, d)
	}
	// Surface per-rule admission hit counts for dead-rule detection (best-effort:
	// the count is auxiliary, so a failure here must not fail the policy list).
	if hits, err := admissionRuleHitCounts(r.Context(), p.db.Pool(), subj.OrgID); err == nil {
		for i := range out {
			out[i].HitCount = hits[out[i].ID.String()]
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"policies": out})
}

type createPolicyBody struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Engine      string `json:"engine"`
	Category    string `json:"category"`
	SpecYAML    string `json:"spec_yaml"`
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
}

func (p *Policies) Create(w http.ResponseWriter, r *http.Request) {
	var body createPolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	if body.Mode == "" {
		body.Mode = "monitor"
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	var id uuid.UUID
	err = p.db.Pool().QueryRow(r.Context(),
		`INSERT INTO policies (org_id, cluster_id, name, description, engine, category, spec_yaml, enabled, mode)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		subj.OrgID, clusterArg, body.Name, body.Description, body.Engine, body.Category,
		body.SpecYAML, body.Enabled, body.Mode).Scan(&id)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "policy.create", TargetKind: "policy", TargetID: id.String(),
		After: body,
	})
	// G3a: record a federated revision when this org is the master.
	handler.LogFedRevision(r.Context(), p.db.Pool(), oid, "policy", id.String(), handler.FedSyncPayload{
		OrgID: oid, Name: body.Name, Description: body.Description, Engine: body.Engine,
		Category: body.Category, SpecYAML: body.SpecYAML, Mode: body.Mode, Enabled: body.Enabled})
	if p.dispatcher != nil {
		_, _ = p.dispatcher.Dispatch(r.Context(), notify.Event{
			Kind: "policy.create", OrgID: oid, Severity: "info",
			Title:    "Policy created: " + body.Name,
			Workload: id.String(),
			Labels:   map[string]string{"engine": body.Engine, "category": body.Category, "mode": body.Mode},
			Payload:  body,
			URL:      "/policies/" + id.String(),
		})
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

type updatePolicyBody struct {
	Enabled  *bool   `json:"enabled,omitempty"`
	Mode     *string `json:"mode,omitempty"`
	SpecYAML *string `json:"spec_yaml,omitempty"`
}

func (p *Policies) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	var body updatePolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	// Fed (master-authored) policies are read-only on a joint: local edits would
	// drift from the master and be silently reverted on the next sync. Reject them.
	if isFed, err := handler.PolicyIsFed(r.Context(), p.db.Pool(), id, subj.OrgID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	} else if isFed {
		httpx.WriteJSON(w, http.StatusForbidden, map[string]string{"error": handler.ErrFedReadOnly().Error()})
		return
	}
	if body.Enabled != nil {
		if _, err := p.db.Pool().Exec(r.Context(),
			`UPDATE policies SET enabled = $2, updated_at = NOW() WHERE id = $1 AND org_id = $3`,
			id, *body.Enabled, subj.OrgID); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if body.Mode != nil {
		if _, err := p.db.Pool().Exec(r.Context(),
			`UPDATE policies SET mode = $2, updated_at = NOW() WHERE id = $1 AND org_id = $3`,
			id, *body.Mode, subj.OrgID); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	if body.SpecYAML != nil {
		if _, err := p.db.Pool().Exec(r.Context(),
			`UPDATE policies SET spec_yaml = $2, updated_at = NOW() WHERE id = $1 AND org_id = $3`,
			id, *body.SpecYAML, subj.OrgID); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
	}
	uid := subj.UserID
	oid := subj.OrgID
	_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
		OrgID: &oid, ActorID: &uid,
		Action: "policy.update", TargetKind: "policy", TargetID: id.String(),
		After: body,
	})
	// G3a: replicate the full post-update policy to joints (master only). Carry
	// enabled so the joint can take a master-enabled policy into effect.
	var pl handler.FedSyncPayload
	if err := p.db.Pool().QueryRow(r.Context(),
		`SELECT name, COALESCE(description,''), engine, category, spec_yaml, mode, enabled
		   FROM policies WHERE id=$1 AND org_id=$2`, id, oid).
		Scan(&pl.Name, &pl.Description, &pl.Engine, &pl.Category, &pl.SpecYAML, &pl.Mode, &pl.Enabled); err == nil {
		pl.OrgID = oid
		handler.LogFedRevision(r.Context(), p.db.Pool(), oid, "policy", id.String(), pl)
	}
	if p.dispatcher != nil {
		_, _ = p.dispatcher.Dispatch(r.Context(), notify.Event{
			Kind: "policy.update", OrgID: oid, Severity: "info",
			Title:    "Policy updated " + id.String(),
			Workload: id.String(),
			Labels:   map[string]string{"lifecycle": "policy.update"},
			Payload:  body,
			URL:      "/policies/" + id.String(),
		})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type simulatePolicyBody struct {
	Manifest          string `json:"manifest"`
	ClusterResourceID string `json:"cluster_resource_id"`
}

type admissionSimulationManifest struct {
	APIVersion string `yaml:"apiVersion" json:"api_version"`
	Kind       string `yaml:"kind" json:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name" json:"name"`
		Namespace   string            `yaml:"namespace" json:"namespace"`
		Labels      map[string]string `yaml:"labels" json:"labels"`
		Annotations map[string]string `yaml:"annotations" json:"annotations"`
	} `yaml:"metadata" json:"metadata"`
	Spec map[string]any `yaml:"spec" json:"-"`
}

type admissionSimulationWorkloadDTO struct {
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	Namespace     string            `json:"namespace"`
	Images        []string          `json:"images"`
	Labels        map[string]string `json:"labels"`
	Privileged    bool              `json:"privileged"`
	RunAsRoot     bool              `json:"run_as_root"`
	LatestTag     bool              `json:"latest_tag"`
	UnsignedImage bool              `json:"unsigned_image"`
}

type admissionSimulationMatchDTO struct {
	PolicyID        string                                 `json:"policy_id"`
	PolicyName      string                                 `json:"policy_name"`
	Category        string                                 `json:"category"`
	Engine          string                                 `json:"engine"`
	Mode            string                                 `json:"mode"`
	Action          string                                 `json:"action"`
	Severity        string                                 `json:"severity"`
	Reason          string                                 `json:"reason"`
	Evidence        []string                               `json:"evidence"`
	EvidenceDetails []admissionSimulationEvidenceDetailDTO `json:"evidence_details,omitempty"`
	Remediation     string                                 `json:"remediation"`
}

type admissionSimulationEvidenceDetailDTO struct {
	Kind       string                                    `json:"kind"`
	Label      string                                    `json:"label"`
	Href       string                                    `json:"href,omitempty"`
	Image      admissionSimulationEvidenceImageDTO       `json:"image"`
	ScanResult *admissionSimulationEvidenceScanResultDTO `json:"scan_result,omitempty"`
	Finding    *admissionSimulationEvidenceFindingDTO    `json:"finding,omitempty"`
	Artifact   *admissionSimulationEvidenceArtifactDTO   `json:"artifact,omitempty"`
}

type admissionSimulationEvidenceImageDTO struct {
	Container string `json:"container,omitempty"`
	Role      string `json:"role,omitempty"`
	Ref       string `json:"ref,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type admissionSimulationEvidenceScanResultDTO struct {
	ID                  string `json:"id"`
	ImageRef            string `json:"image_ref,omitempty"`
	ImageDigest         string `json:"image_digest,omitempty"`
	SourceType          string `json:"source_type,omitempty"`
	SourceRef           string `json:"source_ref,omitempty"`
	LastScannedAt       string `json:"last_scanned_at,omitempty"`
	VulnDBBundleVersion string `json:"vulndb_bundle_version,omitempty"`
	VulnDBBundleHash    string `json:"vulndb_bundle_hash,omitempty"`
	PackageCount        int    `json:"package_count"`
	FindingCount        int    `json:"finding_count"`
}

type admissionSimulationEvidenceFindingDTO struct {
	ID               string `json:"id,omitempty"`
	Key              string `json:"key,omitempty"`
	ExternalID       string `json:"external_id,omitempty"`
	Title            string `json:"title,omitempty"`
	Severity         string `json:"severity,omitempty"`
	RiskScore        int    `json:"risk_score,omitempty"`
	CanonicalEngine  string `json:"canonical_engine,omitempty"`
	PackageEcosystem string `json:"package_ecosystem,omitempty"`
	PackageName      string `json:"package_name,omitempty"`
	PackageVersion   string `json:"package_version,omitempty"`
	PackagePURL      string `json:"package_purl,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
}

type admissionSimulationEvidenceArtifactDTO struct {
	ID        string   `json:"id,omitempty"`
	Type      string   `json:"type,omitempty"`
	Format    string   `json:"format,omitempty"`
	Status    string   `json:"status,omitempty"`
	Identity  string   `json:"identity,omitempty"`
	Path      string   `json:"path,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Title     string   `json:"title,omitempty"`
	RuleID    string   `json:"rule_id,omitempty"`
	RiskTypes []string `json:"risk_types,omitempty"`
	Count     int      `json:"count,omitempty"`
}

type admissionSimulationGuardrailDTO struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Description string `json:"description"`
}

type admissionSimulationReviewDTO struct {
	DryRun           bool   `json:"dry_run"`
	PersistsDecision bool   `json:"persists_decision"`
	SendsWebhook     bool   `json:"sends_webhook"`
	ReviewedAt       string `json:"reviewed_at"`
	Source           string `json:"source"`
}

type admissionSimulationResponseDTO struct {
	Decision         string                            `json:"decision"`
	EnforcementMode  string                            `json:"enforcement_mode"`
	Workload         admissionSimulationWorkloadDTO    `json:"workload"`
	Matches          []admissionSimulationMatchDTO     `json:"matches"`
	Guardrails       []admissionSimulationGuardrailDTO `json:"guardrails"`
	AdmissionReview  admissionSimulationReviewDTO      `json:"admission_review"`
	ClusterResources []clusterResourceSampleDTO        `json:"cluster_resources"`
}

type clusterResourceSampleDTO struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Namespace   string `json:"namespace"`
	Kind        string `json:"kind"`
	LastSeenAt  string `json:"last_seen_at"`
	Manifest    string `json:"manifest"`
	Description string `json:"description"`
}

// Simulate evaluates a Kubernetes manifest against admission policies without
// writing policy_decisions, calling webhooks, or changing cluster state.
func (p *Policies) Simulate(w http.ResponseWriter, r *http.Request) {
	var body simulatePolicyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request"})
		return
	}
	manifest := strings.TrimSpace(body.Manifest)
	source := "pasted manifest"
	if manifest == "" {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "manifest or cluster_resource_id required"})
		return
	}

	workload, err := parseAdmissionWorkload(manifest)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	subj, _ := authctx.SubjectFrom(r.Context())
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	policies, err := p.simulationPolicies(r.Context(), subj.OrgID, clusterArg)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	var evidence constadmission.EvidenceSource
	if p.db != nil {
		evidence = admissionevidence.New(p.db.Pool(), subj.OrgID)
	}
	matches := evaluateAdmissionPolicies(r.Context(), workload, manifest, policies, evidence, clusterArg)
	decision, mode := admissionDecision(matches)
	httpx.WriteJSON(w, http.StatusOK, admissionSimulationResponseDTO{
		Decision:        decision,
		EnforcementMode: mode,
		Workload:        workload,
		Matches:         matches,
		Guardrails: []admissionSimulationGuardrailDTO{
			{ID: "dry-run-only", Name: "Dry-run only", Status: "enforced", Description: "Simulation never creates policy_decisions or sends admission webhooks."},
			{ID: "manifest-redaction", Name: "Manifest redaction", Status: "enforced", Description: "Secret values are not echoed back in the response."},
			{ID: "monitor-vs-enforce", Name: "Monitor before enforce", Status: "enforced", Description: "Monitor-mode matches warn; enforce-mode matches deny."},
		},
		AdmissionReview: admissionSimulationReviewDTO{
			DryRun: true, PersistsDecision: false, SendsWebhook: false,
			ReviewedAt: time.Now().UTC().Format(time.RFC3339), Source: source,
		},
		ClusterResources: []clusterResourceSampleDTO{},
	})
}

func (p *Policies) simulationPolicies(ctx context.Context, orgID uuid.UUID, clusterArg any) ([]policyDTO, error) {
	if p.db == nil {
		return []policyDTO{}, nil
	}
	rows, err := p.db.Pool().Query(ctx,
		`WITH scoped AS (
           SELECT id,
                  name,
                  COALESCE(description, '') AS description,
                  engine,
                  category,
                  enabled,
                  mode,
                  version,
                  spec_yaml,
                  CASE WHEN cluster_id = $2 THEN 1 ELSE 0 END AS scope_rank,
                  updated_at
             FROM policies
            WHERE org_id = $1
              AND enabled = TRUE
              AND engine = 'constellation-admission'
              AND (
                    ($2::uuid IS NULL AND cluster_id IS NULL)
                 OR ($2::uuid IS NOT NULL AND (cluster_id IS NULL OR cluster_id = $2))
              )
         )
         SELECT DISTINCT ON (name)
                id, name, description, engine, category, enabled, mode, version, spec_yaml
           FROM scoped
          ORDER BY name, scope_rank DESC, version DESC, updated_at DESC`, orgID, clusterArg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]policyDTO, 0)
	for rows.Next() {
		var d policyDTO
		if err := rows.Scan(&d.ID, &d.Name, &d.Description, &d.Engine, &d.Category,
			&d.Enabled, &d.Mode, &d.Version, &d.SpecYAML); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func parseAdmissionWorkload(manifest string) (admissionSimulationWorkloadDTO, error) {
	var doc admissionSimulationManifest
	if err := yaml.Unmarshal([]byte(manifest), &doc); err != nil {
		return admissionSimulationWorkloadDTO{}, err
	}
	if doc.Kind == "" || doc.Metadata.Name == "" {
		return admissionSimulationWorkloadDTO{}, errAdmissionManifestIncomplete()
	}
	namespace := doc.Metadata.Namespace
	if namespace == "" {
		namespace = "default"
	}
	workload := admissionSimulationWorkloadDTO{
		Kind: doc.Kind, Name: doc.Metadata.Name, Namespace: namespace,
		Labels: doc.Metadata.Labels,
	}
	if workload.Labels == nil {
		workload.Labels = map[string]string{}
	}
	collectPodSpec(doc.Spec, &workload)
	workload.UnsignedImage = !hasAdmissionSignatureAnnotation(doc) && !allImagesDigestPinned(workload.Images)
	return workload, nil
}

func errAdmissionManifestIncomplete() error {
	return admissionError("manifest must include kind and metadata.name")
}

type admissionError string

func (e admissionError) Error() string { return string(e) }

func collectPodSpec(spec map[string]any, workload *admissionSimulationWorkloadDTO) {
	if spec == nil {
		return
	}
	if template, ok := spec["template"].(map[string]any); ok {
		if templateSpec, ok := template["spec"].(map[string]any); ok {
			collectPodSpec(templateSpec, workload)
		}
	}
	if podSpec, ok := spec["spec"].(map[string]any); ok {
		collectPodSpec(podSpec, workload)
	}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		containers, ok := spec[key].([]any)
		if !ok {
			continue
		}
		for _, raw := range containers {
			c, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if image, ok := c["image"].(string); ok && image != "" {
				workload.Images = append(workload.Images, image)
				if strings.HasSuffix(image, ":latest") || !strings.Contains(image[strings.LastIndex(image, "/")+1:], ":") {
					workload.LatestTag = true
				}
			}
			if sc, ok := c["securityContext"].(map[string]any); ok {
				if v, ok := sc["privileged"].(bool); ok && v {
					workload.Privileged = true
				}
				if v, ok := sc["runAsUser"].(int); ok && v == 0 {
					workload.RunAsRoot = true
				}
			}
		}
	}
	if sc, ok := spec["securityContext"].(map[string]any); ok {
		if v, ok := sc["runAsUser"].(int); ok && v == 0 {
			workload.RunAsRoot = true
		}
	}
}

func allImagesDigestPinned(images []string) bool {
	if len(images) == 0 {
		return false
	}
	for _, image := range images {
		if !strings.Contains(image, "@sha256:") {
			return false
		}
	}
	return true
}

func hasAdmissionSignatureAnnotation(doc admissionSimulationManifest) bool {
	if hasSignatureAnnotation(doc.Metadata.Annotations) {
		return true
	}
	template, ok := doc.Spec["template"].(map[string]any)
	if !ok {
		return false
	}
	metadata, ok := template["metadata"].(map[string]any)
	if !ok {
		return false
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	if !ok {
		return false
	}
	for k, v := range annotations {
		value, ok := v.(string)
		if !ok {
			continue
		}
		if hasSignatureAnnotation(map[string]string{k: value}) {
			return true
		}
	}
	return false
}

func hasSignatureAnnotation(annotations map[string]string) bool {
	return annotations["cosign.sigstore.dev/signature"] != "" ||
		annotations["constellation.dev/signature"] != ""
}

func admissionSimulationPodFromManifest(manifest string) (*corev1.Pod, string, error) {
	rawJSON, err := k8syaml.YAMLToJSON([]byte(manifest))
	if err != nil {
		return nil, "", err
	}
	var meta struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
	}
	if err := json.Unmarshal(rawJSON, &meta); err != nil {
		return nil, "", err
	}
	if strings.EqualFold(meta.Kind, "Pod") {
		var pod corev1.Pod
		if err := json.Unmarshal(rawJSON, &pod); err != nil {
			return nil, "", err
		}
		return &pod, "manifest.kind=Pod", nil
	}
	var doc map[string]any
	if err := json.Unmarshal(rawJSON, &doc); err != nil {
		return nil, "", err
	}
	template, ok := nestedMap(doc, "spec", "template")
	if !ok {
		return nil, "", fmt.Errorf("manifest kind %q does not contain spec.template", meta.Kind)
	}
	templateRaw, err := json.Marshal(template)
	if err != nil {
		return nil, "", err
	}
	var pod corev1.Pod
	if err := json.Unmarshal(templateRaw, &pod); err != nil {
		return nil, "", err
	}
	if pod.Namespace == "" {
		if metadata, ok := nestedMap(doc, "metadata"); ok {
			if namespace, ok := metadata["namespace"].(string); ok {
				pod.Namespace = namespace
			}
		}
	}
	if pod.Name == "" {
		if metadata, ok := nestedMap(doc, "metadata"); ok {
			if name, ok := metadata["name"].(string); ok {
				pod.Name = name
			}
		}
	}
	return &pod, "manifest.kind=" + meta.Kind + ".template", nil
}

func admissionSimulationReviewForPod(pod *corev1.Pod) *admissionv1.AdmissionRequest {
	raw, _ := json.Marshal(pod)
	return &admissionv1.AdmissionRequest{
		UID:       "dry-run",
		Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
		Operation: admissionv1.Create,
		Namespace: pod.Namespace,
		Name:      pod.Name,
		Object:    runtime.RawExtension{Raw: raw},
	}
}

func nestedMap(source map[string]any, path ...string) (map[string]any, bool) {
	current := source
	for _, key := range path {
		next, ok := current[key].(map[string]any)
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func evaluateAdmissionPolicies(ctx context.Context, workload admissionSimulationWorkloadDTO, manifest string, policies []policyDTO, evidence constadmission.EvidenceSource, clusterArg any) []admissionSimulationMatchDTO {
	pod, podSource, podErr := admissionSimulationPodFromManifest(manifest)
	matches := []admissionSimulationMatchDTO{}
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}
		if !strings.EqualFold(policy.Engine, "constellation-admission") {
			continue
		}
		rule, supported, err := constadmission.RuleFromYAML(policy.Name, policy.Name, policy.Description, policy.Mode, policy.SpecYAML)
		if err != nil || !supported {
			continue
		}
		reason := ""
		action := "warn"
		evidenceItems := []string{"engine=constellation-admission"}
		evidenceDetails := []admissionSimulationEvidenceDetailDTO{}
		if podErr == nil {
			engine := &constadmission.PolicyEngine{Rules: []constadmission.Rule{rule}, Evidence: evidence}
			resp := engine.Evaluate(ctx, admissionSimulationReviewForPod(pod))
			switch {
			case !resp.Allowed:
				action = "deny"
				if resp.Result != nil {
					reason = strings.TrimSpace(resp.Result.Message)
				}
			case len(resp.Warnings) > 0:
				action = "warn"
				reason = strings.TrimSpace(resp.Warnings[0])
			default:
				continue
			}
			evidenceItems = append(evidenceItems, podSource)
			if provider, ok := evidence.(constadmission.DetailedEvidenceSource); ok && len(rule.Conditions.EvidenceGates) > 0 {
				if _, hit, details, err := provider.EvaluateAdmissionEvidenceWithDetails(ctx, rule, pod); err == nil && hit {
					evidenceDetails = admissionSimulationEvidenceDetails(details, clusterArg)
				}
			}
		} else if reason, action = fallbackAdmissionPolicyMatch(workload, policy, rule); reason == "" {
			continue
		}
		if action == "warn" && policy.Mode == "enforce" {
			action = "deny"
		}
		if reason == "" {
			reason = "policy matched dry-run admission review"
		}
		matches = append(matches, admissionSimulationMatchDTO{
			PolicyID: policy.ID.String(), PolicyName: policy.Name, Category: policy.Category,
			Engine: policy.Engine, Mode: policy.Mode, Action: action, Severity: admissionSimulationSeverity(rule, reason),
			Reason: reason, Evidence: evidenceItems, EvidenceDetails: evidenceDetails,
			Remediation: admissionSimulationRemediation(rule),
		})
	}
	return matches
}

func admissionSimulationEvidenceDetails(details []constadmission.EvidenceDetail, clusterArg any) []admissionSimulationEvidenceDetailDTO {
	clusterID, _ := clusterArg.(uuid.UUID)
	out := make([]admissionSimulationEvidenceDetailDTO, 0, len(details))
	for _, detail := range details {
		item := admissionSimulationEvidenceDetailDTO{
			Kind:  detail.Kind,
			Label: firstNonEmpty(detail.Label, "Scan evidence"),
			Image: admissionSimulationEvidenceImageDTO{
				Container: detail.Image.Container,
				Role:      detail.Image.Role,
				Ref:       detail.Image.Ref,
				Digest:    detail.Image.Digest,
			},
		}
		if detail.ScanResult != nil {
			item.ScanResult = &admissionSimulationEvidenceScanResultDTO{
				ID:                  detail.ScanResult.ID,
				ImageRef:            detail.ScanResult.ImageRef,
				ImageDigest:         detail.ScanResult.ImageDigest,
				SourceType:          detail.ScanResult.SourceType,
				SourceRef:           detail.ScanResult.SourceRef,
				VulnDBBundleVersion: detail.ScanResult.VulnDBBundleVersion,
				VulnDBBundleHash:    detail.ScanResult.VulnDBBundleHash,
				PackageCount:        detail.ScanResult.PackageCount,
				FindingCount:        detail.ScanResult.FindingCount,
			}
			if !detail.ScanResult.LastScannedAt.IsZero() {
				item.ScanResult.LastScannedAt = detail.ScanResult.LastScannedAt.UTC().Format(time.RFC3339)
			}
			if clusterID != uuid.Nil {
				item.Href = fmt.Sprintf("/clusters/%s/images/%s", clusterID, detail.ScanResult.ID)
			}
		}
		if detail.Finding != nil {
			item.Finding = &admissionSimulationEvidenceFindingDTO{
				ID:               detail.Finding.ID,
				Key:              detail.Finding.Key,
				ExternalID:       detail.Finding.ExternalID,
				Title:            detail.Finding.Title,
				Severity:         detail.Finding.Severity,
				RiskScore:        detail.Finding.RiskScore,
				CanonicalEngine:  detail.Finding.CanonicalEngine,
				PackageEcosystem: detail.Finding.PackageEcosystem,
				PackageName:      detail.Finding.PackageName,
				PackageVersion:   detail.Finding.PackageVersion,
				PackagePURL:      detail.Finding.PackagePURL,
				FixedVersion:     detail.Finding.FixedVersion,
			}
		}
		if detail.Artifact != nil {
			artifact := &admissionSimulationEvidenceArtifactDTO{
				Type:      detail.Artifact.Type,
				Format:    detail.Artifact.Format,
				Status:    detail.Artifact.Status,
				Identity:  detail.Artifact.Identity,
				Path:      detail.Artifact.Path,
				Severity:  detail.Artifact.Severity,
				Title:     detail.Artifact.Title,
				RuleID:    detail.Artifact.RuleID,
				RiskTypes: append([]string(nil), detail.Artifact.RiskTypes...),
				Count:     detail.Artifact.Count,
			}
			artifact.ID = detail.Artifact.ID
			item.Artifact = artifact
		}
		out = append(out, item)
	}
	return out
}

func fallbackAdmissionPolicyMatch(workload admissionSimulationWorkloadDTO, policy policyDTO, rule constadmission.Rule) (string, string) {
	spec := strings.ToLower(policy.SpecYAML + "\n" + policy.Name + "\n" + policy.Category)
	switch {
	case strings.Contains(spec, "unsigned") && workload.UnsignedImage:
		return "image signature was not found on the manifest or digest reference", actionForMode(policy.Mode)
	case strings.Contains(spec, "privileged") && workload.Privileged:
		return "container requests privileged=true", actionForMode(policy.Mode)
	case strings.Contains(spec, "runasroot") && workload.RunAsRoot:
		return "container or pod securityContext runs as UID 0", actionForMode(policy.Mode)
	case strings.Contains(spec, "latest") && workload.LatestTag:
		return "image uses the latest or implicit tag", actionForMode(policy.Mode)
	default:
		if len(rule.Conditions.EvidenceGates) > 0 {
			return "stored scan evidence requires a Pod manifest for dry-run evaluation", actionForMode(policy.Mode)
		}
		return "", ""
	}
}

func actionForMode(mode string) string {
	if mode == "enforce" {
		return "deny"
	}
	return "warn"
}

func admissionSimulationSeverity(rule constadmission.Rule, reason string) string {
	lower := strings.ToLower(reason)
	switch {
	case strings.Contains(lower, "critical"):
		return "critical"
	case strings.Contains(lower, "high"), len(rule.Conditions.EvidenceGates) > 0:
		return "high"
	case strings.Contains(lower, "privileged"), strings.Contains(lower, "root"):
		return "critical"
	default:
		return "medium"
	}
}

func admissionSimulationRemediation(rule constadmission.Rule) string {
	if len(rule.Conditions.EvidenceGates) > 0 {
		return "Refresh the image scan, resolve or except matching findings, and ensure required VulnDB/signature evidence is present before enforcing."
	}
	return "Use signed digest-pinned images and remove privileged/root execution before switching to enforce."
}

func admissionDecision(matches []admissionSimulationMatchDTO) (string, string) {
	decision := "allow"
	mode := "none"
	for _, match := range matches {
		if match.Action == "deny" {
			return "deny", "enforce"
		}
		if match.Action == "warn" {
			decision = "warn"
			mode = "monitor"
		}
	}
	return decision, mode
}
