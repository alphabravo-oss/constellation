// Package admission is the Constellation admission webhook engine.
//
// At v1 the engine evaluates a small built-in policy set: image-signature-required,
// privileged-containers-forbidden, host-network-forbidden, read-only-root-filesystem,
// no-wildcard-rbac. Customers extend the catalog via the policies UI; rules persisted
// in the DB are hot-reloaded by the webhook process.
//
// The Kyverno-based engine is intentionally pluggable — Phase 3 wires Kyverno directly,
// Phase 5 adds OPA/Rego + Kubernetes CEL admission via the same Engine interface.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/alphabravocompany/constellation/pkg/quarantine"
)

// Engine evaluates one AdmissionReview against the policy catalog and returns a decision.
type Engine interface {
	Evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse
}

// ChainEngine fans an AdmissionRequest across several Engine implementations.
// The built-in PolicyEngine is always evaluated; the Rego (engine='opa') and
// K8s CEL (engine='cel') engines are attached only when the policy source loads
// matching rows, and are hot-swapped on each reload via SetRego/SetCEL.
//
// A deny from ANY engine denies the request (first-deny-wins across engines);
// the first deny wins and its result is returned. Monitor-mode warnings from
// every engine that ran are accumulated onto the response.
//
// NOTE: this first-deny-wins behavior is *engine-internal* — it governs how the
// chain combines its constituent engines once a request reaches the webhook. It
// is NOT a cluster-level fail-closed guarantee: whether an unreachable/errored
// webhook blocks admission is controlled by the ValidatingWebhookConfiguration's
// failurePolicy, which defaults to Ignore (fail-OPEN) in the shipped chart. Do
// not describe Constellation admission as "categorically fail-closed."
type ChainEngine struct {
	mu     sync.RWMutex
	policy *PolicyEngine
	rego   *RegoEngine
	cel    *CELEngine

	// onDeny fans a Rego/CEL deny out to the same DenyHook the built-in
	// PolicyEngine uses (admission.deny audit row + EventAdmission response
	// rules). The PolicyEngine fires its OWN OnDeny for built-in/quarantine/PVC
	// denies, so the chain only fires onDeny for the Rego/CEL engines to avoid
	// double-recording. Nil = no-op.
	onDeny DenyHook
}

// NewChainEngine wraps the built-in PolicyEngine. Rego/CEL engines are attached
// later by the policy reloader once their rows are loaded and compiled.
func NewChainEngine(policy *PolicyEngine) *ChainEngine {
	return &ChainEngine{policy: policy}
}

// Policy returns the wrapped built-in engine (for quarantine/evidence/OnDeny wiring).
func (c *ChainEngine) Policy() *PolicyEngine { return c.policy }

// SetRego swaps the active Rego engine. A nil engine disables Rego evaluation.
// Safe to call while Evaluate is serving requests.
func (c *ChainEngine) SetRego(e *RegoEngine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rego = e
}

// SetCEL swaps the active CEL engine. A nil engine disables CEL evaluation.
// Safe to call while Evaluate is serving requests.
func (c *ChainEngine) SetCEL(e *CELEngine) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cel = e
}

// SetOnDeny installs the DenyHook the chain fires when a Rego or CEL enforce
// rule denies. Wire it to the SAME hook installed on the built-in PolicyEngine
// (PolicyEngine.OnDeny) so OPA/CEL denies produce the admission.deny audit row
// and fire EventAdmission response rules exactly like built-in denies. Safe to
// call while Evaluate is serving requests.
func (c *ChainEngine) SetOnDeny(h DenyHook) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onDeny = h
}

// Evaluate runs the built-in engine then any attached Rego/CEL engines. The
// first deny short-circuits and is returned with the warnings gathered so far.
func (c *ChainEngine) Evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	c.mu.RLock()
	policy := c.policy
	rego := c.rego
	cel := c.cel
	onDeny := c.onDeny
	c.mu.RUnlock()

	var warnings []string

	// Built-in PolicyEngine first. It invokes its OWN OnDeny hook for built-in,
	// quarantine and PVC denies, so the chain must NOT re-fire onDeny here.
	presp := policy.Evaluate(ctx, req)
	warnings = append(warnings, presp.Warnings...)
	if !presp.Allowed {
		presp.Warnings = warnings
		return presp
	}

	// Rego / CEL denies never reached a DenyHook before — the chain fires onDeny
	// for them here so an OPA/CEL enforce deny is audited and runs response rules.
	if rego != nil {
		resp, ruleID := rego.evaluate(ctx, req)
		warnings = append(warnings, resp.Warnings...)
		if !resp.Allowed {
			c.fireDeny(ctx, onDeny, req, ruleID, resp)
			resp.Warnings = warnings
			return resp
		}
	}
	if cel != nil {
		resp, ruleID := cel.evaluate(ctx, req)
		warnings = append(warnings, resp.Warnings...)
		if !resp.Allowed {
			c.fireDeny(ctx, onDeny, req, ruleID, resp)
			resp.Warnings = warnings
			return resp
		}
	}

	return &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true, Warnings: warnings}
}

// fireDeny builds a DenyEvent for a Rego/CEL deny and invokes the chain's
// DenyHook. Panic-isolated and best-effort: a notifier/audit bug must never
// block admission (the verdict has already been decided by the caller).
func (c *ChainEngine) fireDeny(ctx context.Context, onDeny DenyHook, req *admissionv1.AdmissionRequest, ruleID string, resp *admissionv1.AdmissionResponse) {
	if onDeny == nil {
		return
	}
	reason := ""
	if resp.Result != nil {
		reason = resp.Result.Message
	}
	ns, name := denyTargetFromRequest(req)
	func() {
		defer func() { _ = recover() }()
		onDeny(ctx, DenyEvent{
			RuleID:    ruleID,
			Reason:    reason,
			Namespace: ns,
			Pod:       name,
			Operation: string(req.Operation),
			UserInfo:  req.UserInfo.Username,
		})
	}()
}

// denyTargetFromRequest extracts the namespace and object name from an
// AdmissionRequest for a deny event. The namespace prefers req.Namespace and
// falls back to the object's metadata; the name comes from the object metadata
// (pod name, or the controller name for a pod-template kind).
func denyTargetFromRequest(req *admissionv1.AdmissionRequest) (namespace, name string) {
	namespace = req.Namespace
	if len(req.Object.Raw) > 0 {
		var meta struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(req.Object.Raw, &meta); err == nil {
			name = meta.Metadata.Name
			if namespace == "" {
				namespace = meta.Metadata.Namespace
			}
		}
	}
	return namespace, name
}

// DenyHook is the (optional) callback the webhook server installs so a deny decision
// fans out to notifiers. It's invoked AFTER the decision has been made; failures are
// ignored so the admission path is never blocked by an external integration.
type DenyHook func(ctx context.Context, ev DenyEvent)

// DenyEvent describes one admission rule match. The webhook server lifts this
// onto the notify.Event hierarchy as "admission.deny" for enforce denies and
// "admission.monitor" for monitor-mode matches (see Monitor).
type DenyEvent struct {
	RuleID          string
	Reason          string
	Namespace       string
	Pod             string
	Operation       string
	UserInfo        string
	EvidenceDetails []EvidenceDetail

	// Monitor is true when this event records a MONITOR-mode rule match rather
	// than an enforce deny. Monitor matches are observe-only: the webhook admits
	// the request but persists a durable 'admission.monitor' audit row and counts
	// the hit (NeuVector CLUSAuditAdmCtrlK8sReqViolation parity), so operators can
	// tune rules before flipping them to enforce. Response-rule actions
	// (quarantine/etc) MUST NOT fire for monitor matches.
	Monitor bool
}

// fireHook invokes an admission hook best-effort and panic-isolated: a notifier
// or audit bug must never panic out of the admission path (the verdict has
// already been decided by the caller). Used for both enforce denies and
// monitor-mode matches (DenyEvent.Monitor discriminates).
func fireHook(ctx context.Context, hook DenyHook, ev DenyEvent) {
	if hook == nil {
		return
	}
	defer func() { _ = recover() }()
	hook(ctx, ev)
}

// EvidenceSource evaluates admission rules that require persisted scanner or
// finding state. The cmd/constellation-admission binary provides the Postgres
// implementation; tests can install a fake source.
type EvidenceSource interface {
	EvaluateAdmissionEvidence(ctx context.Context, rule Rule, pod *corev1.Pod) (reason string, hit bool, err error)
}

// DetailedEvidenceSource extends EvidenceSource for audit/simulation paths that
// need machine-readable evidence rather than only a human denial string.
type DetailedEvidenceSource interface {
	EvaluateAdmissionEvidenceWithDetails(ctx context.Context, rule Rule, pod *corev1.Pod) (reason string, hit bool, details []EvidenceDetail, err error)
}

// EvidenceDetail is the shared audit contract for evidence-backed admission
// decisions. It identifies the admitted image and the persisted scan objects
// that caused a rule to warn or deny.
type EvidenceDetail struct {
	Kind       string                    `json:"kind"`
	Label      string                    `json:"label,omitempty"`
	Image      EvidenceImageDetail       `json:"image"`
	ScanResult *EvidenceScanResultDetail `json:"scan_result,omitempty"`
	Finding    *EvidenceFindingDetail    `json:"finding,omitempty"`
	Artifact   *EvidenceArtifactDetail   `json:"artifact,omitempty"`
}

type EvidenceImageDetail struct {
	Container string `json:"container,omitempty"`
	Role      string `json:"role,omitempty"`
	Ref       string `json:"ref,omitempty"`
	Digest    string `json:"digest,omitempty"`
}

type EvidenceScanResultDetail struct {
	ID                  string    `json:"id"`
	ImageRef            string    `json:"image_ref,omitempty"`
	ImageDigest         string    `json:"image_digest,omitempty"`
	SourceType          string    `json:"source_type,omitempty"`
	SourceRef           string    `json:"source_ref,omitempty"`
	LastScannedAt       time.Time `json:"last_scanned_at,omitempty"`
	VulnDBBundleVersion string    `json:"vulndb_bundle_version,omitempty"`
	VulnDBBundleHash    string    `json:"vulndb_bundle_hash,omitempty"`
	PackageCount        int       `json:"package_count"`
	FindingCount        int       `json:"finding_count"`
}

type EvidenceFindingDetail struct {
	ID               string `json:"id,omitempty"`
	Key              string `json:"key,omitempty"`
	ExternalID       string `json:"external_id,omitempty"`
	Title            string `json:"title,omitempty"`
	Severity         string `json:"severity,omitempty"`
	RiskScore        int    `json:"risk_score"`
	CanonicalEngine  string `json:"canonical_engine,omitempty"`
	PackageEcosystem string `json:"package_ecosystem,omitempty"`
	PackageName      string `json:"package_name,omitempty"`
	PackageVersion   string `json:"package_version,omitempty"`
	PackagePURL      string `json:"package_purl,omitempty"`
	FixedVersion     string `json:"fixed_version,omitempty"`
}

type EvidenceArtifactDetail struct {
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
	Count     int      `json:"count"`
}

// PolicyEngine is the built-in evaluator. Policies are simple structured rules — anything
// requiring Rego/CEL goes through the Phase-5 plugin engines.
type PolicyEngine struct {
	mu sync.RWMutex

	// Rules is the active policy set. Hot-reloaded by the webhook server.
	Rules []Rule

	// Evidence answers rules that need persisted image/finding state.
	Evidence EvidenceSource

	// OnDeny is invoked when an enforce-mode rule denies a request. Wave N3 wires this
	// to the notify Dispatcher so receivers ping on every block. Nil = no-op.
	OnDeny DenyHook

	// Quarantine is the runtime-driven deny list (E4). Checked BEFORE
	// Rules. When set and a request's pod matches, admission denies
	// regardless of policy mode — quarantine is an incident-response
	// override, not a configurable policy.
	//
	// The webhook server constructs the Source from a pgxpool-backed
	// loader and calls engine.SetQuarantine(source); a nil source means
	// "feature disabled" (the default for installs that don't enable
	// the admission webhook at all).
	Quarantine *quarantine.Source

	// RBAC resolves a pod ServiceAccount's risky-role exposure for the
	// saBindRiskyRole criterion. The cmd binary installs a client-go backed
	// resolver; nil means the feature is disabled (rules using it fail open).
	RBAC RBACResolver

	// NamespaceLabeler resolves a namespace's labels for the per-rule
	// namespaceSelector (A5). nil means the feature is unwired: rules that
	// carry a NamespaceSelector never fire (name-based Namespaces still work).
	// TODO(matrix): install a client-go namespace lister backed resolver in the
	// webhook cmd so label-selected per-rule scoping is enforced live.
	NamespaceLabeler NamespaceLabelResolver
}

// NamespaceLabelResolver resolves the labels of a namespace by name, used by the
// per-rule namespaceSelector (A5).
type NamespaceLabelResolver interface {
	NamespaceLabels(ctx context.Context, namespace string) (map[string]string, error)
}

// SetRBAC attaches the RBAC resolver used by the saBindRiskyRole criterion.
// Safe to call on a running engine.
func (e *PolicyEngine) SetRBAC(r RBACResolver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.RBAC = r
}

// SetNamespaceLabeler attaches the namespace label resolver used by the per-rule
// namespaceSelector (A5). Safe to call on a running engine.
func (e *PolicyEngine) SetNamespaceLabeler(r NamespaceLabelResolver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.NamespaceLabeler = r
}

// SetQuarantine attaches the runtime quarantine source. Safe to call on a
// running engine — the snapshot pointer is read once per Evaluate() and
// each individual snapshot is immutable.
func (e *PolicyEngine) SetQuarantine(src *quarantine.Source) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Quarantine = src
}

// SetEvidenceSource attaches the persisted evidence source. Safe to call on a
// running engine.
func (e *PolicyEngine) SetEvidenceSource(src EvidenceSource) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Evidence = src
}

// Effect is a rule's verdict when its conditions match. Rules are DENY by
// default; an ALLOW (a.k.a. "except"/"exception") rule is a carve-out that takes
// precedence over deny rules (P1-3, modelled on NeuVector's
// exception-before-deny admission evaluation).
const (
	EffectDeny  = "deny"  // default: a matching rule blocks (enforce) or warns (monitor)
	EffectAllow = "allow" // carve-out: a matching rule admits, short-circuiting deny evaluation
)

// Rule is one structured policy. Each carries a Match (when to fire) + Effect (allow/deny).
type Rule struct {
	ID          string // stable id, e.g. "block-privileged"
	Title       string
	Description string
	Mode        string // monitor | enforce
	// Effect is EffectDeny (default, empty string also means deny) or
	// EffectAllow. Allow/except rules are evaluated before deny rules and a
	// match short-circuits admission to ADMIT.
	Effect string
	Kinds  []string // pod, deployment, statefulset…

	// Namespaces, when non-empty, scopes the rule to requests whose namespace
	// name is in this list (exact, case-sensitive match on the Kubernetes
	// namespace name). Empty = all namespaces. This is per-rule namespace
	// targeting (A5), letting one webhook carry namespace-differentiated rules
	// instead of relying solely on the webhook-level namespaceSelector. Models
	// NeuVector's per-rule CriteriaKeyNamespace.
	Namespaces []string
	// NamespaceSelector, when non-empty, scopes the rule to requests whose
	// namespace carries ALL of these labels (matchLabels semantics). Requires a
	// NamespaceLabeler on the engine to resolve namespace labels; if none is
	// wired the selector never matches (the rule is skipped) so an unresolvable
	// selector can't broaden a deny into namespaces it wasn't scoped to.
	// Namespaces and NamespaceSelector are OR-combined: a request in a listed
	// namespace OR a namespace whose labels match fires the rule.
	NamespaceSelector map[string]string

	Conditions RuleConditions
}

// isAllow reports whether the rule is an allow/except carve-out rather than the
// default deny.
func (r Rule) isAllow() bool { return r.Effect == EffectAllow }

// RuleConditions describes what the rule looks for.
type RuleConditions struct {
	Privileged  *bool // when true, denies privileged: true
	HostNetwork *bool // when true, denies hostNetwork: true
	HostPID     *bool
	// HostIPC, when true, denies pods that share the host IPC namespace
	// (spec.hostIPC=true). NeuVector CriteriaKeyShareIpcWithHost (ADM-26).
	HostIPC *bool
	// AllowPrivilegeEscalation, when true, denies any container whose
	// securityContext.allowPrivilegeEscalation is true. Standalone criterion
	// (NeuVector CriteriaKeyAllowPrivEscalation, ADM-26); distinct from the
	// privileged check.
	AllowPrivilegeEscalation *bool
	// ImageNoOS, when true, denies pods whose image carries no OS layer (a
	// scratch/distroless base with no package database to scan). The scanner's
	// pre-admission mutation stamps ${ImageNoOSAnnotation}="true" on such pods —
	// mirroring the RequireImageSignature annotation contract — because the base
	// OS cannot be derived from the pod spec alone. NeuVector CriteriaKeyImageNoOS
	// (ADM-26).
	ImageNoOS *bool
	// ResourceLimit, when set, denies containers that omit or exceed cpu/memory
	// requests and limits. NeuVector CriteriaKeyRequestLimit (ADM-26).
	ResourceLimit             *ResourceLimitCondition
	ReadOnlyRootFS            *bool    // when true, denies missing readOnlyRootFilesystem
	AllowedImageRegistries    []string // image registry allowlist; empty = no restriction
	RequireImageSignature     *bool    // when true, denies images without ${SignatureAnnotation}
	SignatureAnnotation       string
	RequireNonRoot            *bool
	DisallowLatestTag         *bool
	DisallowImplicitTag       *bool
	RequireDigest             *bool
	RequirePrivilegedApproval *bool
	ApprovalAnnotation        string
	ApprovedValues            []string
	DenyEnvVarSecrets         *bool // when true, denies pods whose container env literal values look like secrets (NeuVector CriteriaKeyEnvVarSecrets)

	// PSSLevel, when set to "baseline" or "restricted", runs the full Pod
	// Security Standards engine (pss.go) over the pod spec. A non-empty list of
	// control violations denies (enforce) or warns (monitor).
	PSSLevel string

	// AllowedStorageClasses, when non-empty, gates PersistentVolumeClaim
	// admission: a PVC whose spec.storageClassName is not in this list is
	// denied (enforce) or warned (monitor). An unset storageClassName on the
	// PVC (cluster-default) only passes if "" is included in the list.
	AllowedStorageClasses []string

	// UserMatch, when set, is an anchored regexp evaluated against the
	// AdmissionReview userInfo.username. The rule fires when the requesting
	// user matches. Empty = no user constraint.
	UserMatch string
	// GroupMatch, when set, is an anchored regexp evaluated against each of the
	// AdmissionReview userInfo.groups. The rule fires when any group matches.
	// Empty = no group constraint.
	GroupMatch string
	// SABindRiskyRole, when true, fires when the pod's ServiceAccount binds one
	// of the five risky RBAC roles (cluster-admin, broad secrets access,
	// pods/exec, escalate/bind, or wildcard verbs/resources). Resolved through
	// the engine's RBACResolver. NeuVector CriteriaKeySaBindRiskyRole.
	SABindRiskyRole *bool

	EvidenceGates []EvidenceGate
}

// EvidenceGate is an admission rule condition backed by scanner/finding state.
type EvidenceGate struct {
	Type                         string   // vulnerability | finding | artifact
	MaxAllowedSeverity           string   // vulnerability: deny severities above this value
	MaxCriticalCVEs              *int     // vulnerability: deny if distinct critical CVEs exceed this (nil = unset)
	MaxHighCVEs                  *int     // vulnerability: deny if distinct high CVEs exceed this (nil = unset)
	MaxMediumCVEs                *int     // vulnerability: deny if distinct medium CVEs exceed this (nil = unset; NeuVector-style cveMediumCount, ADM-29)
	MaxCriticalWithFixCVEs       *int     // vulnerability: deny if distinct critical CVEs that have a fix available exceed this (nil = unset; ADM-29)
	MaxHighWithFixCVEs           *int     // vulnerability: deny if distinct high CVEs that have a fix available exceed this (nil = unset; ADM-29)
	MaxCVEsAtOrAboveScore        *int     // vulnerability: deny if distinct CVEs with CVSS base score >= MinCVEScore exceed this (nil = unset; NeuVector CriteriaKeyCVEScoreCount)
	MinCVEScore                  float64  // vulnerability: CVSS base score threshold for MaxCVEsAtOrAboveScore
	DeniedCVEs                   []string // vulnerability: deny if any of these CVE ids is present, regardless of severity/count (NeuVector CriteriaKeyCVENames). Normalized upper-case.
	CVEGraceDays                 *int     // vulnerability: ignore CVEs published within this many days when counting/denying (NeuVector SubCriteriaPublishDays). nil/<=0 = no grace window.
	RequireKnownScanResult       bool
	HonorActiveExceptions        bool
	MaxScanAgeSeconds            int64
	RequireVulnDBBundle          bool
	AllowedSourceTypes           []string
	RequireDigestMatch           bool
	RequireTrustedAttestation    bool
	AttestationPredicateTypes    []string
	AllowedAttestationIdentities []string
	AllowedAttestationIssuers    []string
	AllowedCanonicalEngines      []string
	RequireFixAvailable          bool
	FindingKinds                 []string
	MinimumSeverity              string
	MinimumConfidence            string
	Artifact                     string // secret | file-risk | signature
	MaxAllowedCount              int
	RiskTypes                    []string
	RequireTrustedSignature      bool
	RequireVerifierIdentity      bool
	AllowedSignatureStatuses     []string
	AllowedVerifierIdentities    []string
}

// ResourceLimitCondition denies containers that omit or exceed cpu/memory
// requests and limits (NeuVector CriteriaKeyRequestLimit, ADM-26). The Require*
// flags catch a missing request/limit; the Max* thresholds (Kubernetes quantity
// strings such as "500m" or "512Mi") catch a limit set too high. Empty Max*
// strings disable the exceed check for that resource.
type ResourceLimitCondition struct {
	RequireCPURequest    bool
	RequireCPULimit      bool
	RequireMemoryRequest bool
	RequireMemoryLimit   bool
	MaxCPULimit          string
	MaxMemoryLimit       string
}

func (r *ResourceLimitCondition) any() bool {
	return r != nil && (r.RequireCPURequest || r.RequireCPULimit || r.RequireMemoryRequest ||
		r.RequireMemoryLimit || strings.TrimSpace(r.MaxCPULimit) != "" || strings.TrimSpace(r.MaxMemoryLimit) != "")
}

// SignatureAnnotation is the pod annotation that surfaces "image is signed by trusted identity".
// In production this is set by the scanner's signature verifier as a pre-admission mutation.
const SignatureAnnotation = "constellation.alphabravo.io/image-signed"

// ImageNoOSAnnotation is the pod annotation the scanner's pre-admission mutation
// stamps ("true") when a container image has no OS layer (a scratch/distroless
// base with no package database). The ImageNoOS condition reads it because the
// base OS is not derivable from the pod spec. NeuVector CriteriaKeyImageNoOS.
const ImageNoOSAnnotation = "constellation.alphabravo.io/image-no-os"

// NewEngine constructs an Engine with the v1 built-in defaults.
func NewEngine() *PolicyEngine {
	return &PolicyEngine{Rules: DefaultRules()}
}

// DefaultRules returns the built-in admission policy catalog.
func DefaultRules() []Rule {
	t := true
	return []Rule{
		{
			ID: "block-privileged", Title: "Block privileged containers",
			Mode: "enforce", Kinds: []string{"Pod"},
			Conditions: RuleConditions{Privileged: &t},
		},
		{
			ID: "block-host-network", Title: "Block pods using hostNetwork",
			Mode: "enforce", Kinds: []string{"Pod"},
			Conditions: RuleConditions{HostNetwork: &t},
		},
		{
			ID: "block-host-pid", Title: "Block pods sharing the host PID namespace",
			Mode: "enforce", Kinds: []string{"Pod"},
			Conditions: RuleConditions{HostPID: &t},
		},
		{
			ID: "require-image-signature", Title: "Images must be signed",
			Mode: "monitor", Kinds: []string{"Pod"},
			Conditions: RuleConditions{RequireImageSignature: &t},
		},
		{
			ID: "require-read-only-rootfs", Title: "Containers must have readOnlyRootFilesystem=true",
			Mode: "monitor", Kinds: []string{"Pod"},
			Conditions: RuleConditions{ReadOnlyRootFS: &t},
		},
	}
}

// SetRules replaces the active rules. It is safe to call while Evaluate is serving requests.
func (e *PolicyEngine) SetRules(rules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Rules = append([]Rule(nil), rules...)
}

// SnapshotRules returns a copy of the current rules.
func (e *PolicyEngine) SnapshotRules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Rule(nil), e.Rules...)
}

// Evaluate runs each Rule against the request. The first enforce-mode deny wins; monitor-mode
// matches surface as warnings (returned via the response Warnings field) but do not block.
func (e *PolicyEngine) Evaluate(ctx context.Context, req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}

	e.mu.RLock()
	rules := append([]Rule(nil), e.Rules...)
	evidence := e.Evidence
	qsrc := e.Quarantine
	onDeny := e.OnDeny
	rbac := e.RBAC
	labeler := e.NamespaceLabeler
	e.mu.RUnlock()

	// Per-rule namespace targeting (A5). Resolved once per request; the matcher
	// memoises the namespace label lookup so a namespaceSelector rule costs at
	// most one resolver call per admission.
	matchesNamespace := namespaceMatcher(ctx, labeler, requestNamespace(req))

	// PersistentVolumeClaims have no pod spec; they are gated separately on
	// storageClassName by any rule that scopes to PersistentVolumeClaim.
	if req.Kind.Kind == "PersistentVolumeClaim" {
		return e.evaluatePVC(ctx, req, rules, onDeny, matchesNamespace)
	}

	// Pod, or a controller kind that embeds a pod template — both reduce to a
	// pod we can run the existing pod checks against.
	if req.Kind.Kind != "Pod" && !isPodTemplateKind(req.Kind.Kind) {
		return resp
	}

	pod, err := extractPodFromObject(req.Kind.Kind, req.Object.Raw)
	if err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: "admission: decode " + req.Kind.Kind + ": " + err.Error()}
		return resp
	}

	// Quarantine check first — runtime-driven, no monitor-mode override.
	// If the snapshot match returns a hit, deny immediately and emit a
	// deny event whose RuleID encodes the quarantine entry id so the
	// audit trail links pod → quarantine entry → upstream alert.
	if qsrc != nil {
		if hit := qsrc.Current().Match(pod); hit != nil {
			resp.Allowed = false
			resp.Result = &metav1.Status{
				Message: fmt.Sprintf("quarantined by constellation (scope=%s match=%s): %s",
					hit.Entry.Scope, hit.MatchValue, hit.Entry.Reason),
			}
			if onDeny != nil {
				func() {
					defer func() { _ = recover() }()
					onDeny(ctx, DenyEvent{
						RuleID:    "quarantine:" + hit.Entry.ID.String(),
						Reason:    hit.Entry.Reason,
						Namespace: pod.Namespace,
						Pod:       pod.Name,
						Operation: string(req.Operation),
						UserInfo:  req.UserInfo.Username,
					})
				}()
			}
			return resp
		}
	}

	var warnings []string

	// P1-3 allow/except precedence: allow rules are evaluated BEFORE deny rules.
	// A matching enforce-mode allow rule short-circuits to ADMIT, carving the
	// workload out of any broad deny rule that would otherwise fire (NeuVector's
	// exception-before-deny model). Monitor-mode allow rules only OBSERVE: they
	// record a warning and let deny evaluation proceed, so a seeded carve-out
	// never silently widens admission until an operator flips it to enforce.
	for _, rule := range rules {
		if !rule.isAllow() || !matchesKind(rule.Kinds, req.Kind.Kind) || !matchesNamespace(rule) {
			continue
		}
		reason, hit, _ := evalPodRule(ctx, rule, pod, evidence)
		if !hit {
			reason, hit = evalIdentityRule(ctx, rule, pod, &req.UserInfo, rbac)
		}
		if !hit {
			continue
		}
		if rule.Mode == "enforce" {
			resp.Warnings = append(warnings, fmt.Sprintf("policy %q (allow): admitted by carve-out: %s", rule.ID, reason))
			return resp
		}
		warnings = append(warnings, fmt.Sprintf("policy %q (allow, monitor): would carve out of deny rules: %s", rule.ID, reason))
	}

	for _, rule := range rules {
		if rule.isAllow() {
			continue // allow rules were handled in the precedence pass above
		}
		if !matchesKind(rule.Kinds, req.Kind.Kind) || !matchesNamespace(rule) {
			continue
		}
		reason, hit, details := evalPodRule(ctx, rule, pod, evidence)
		if !hit {
			// Identity / RBAC criteria are sourced from the AdmissionReview and
			// the cluster's RBAC graph rather than the pod spec, so they run
			// after the pod-spec checks (same first-hit-wins model).
			reason, hit = evalIdentityRule(ctx, rule, pod, &req.UserInfo, rbac)
		}
		if !hit {
			continue
		}
		if rule.Mode == "enforce" {
			resp.Allowed = false
			resp.Result = &metav1.Status{
				Message: fmt.Sprintf("denied by constellation policy %q: %s", rule.ID, reason),
			}
			resp.Warnings = warnings
			// Best-effort notify hook; never panic-out of admission on a notifier bug.
			if onDeny != nil {
				func() {
					defer func() { _ = recover() }()
					onDeny(ctx, DenyEvent{
						RuleID:          rule.ID,
						Reason:          reason,
						Namespace:       pod.Namespace,
						Pod:             pod.Name,
						Operation:       string(req.Operation),
						UserInfo:        req.UserInfo.Username,
						EvidenceDetails: append([]EvidenceDetail(nil), details...),
					})
				}()
			}
			return resp
		}
		warnings = append(warnings, fmt.Sprintf("policy %q (monitor): %s", rule.ID, reason))
		// Monitor-mode match: admit but record the violation so it is auditable and
		// counted (NeuVector monitor-then-enforce tuning workflow). Fires the SAME
		// hook as a deny with Monitor=true; the audit hook writes 'admission.monitor'
		// and skips response-rule actions.
		fireHook(ctx, onDeny, DenyEvent{
			Monitor:         true,
			RuleID:          rule.ID,
			Reason:          reason,
			Namespace:       pod.Namespace,
			Pod:             pod.Name,
			Operation:       string(req.Operation),
			UserInfo:        req.UserInfo.Username,
			EvidenceDetails: append([]EvidenceDetail(nil), details...),
		})
	}
	resp.Warnings = warnings
	return resp
}

// evaluatePVC gates a PersistentVolumeClaim on its storageClassName against any
// rule that scopes to PersistentVolumeClaim and carries an AllowedStorageClasses
// allowlist. enforce denies; monitor warns.
func (e *PolicyEngine) evaluatePVC(ctx context.Context, req *admissionv1.AdmissionRequest, rules []Rule, onDeny func(context.Context, DenyEvent), matchesNamespace func(Rule) bool) *admissionv1.AdmissionResponse {
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}

	name, namespace, storageClass, err := extractPVCStorageClass(req.Object.Raw)
	if err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: "admission: decode PersistentVolumeClaim: " + err.Error()}
		return resp
	}

	var warnings []string
	for _, rule := range rules {
		if rule.isAllow() {
			// Allow/except carve-outs use the AllowedStorageClasses field with
			// reversed (match=admit) semantics that this deny loop does not model;
			// skip them here so a carve-out is never mistaken for a PVC deny.
			continue
		}
		if !matchesKind(rule.Kinds, "PersistentVolumeClaim") || !matchesNamespace(rule) {
			continue
		}
		allowed := rule.Conditions.AllowedStorageClasses
		if len(allowed) == 0 {
			continue
		}
		if storageClassAllowed(storageClass, allowed) {
			continue
		}
		shown := storageClass
		if shown == "" {
			shown = "(cluster default)"
		}
		reason := fmt.Sprintf("PersistentVolumeClaim storageClassName %s is not in the allowlist %v", shown, allowed)
		if rule.Mode == "enforce" {
			resp.Allowed = false
			resp.Result = &metav1.Status{
				Message: fmt.Sprintf("denied by constellation policy %q: %s", rule.ID, reason),
			}
			resp.Warnings = warnings
			if onDeny != nil {
				func() {
					defer func() { _ = recover() }()
					onDeny(ctx, DenyEvent{
						RuleID:    rule.ID,
						Reason:    reason,
						Namespace: namespace,
						Pod:       name,
						Operation: string(req.Operation),
						UserInfo:  req.UserInfo.Username,
					})
				}()
			}
			return resp
		}
		warnings = append(warnings, fmt.Sprintf("policy %q (monitor): %s", rule.ID, reason))
		// Monitor-mode PVC match: audit + count the violation without blocking (see
		// the pod monitor branch above).
		fireHook(ctx, onDeny, DenyEvent{
			Monitor:   true,
			RuleID:    rule.ID,
			Reason:    reason,
			Namespace: namespace,
			Pod:       name,
			Operation: string(req.Operation),
			UserInfo:  req.UserInfo.Username,
		})
	}
	resp.Warnings = warnings
	return resp
}

func storageClassAllowed(sc string, allowed []string) bool {
	for _, a := range allowed {
		if sc == a {
			return true
		}
	}
	return false
}

// identityRegexCache memoises compiled UserMatch/GroupMatch patterns so a hot
// admission path doesn't recompile on every request. Patterns are anchored
// (full-string match) to match NeuVector's exact-match-by-default semantics
// while still allowing regex metacharacters.
//
// C3: these are case-SENSITIVE Go regexes. An IdP-supplied username/group that
// differs only in case from the pattern (e.g. "Admin@corp" vs "admin@corp") will
// not match. Author patterns accordingly, or prefix "(?i)" for a case-insensitive
// match. Invalid patterns are rejected at rule-load time (validateIdentityRegex)
// so a malformed pattern can never silently degrade a deny rule into a no-op.
var (
	identityRegexMu    sync.RWMutex
	identityRegexCache = map[string]*regexp.Regexp{}
)

// validateIdentityRegex reports whether pattern compiles under the same anchoring
// compileIdentityRegex applies. Used by RuleFromYAML to fail loudly on a malformed
// UserMatch/GroupMatch instead of silently failing open at evaluation time.
func validateIdentityRegex(field, pattern string) error {
	if _, err := regexp.Compile("^(?:" + pattern + ")$"); err != nil {
		return fmt.Errorf("invalid %s regex %q: %w", field, pattern, err)
	}
	return nil
}

func compileIdentityRegex(pattern string) *regexp.Regexp {
	identityRegexMu.RLock()
	re, ok := identityRegexCache[pattern]
	identityRegexMu.RUnlock()
	if ok {
		return re
	}
	// Anchor so "system:.*" matches the whole username, not a substring.
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	if err != nil {
		re = nil // invalid pattern never matches; cached as nil to avoid recompiling.
	}
	identityRegexMu.Lock()
	identityRegexCache[pattern] = re
	identityRegexMu.Unlock()
	return re
}

// evalIdentityRule evaluates the identity/RBAC criteria (UserMatch, GroupMatch,
// SABindRiskyRole) sourced from the AdmissionReview userInfo and the cluster
// RBAC graph. It returns (reason, matched) using the same first-hit-wins model
// as evalPodRule. Criteria are OR-combined: any one matching fires the rule.
func evalIdentityRule(ctx context.Context, r Rule, pod *corev1.Pod, user *authenticationv1.UserInfo, rbac RBACResolver) (string, bool) {
	c := r.Conditions

	if c.UserMatch != "" && user != nil {
		if re := compileIdentityRegex(c.UserMatch); re != nil && re.MatchString(user.Username) {
			return fmt.Sprintf("request user %q matches %q", user.Username, c.UserMatch), true
		}
	}
	if c.GroupMatch != "" && user != nil {
		if re := compileIdentityRegex(c.GroupMatch); re != nil {
			for _, g := range user.Groups {
				if re.MatchString(g) {
					return fmt.Sprintf("request group %q matches %q", g, c.GroupMatch), true
				}
			}
		}
	}
	if c.SABindRiskyRole != nil && *c.SABindRiskyRole && rbac != nil {
		ns := pod.Namespace
		if ns == "" {
			ns = "default"
		}
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}
		flags, roles, err := rbac.RiskyRolesForServiceAccount(ctx, ns, sa)
		if err == nil && flags != 0 {
			return fmt.Sprintf("service account %q binds risky role(s) [%s] granting [%s]",
				sa, strings.Join(roles, ", "), strings.Join(flags.Labels(), ", ")), true
		}
	}
	return "", false
}

// evalPodRule returns (reasonString, matched, evidenceDetails).
func evalPodRule(ctx context.Context, r Rule, pod *corev1.Pod, evidence EvidenceSource) (string, bool, []EvidenceDetail) {
	c := r.Conditions

	if c.PSSLevel != "" {
		if violations := evaluatePSS(pod, PSSLevel(c.PSSLevel)); len(violations) > 0 {
			return fmt.Sprintf("Pod Security Standards %s: %s", c.PSSLevel, strings.Join(violations, "; ")), true, nil
		}
	}
	if c.Privileged != nil && *c.Privileged {
		for _, ctr := range allContainers(pod) {
			if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
				return fmt.Sprintf("container %q is privileged", ctr.Name), true, nil
			}
		}
	}
	if c.HostNetwork != nil && *c.HostNetwork {
		if pod.Spec.HostNetwork {
			return "hostNetwork=true", true, nil
		}
	}
	if c.HostPID != nil && *c.HostPID {
		if pod.Spec.HostPID {
			return "hostPID=true", true, nil
		}
	}
	if c.HostIPC != nil && *c.HostIPC {
		if pod.Spec.HostIPC {
			return "hostIPC=true", true, nil
		}
	}
	if c.AllowPrivilegeEscalation != nil && *c.AllowPrivilegeEscalation {
		for _, ctr := range allContainers(pod) {
			if ctr.SecurityContext != nil && ctr.SecurityContext.AllowPrivilegeEscalation != nil && *ctr.SecurityContext.AllowPrivilegeEscalation {
				return fmt.Sprintf("container %q allows privilege escalation", ctr.Name), true, nil
			}
		}
	}
	if c.ImageNoOS != nil && *c.ImageNoOS {
		if pod.Annotations[ImageNoOSAnnotation] == "true" {
			return "image has no OS layer", true, nil
		}
	}
	if c.ResourceLimit.any() {
		if reason, hit := podResourceLimitViolation(pod, c.ResourceLimit); hit {
			return reason, true, nil
		}
	}
	if c.ReadOnlyRootFS != nil && *c.ReadOnlyRootFS {
		for _, ctr := range allContainers(pod) {
			if ctr.SecurityContext == nil || ctr.SecurityContext.ReadOnlyRootFilesystem == nil || !*ctr.SecurityContext.ReadOnlyRootFilesystem {
				return fmt.Sprintf("container %q has writable root filesystem", ctr.Name), true, nil
			}
		}
	}
	if c.RequireImageSignature != nil && *c.RequireImageSignature {
		annotation := c.SignatureAnnotation
		if annotation == "" {
			annotation = SignatureAnnotation
		}
		signed := pod.Annotations[annotation] == "true"
		if !signed {
			if annotation == SignatureAnnotation {
				return "missing constellation image-signed annotation", true, nil
			}
			return fmt.Sprintf("missing %s annotation", annotation), true, nil
		}
	}
	if c.RequireNonRoot != nil && *c.RequireNonRoot {
		if reason, hit := podRunsAsRoot(pod); hit {
			return reason, true, nil
		}
	}
	if c.DisallowLatestTag != nil && *c.DisallowLatestTag {
		for _, ctr := range allContainers(pod) {
			if imageHasLatestTag(ctr.Image) {
				return fmt.Sprintf("container %q uses latest image tag", ctr.Name), true, nil
			}
		}
	}
	if c.DisallowImplicitTag != nil && *c.DisallowImplicitTag {
		for _, ctr := range allContainers(pod) {
			if imageHasImplicitTag(ctr.Image) {
				return fmt.Sprintf("container %q uses implicit image tag", ctr.Name), true, nil
			}
		}
	}
	if c.RequireDigest != nil && *c.RequireDigest {
		for _, ctr := range allContainers(pod) {
			if !strings.Contains(ctr.Image, "@sha256:") {
				return fmt.Sprintf("container %q image is not digest-pinned", ctr.Name), true, nil
			}
		}
	}
	if c.RequirePrivilegedApproval != nil && *c.RequirePrivilegedApproval {
		if reason, hit := privilegedOrHostAccess(pod); hit {
			if !approvalPresent(pod, c.ApprovalAnnotation, c.ApprovedValues) {
				return reason + " without approval", true, nil
			}
		}
	}
	if len(c.AllowedImageRegistries) > 0 {
		for _, ctr := range allContainers(pod) {
			if !imageInAllowlist(ctr.Image, c.AllowedImageRegistries) {
				return fmt.Sprintf("container %q uses image %q from non-allowlisted registry", ctr.Name, ctr.Image), true, nil
			}
		}
	}
	if c.DenyEnvVarSecrets != nil && *c.DenyEnvVarSecrets {
		if reason, hit := podEnvVarSecret(pod); hit {
			return reason, true, nil
		}
	}
	if len(c.EvidenceGates) > 0 {
		if evidence == nil {
			return "admission evidence source unavailable", true, nil
		}
		if detailed, ok := evidence.(DetailedEvidenceSource); ok {
			reason, hit, details, err := detailed.EvaluateAdmissionEvidenceWithDetails(ctx, r, pod)
			if err != nil {
				return "admission evidence lookup failed: " + err.Error(), true, nil
			}
			if hit {
				return reason, true, append([]EvidenceDetail(nil), details...)
			}
			return "", false, nil
		}
		reason, hit, err := evidence.EvaluateAdmissionEvidence(ctx, r, pod)
		if err != nil {
			return "admission evidence lookup failed: " + err.Error(), true, nil
		}
		if hit {
			return reason, true, nil
		}
	}
	return "", false, nil
}

func podRunsAsRoot(pod *corev1.Pod) (string, bool) {
	podRunAsNonRoot := false
	if pod.Spec.SecurityContext != nil {
		if pod.Spec.SecurityContext.RunAsUser != nil && *pod.Spec.SecurityContext.RunAsUser == 0 {
			return "pod securityContext.runAsUser=0", true
		}
		if pod.Spec.SecurityContext.RunAsNonRoot != nil && *pod.Spec.SecurityContext.RunAsNonRoot {
			podRunAsNonRoot = true
		}
	}
	for _, ctr := range allContainers(pod) {
		ctrRunAsNonRoot := podRunAsNonRoot
		if ctr.SecurityContext != nil {
			if ctr.SecurityContext.RunAsUser != nil && *ctr.SecurityContext.RunAsUser == 0 {
				return fmt.Sprintf("container %q securityContext.runAsUser=0", ctr.Name), true
			}
			if ctr.SecurityContext.RunAsNonRoot != nil {
				if !*ctr.SecurityContext.RunAsNonRoot {
					return fmt.Sprintf("container %q securityContext.runAsNonRoot=false", ctr.Name), true
				}
				ctrRunAsNonRoot = true
			}
		}
		if !ctrRunAsNonRoot {
			return fmt.Sprintf("container %q does not set runAsNonRoot=true", ctr.Name), true
		}
	}
	return "", false
}

// podResourceLimitViolation reports the first container that omits a required
// cpu/memory request or limit, or whose cpu/memory limit exceeds the configured
// maximum. Returns (reason, true) on the first violation, ("", false) if every
// container satisfies the condition (ADM-26, NeuVector CriteriaKeyRequestLimit).
func podResourceLimitViolation(pod *corev1.Pod, cond *ResourceLimitCondition) (string, bool) {
	for _, ctr := range allContainers(pod) {
		if cond.RequireCPURequest && ctr.Resources.Requests.Cpu().IsZero() {
			return fmt.Sprintf("container %q has no CPU request", ctr.Name), true
		}
		if cond.RequireCPULimit && ctr.Resources.Limits.Cpu().IsZero() {
			return fmt.Sprintf("container %q has no CPU limit", ctr.Name), true
		}
		if cond.RequireMemoryRequest && ctr.Resources.Requests.Memory().IsZero() {
			return fmt.Sprintf("container %q has no memory request", ctr.Name), true
		}
		if cond.RequireMemoryLimit && ctr.Resources.Limits.Memory().IsZero() {
			return fmt.Sprintf("container %q has no memory limit", ctr.Name), true
		}
		if max := strings.TrimSpace(cond.MaxCPULimit); max != "" {
			if q, err := resource.ParseQuantity(max); err == nil {
				if cpu := ctr.Resources.Limits.Cpu(); !cpu.IsZero() && cpu.Cmp(q) > 0 {
					return fmt.Sprintf("container %q CPU limit %s exceeds max %s", ctr.Name, cpu.String(), max), true
				}
			}
		}
		if max := strings.TrimSpace(cond.MaxMemoryLimit); max != "" {
			if q, err := resource.ParseQuantity(max); err == nil {
				if mem := ctr.Resources.Limits.Memory(); !mem.IsZero() && mem.Cmp(q) > 0 {
					return fmt.Sprintf("container %q memory limit %s exceeds max %s", ctr.Name, mem.String(), max), true
				}
			}
		}
	}
	return "", false
}

func privilegedOrHostAccess(pod *corev1.Pod) (string, bool) {
	if pod.Spec.HostNetwork {
		return "hostNetwork=true", true
	}
	if pod.Spec.HostPID {
		return "hostPID=true", true
	}
	for _, ctr := range allContainers(pod) {
		if ctr.SecurityContext != nil && ctr.SecurityContext.Privileged != nil && *ctr.SecurityContext.Privileged {
			return fmt.Sprintf("container %q is privileged", ctr.Name), true
		}
	}
	return "", false
}

func approvalPresent(pod *corev1.Pod, annotation string, approvedValues []string) bool {
	if annotation == "" {
		annotation = "constellation.alphabravo.io/privileged-approval"
	}
	value := pod.Annotations[annotation]
	if len(approvedValues) == 0 {
		return value != ""
	}
	for _, approved := range approvedValues {
		if value == approved {
			return true
		}
	}
	return false
}

func allContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.Containers)+len(pod.Spec.InitContainers))
	out = append(out, pod.Spec.Containers...)
	out = append(out, pod.Spec.InitContainers...)
	for _, ctr := range pod.Spec.EphemeralContainers {
		out = append(out, corev1.Container{
			Name:            ctr.Name,
			Image:           ctr.Image,
			SecurityContext: ctr.SecurityContext,
		})
	}
	return out
}

// envSecretPatterns is a small high-confidence secret pattern set for the
// env-var-secret admission gate (NeuVector CriteriaKeyEnvVarSecrets). Each entry
// is a label + a compiled regex; a literal container env value matching any of
// them denies admission. These mirror the highest-confidence subset of the
// runtime DLP signature pack (internal/runtime/dlp.BuiltinSensor) — AWS keys,
// private-key PEM headers, and well-known provider token prefixes — chosen to
// minimise false positives on benign config values.
//
// ponytail: this is a deliberately tiny pattern set, not a full secret scanner.
// The upgrade path is to route env literals through the same detector the
// scanner uses (internal/scanner secrets via Trivy / a shared gitleaks-style
// ruleset) so admission and image scanning share one signature source, as
// NeuVector does with its `secrets` package.
var envSecretPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"AWS access key id", regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`)},
	{"private key", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[abps]-[A-Za-z0-9-]{10,48}\b`)},
	{"Stripe secret key", regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{24,}\b`)},
}

// podEnvVarSecret denies when any container's literal env value looks like a
// secret. Only inline literals (env[].value) are inspected; valueFrom
// (secretKeyRef/configMapRef) and envFrom references are by design NOT flagged —
// those are the correct, safe way to inject secrets and carry no literal here.
func podEnvVarSecret(pod *corev1.Pod) (string, bool) {
	containers := append([]corev1.Container(nil), pod.Spec.Containers...)
	containers = append(containers, pod.Spec.InitContainers...)
	for _, ctr := range containers {
		for _, env := range ctr.Env {
			if env.Value == "" {
				continue // valueFrom: not a literal — nothing to inspect.
			}
			for _, p := range envSecretPatterns {
				if p.re.MatchString(env.Value) {
					return fmt.Sprintf("container %q env %q holds a secret-like value (%s)", ctr.Name, env.Name, p.label), true
				}
			}
		}
		// envFrom references whole secrets/configmaps by reference (no literal to
		// scan here); we leave them untouched — see podEnvVarSecret doc + ponytail.
	}
	return "", false
}

// requestNamespace resolves the namespace an admission request targets. It
// prefers the authoritative req.Namespace set by the API server and falls back
// to the object metadata (so unit tests that only populate the object body still
// resolve a namespace).
func requestNamespace(req *admissionv1.AdmissionRequest) string {
	ns, _ := denyTargetFromRequest(req)
	return ns
}

// namespaceMatcher returns a per-rule predicate for the per-rule namespace
// targeting (A5). The returned closure memoises the namespace label lookup so a
// request pays at most one resolver call regardless of how many rules carry a
// namespaceSelector. A rule with neither Namespaces nor NamespaceSelector always
// matches (cluster-wide). Namespaces (name list) and NamespaceSelector (labels)
// are OR-combined.
func namespaceMatcher(ctx context.Context, labeler NamespaceLabelResolver, namespace string) func(Rule) bool {
	var (
		labels   map[string]string
		resolved bool
		resolErr error
	)
	return func(r Rule) bool {
		if len(r.Namespaces) == 0 && len(r.NamespaceSelector) == 0 {
			return true
		}
		if len(r.Namespaces) > 0 {
			for _, ns := range r.Namespaces {
				if ns == namespace {
					return true
				}
			}
		}
		if len(r.NamespaceSelector) > 0 {
			if labeler == nil {
				// TODO(matrix): no namespace label resolver wired; a
				// label-selected rule cannot be evaluated so it does not fire.
				return false
			}
			if !resolved {
				labels, resolErr = labeler.NamespaceLabels(ctx, namespace)
				resolved = true
			}
			if resolErr == nil && labelsMatchSelector(labels, r.NamespaceSelector) {
				return true
			}
		}
		return false
	}
}

// labelsMatchSelector reports whether labels contains every key/value pair in
// selector (matchLabels semantics). An empty selector matches everything.
func labelsMatchSelector(labels, selector map[string]string) bool {
	for k, v := range selector {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func matchesKind(kinds []string, kind string) bool {
	for _, k := range kinds {
		if strings.EqualFold(k, kind) {
			return true
		}
		// Controller kinds carry an embedded pod template that we validate with
		// the same pod checks, so a rule scoped to "Pod" also applies to any
		// pod-template-bearing controller (Deployment, Job, CronJob, …).
		if strings.EqualFold(k, "Pod") && isPodTemplateKind(kind) {
			return true
		}
	}
	return false
}

// podTemplateKinds are the apps/batch/core controller kinds that embed a
// PodTemplateSpec. Validating one means validating the pod it will create.
var podTemplateKinds = map[string]bool{
	"Deployment":            true,
	"StatefulSet":           true,
	"DaemonSet":             true,
	"ReplicaSet":            true,
	"ReplicationController": true,
	"Job":                   true,
	"CronJob":               true,
	// OpenShift DeploymentConfig (apps.openshift.io/v1) embeds its PodTemplateSpec
	// at spec.template, the same path as the apps/v1 controllers, so the generic
	// extractor handles it unchanged. Without this entry admission is bypassed for
	// DeploymentConfig-created pods on OCP (ADM-30).
	"DeploymentConfig": true,
}

// isPodTemplateKind reports whether kind is a controller whose object embeds a
// PodTemplateSpec (matched case-insensitively).
func isPodTemplateKind(kind string) bool {
	for k := range podTemplateKinds {
		if strings.EqualFold(k, kind) {
			return true
		}
	}
	return false
}

// extractPodFromObject decodes the admission object into a *corev1.Pod. For a
// Pod it decodes directly; for a controller kind it locates the embedded
// PodTemplateSpec (spec.template for apps/batch controllers, or
// spec.jobTemplate.spec.template for CronJob) and builds a synthetic pod from
// it so the existing pod checks apply unchanged. The returned pod inherits the
// controller's name/namespace so deny events and evidence reference it.
func extractPodFromObject(kind string, raw []byte) (*corev1.Pod, error) {
	if strings.EqualFold(kind, "Pod") {
		pod := &corev1.Pod{}
		if err := json.Unmarshal(raw, pod); err != nil {
			return nil, err
		}
		return pod, nil
	}
	if !isPodTemplateKind(kind) {
		return nil, fmt.Errorf("kind %q has no pod template", kind)
	}

	// A controller's metadata plus the template under a kind-specific path. We
	// decode generically rather than importing every apps/batch type.
	var obj struct {
		Metadata metav1.ObjectMeta `json:"metadata"`
		Spec     struct {
			Template *corev1.PodTemplateSpec `json:"template"`
			// CronJob nests the template one level deeper.
			JobTemplate *struct {
				Spec struct {
					Template *corev1.PodTemplateSpec `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}

	tmpl := obj.Spec.Template
	if tmpl == nil && obj.Spec.JobTemplate != nil {
		tmpl = obj.Spec.JobTemplate.Spec.Template
	}
	if tmpl == nil {
		return nil, fmt.Errorf("%s has no pod template", kind)
	}

	pod := &corev1.Pod{Spec: tmpl.Spec}
	pod.ObjectMeta = tmpl.ObjectMeta
	// Fall back to the controller's identity so audit events are attributable.
	if pod.Name == "" {
		pod.Name = obj.Metadata.Name
	}
	if pod.Namespace == "" {
		pod.Namespace = obj.Metadata.Namespace
	}
	return pod, nil
}

// extractPVCStorageClass decodes a PersistentVolumeClaim and returns its
// requested storageClassName (empty string means the field was unset, i.e. the
// cluster default StorageClass would be used) along with the claim's identity.
func extractPVCStorageClass(raw []byte) (name, namespace, storageClass string, err error) {
	pvc := &corev1.PersistentVolumeClaim{}
	if err := json.Unmarshal(raw, pvc); err != nil {
		return "", "", "", err
	}
	sc := ""
	if pvc.Spec.StorageClassName != nil {
		sc = *pvc.Spec.StorageClassName
	}
	return pvc.Name, pvc.Namespace, sc, nil
}

func imageInAllowlist(image string, allowlist []string) bool {
	// Parse so we compare the registry host on an exact boundary rather than a
	// raw prefix: entry "registry.corp.com" must NOT admit
	// "registry.corp.com.evil.io/malware". Entries that include a path keep
	// path-prefix semantics (host must still match exactly).
	ref := ParseReqImageName(image)
	host := ref.Registry
	if idx := strings.Index(host, "://"); idx != -1 {
		host = host[idx+3:]
	}
	host = strings.TrimSuffix(host, "/")
	for _, entry := range allowlist {
		e := entry
		if idx := strings.Index(e, "://"); idx != -1 {
			e = e[idx+3:]
		}
		e = strings.TrimSuffix(e, "/")
		if e == "" {
			continue
		}
		eHost, ePath := e, ""
		if slash := strings.Index(e, "/"); slash != -1 {
			eHost, ePath = e[:slash], e[slash+1:]
		}
		if !strings.EqualFold(eHost, host) {
			continue
		}
		if ePath == "" {
			return true
		}
		// path-prefix, boundary-aware: exact repo or a "/"-delimited descendant.
		if ref.Repo == ePath || strings.HasPrefix(ref.Repo, ePath+"/") {
			return true
		}
	}
	return false
}

func imageHasLatestTag(image string) bool {
	tag, ok := explicitImageTag(image)
	return ok && tag == "latest"
}

func imageHasImplicitTag(image string) bool {
	ref := image
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	return lastColon <= lastSlash
}

func explicitImageTag(image string) (string, bool) {
	ref := image
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon <= lastSlash {
		return "", false
	}
	return ref[lastColon+1:], true
}

// runtimeScheme is exported only so the webhook server can register types when wiring TLS.
var runtimeScheme = runtime.NewScheme()
