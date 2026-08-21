package admission

import (
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

type admissionRuleDocument struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec admissionRuleSpec `yaml:"spec"`
}

type admissionRuleSpec struct {
	Match struct {
		Kinds []string `yaml:"kinds"`
		// Namespaces scopes the rule to requests in these namespaces (exact name
		// match). Empty = all namespaces. Per-rule namespace targeting (A5,
		// NeuVector CriteriaKeyNamespace).
		Namespaces []string `yaml:"namespaces"`
		// NamespaceSelector scopes the rule to namespaces carrying all of these
		// labels (matchLabels). Requires a namespace label resolver on the engine.
		NamespaceSelector map[string]string `yaml:"namespaceSelector"`
	} `yaml:"match"`
	Conditions struct {
		Any []admissionRuleCondition `yaml:"any"`
	} `yaml:"conditions"`
	Provenance struct {
		RequireSignatureAnnotation string `yaml:"requireSignatureAnnotation"`
	} `yaml:"provenance"`
	Containers struct {
		RequireReadOnlyRootFilesystem bool `yaml:"requireReadOnlyRootFilesystem"`
		RequireNonRoot                bool `yaml:"requireNonRoot"`
		DenyEnvVarSecrets             bool `yaml:"denyEnvVarSecrets"` // deny pods whose env literal values look like secrets
	} `yaml:"containers"`
	Images struct {
		DisallowLatestTag   bool     `yaml:"disallowLatestTag"`
		DisallowImplicitTag bool     `yaml:"disallowImplicitTag"`
		RequireDigest       bool     `yaml:"requireDigest"`
		AllowedRegistries   []string `yaml:"allowedRegistries"`
	} `yaml:"images"`
	ScanEvidence  admissionRuleScanEvidence `yaml:"scanEvidence"`
	Vulnerability struct {
		MaxAllowedSeverity      string   `yaml:"maxAllowedSeverity"`
		MaxCriticalCount        *int     `yaml:"maxCriticalCount"`
		MaxHighCount            *int     `yaml:"maxHighCount"`
		MaxMediumCount          *int     `yaml:"maxMediumCount"`          // ADM-29: deny if distinct medium CVEs exceed this
		MaxCriticalWithFixCount *int     `yaml:"maxCriticalWithFixCount"` // ADM-29: deny if distinct critical CVEs that have a fix exceed this
		MaxHighWithFixCount     *int     `yaml:"maxHighWithFixCount"`     // ADM-29: deny if distinct high CVEs that have a fix exceed this
		MaxCveScoreCount        *int     `yaml:"maxCveScoreCount"`        // deny if CVEs with CVSS score >= cveScore exceed this count
		CveScore                float64  `yaml:"cveScore"`                // CVSS base score threshold for maxCveScoreCount
		DeniedCVEs              []string `yaml:"deniedCVEs"`              // deny if any of these CVE ids is present regardless of severity/count (NeuVector CriteriaKeyCVENames)
		CveGraceDays            *int     `yaml:"cveGraceDays"`            // ignore CVEs published within this many days when counting/denying (NeuVector SubCriteriaPublishDays)
		RequireKnownScanResult  bool     `yaml:"requireKnownScanResult"`
		HonorActiveExceptions   bool     `yaml:"honorActiveExceptions"`
		MaxScanAge              string   `yaml:"maxScanAge"`
		RequireVulnDBBundle     bool     `yaml:"requireVulnDBBundle"`
		CanonicalEngine         string   `yaml:"canonicalEngine"`
		CanonicalEngines        []string `yaml:"canonicalEngines"`
		RequireFixAvailable     bool     `yaml:"requireFixAvailable"`
	} `yaml:"vulnerability"`
	Findings struct {
		Kinds             []string `yaml:"kinds"`
		MinimumSeverity   string   `yaml:"minimumSeverity"`
		MinimumConfidence string   `yaml:"minimumConfidence"`
	} `yaml:"findings"`
	ImageArtifacts struct {
		Secrets struct {
			MaxAllowed      *int   `yaml:"maxAllowed"`
			MinimumSeverity string `yaml:"minimumSeverity"`
		} `yaml:"secrets"`
		FileRisks struct {
			MaxAllowed      *int     `yaml:"maxAllowed"`
			MinimumSeverity string   `yaml:"minimumSeverity"`
			RiskTypes       []string `yaml:"riskTypes"`
		} `yaml:"fileRisks"`
		Signature struct {
			RequireKnownScanResult  bool     `yaml:"requireKnownScanResult"`
			RequireTrusted          bool     `yaml:"requireTrusted"`
			RequireVerifierIdentity bool     `yaml:"requireVerifierIdentity"`
			AllowedStatuses         []string `yaml:"allowedStatuses"`
			AllowedIdentities       []string `yaml:"allowedIdentities"`
		} `yaml:"signature"`
	} `yaml:"imageArtifacts"`
	RequireApproval struct {
		Annotation     string   `yaml:"annotation"`
		ApprovedValues []string `yaml:"approvedValues"`
	} `yaml:"requireApproval"`
	PodSecurityStandard struct {
		Level string `yaml:"level"` // baseline | restricted
	} `yaml:"podSecurityStandard"`
	PersistentVolumeClaim struct {
		// AllowedStorageClasses gates PVC admission. An empty string entry
		// permits PVCs that omit storageClassName (cluster default).
		AllowedStorageClasses []string `yaml:"allowedStorageClasses"`
	} `yaml:"persistentVolumeClaim"`
	// Pod carries long-tail pod-spec criteria (ADM-26) that are not simple
	// boolean field-equals conditions. Boolean pod criteria (hostIPC,
	// allowPrivilegeEscalation, imageNoOS) go through conditions.any instead.
	Pod struct {
		ResourceLimit struct {
			RequireCPURequest    bool   `yaml:"requireCpuRequest"`
			RequireCPULimit      bool   `yaml:"requireCpuLimit"`
			RequireMemoryRequest bool   `yaml:"requireMemoryRequest"`
			RequireMemoryLimit   bool   `yaml:"requireMemoryLimit"`
			MaxCPULimit          string `yaml:"maxCpuLimit"`
			MaxMemoryLimit       string `yaml:"maxMemoryLimit"`
		} `yaml:"resourceLimit"`
	} `yaml:"pod"`
	Identity struct {
		// UserMatch / GroupMatch are anchored regexps evaluated against the
		// AdmissionReview userInfo (username and groups). A match fires the rule.
		UserMatch  string `yaml:"userMatch"`
		GroupMatch string `yaml:"groupMatch"`
		// SaBindRiskyRole fires when the pod ServiceAccount binds one of the
		// five risky RBAC roles. Resolved through the engine's RBACResolver.
		SaBindRiskyRole bool `yaml:"saBindRiskyRole"`
	} `yaml:"identity"`
	Action string `yaml:"action"`
}

type admissionRuleCondition struct {
	Field  string `yaml:"field"`
	Equals any    `yaml:"equals"`
}

type admissionRuleScanEvidence struct {
	MaxAge                       string   `yaml:"maxAge"`
	RequireVulnDBBundle          bool     `yaml:"requireVulnDBBundle"`
	SourceType                   string   `yaml:"sourceType"`
	SourceTypes                  []string `yaml:"sourceTypes"`
	RequireDigestMatch           bool     `yaml:"requireDigestMatch"`
	RequireTrustedAttestation    bool     `yaml:"requireTrustedAttestation"`
	AttestationPredicateType     string   `yaml:"attestationPredicateType"`
	AttestationPredicateTypes    []string `yaml:"attestationPredicateTypes"`
	AllowedAttestationIdentities []string `yaml:"allowedAttestationIdentities"`
	AllowedAttestationIssuers    []string `yaml:"allowedAttestationIssuers"`
	CanonicalEngine              string   `yaml:"canonicalEngine"`
	CanonicalEngines             []string `yaml:"canonicalEngines"`
}

// RuleFromYAML converts a Constellation AdmissionRule YAML document into a
// PolicyEngine rule. It returns supported=false for valid profile rules that
// need external finding or vulnerability state and therefore cannot be enforced
// by the local pod-spec evaluator.
func RuleFromYAML(id, title, description, mode, specYAML string) (rule Rule, supported bool, err error) {
	var doc admissionRuleDocument
	if err := yaml.Unmarshal([]byte(specYAML), &doc); err != nil {
		return Rule{}, false, fmt.Errorf("parse admission rule yaml: %w", err)
	}
	if doc.Kind != "" && doc.Kind != "AdmissionRule" {
		return Rule{}, false, fmt.Errorf("unsupported admission rule kind %q", doc.Kind)
	}
	if !validAdmissionMode(mode) {
		return Rule{}, false, fmt.Errorf("unsupported admission rule mode %q", mode)
	}
	effect, err := admissionEffectFromAction(doc.Spec.Action)
	if err != nil {
		return Rule{}, false, err
	}
	if id == "" {
		id = doc.Metadata.Name
	}
	if title == "" {
		title = doc.Metadata.Name
	}
	if mode == "" {
		mode = "monitor"
	}
	rule = Rule{
		ID:          id,
		Title:       title,
		Description: description,
		Mode:        mode,
		Effect:      effect,
		Kinds:       doc.Spec.Match.Kinds,
	}
	if len(rule.Kinds) == 0 {
		rule.Kinds = []string{"Pod"}
	}
	// Per-rule namespace targeting (A5). Namespace names are case-sensitive, so
	// only whitespace is trimmed. NamespaceSelector keys/values are passed
	// through verbatim for matchLabels equality against namespace labels.
	if len(doc.Spec.Match.Namespaces) > 0 {
		namespaces := make([]string, 0, len(doc.Spec.Match.Namespaces))
		for _, ns := range doc.Spec.Match.Namespaces {
			if trimmed := strings.TrimSpace(ns); trimmed != "" {
				namespaces = append(namespaces, trimmed)
			}
		}
		rule.Namespaces = namespaces
	}
	if len(doc.Spec.Match.NamespaceSelector) > 0 {
		selector := make(map[string]string, len(doc.Spec.Match.NamespaceSelector))
		for k, v := range doc.Spec.Match.NamespaceSelector {
			if key := strings.TrimSpace(k); key != "" {
				selector[key] = strings.TrimSpace(v)
			}
		}
		if len(selector) > 0 {
			rule.NamespaceSelector = selector
		}
	}

	var conditions RuleConditions
	var elevatedFields admissionElevatedFields
	for _, cond := range doc.Spec.Conditions.Any {
		if !conditionEqualsTrue(cond.Equals) {
			continue
		}
		switch normalizeFieldPath(cond.Field) {
		case "spec.containers[*].securitycontext.privileged",
			"spec.initcontainers[*].securitycontext.privileged",
			"spec.ephemeralcontainers[*].securitycontext.privileged":
			elevatedFields.privileged = true
		case "spec.hostnetwork":
			elevatedFields.hostNetwork = true
		case "spec.hostpid":
			elevatedFields.hostPID = true
		case "spec.hostipc":
			// ADM-26: share host IPC namespace (NeuVector CriteriaKeyShareIpcWithHost).
			conditions.HostIPC = boolPtr(true)
		case "spec.containers[*].securitycontext.allowprivilegeescalation",
			"spec.initcontainers[*].securitycontext.allowprivilegeescalation",
			"spec.ephemeralcontainers[*].securitycontext.allowprivilegeescalation":
			// ADM-26: standalone allowPrivilegeEscalation (NeuVector CriteriaKeyAllowPrivEscalation).
			conditions.AllowPrivilegeEscalation = boolPtr(true)
		case "spec.imagenoos":
			// ADM-26: image without OS layer (NeuVector CriteriaKeyImageNoOS).
			conditions.ImageNoOS = boolPtr(true)
		}
	}

	if doc.Spec.RequireApproval.Annotation != "" {
		if elevatedFields.any() {
			conditions.RequirePrivilegedApproval = boolPtr(true)
			conditions.ApprovalAnnotation = doc.Spec.RequireApproval.Annotation
			conditions.ApprovedValues = append([]string(nil), doc.Spec.RequireApproval.ApprovedValues...)
		}
	} else {
		if elevatedFields.privileged {
			conditions.Privileged = boolPtr(true)
		}
		if elevatedFields.hostNetwork {
			conditions.HostNetwork = boolPtr(true)
		}
		if elevatedFields.hostPID {
			conditions.HostPID = boolPtr(true)
		}
	}
	if doc.Spec.Provenance.RequireSignatureAnnotation != "" {
		conditions.RequireImageSignature = boolPtr(true)
		conditions.SignatureAnnotation = doc.Spec.Provenance.RequireSignatureAnnotation
	}
	if doc.Spec.Containers.RequireReadOnlyRootFilesystem {
		conditions.ReadOnlyRootFS = boolPtr(true)
	}
	if doc.Spec.Containers.RequireNonRoot {
		conditions.RequireNonRoot = boolPtr(true)
	}
	if doc.Spec.Containers.DenyEnvVarSecrets {
		conditions.DenyEnvVarSecrets = boolPtr(true)
	}
	if level := strings.ToLower(strings.TrimSpace(doc.Spec.PodSecurityStandard.Level)); level != "" {
		if level != string(PSSLevelBaseline) && level != string(PSSLevelRestricted) {
			return Rule{}, false, fmt.Errorf("unsupported podSecurityStandard.level %q (want baseline or restricted)", doc.Spec.PodSecurityStandard.Level)
		}
		conditions.PSSLevel = level
	}
	if len(doc.Spec.PersistentVolumeClaim.AllowedStorageClasses) > 0 {
		conditions.AllowedStorageClasses = append([]string(nil), doc.Spec.PersistentVolumeClaim.AllowedStorageClasses...)
	}
	// ADM-26: long-tail resource-limit criterion. Validate any Max* quantity at
	// load time so a malformed threshold surfaces to the operator instead of
	// silently failing open at evaluation.
	rl := doc.Spec.Pod.ResourceLimit
	resourceCond := &ResourceLimitCondition{
		RequireCPURequest:    rl.RequireCPURequest,
		RequireCPULimit:      rl.RequireCPULimit,
		RequireMemoryRequest: rl.RequireMemoryRequest,
		RequireMemoryLimit:   rl.RequireMemoryLimit,
		MaxCPULimit:          strings.TrimSpace(rl.MaxCPULimit),
		MaxMemoryLimit:       strings.TrimSpace(rl.MaxMemoryLimit),
	}
	if resourceCond.MaxCPULimit != "" {
		if _, err := resource.ParseQuantity(resourceCond.MaxCPULimit); err != nil {
			return Rule{}, false, fmt.Errorf("pod.resourceLimit.maxCpuLimit %q is not a valid quantity: %w", resourceCond.MaxCPULimit, err)
		}
	}
	if resourceCond.MaxMemoryLimit != "" {
		if _, err := resource.ParseQuantity(resourceCond.MaxMemoryLimit); err != nil {
			return Rule{}, false, fmt.Errorf("pod.resourceLimit.maxMemoryLimit %q is not a valid quantity: %w", resourceCond.MaxMemoryLimit, err)
		}
	}
	if resourceCond.any() {
		conditions.ResourceLimit = resourceCond
	}
	if v := strings.TrimSpace(doc.Spec.Identity.UserMatch); v != "" {
		// C3: reject an uncompilable identity regex at load time. An invalid
		// pattern would otherwise compile to nil at evaluation and silently never
		// fire (fail open), turning a deny rule into a no-op with no operator
		// signal. UserMatch/GroupMatch are anchored, case-sensitive Go regexes.
		if err := validateIdentityRegex("userMatch", v); err != nil {
			return Rule{}, false, err
		}
		conditions.UserMatch = v
	}
	if v := strings.TrimSpace(doc.Spec.Identity.GroupMatch); v != "" {
		if err := validateIdentityRegex("groupMatch", v); err != nil {
			return Rule{}, false, err
		}
		conditions.GroupMatch = v
	}
	if doc.Spec.Identity.SaBindRiskyRole {
		conditions.SABindRiskyRole = boolPtr(true)
	}
	if doc.Spec.Images.DisallowLatestTag {
		conditions.DisallowLatestTag = boolPtr(true)
	}
	if doc.Spec.Images.DisallowImplicitTag {
		conditions.DisallowImplicitTag = boolPtr(true)
	}
	if doc.Spec.Images.RequireDigest {
		conditions.RequireDigest = boolPtr(true)
	}
	if len(doc.Spec.Images.AllowedRegistries) > 0 {
		conditions.AllowedImageRegistries = append([]string(nil), doc.Spec.Images.AllowedRegistries...)
	}
	scanEvidence, err := admissionScanEvidenceGateFields(doc.Spec.ScanEvidence)
	if err != nil {
		return Rule{}, false, err
	}
	deniedCVEs := normalizeCVEList(doc.Spec.Vulnerability.DeniedCVEs)
	if doc.Spec.Vulnerability.MaxAllowedSeverity != "" ||
		doc.Spec.Vulnerability.MaxCriticalCount != nil ||
		doc.Spec.Vulnerability.MaxHighCount != nil ||
		doc.Spec.Vulnerability.MaxMediumCount != nil ||
		doc.Spec.Vulnerability.MaxCriticalWithFixCount != nil ||
		doc.Spec.Vulnerability.MaxHighWithFixCount != nil ||
		doc.Spec.Vulnerability.MaxCveScoreCount != nil ||
		doc.Spec.Vulnerability.RequireFixAvailable ||
		doc.Spec.Vulnerability.RequireKnownScanResult ||
		len(deniedCVEs) > 0 {
		gate := EvidenceGate{
			Type:                   "vulnerability",
			MaxAllowedSeverity:     strings.ToLower(strings.TrimSpace(doc.Spec.Vulnerability.MaxAllowedSeverity)),
			MaxCriticalCVEs:        doc.Spec.Vulnerability.MaxCriticalCount,
			MaxHighCVEs:            doc.Spec.Vulnerability.MaxHighCount,
			MaxMediumCVEs:          doc.Spec.Vulnerability.MaxMediumCount,
			MaxCriticalWithFixCVEs: doc.Spec.Vulnerability.MaxCriticalWithFixCount,
			MaxHighWithFixCVEs:     doc.Spec.Vulnerability.MaxHighWithFixCount,
			MaxCVEsAtOrAboveScore:  doc.Spec.Vulnerability.MaxCveScoreCount,
			MinCVEScore:            doc.Spec.Vulnerability.CveScore,
			DeniedCVEs:             deniedCVEs,
			RequireKnownScanResult: doc.Spec.Vulnerability.RequireKnownScanResult,
			HonorActiveExceptions:  doc.Spec.Vulnerability.HonorActiveExceptions,
			RequireFixAvailable:    doc.Spec.Vulnerability.RequireFixAvailable,
		}
		// CVE publish-age grace window (A4): a positive value ignores CVEs
		// published within that many days when counting/denying. Non-positive or
		// unset means no grace window.
		if doc.Spec.Vulnerability.CveGraceDays != nil && *doc.Spec.Vulnerability.CveGraceDays > 0 {
			days := *doc.Spec.Vulnerability.CveGraceDays
			gate.CVEGraceDays = &days
		}
		applyScanEvidenceFields(&gate, scanEvidence)
		if doc.Spec.Vulnerability.MaxScanAge != "" {
			seconds, err := parseAdmissionDurationSeconds(doc.Spec.Vulnerability.MaxScanAge, "vulnerability.maxScanAge")
			if err != nil {
				return Rule{}, false, err
			}
			gate.MaxScanAgeSeconds = seconds
		}
		if doc.Spec.Vulnerability.RequireVulnDBBundle {
			gate.RequireVulnDBBundle = true
		}
		if doc.Spec.Vulnerability.CanonicalEngine != "" {
			gate.AllowedCanonicalEngines = normalizeStringList(append(gate.AllowedCanonicalEngines, doc.Spec.Vulnerability.CanonicalEngine))
		}
		if len(doc.Spec.Vulnerability.CanonicalEngines) > 0 {
			gate.AllowedCanonicalEngines = normalizeStringList(append(gate.AllowedCanonicalEngines, doc.Spec.Vulnerability.CanonicalEngines...))
		}
		conditions.EvidenceGates = append(conditions.EvidenceGates, gate)
	}
	if len(doc.Spec.Findings.Kinds) > 0 {
		kinds := make([]string, 0, len(doc.Spec.Findings.Kinds))
		for _, kind := range doc.Spec.Findings.Kinds {
			if trimmed := strings.ToLower(strings.TrimSpace(kind)); trimmed != "" {
				kinds = append(kinds, trimmed)
			}
		}
		if len(kinds) > 0 {
			conditions.EvidenceGates = append(conditions.EvidenceGates, EvidenceGate{
				Type:              "finding",
				FindingKinds:      kinds,
				MinimumSeverity:   strings.ToLower(strings.TrimSpace(doc.Spec.Findings.MinimumSeverity)),
				MinimumConfidence: strings.ToLower(strings.TrimSpace(doc.Spec.Findings.MinimumConfidence)),
			})
			applyScanEvidenceFields(&conditions.EvidenceGates[len(conditions.EvidenceGates)-1], scanEvidence)
		}
	}
	if doc.Spec.ImageArtifacts.Secrets.MaxAllowed != nil {
		gate := EvidenceGate{
			Type:            "artifact",
			Artifact:        "secret",
			MaxAllowedCount: *doc.Spec.ImageArtifacts.Secrets.MaxAllowed,
			MinimumSeverity: strings.ToLower(strings.TrimSpace(doc.Spec.ImageArtifacts.Secrets.MinimumSeverity)),
			FindingKinds:    []string{"secret"},
		}
		applyScanEvidenceFields(&gate, scanEvidence)
		conditions.EvidenceGates = append(conditions.EvidenceGates, gate)
	}
	if doc.Spec.ImageArtifacts.FileRisks.MaxAllowed != nil {
		riskTypes := normalizeStringList(doc.Spec.ImageArtifacts.FileRisks.RiskTypes)
		gate := EvidenceGate{
			Type:            "artifact",
			Artifact:        "file-risk",
			MaxAllowedCount: *doc.Spec.ImageArtifacts.FileRisks.MaxAllowed,
			MinimumSeverity: strings.ToLower(strings.TrimSpace(doc.Spec.ImageArtifacts.FileRisks.MinimumSeverity)),
			FindingKinds:    append([]string{"file-risk"}, riskTypes...),
			RiskTypes:       riskTypes,
		}
		applyScanEvidenceFields(&gate, scanEvidence)
		conditions.EvidenceGates = append(conditions.EvidenceGates, gate)
	}
	if doc.Spec.ImageArtifacts.Signature.RequireTrusted ||
		doc.Spec.ImageArtifacts.Signature.RequireVerifierIdentity ||
		doc.Spec.ImageArtifacts.Signature.RequireKnownScanResult ||
		len(doc.Spec.ImageArtifacts.Signature.AllowedStatuses) > 0 ||
		len(doc.Spec.ImageArtifacts.Signature.AllowedIdentities) > 0 {
		gate := EvidenceGate{
			Type:                      "artifact",
			Artifact:                  "signature",
			RequireKnownScanResult:    doc.Spec.ImageArtifacts.Signature.RequireKnownScanResult,
			RequireTrustedSignature:   doc.Spec.ImageArtifacts.Signature.RequireTrusted,
			RequireVerifierIdentity:   doc.Spec.ImageArtifacts.Signature.RequireVerifierIdentity,
			AllowedSignatureStatuses:  normalizeStringList(doc.Spec.ImageArtifacts.Signature.AllowedStatuses),
			FindingKinds:              []string{"signature"},
			AllowedVerifierIdentities: normalizeStringList(doc.Spec.ImageArtifacts.Signature.AllowedIdentities),
		}
		applyScanEvidenceFields(&gate, scanEvidence)
		conditions.EvidenceGates = append(conditions.EvidenceGates, gate)
	}

	if !hasSupportedConditions(conditions) {
		return Rule{}, false, nil
	}
	rule.Conditions = conditions
	return rule, true, nil
}

func admissionScanEvidenceGateFields(source admissionRuleScanEvidence) (EvidenceGate, error) {
	var out EvidenceGate
	if source.MaxAge != "" {
		seconds, err := parseAdmissionDurationSeconds(source.MaxAge, "scanEvidence.maxAge")
		if err != nil {
			return EvidenceGate{}, err
		}
		out.MaxScanAgeSeconds = seconds
	}
	out.RequireVulnDBBundle = source.RequireVulnDBBundle
	out.AllowedSourceTypes = normalizeStringList(source.SourceTypes)
	if source.SourceType != "" {
		out.AllowedSourceTypes = normalizeStringList(append(out.AllowedSourceTypes, source.SourceType))
	}
	out.RequireDigestMatch = source.RequireDigestMatch
	out.RequireTrustedAttestation = source.RequireTrustedAttestation
	out.AttestationPredicateTypes = normalizeStringList(source.AttestationPredicateTypes)
	if source.AttestationPredicateType != "" {
		out.AttestationPredicateTypes = normalizeStringList(append(out.AttestationPredicateTypes, source.AttestationPredicateType))
	}
	out.AllowedAttestationIdentities = normalizeStringList(source.AllowedAttestationIdentities)
	out.AllowedAttestationIssuers = normalizeStringList(source.AllowedAttestationIssuers)
	out.AllowedCanonicalEngines = normalizeStringList(source.CanonicalEngines)
	if source.CanonicalEngine != "" {
		out.AllowedCanonicalEngines = normalizeStringList(append(out.AllowedCanonicalEngines, source.CanonicalEngine))
	}
	return out, nil
}

func applyScanEvidenceFields(gate *EvidenceGate, source EvidenceGate) {
	if source.MaxScanAgeSeconds > 0 && gate.MaxScanAgeSeconds == 0 {
		gate.MaxScanAgeSeconds = source.MaxScanAgeSeconds
	}
	if source.RequireVulnDBBundle {
		gate.RequireVulnDBBundle = true
	}
	if len(source.AllowedSourceTypes) > 0 {
		gate.AllowedSourceTypes = normalizeStringList(append(gate.AllowedSourceTypes, source.AllowedSourceTypes...))
	}
	if source.RequireDigestMatch {
		gate.RequireDigestMatch = true
	}
	if source.RequireTrustedAttestation {
		gate.RequireTrustedAttestation = true
	}
	if len(source.AttestationPredicateTypes) > 0 {
		gate.AttestationPredicateTypes = normalizeStringList(append(gate.AttestationPredicateTypes, source.AttestationPredicateTypes...))
	}
	if len(source.AllowedAttestationIdentities) > 0 {
		gate.AllowedAttestationIdentities = normalizeStringList(append(gate.AllowedAttestationIdentities, source.AllowedAttestationIdentities...))
	}
	if len(source.AllowedAttestationIssuers) > 0 {
		gate.AllowedAttestationIssuers = normalizeStringList(append(gate.AllowedAttestationIssuers, source.AllowedAttestationIssuers...))
	}
	if len(source.AllowedCanonicalEngines) > 0 {
		gate.AllowedCanonicalEngines = normalizeStringList(append(gate.AllowedCanonicalEngines, source.AllowedCanonicalEngines...))
	}
}

func parseAdmissionDurationSeconds(value, field string) (int64, error) {
	duration, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration such as 24h", field)
	}
	return int64(duration / time.Second), nil
}

type admissionElevatedFields struct {
	privileged  bool
	hostNetwork bool
	hostPID     bool
}

func (f admissionElevatedFields) any() bool {
	return f.privileged || f.hostNetwork || f.hostPID
}

func validAdmissionMode(mode string) bool {
	return mode == "" || mode == "monitor" || mode == "enforce"
}

// admissionEffectFromAction maps the spec.action field to a rule Effect.
// "deny" (or empty) is the historical default; "allow"/"except"/"exception"
// select the P1-3 carve-out effect that takes precedence over deny rules.
func admissionEffectFromAction(action string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "deny":
		return EffectDeny, nil
	case "allow", "except", "exception":
		return EffectAllow, nil
	default:
		return "", fmt.Errorf("unsupported admission rule action %q (want deny, allow, or except)", action)
	}
}

func conditionEqualsTrue(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

func normalizeFieldPath(field string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(field), " ", ""))
}

// normalizeCVEList upper-cases and de-duplicates CVE ids so the named-CVE deny
// list (A3) matches image scan finding external_ids case-insensitively. CVE ids
// are conventionally upper-case (e.g. "CVE-2026-1234").
func normalizeCVEList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToUpper(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normalizeStringList(values []string) []string {
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func hasSupportedConditions(c RuleConditions) bool {
	return c.Privileged != nil ||
		c.HostNetwork != nil ||
		c.HostPID != nil ||
		c.HostIPC != nil ||
		c.AllowPrivilegeEscalation != nil ||
		c.ImageNoOS != nil ||
		c.ResourceLimit.any() ||
		c.ReadOnlyRootFS != nil ||
		c.RequireImageSignature != nil ||
		c.RequireNonRoot != nil ||
		c.DisallowLatestTag != nil ||
		c.DisallowImplicitTag != nil ||
		c.RequireDigest != nil ||
		c.RequirePrivilegedApproval != nil ||
		c.DenyEnvVarSecrets != nil ||
		c.PSSLevel != "" ||
		c.UserMatch != "" ||
		c.GroupMatch != "" ||
		c.SABindRiskyRole != nil ||
		len(c.AllowedImageRegistries) > 0 ||
		len(c.AllowedStorageClasses) > 0 ||
		len(c.EvidenceGates) > 0
}

func boolPtr(v bool) *bool {
	return &v
}
