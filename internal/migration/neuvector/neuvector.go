// Package neuvector migrates a NeuVector export (admission rules + response rules) into
// Constellation policy + accept-risk records.
//
// NeuVector exports policies via the REST API `/v1/policy/<id>` or the GUI's
// "Export Settings" → YAML. We accept either; the YAML is a dict-of-arrays per kind:
//
//	admission:
//	  rules:
//	    - id: 1001
//	      criteria:
//	        - key: image_name
//	          op: regex
//	          value: ".*:latest$"
//	      action: deny
//	      desc: Block latest tag
//
//	response:
//	  rules:
//	    - id: 2001
//	      event: process
//	      conditions:
//	        - type: process_baseline
//	      actions: [alert, quarantine]
package neuvector

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/alphabravocompany/constellation/pkg/admission"
	"gopkg.in/yaml.v3"
)

// SourceExport is the subset of NeuVector's settings export we read.
type SourceExport struct {
	Admission    AdmissionSection         `yaml:"admission" json:"admission"`
	Response     ResponseSection          `yaml:"response"  json:"response"`
	FileMonitor  FileMonitorSection       `yaml:"file_monitor" json:"file_monitor"`
	FileProfiles []FileMonitorProfile     `yaml:"file_profiles" json:"file_profiles"`
	Profile      *FileMonitorProfile      `yaml:"profile" json:"profile"`
	Profiles     []FileMonitorProfile     `yaml:"profiles" json:"profiles"`
	Items        []NvSecurityRuleDocument `yaml:"items" json:"items"`
	Kind         string                   `yaml:"kind" json:"kind"`
	Metadata     ObjectMetadata           `yaml:"metadata" json:"metadata"`
	Spec         NvSecurityRuleSpec       `yaml:"spec" json:"spec"`
}

type AdmissionSection struct {
	Rules []AdmissionRule `yaml:"rules" json:"rules"`
}

type AdmissionRule struct {
	ID       int                  `yaml:"id"        json:"id"`
	Desc     string               `yaml:"desc"      json:"desc"`
	Criteria []AdmissionCriterion `yaml:"criteria"  json:"criteria"`
	Action   string               `yaml:"action"    json:"action"` // allow | deny
	Disabled bool                 `yaml:"disabled"  json:"disabled"`
}

type AdmissionCriterion struct {
	Key   string `yaml:"key"   json:"key"`
	Op    string `yaml:"op"    json:"op"` // regex | eq | contains
	Value string `yaml:"value" json:"value"`
}

type ResponseSection struct {
	Rules []ResponseRule `yaml:"rules" json:"rules"`
}

type ResponseRule struct {
	ID         int      `yaml:"id"         json:"id"`
	Event      string   `yaml:"event"      json:"event"`
	Conditions []string `yaml:"conditions" json:"conditions"`
	Actions    []string `yaml:"actions"    json:"actions"`
	Disabled   bool     `yaml:"disabled"   json:"disabled"`
}

type FileMonitorSection struct {
	Profile  *FileMonitorProfile  `yaml:"profile" json:"profile"`
	Profiles []FileMonitorProfile `yaml:"profiles" json:"profiles"`
	Rules    []FileMonitorRule    `yaml:"rules" json:"rules"`
}

type FileMonitorProfile struct {
	Group       string            `yaml:"group" json:"group"`
	Name        string            `yaml:"name" json:"name"`
	Mode        string            `yaml:"mode" json:"mode"`
	CfgType     string            `yaml:"cfg_type" json:"cfg_type"`
	Description string            `yaml:"description" json:"description"`
	Filters     []FileMonitorRule `yaml:"filters" json:"filters"`
	Rules       []FileMonitorRule `yaml:"rules" json:"rules"`
}

type FileMonitorRule struct {
	Filter       string   `yaml:"filter" json:"filter"`
	Recursive    bool     `yaml:"recursive" json:"recursive"`
	Behavior     string   `yaml:"behavior" json:"behavior"`
	Applications []string `yaml:"applications" json:"applications"`
	App          []string `yaml:"app" json:"app"`
	Group        string   `yaml:"group" json:"group"`
	CfgType      string   `yaml:"cfg_type" json:"cfg_type"`
	Disabled     bool     `yaml:"disabled" json:"disabled"`
}

type ObjectMetadata struct {
	Name      string `yaml:"name" json:"name"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

type NvSecurityRuleDocument struct {
	Kind     string             `yaml:"kind" json:"kind"`
	Metadata ObjectMetadata     `yaml:"metadata" json:"metadata"`
	Spec     NvSecurityRuleSpec `yaml:"spec" json:"spec"`
}

type NvSecurityRuleSpec struct {
	Target         NvSecurityTarget          `yaml:"target" json:"target"`
	ProcessProfile *NvSecurityProcessProfile `yaml:"process_profile" json:"process_profile"`
	FileRule       []FileMonitorRule         `yaml:"file" json:"file"`
}

type NvSecurityTarget struct {
	PolicyMode *string     `yaml:"policymode" json:"policymode"`
	Selector   GroupConfig `yaml:"selector" json:"selector"`
}

type GroupConfig struct {
	OriginalName string `yaml:"original_name" json:"original_name"`
	Name         string `yaml:"name" json:"name"`
	Comment      string `yaml:"comment" json:"comment"`
}

type NvSecurityProcessProfile struct {
	Mode *string `yaml:"mode" json:"mode"`
}

// TargetPolicy mirrors the migration/stackrox shape so the persistence layer is shared.
type TargetPolicy struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Engine      string            `json:"engine"`
	Category    string            `json:"category"`
	Enabled     bool              `json:"enabled"`
	Mode        string            `json:"mode"`
	SpecYAML    string            `json:"spec_yaml"`
	Imported    map[string]string `json:"imported_from,omitempty"`
}

type TargetFileProfile struct {
	Group       string                  `json:"group"`
	Mode        string                  `json:"mode"`
	CfgType     string                  `json:"cfg_type,omitempty"`
	Description string                  `json:"description,omitempty"`
	Rules       []TargetFileProfileRule `json:"rules"`
	Imported    map[string]string       `json:"imported_from,omitempty"`
}

type TargetFileProfileRule struct {
	Filter       string   `json:"filter"`
	Recursive    bool     `json:"recursive"`
	Behavior     string   `json:"behavior"`
	Applications []string `json:"applications"`
	Enabled      bool     `json:"enabled"`
	SourceGroup  string   `json:"source_group,omitempty"`
	CfgType      string   `json:"cfg_type,omitempty"`
}

// Convert parses a NeuVector export and returns Constellation TargetPolicy rows.
func Convert(raw []byte) ([]TargetPolicy, error) {
	doc, err := parseSourceExport(raw)
	if err != nil {
		return nil, err
	}

	out := []TargetPolicy{}
	for _, r := range doc.Admission.Rules {
		// Use the parity-correct admission profile translation: it walks the full
		// Criteria list (not just Criteria[0]), emits real constellation-admission
		// rules for supported criteria, and routes unsupported criteria to a
		// disabled manual-review rule instead of a no-op enforce Kyverno policy.
		for _, pr := range translateAdmissionProfileRules(r) {
			out = append(out, admissionProfileRuleToTargetPolicy(r, pr))
		}
	}
	for _, r := range doc.Response.Rules {
		out = append(out, translateResponse(r))
	}
	return out, nil
}

// admissionProfileRuleToTargetPolicy adapts a parity-correct AdmissionProfileRule
// into the migration TargetPolicy shape the preview handler consumes.
func admissionProfileRuleToTargetPolicy(r AdmissionRule, pr admission.AdmissionProfileRule) TargetPolicy {
	return TargetPolicy{
		Name:        pr.Name,
		Description: pr.Description,
		Engine:      pr.Engine,
		Category:    pr.Category,
		Enabled:     pr.Enabled,
		Mode:        pr.Mode,
		SpecYAML:    pr.SpecYAML,
		Imported:    map[string]string{"source": "neuvector", "source_id": fmt.Sprintf("%d", r.ID)},
	}
}

// ConvertFileProfiles parses NeuVector REST file monitor exports and
// NvSecurityRule CRD YAML into first-class Constellation file profile targets.
func ConvertFileProfiles(raw []byte) ([]TargetFileProfile, error) {
	docs, err := parseSourceExports(raw)
	if err != nil {
		return nil, err
	}
	profiles := []FileMonitorProfile{}
	for _, doc := range docs {
		profiles = append(profiles, collectFileProfiles(doc)...)
	}
	if len(profiles) == 0 {
		return nil, nil
	}
	out := make([]TargetFileProfile, 0, len(profiles))
	for _, profile := range profiles {
		converted := translateFileProfile(profile)
		if len(converted.Rules) == 0 {
			continue
		}
		out = append(out, converted)
	}
	return out, nil
}

// ConvertAdmissionProfileBundle parses NeuVector admission rules into the
// first-class Constellation admission profile bundle format. Locally
// enforceable criteria are emitted as constellation-admission rules. Criteria
// that do not have a supported Constellation admission analogue are retained as
// disabled manual-review rules so migration parity tests can prove no
// NeuVector rule intent is lost.
func ConvertAdmissionProfileBundle(raw []byte) (admission.AdmissionProfileBundle, error) {
	doc, err := parseSourceExport(raw)
	if err != nil {
		return admission.AdmissionProfileBundle{}, err
	}
	rules := make([]admission.AdmissionProfileRule, 0, len(doc.Admission.Rules))
	for _, r := range doc.Admission.Rules {
		rules = append(rules, translateAdmissionProfileRules(r)...)
	}
	if len(rules) == 0 {
		return admission.AdmissionProfileBundle{}, errors.New("neuvector: export contains no admission rules")
	}

	profile := admission.AdmissionProfile{
		ID:            "neuvector-import",
		Name:          "NeuVector admission import",
		Description:   "Admission rules converted from a NeuVector settings export. Unsupported criteria are retained as disabled manual-review rules.",
		FailurePolicy: admissionProfileFailurePolicy(rules),
		NamespaceSelector: map[string]any{
			"matchLabels": map[string]string{"constellation.alphabravo.io/migrated-admission": "neuvector"},
		},
		Rules: rules,
	}
	return admission.AdmissionProfileBundleFor(profile), nil
}

func parseSourceExport(raw []byte) (SourceExport, error) {
	if len(raw) == 0 {
		return SourceExport{}, errors.New("neuvector: empty export")
	}
	var doc SourceExport
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return SourceExport{}, fmt.Errorf("neuvector: parse: %w", err)
	}
	return doc, nil
}

func parseSourceExports(raw []byte) ([]SourceExport, error) {
	if len(raw) == 0 {
		return nil, errors.New("neuvector: empty export")
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	out := []SourceExport{}
	for {
		var doc SourceExport
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("neuvector: parse: %w", err)
		}
		if sourceExportEmpty(doc) {
			continue
		}
		out = append(out, doc)
	}
	if len(out) == 0 {
		return nil, errors.New("neuvector: empty export")
	}
	return out, nil
}

func sourceExportEmpty(doc SourceExport) bool {
	return len(doc.Admission.Rules) == 0 &&
		len(doc.Response.Rules) == 0 &&
		doc.FileMonitor.Profile == nil &&
		len(doc.FileMonitor.Profiles) == 0 &&
		len(doc.FileMonitor.Rules) == 0 &&
		len(doc.FileProfiles) == 0 &&
		doc.Profile == nil &&
		len(doc.Profiles) == 0 &&
		len(doc.Items) == 0 &&
		strings.TrimSpace(doc.Kind) == "" &&
		len(doc.Spec.FileRule) == 0
}

func translateResponse(r ResponseRule) TargetPolicy {
	enforces := false
	for _, a := range r.Actions {
		if a == "quarantine" || a == "block" {
			enforces = true
		}
	}
	mode := "monitor"
	if enforces {
		mode = "enforce"
	}
	return TargetPolicy{
		Name:        fmt.Sprintf("nv-response-%d", r.ID),
		Description: fmt.Sprintf("NeuVector response rule (event=%s)", r.Event),
		Engine:      "constellation-builtin",
		Category:    "runtime",
		Enabled:     !r.Disabled,
		Mode:        mode,
		SpecYAML:    emitResponseRule(r),
		Imported:    map[string]string{"source": "neuvector", "source_id": fmt.Sprintf("%d", r.ID)},
	}
}

func collectFileProfiles(doc SourceExport) []FileMonitorProfile {
	out := []FileMonitorProfile{}
	add := func(profile FileMonitorProfile) {
		if len(profile.Filters) == 0 && len(profile.Rules) == 0 {
			return
		}
		out = append(out, profile)
	}
	if doc.FileMonitor.Profile != nil {
		add(*doc.FileMonitor.Profile)
	}
	for _, profile := range doc.FileMonitor.Profiles {
		add(profile)
	}
	if len(doc.FileMonitor.Rules) > 0 {
		add(FileMonitorProfile{Group: "neuvector-file-monitor", Rules: doc.FileMonitor.Rules})
	}
	if doc.Profile != nil {
		add(*doc.Profile)
	}
	for _, profile := range doc.FileProfiles {
		add(profile)
	}
	for _, profile := range doc.Profiles {
		add(profile)
	}
	if len(doc.Spec.FileRule) > 0 {
		add(fileProfileFromNvSecurityRule(NvSecurityRuleDocument{
			Kind:     doc.Kind,
			Metadata: doc.Metadata,
			Spec:     doc.Spec,
		}))
	}
	for _, item := range doc.Items {
		if len(item.Spec.FileRule) > 0 {
			add(fileProfileFromNvSecurityRule(item))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return fileProfileGroup(out[i]) < fileProfileGroup(out[j])
	})
	return out
}

func fileProfileFromNvSecurityRule(doc NvSecurityRuleDocument) FileMonitorProfile {
	group := strings.TrimSpace(doc.Spec.Target.Selector.Name)
	if group == "" {
		group = strings.TrimSpace(doc.Spec.Target.Selector.OriginalName)
	}
	if group == "" {
		group = strings.TrimSpace(doc.Metadata.Name)
	}
	mode := ""
	if doc.Spec.ProcessProfile != nil && doc.Spec.ProcessProfile.Mode != nil {
		mode = *doc.Spec.ProcessProfile.Mode
	}
	if mode == "" && doc.Spec.Target.PolicyMode != nil {
		mode = *doc.Spec.Target.PolicyMode
	}
	return FileMonitorProfile{
		Group:       group,
		Name:        doc.Metadata.Name,
		Mode:        mode,
		Description: "",
		Filters:     append([]FileMonitorRule(nil), doc.Spec.FileRule...),
	}
}

func translateFileProfile(profile FileMonitorProfile) TargetFileProfile {
	group := fileProfileGroup(profile)
	rules := fileProfileRules(profile)
	converted := make([]TargetFileProfileRule, 0, len(rules))
	seen := map[string]int{}
	for _, rule := range rules {
		filter := strings.TrimSpace(rule.Filter)
		if filter == "" {
			continue
		}
		behavior := normalizeFileBehavior(rule.Behavior)
		apps := normalizeStrings(append(append([]string{}, rule.Applications...), rule.App...))
		cfgType := strings.TrimSpace(rule.CfgType)
		if cfgType == "" {
			cfgType = strings.TrimSpace(profile.CfgType)
		}
		target := TargetFileProfileRule{
			Filter:       filter,
			Recursive:    rule.Recursive,
			Behavior:     behavior,
			Applications: apps,
			Enabled:      !rule.Disabled,
			SourceGroup:  firstNonEmpty(rule.Group, group),
			CfgType:      cfgType,
		}
		if idx, ok := seen[filter]; ok {
			converted[idx] = mergeFileProfileRule(converted[idx], target)
			continue
		}
		seen[filter] = len(converted)
		converted = append(converted, target)
	}
	sort.SliceStable(converted, func(i, j int) bool {
		return converted[i].Filter < converted[j].Filter
	})
	return TargetFileProfile{
		Group:       group,
		Mode:        normalizeFileProfileMode(profile.Mode),
		CfgType:     strings.TrimSpace(profile.CfgType),
		Description: fmt.Sprintf("NeuVector file monitor profile %s", group),
		Rules:       converted,
		Imported:    map[string]string{"source": "neuvector", "source_id": group},
	}
}

func fileProfileGroup(profile FileMonitorProfile) string {
	return firstNonEmpty(profile.Group, profile.Name, "neuvector-file-monitor")
}

func fileProfileRules(profile FileMonitorProfile) []FileMonitorRule {
	out := make([]FileMonitorRule, 0, len(profile.Filters)+len(profile.Rules))
	out = append(out, profile.Filters...)
	out = append(out, profile.Rules...)
	return out
}

func mergeFileProfileRule(base, next TargetFileProfileRule) TargetFileProfileRule {
	base.Applications = normalizeStrings(append(base.Applications, next.Applications...))
	if next.Behavior == "block_access" {
		base.Behavior = next.Behavior
	}
	if next.Recursive {
		base.Recursive = true
	}
	if !next.Enabled {
		base.Enabled = false
	}
	if base.CfgType == "" {
		base.CfgType = next.CfgType
	}
	if base.SourceGroup == "" {
		base.SourceGroup = next.SourceGroup
	}
	return base
}

func normalizeFileBehavior(behavior string) string {
	switch strings.ToLower(strings.TrimSpace(behavior)) {
	case "block_access", "block", "deny":
		return "block_access"
	default:
		return "monitor_change"
	}
}

func normalizeFileProfileMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "learn", "learning", "discover", "discovery":
		return "learn"
	case "protect", "enforce", "enforced":
		return "enforce"
	default:
		return "monitor"
	}
}

func normalizeStrings(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

type convertedAdmissionCriteria struct {
	privileged          bool
	hostNetwork         bool
	hostPID             bool
	requireReadOnlyRoot bool
	requireNonRoot      bool
	disallowLatestTag   bool
	disallowImplicitTag bool
	requireDigest       bool
	requireSignature    bool
	allowedRegistries   []string
	vulnerabilityGate   string
	secretGate          bool
	misconfigGate       string
}

func translateAdmissionProfileRules(r AdmissionRule) []admission.AdmissionProfileRule {
	converted := convertedAdmissionCriteria{}
	unsupported := make([]AdmissionCriterion, 0)
	for _, c := range r.Criteria {
		if !converted.add(c) {
			unsupported = append(unsupported, c)
		}
	}

	out := []admission.AdmissionProfileRule{}
	if converted.any() {
		name := profileRuleName(r, "")
		out = append(out, admission.AdmissionProfileRule{
			Name:        name,
			Description: profileRuleDescription(r, ""),
			Engine:      "constellation-admission",
			Category:    converted.category(),
			Mode:        admissionRuleMode(r),
			Enabled:     !r.Disabled,
			SpecYAML:    emitAdmissionProfileRuleYAML(r, converted, name),
		})
	}
	if len(unsupported) > 0 || !converted.any() {
		reviewCriteria := unsupported
		if len(reviewCriteria) == 0 {
			reviewCriteria = r.Criteria
		}
		out = append(out, manualReviewAdmissionProfileRule(r, reviewCriteria))
	}
	return out
}

func (c *convertedAdmissionCriteria) add(crit AdmissionCriterion) bool {
	key := normalizeNeuVectorKey(crit.Key)
	value := strings.ToLower(strings.TrimSpace(crit.Value))

	switch {
	case key == "privileged" || key == "privilegedcontainer" || key == "containerprivileged":
		if criterionBoolTrue(crit) {
			c.privileged = true
			return true
		}
	case key == "hostnetwork" || key == "hostnetworking":
		if criterionBoolTrue(crit) {
			c.hostNetwork = true
			return true
		}
	case key == "hostpid":
		if criterionBoolTrue(crit) {
			c.hostPID = true
			return true
		}
	case key == "readonlyrootfs" || key == "readonlyrootfilesystem" || key == "rootfilesystemreadonly":
		if criterionBoolFalse(crit) || criterionBoolTrue(crit) {
			c.requireReadOnlyRoot = true
			return true
		}
	case key == "runasroot" || key == "runasuser" || key == "rootuser":
		if value == "" || value == "0" || value == "root" || criterionBoolTrue(crit) {
			c.requireNonRoot = true
			return true
		}
	case key == "image" || key == "imagename" || key == "imagetag" || key == "tag":
		if criterionReferencesLatest(crit) {
			c.disallowLatestTag = true
			return true
		}
	case key == "implicitimagetag" || key == "missingimagetag":
		if criterionBoolTrue(crit) {
			c.disallowImplicitTag = true
			return true
		}
	case key == "imagedigest" || key == "digest" || key == "missingdigest" || key == "unpinnedimage":
		if key == "missingdigest" || key == "unpinnedimage" || criterionBoolFalse(crit) {
			c.requireDigest = true
			return true
		}
	case key == "imagesigned" || key == "imagesignature" || key == "signature" || key == "signed":
		if criterionBoolFalse(crit) || strings.Contains(value, "unsigned") {
			c.requireSignature = true
			return true
		}
	case key == "registry" || key == "imageregistry":
		if strings.TrimSpace(crit.Value) != "" && !looksLikeRegex(crit.Value) {
			c.allowedRegistries = append(c.allowedRegistries, strings.TrimSpace(crit.Value))
			return true
		}
	case key == "severity" || key == "vulnerability" || key == "vulnerabilities" || key == "imagescanresult" || key == "scanresult" || key == "cve":
		if severity := maxAllowedSeverityForBlockedValue(crit.Value); severity != "" {
			c.vulnerabilityGate = severity
			return true
		}
	case strings.Contains(key, "criticalvuln") || strings.Contains(key, "criticalcve"):
		c.vulnerabilityGate = "high"
		return true
	case strings.Contains(key, "highvuln") || strings.Contains(key, "highcve"):
		c.vulnerabilityGate = "medium"
		return true
	case strings.Contains(key, "secret"):
		c.secretGate = true
		return true
	case strings.Contains(key, "misconfig") || strings.Contains(key, "compliance"):
		if severity := maxAllowedSeverityForBlockedValue(crit.Value); severity != "" {
			c.misconfigGate = severity
		} else {
			c.misconfigGate = "high"
		}
		return true
	}
	return false
}

func (c convertedAdmissionCriteria) any() bool {
	return c.privileged ||
		c.hostNetwork ||
		c.hostPID ||
		c.requireReadOnlyRoot ||
		c.requireNonRoot ||
		c.disallowLatestTag ||
		c.disallowImplicitTag ||
		c.requireDigest ||
		c.requireSignature ||
		len(c.allowedRegistries) > 0 ||
		c.vulnerabilityGate != "" ||
		c.secretGate ||
		c.misconfigGate != ""
}

func (c convertedAdmissionCriteria) category() string {
	switch {
	case c.vulnerabilityGate != "":
		return "vulnerability-gating"
	case c.secretGate:
		return "secrets"
	case c.misconfigGate != "":
		return "misconfiguration"
	case c.requireSignature || c.requireDigest:
		return "signature-verification"
	default:
		return "admission"
	}
}

func emitAdmissionProfileRuleYAML(r AdmissionRule, c convertedAdmissionCriteria, name string) string {
	spec := map[string]any{
		"match":  map[string]any{"kinds": []string{"Pod"}},
		"action": "deny",
	}
	conditions := []map[string]any{}
	if c.privileged {
		conditions = append(conditions,
			map[string]any{"field": "spec.containers[*].securityContext.privileged", "equals": true},
			map[string]any{"field": "spec.initContainers[*].securityContext.privileged", "equals": true},
			map[string]any{"field": "spec.ephemeralContainers[*].securityContext.privileged", "equals": true},
		)
	}
	if c.hostNetwork {
		conditions = append(conditions, map[string]any{"field": "spec.hostNetwork", "equals": true})
	}
	if c.hostPID {
		conditions = append(conditions, map[string]any{"field": "spec.hostPID", "equals": true})
	}
	if len(conditions) > 0 {
		spec["conditions"] = map[string]any{"any": conditions}
	}
	containerSpec := map[string]any{}
	if c.requireReadOnlyRoot {
		containerSpec["requireReadOnlyRootFilesystem"] = true
	}
	if c.requireNonRoot {
		containerSpec["requireNonRoot"] = true
	}
	if len(containerSpec) > 0 {
		spec["containers"] = containerSpec
	}
	imageSpec := map[string]any{}
	if c.disallowLatestTag {
		imageSpec["disallowLatestTag"] = true
	}
	if c.disallowImplicitTag {
		imageSpec["disallowImplicitTag"] = true
	}
	if c.requireDigest {
		imageSpec["requireDigest"] = true
	}
	if len(c.allowedRegistries) > 0 {
		imageSpec["allowedRegistries"] = append([]string(nil), c.allowedRegistries...)
	}
	if len(imageSpec) > 0 {
		spec["images"] = imageSpec
	}
	if c.requireSignature {
		spec["provenance"] = map[string]any{"requireSignatureAnnotation": admission.SignatureAnnotation}
	}
	if c.vulnerabilityGate != "" {
		spec["vulnerability"] = map[string]any{
			"maxAllowedSeverity":      c.vulnerabilityGate,
			"requireKnownScanResult":  true,
			"honorActiveExceptions":   true,
			"source":                  "neuvector-import",
			"requiresEvidenceBackend": true,
		}
	}
	findings := []string{}
	if c.secretGate {
		findings = append(findings, "secret")
	}
	if c.misconfigGate != "" {
		findings = append(findings, "misconfiguration")
	}
	if len(findings) > 0 {
		findingSpec := map[string]any{"kinds": findings}
		if c.misconfigGate != "" {
			findingSpec["minimumSeverity"] = c.misconfigGate
		}
		if c.secretGate {
			findingSpec["minimumConfidence"] = "high"
		}
		spec["findings"] = findingSpec
	}

	doc := map[string]any{
		"apiVersion": admission.AdmissionProfileAPIVersion,
		"kind":       "AdmissionRule",
		"metadata": map[string]any{
			"name": name,
			"annotations": map[string]string{
				"constellation.alphabravo.io/imported-from": "neuvector",
				"constellation.alphabravo.io/imported-id":   fmt.Sprintf("%d", r.ID),
			},
		},
		"spec": spec,
	}
	b, _ := yaml.Marshal(doc)
	return string(b)
}

func manualReviewAdmissionProfileRule(r AdmissionRule, criteria []AdmissionCriterion) admission.AdmissionProfileRule {
	name := profileRuleName(r, "manual-review")
	criteriaYAML := make([]map[string]string, 0, len(criteria))
	for _, c := range criteria {
		criteriaYAML = append(criteriaYAML, map[string]string{
			"key":   c.Key,
			"op":    c.Op,
			"value": c.Value,
		})
	}
	doc := map[string]any{
		"apiVersion": admission.AdmissionProfileAPIVersion,
		"kind":       "AdmissionMigrationReview",
		"metadata": map[string]any{
			"name": name,
			"annotations": map[string]string{
				"constellation.alphabravo.io/imported-from": "neuvector",
				"constellation.alphabravo.io/imported-id":   fmt.Sprintf("%d", r.ID),
			},
		},
		"spec": map[string]any{
			"source":   "neuvector",
			"sourceID": fmt.Sprintf("%d", r.ID),
			"criteria": criteriaYAML,
			"reason":   "criterion requires manual mapping before live admission enforcement",
		},
	}
	b, _ := yaml.Marshal(doc)
	return admission.AdmissionProfileRule{
		Name:        name,
		Description: profileRuleDescription(r, "manual review required for unsupported NeuVector admission criteria"),
		Engine:      "manual-review",
		Category:    "admission-migration",
		Mode:        "monitor",
		Enabled:     false,
		SpecYAML:    string(b),
	}
}

func admissionProfileFailurePolicy(rules []admission.AdmissionProfileRule) string {
	for _, rule := range rules {
		if rule.Enabled && rule.Mode == "enforce" && rule.Engine == "constellation-admission" {
			return "Fail"
		}
	}
	return "Ignore"
}

func admissionRuleMode(r AdmissionRule) string {
	if r.Action == "allow" || r.Disabled {
		return "monitor"
	}
	return "enforce"
}

func profileRuleName(r AdmissionRule, suffix string) string {
	base := fmt.Sprintf("nv-admission-%d", r.ID)
	if r.Desc != "" {
		base = fmt.Sprintf("nv-%d-%s", r.ID, slug(r.Desc))
	}
	if suffix != "" {
		return base + "-" + suffix
	}
	return base
}

func profileRuleDescription(r AdmissionRule, note string) string {
	desc := strings.TrimSpace(r.Desc)
	if desc == "" {
		desc = fmt.Sprintf("NeuVector admission rule %d", r.ID)
	}
	if note == "" {
		return desc
	}
	return desc + " (" + note + ")"
}

func normalizeNeuVectorKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	replacer := strings.NewReplacer("_", "", "-", "", " ", "", ".", "")
	return replacer.Replace(s)
}

func criterionBoolTrue(c AdmissionCriterion) bool {
	switch strings.ToLower(strings.TrimSpace(c.Value)) {
	case "", "true", "1", "yes", "enabled", "on":
		return true
	default:
		return false
	}
}

func criterionBoolFalse(c AdmissionCriterion) bool {
	switch strings.ToLower(strings.TrimSpace(c.Value)) {
	case "false", "0", "no", "disabled", "off":
		return true
	default:
		return false
	}
}

func criterionReferencesLatest(c AdmissionCriterion) bool {
	value := strings.ToLower(strings.TrimSpace(c.Value))
	return value == "latest" ||
		strings.Contains(value, ":latest") ||
		strings.Contains(value, "latest$") ||
		strings.Contains(value, "tag=latest")
}

func maxAllowedSeverityForBlockedValue(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	switch {
	case strings.Contains(v, "critical"):
		return "high"
	case strings.Contains(v, "high"):
		return "medium"
	case strings.Contains(v, "medium"):
		return "low"
	default:
		return ""
	}
}

func looksLikeRegex(value string) bool {
	return strings.ContainsAny(value, ".*+?[]()|^$")
}

func emitResponseRule(r ResponseRule) string {
	rule := map[string]any{
		"apiVersion": "constellation.alphabravo.io/v1",
		"kind":       "BuiltinRule",
		"metadata":   map[string]string{"name": fmt.Sprintf("nv-response-%d", r.ID), "imported.from": "neuvector"},
		"spec": map[string]any{
			"kind":       "runtime-rule",
			"event":      r.Event,
			"conditions": r.Conditions,
			"actions":    r.Actions,
		},
	}
	b, _ := yaml.Marshal(rule)
	return string(b)
}

func slug(s string) string {
	s = strings.ToLower(s)
	out := make([]byte, 0, len(s))
	prevDash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
			prevDash = false
		default:
			if !prevDash {
				out = append(out, '-')
				prevDash = true
			}
		}
	}
	return strings.Trim(string(out), "-")
}
