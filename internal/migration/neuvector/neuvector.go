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
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/alphabravocompany/constellation/pkg/admission"
	"gopkg.in/yaml.v3"
)

// SourceExport is the subset of NeuVector's settings export we read.
type SourceExport struct {
	Admission       AdmissionSection         `yaml:"admission" json:"admission"`
	Rules           []AdmissionRule          `yaml:"rules" json:"rules"`
	Rule            *AdmissionRule           `yaml:"rule" json:"rule"`
	Response        ResponseSection          `yaml:"response"  json:"response"`
	FileMonitor     FileMonitorSection       `yaml:"file_monitor" json:"file_monitor"`
	FileProfiles    []FileMonitorProfile     `yaml:"file_profiles" json:"file_profiles"`
	Profile         *FileMonitorProfile      `yaml:"profile" json:"profile"`
	Profiles        []FileMonitorProfile     `yaml:"profiles" json:"profiles"`
	Process         ProcessProfileSection    `yaml:"process" json:"process"`
	ProcessProfile  *ProcessProfile          `yaml:"process_profile" json:"process_profile"`
	ProcessProfiles []ProcessProfile         `yaml:"process_profiles" json:"process_profiles"`
	Group           *NVGroupConfig           `yaml:"group" json:"group"`
	Config          *NVGroupConfig           `yaml:"config" json:"config"`
	Groups          []NVGroupConfig          `yaml:"groups" json:"groups"`
	Configs         []NVGroupConfig          `yaml:"configs" json:"configs"`
	DLP             DPISensorSection         `yaml:"dlp" json:"dlp"`
	WAF             DPISensorSection         `yaml:"waf" json:"waf"`
	DLPSensors      []DPISensor              `yaml:"dlp_sensors" json:"dlp_sensors"`
	WAFSensors      []DPISensor              `yaml:"waf_sensors" json:"waf_sensors"`
	DLPGroups       []DPISensorGroup         `yaml:"dlp_groups" json:"dlp_groups"`
	WAFGroups       []DPISensorGroup         `yaml:"waf_groups" json:"waf_groups"`
	Sensor          *DPISensor               `yaml:"sensor" json:"sensor"`
	Sensors         []DPISensor              `yaml:"sensors" json:"sensors"`
	Policy          networkRuleSection       `yaml:"policy" json:"policy"`
	Network         networkRuleSection       `yaml:"network" json:"network"`
	NetworkRules    []NVNetworkRule          `yaml:"network_rules" json:"network_rules"`
	PolicyRules     []NVNetworkRule          `yaml:"policy_rules" json:"policy_rules"`
	Items           []NvSecurityRuleDocument `yaml:"items" json:"items"`
	Kind            string                   `yaml:"kind" json:"kind"`
	Metadata        ObjectMetadata           `yaml:"metadata" json:"metadata"`
	Spec            NvSecurityRuleSpec       `yaml:"spec" json:"spec"`
}

type AdmissionSection struct {
	Rules []AdmissionRule `yaml:"rules" json:"rules"`
}

type AdmissionRule struct {
	ID           int                  `yaml:"id"         json:"id"`
	Category     string               `yaml:"category"   json:"category"`
	Desc         string               `yaml:"desc"       json:"desc"`
	Comment      string               `yaml:"comment"    json:"comment"`
	Criteria     []AdmissionCriterion `yaml:"criteria"   json:"criteria"`
	Action       string               `yaml:"action"     json:"action"`    // allow | deny
	RuleType     string               `yaml:"rule_type"  json:"rule_type"` // exception | deny
	RuleMode     string               `yaml:"rule_mode"  json:"rule_mode"` // monitor | protect
	Disabled     bool                 `yaml:"disabled"   json:"disabled"`
	Disable      bool                 `yaml:"disable"    json:"disable"`
	From         string               `yaml:"from"       json:"from"`
	To           string               `yaml:"to"         json:"to"`
	Ports        string               `yaml:"ports"      json:"ports"`
	Applications []string             `yaml:"applications" json:"applications"`
	Containers   []string             `yaml:"containers" json:"containers"`
}

type AdmissionCriterion struct {
	Key         string               `yaml:"key"          json:"key"`
	Name        string               `yaml:"name"         json:"name"`
	Op          string               `yaml:"op"           json:"op"` // regex | eq | contains
	Value       string               `yaml:"value"        json:"value"`
	Type        string               `yaml:"type"         json:"type,omitempty"`
	Kind        string               `yaml:"template_kind" json:"template_kind,omitempty"`
	Path        string               `yaml:"path"         json:"path,omitempty"`
	ValueType   string               `yaml:"value_type"   json:"value_type,omitempty"`
	SubCriteria []AdmissionCriterion `yaml:"sub_criteria" json:"sub_criteria,omitempty"`
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
	Selector       GroupConfig               `yaml:"selector" json:"selector"`
	IngressRule    []NvSecurityRuleDetail    `yaml:"ingress" json:"ingress"`
	EgressRule     []NvSecurityRuleDetail    `yaml:"egress" json:"egress"`
	ProcessProfile *NvSecurityProcessProfile `yaml:"process_profile" json:"process_profile"`
	ProcessRule    []ProcessProfileEntry     `yaml:"process" json:"process"`
	FileRule       []FileMonitorRule         `yaml:"file" json:"file"`
	Sensor         *DPISensor                `yaml:"sensor" json:"sensor"`
}

type NvSecurityTarget struct {
	PolicyMode *string     `yaml:"policymode" json:"policymode"`
	Selector   GroupConfig `yaml:"selector" json:"selector"`
}

type GroupConfig struct {
	OriginalName string             `yaml:"original_name" json:"original_name"`
	Name         string             `yaml:"name" json:"name"`
	Comment      string             `yaml:"comment" json:"comment"`
	CfgType      string             `yaml:"cfg_type" json:"cfg_type"`
	PolicyMode   string             `yaml:"policy_mode" json:"policy_mode"`
	ProfileMode  string             `yaml:"profile_mode" json:"profile_mode"`
	Learned      bool               `yaml:"learned" json:"learned"`
	Criteria     []NVGroupCriterion `yaml:"criteria" json:"criteria"`
}

type NvSecurityRuleDetail struct {
	Selector     GroupConfig `yaml:"selector" json:"selector"`
	Applications []string    `yaml:"applications" json:"applications"`
	Ports        string      `yaml:"ports" json:"ports"`
	Action       string      `yaml:"action" json:"action"`
	Name         string      `yaml:"name" json:"name"`
	Priority     uint32      `yaml:"priority" json:"priority"`
}

type NVGroupConfig struct {
	Name        string             `yaml:"name" json:"name"`
	Comment     string             `yaml:"comment" json:"comment"`
	CfgType     string             `yaml:"cfg_type" json:"cfg_type"`
	PolicyMode  string             `yaml:"policy_mode" json:"policy_mode"`
	ProfileMode string             `yaml:"profile_mode" json:"profile_mode"`
	Kind        string             `yaml:"kind" json:"kind"`
	Learned     bool               `yaml:"learned" json:"learned"`
	Criteria    []NVGroupCriterion `yaml:"criteria" json:"criteria"`
}

type NVGroupCriterion struct {
	Key   string `yaml:"key" json:"key"`
	Op    string `yaml:"op" json:"op"`
	Value string `yaml:"value" json:"value"`
}

type NvSecurityProcessProfile struct {
	Baseline *string `yaml:"baseline" json:"baseline"`
	Mode     *string `yaml:"mode" json:"mode"`
}

type ProcessProfileSection struct {
	Profile  *ProcessProfile  `yaml:"profile" json:"profile"`
	Profiles []ProcessProfile `yaml:"profiles" json:"profiles"`
}

type ProcessProfile struct {
	Group        string                `yaml:"group" json:"group"`
	Name         string                `yaml:"name" json:"name"`
	Mode         string                `yaml:"mode" json:"mode"`
	Baseline     string                `yaml:"baseline" json:"baseline"`
	CfgType      string                `yaml:"cfg_type" json:"cfg_type"`
	Description  string                `yaml:"description" json:"description"`
	AlertDisable bool                  `yaml:"alert_disabled" json:"alert_disabled"`
	HashEnable   bool                  `yaml:"hash_enabled" json:"hash_enabled"`
	ProcessList  []ProcessProfileEntry `yaml:"process_list" json:"process_list"`
	Process      []ProcessProfileEntry `yaml:"process" json:"process"`
	Rules        []ProcessProfileEntry `yaml:"rules" json:"rules"`
}

type ProcessProfileEntry struct {
	Name            string `yaml:"name" json:"name"`
	Path            string `yaml:"path" json:"path"`
	User            string `yaml:"user" json:"user"`
	Action          string `yaml:"action" json:"action"`
	CfgType         string `yaml:"cfg_type" json:"cfg_type"`
	UUID            string `yaml:"uuid" json:"uuid"`
	Group           string `yaml:"group" json:"group"`
	SHA256          string `yaml:"sha256" json:"sha256"`
	ParentName      string `yaml:"parent_name" json:"parent_name"`
	AllowFileUpdate bool   `yaml:"allow_update" json:"allow_update"`
	Disabled        bool   `yaml:"disabled" json:"disabled"`
	Disable         bool   `yaml:"disable" json:"disable"`
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

type TargetProcessProfile struct {
	Group       string                     `json:"group"`
	Mode        string                     `json:"mode"`
	Baseline    string                     `json:"baseline,omitempty"`
	CfgType     string                     `json:"cfg_type,omitempty"`
	Description string                     `json:"description,omitempty"`
	Rules       []TargetProcessProfileRule `json:"rules"`
	Imported    map[string]string          `json:"imported_from,omitempty"`
}

type TargetProcessProfileRule struct {
	Name        string `json:"name"`
	Path        string `json:"path"`
	User        string `json:"user,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	ParentName  string `json:"parent_name,omitempty"`
	Action      string `json:"action"`
	CfgType     string `json:"cfg_type,omitempty"`
	UUID        string `json:"uuid,omitempty"`
	AllowUpdate bool   `json:"allow_update"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
}

type TargetGroup struct {
	Name        string                 `json:"name"`
	Kind        string                 `json:"kind"`
	Comment     string                 `json:"comment,omitempty"`
	CfgType     string                 `json:"cfg_type,omitempty"`
	PolicyMode  string                 `json:"policy_mode,omitempty"`
	ProfileMode string                 `json:"profile_mode,omitempty"`
	Criteria    []TargetGroupCriterion `json:"criteria"`
	Imported    map[string]string      `json:"imported_from,omitempty"`
}

type TargetGroupCriterion struct {
	Key   string `json:"key"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type TargetNetworkRule struct {
	Name         string            `json:"name"`
	FromGroup    string            `json:"from_group"`
	ToGroup      string            `json:"to_group"`
	Ports        []TargetPortSpec  `json:"ports"`
	Mode         string            `json:"mode"`
	Comment      string            `json:"comment,omitempty"`
	Priority     int               `json:"priority"`
	SourceAction string            `json:"source_action,omitempty"`
	Imported     map[string]string `json:"imported_from,omitempty"`
}

type TargetPortSpec struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
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

type DPISensorSection struct {
	Sensor  *DPISensor  `yaml:"sensor" json:"sensor"`
	Sensors []DPISensor `yaml:"sensors" json:"sensors"`
	Rules   []DPIRule   `yaml:"rules" json:"rules"`
}

type DPISensor struct {
	Name      string    `yaml:"name" json:"name"`
	GroupList []string  `yaml:"groups" json:"groups"`
	RuleList  []DPIRule `yaml:"rules" json:"rules"`
	Comment   string    `yaml:"comment" json:"comment"`
	Predefine bool      `yaml:"predefine" json:"predefine"`
	CfgType   string    `yaml:"cfg_type" json:"cfg_type"`
}

type DPIRule struct {
	Name     string         `yaml:"name" json:"name"`
	ID       int            `yaml:"id" json:"id"`
	Patterns []DPICriterion `yaml:"patterns" json:"patterns"`
	CfgType  string         `yaml:"cfg_type" json:"cfg_type"`
}

type DPICriterion struct {
	Key     string `yaml:"key" json:"key"`
	Value   string `yaml:"value" json:"value"`
	Op      string `yaml:"op" json:"op"`
	Context string `yaml:"context,omitempty" json:"context,omitempty"`
}

type DPISensorGroup struct {
	Name    string             `yaml:"name" json:"name"`
	Status  *bool              `yaml:"status" json:"status"`
	Sensors []DPISensorSetting `yaml:"sensors" json:"sensors"`
	CfgType string             `yaml:"cfg_type" json:"cfg_type"`
}

type DPISensorSetting struct {
	Name    string `yaml:"name" json:"name"`
	Action  string `yaml:"action" json:"action"`
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
	CfgType string `yaml:"cfg_type" json:"cfg_type"`
}

type NVNetworkRule struct {
	ID           uint32   `yaml:"id" json:"id"`
	Comment      string   `yaml:"comment" json:"comment"`
	From         string   `yaml:"from" json:"from"`
	To           string   `yaml:"to" json:"to"`
	Ports        string   `yaml:"ports" json:"ports"`
	Action       string   `yaml:"action" json:"action"`
	Applications []string `yaml:"applications" json:"applications"`
	Learned      bool     `yaml:"learned" json:"learned"`
	Disable      bool     `yaml:"disable" json:"disable"`
	CfgType      string   `yaml:"cfg_type" json:"cfg_type"`
	Priority     uint32   `yaml:"priority" json:"priority"`
}

type networkRuleSection struct {
	Rule  *NVNetworkRule  `yaml:"rule" json:"rule"`
	Rules []NVNetworkRule `yaml:"rules" json:"rules"`
}

type networkSourceExport struct {
	Policy       networkRuleSection       `yaml:"policy" json:"policy"`
	Network      networkRuleSection       `yaml:"network" json:"network"`
	Rule         *NVNetworkRule           `yaml:"rule" json:"rule"`
	Rules        []NVNetworkRule          `yaml:"rules" json:"rules"`
	NetworkRules []NVNetworkRule          `yaml:"network_rules" json:"network_rules"`
	PolicyRules  []NVNetworkRule          `yaml:"policy_rules" json:"policy_rules"`
	Items        []NvSecurityRuleDocument `yaml:"items" json:"items"`
	Kind         string                   `yaml:"kind" json:"kind"`
	Metadata     ObjectMetadata           `yaml:"metadata" json:"metadata"`
	Spec         NvSecurityRuleSpec       `yaml:"spec" json:"spec"`
}

type DPIPatternSpec struct {
	Pattern string `json:"pattern" yaml:"pattern"`
	Op      string `json:"op,omitempty" yaml:"op,omitempty"`
	Context string `json:"context,omitempty" yaml:"context,omitempty"`
}

type TargetDPIRule struct {
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	ApplyDir          int16             `json:"apply_dir"`
	Severity          int16             `json:"severity"`
	Mode              string            `json:"mode"`
	Patterns          []DPIPatternSpec  `json:"patterns"`
	Description       string            `json:"description,omitempty"`
	SourceSensor      string            `json:"source_sensor,omitempty"`
	SourceGroups      []string          `json:"source_groups,omitempty"`
	SourcePath        string            `json:"source_path,omitempty"`
	SourceCfgType     string            `json:"source_cfg_type,omitempty"`
	SourceRuleCfgType string            `json:"source_rule_cfg_type,omitempty"`
	Federated         bool              `json:"federated,omitempty"`
	Imported          map[string]string `json:"imported_from,omitempty"`
}

type TargetDPIBinding struct {
	SourceGroup   string            `json:"source_group"`
	Category      string            `json:"category"`
	SensorKind    string            `json:"sensor_kind"`
	SourceSensors []string          `json:"source_sensors,omitempty"`
	Imported      map[string]string `json:"imported_from,omitempty"`
}

type UnsupportedObject struct {
	Kind       string         `json:"kind"`
	Name       string         `json:"name"`
	Reason     string         `json:"reason"`
	Suggestion string         `json:"suggestion,omitempty"`
	Source     map[string]any `json:"source,omitempty"`
}

type dpiSensorCandidate struct {
	Sensor        DPISensor
	SourcePath    string
	SourceCfgType string
	Federated     bool
}

type SourceObjectCounts struct {
	Policies        int
	AdmissionRules  int
	ResponseRules   int
	FileProfiles    int
	ProcessProfiles int
	Groups          int
	NetworkRules    int
	DPIRules        int
	DPIBindings     int
}

func (c SourceObjectCounts) Total() int {
	return c.Policies + c.FileProfiles + c.ProcessProfiles + c.Groups + c.NetworkRules + c.DPIRules + c.DPIBindings
}

func (c SourceObjectCounts) Map() map[string]int {
	return map[string]int{
		"policies":         c.Policies,
		"admission_rules":  c.AdmissionRules,
		"response_rules":   c.ResponseRules,
		"file_profiles":    c.FileProfiles,
		"process_profiles": c.ProcessProfiles,
		"groups":           c.Groups,
		"network_rules":    c.NetworkRules,
		"dpi_rules":        c.DPIRules,
		"dpi_bindings":     c.DPIBindings,
	}
}

func CountSourceObjects(raw []byte) (SourceObjectCounts, error) {
	docs, err := parseSourceExports(raw)
	if err != nil {
		return SourceObjectCounts{}, err
	}
	counts := SourceObjectCounts{}
	groupNames := map[string]bool{}
	for _, doc := range docs {
		admissionRules := collectAdmissionRules(doc)
		counts.AdmissionRules += len(admissionRules)
		counts.ResponseRules += len(doc.Response.Rules)
		counts.FileProfiles += len(collectFileProfiles(doc))
		counts.ProcessProfiles += len(collectProcessProfiles(doc))
		for _, group := range collectGroups(doc) {
			name := strings.TrimSpace(group.Name)
			if name != "" {
				groupNames[name] = true
			}
		}
		for _, sensor := range collectDPISensors(doc, "dlp") {
			counts.DPIRules += len(sensor.RuleList)
		}
		for _, sensor := range collectDPISensors(doc, "waf") {
			counts.DPIRules += len(sensor.RuleList)
		}
		counts.DPIBindings += len(translateDPIGroupBindings(doc.DLPGroups, "dlp"))
		counts.DPIBindings += len(translateDPIGroupBindings(doc.WAFGroups, "waf"))
	}
	counts.Groups = len(groupNames)
	counts.Policies = counts.AdmissionRules + counts.ResponseRules

	networkDocs, err := parseNetworkSourceExports(raw)
	if err != nil {
		return SourceObjectCounts{}, err
	}
	for _, doc := range networkDocs {
		counts.NetworkRules += len(collectNetworkRules(doc))
	}
	return counts, nil
}

// Convert parses a NeuVector export and returns Constellation TargetPolicy rows.
func Convert(raw []byte) ([]TargetPolicy, error) {
	doc, err := parseSourceExport(raw)
	if err != nil {
		return nil, err
	}

	out := []TargetPolicy{}
	for _, r := range collectAdmissionRules(doc) {
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

// ConvertProcessProfiles parses NeuVector process profile REST exports and
// NvSecurityRule CRD process sections into group-scoped process baseline targets.
func ConvertProcessProfiles(raw []byte) ([]TargetProcessProfile, []UnsupportedObject, error) {
	docs, err := parseSourceExports(raw)
	if err != nil {
		return nil, nil, err
	}
	profiles := []ProcessProfile{}
	for _, doc := range docs {
		profiles = append(profiles, collectProcessProfiles(doc)...)
	}
	if len(profiles) == 0 {
		return nil, nil, nil
	}
	out := []TargetProcessProfile{}
	unsupported := []UnsupportedObject{}
	for _, profile := range profiles {
		converted, skipped := translateProcessProfile(profile)
		unsupported = append(unsupported, skipped...)
		if converted.Group == "" {
			continue
		}
		if len(converted.Rules) == 0 && strings.TrimSpace(profile.Mode) == "" && strings.TrimSpace(profile.Baseline) == "" {
			continue
		}
		out = append(out, converted)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Group < out[j].Group
	})
	return out, unsupported, nil
}

// ConvertDPIRules parses NeuVector DLP/WAF sensor exports into enforced
// runtime_dlp_rules targets. NeuVector exports these sensors as NvDlpSecurityRule
// and NvWafSecurityRule CRDs; federated exports may also carry dlp_sensors,
// waf_sensors, dlp_groups, and waf_groups arrays. Group binding candidates are
// returned separately because the migration handler resolves source group names
// to target Constellation group IDs at preview time.
func ConvertDPIRules(raw []byte) ([]TargetDPIRule, []TargetDPIBinding, []UnsupportedObject, error) {
	docs, err := parseSourceExports(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	out := []TargetDPIRule{}
	bindings := []TargetDPIBinding{}
	unsupported := []UnsupportedObject{}
	names := map[string]int{}
	for i, doc := range docs {
		docPath := dpiDocumentPath(i, len(docs))
		for _, sensor := range collectDPISensorCandidates(doc, "dlp", docPath) {
			converted, skipped := translateDPISensor(sensor, "dlp", names)
			out = append(out, converted...)
			unsupported = append(unsupported, skipped...)
		}
		for _, sensor := range collectDPISensorCandidates(doc, "waf", docPath) {
			converted, skipped := translateDPISensor(sensor, "waf", names)
			out = append(out, converted...)
			unsupported = append(unsupported, skipped...)
		}
		bindings = append(bindings, translateDPIGroupBindings(doc.DLPGroups, "dlp")...)
		bindings = append(bindings, translateDPIGroupBindings(doc.WAFGroups, "waf")...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return out[i].Name < out[j].Name
	})
	sort.SliceStable(bindings, func(i, j int) bool {
		if bindings[i].SensorKind != bindings[j].SensorKind {
			return bindings[i].SensorKind < bindings[j].SensorKind
		}
		return bindings[i].SourceGroup < bindings[j].SourceGroup
	})
	sort.SliceStable(unsupported, func(i, j int) bool {
		if unsupported[i].Kind != unsupported[j].Kind {
			return unsupported[i].Kind < unsupported[j].Kind
		}
		return unsupported[i].Name < unsupported[j].Name
	})
	return out, bindings, unsupported, nil
}

// ConvertGroups parses NeuVector group exports and NvGroupDefinition selectors
// into Constellation group targets. It intentionally skips groups with any
// unsupported selector criteria so automated imports cannot silently broaden or
// narrow the runtime enforcement scope.
func ConvertGroups(raw []byte) ([]TargetGroup, []UnsupportedObject, error) {
	docs, err := parseSourceExports(raw)
	if err != nil {
		return nil, nil, err
	}
	candidates := []NVGroupConfig{}
	for _, doc := range docs {
		candidates = append(candidates, collectGroups(doc)...)
	}
	if len(candidates) == 0 {
		return []TargetGroup{}, []UnsupportedObject{}, nil
	}
	byName := map[string]NVGroupConfig{}
	order := []string{}
	for _, candidate := range candidates {
		name := strings.TrimSpace(candidate.Name)
		if name == "" {
			continue
		}
		if existing, ok := byName[name]; ok {
			if len(candidate.Criteria) > len(existing.Criteria) {
				byName[name] = candidate
			}
			continue
		}
		byName[name] = candidate
		order = append(order, name)
	}
	sort.Strings(order)

	groups := make([]TargetGroup, 0, len(order))
	unsupported := []UnsupportedObject{}
	for _, name := range order {
		group, skipped := translateGroup(byName[name])
		if len(skipped) > 0 {
			unsupported = append(unsupported, skipped...)
			continue
		}
		groups = append(groups, group)
	}
	sort.SliceStable(unsupported, func(i, j int) bool {
		if unsupported[i].Kind != unsupported[j].Kind {
			return unsupported[i].Kind < unsupported[j].Kind
		}
		return unsupported[i].Name < unsupported[j].Name
	})
	return groups, unsupported, nil
}

// ConvertNetworkRules parses NeuVector RESTPolicyRule and NvSecurityRule
// ingress/egress rules into Constellation group-to-group network edges. Only
// allow rules with L4 ports and no application predicate are converted; deny,
// disabled, L7 application-scoped, and malformed rules are retained as
// unsupported because the group-edge model cannot enforce those semantics
// faithfully today.
func ConvertNetworkRules(raw []byte) ([]TargetNetworkRule, []UnsupportedObject, error) {
	docs, err := parseNetworkSourceExports(raw)
	if err != nil {
		return nil, nil, err
	}
	out := []TargetNetworkRule{}
	unsupported := []UnsupportedObject{}
	byPair := map[string]int{}
	for _, doc := range docs {
		for _, rule := range collectNetworkRules(doc) {
			converted, skipped, ok := translateNetworkRule(rule)
			if len(skipped) > 0 {
				unsupported = append(unsupported, skipped...)
				continue
			}
			if !ok {
				continue
			}
			key := converted.FromGroup + "\x00" + converted.ToGroup
			if idx, exists := byPair[key]; exists {
				out[idx] = mergeNetworkRule(out[idx], converted)
				continue
			}
			byPair[key] = len(out)
			out = append(out, converted)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		if out[i].FromGroup != out[j].FromGroup {
			return out[i].FromGroup < out[j].FromGroup
		}
		return out[i].ToGroup < out[j].ToGroup
	})
	sort.SliceStable(unsupported, func(i, j int) bool {
		if unsupported[i].Kind != unsupported[j].Kind {
			return unsupported[i].Kind < unsupported[j].Kind
		}
		return unsupported[i].Name < unsupported[j].Name
	})
	return out, unsupported, nil
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
	for _, r := range collectAdmissionRules(doc) {
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

func parseNetworkSourceExports(raw []byte) ([]networkSourceExport, error) {
	if len(raw) == 0 {
		return nil, errors.New("neuvector: empty export")
	}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	out := []networkSourceExport{}
	for {
		var doc networkSourceExport
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("neuvector: parse: %w", err)
		}
		if networkSourceExportEmpty(doc) {
			continue
		}
		out = append(out, doc)
	}
	if len(out) == 0 {
		return []networkSourceExport{}, nil
	}
	return out, nil
}

func sourceExportEmpty(doc SourceExport) bool {
	return len(doc.Admission.Rules) == 0 &&
		len(doc.Rules) == 0 &&
		doc.Rule == nil &&
		len(doc.Response.Rules) == 0 &&
		doc.FileMonitor.Profile == nil &&
		len(doc.FileMonitor.Profiles) == 0 &&
		len(doc.FileMonitor.Rules) == 0 &&
		len(doc.FileProfiles) == 0 &&
		doc.Profile == nil &&
		len(doc.Profiles) == 0 &&
		doc.Process.Profile == nil &&
		len(doc.Process.Profiles) == 0 &&
		doc.ProcessProfile == nil &&
		len(doc.ProcessProfiles) == 0 &&
		doc.Group == nil &&
		doc.Config == nil &&
		len(doc.Groups) == 0 &&
		len(doc.Configs) == 0 &&
		doc.DLP.Sensor == nil &&
		len(doc.DLP.Sensors) == 0 &&
		len(doc.DLP.Rules) == 0 &&
		doc.WAF.Sensor == nil &&
		len(doc.WAF.Sensors) == 0 &&
		len(doc.WAF.Rules) == 0 &&
		len(doc.DLPSensors) == 0 &&
		len(doc.WAFSensors) == 0 &&
		len(doc.DLPGroups) == 0 &&
		len(doc.WAFGroups) == 0 &&
		doc.Sensor == nil &&
		len(doc.Sensors) == 0 &&
		doc.Policy.Rule == nil &&
		len(doc.Policy.Rules) == 0 &&
		doc.Network.Rule == nil &&
		len(doc.Network.Rules) == 0 &&
		len(doc.NetworkRules) == 0 &&
		len(doc.PolicyRules) == 0 &&
		len(doc.Items) == 0 &&
		strings.TrimSpace(doc.Kind) == "" &&
		len(doc.Spec.FileRule) == 0 &&
		len(doc.Spec.ProcessRule) == 0 &&
		doc.Spec.ProcessProfile == nil &&
		len(doc.Spec.IngressRule) == 0 &&
		len(doc.Spec.EgressRule) == 0 &&
		doc.Spec.Sensor == nil &&
		emptyGroupConfig(doc.Spec.Selector) &&
		emptyGroupConfig(doc.Spec.Target.Selector)
}

func networkSourceExportEmpty(doc networkSourceExport) bool {
	return doc.Policy.Rule == nil &&
		len(doc.Policy.Rules) == 0 &&
		doc.Network.Rule == nil &&
		len(doc.Network.Rules) == 0 &&
		doc.Rule == nil &&
		len(doc.Rules) == 0 &&
		len(doc.NetworkRules) == 0 &&
		len(doc.PolicyRules) == 0 &&
		len(doc.Items) == 0 &&
		strings.TrimSpace(doc.Kind) == "" &&
		len(doc.Spec.IngressRule) == 0 &&
		len(doc.Spec.EgressRule) == 0
}

func collectAdmissionRules(doc SourceExport) []AdmissionRule {
	out := make([]AdmissionRule, 0, len(doc.Admission.Rules)+len(doc.Rules)+1)
	out = append(out, doc.Admission.Rules...)
	for _, rule := range doc.Rules {
		if !admissionRuleLooksLikeNetworkRule(rule) {
			out = append(out, rule)
		}
	}
	if doc.Rule != nil && !admissionRuleLooksLikeNetworkRule(*doc.Rule) {
		out = append(out, *doc.Rule)
	}
	return out
}

func admissionRuleLooksLikeNetworkRule(rule AdmissionRule) bool {
	return strings.TrimSpace(rule.From) != "" ||
		strings.TrimSpace(rule.To) != "" ||
		strings.TrimSpace(rule.Ports) != "" ||
		len(rule.Applications) > 0
}

func collectNetworkRules(doc networkSourceExport) []NVNetworkRule {
	out := []NVNetworkRule{}
	add := func(rule NVNetworkRule) {
		if !networkRuleLooksLikePolicyRule(rule) {
			return
		}
		out = append(out, rule)
	}
	addSection := func(section networkRuleSection) {
		if section.Rule != nil {
			add(*section.Rule)
		}
		for _, rule := range section.Rules {
			add(rule)
		}
	}
	addSection(doc.Policy)
	addSection(doc.Network)
	if doc.Rule != nil {
		add(*doc.Rule)
	}
	for _, rule := range doc.Rules {
		add(rule)
	}
	for _, rule := range doc.NetworkRules {
		add(rule)
	}
	for _, rule := range doc.PolicyRules {
		add(rule)
	}

	topLevel := NvSecurityRuleDocument{Kind: doc.Kind, Metadata: doc.Metadata, Spec: doc.Spec}
	out = append(out, networkRulesFromNvSecurityRule(topLevel)...)
	for _, item := range doc.Items {
		out = append(out, networkRulesFromNvSecurityRule(item)...)
	}
	return out
}

func networkRuleLooksLikePolicyRule(rule NVNetworkRule) bool {
	return strings.TrimSpace(rule.From) != "" ||
		strings.TrimSpace(rule.To) != "" ||
		strings.TrimSpace(rule.Ports) != "" ||
		len(rule.Applications) > 0
}

func networkRulesFromNvSecurityRule(doc NvSecurityRuleDocument) []NVNetworkRule {
	if !isNetworkSecurityRuleKind(doc.Kind) && len(doc.Spec.IngressRule) == 0 && len(doc.Spec.EgressRule) == 0 {
		return nil
	}
	target := groupNameFromSelector(doc.Spec.Target.Selector)
	if target == "" {
		target = groupNameFromSelector(doc.Spec.Selector)
	}
	if target == "" {
		target = strings.TrimSpace(doc.Metadata.Name)
	}
	out := make([]NVNetworkRule, 0, len(doc.Spec.IngressRule)+len(doc.Spec.EgressRule))
	for _, detail := range doc.Spec.IngressRule {
		peer := groupNameFromSelector(detail.Selector)
		rule := networkRuleFromSecurityDetail(detail)
		rule.From = peer
		rule.To = target
		out = append(out, rule)
	}
	for _, detail := range doc.Spec.EgressRule {
		peer := groupNameFromSelector(detail.Selector)
		rule := networkRuleFromSecurityDetail(detail)
		rule.From = target
		rule.To = peer
		out = append(out, rule)
	}
	return out
}

func networkRuleFromSecurityDetail(detail NvSecurityRuleDetail) NVNetworkRule {
	return NVNetworkRule{
		Comment:      strings.TrimSpace(detail.Name),
		Ports:        detail.Ports,
		Action:       detail.Action,
		Applications: append([]string(nil), detail.Applications...),
		Priority:     detail.Priority,
	}
}

func groupNameFromSelector(selector GroupConfig) string {
	return firstNonEmpty(selector.Name, selector.OriginalName)
}

func isNetworkSecurityRuleKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "nvsecurityrule", "nvsecurityrulelist":
		return true
	default:
		return false
	}
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

func collectProcessProfiles(doc SourceExport) []ProcessProfile {
	out := []ProcessProfile{}
	add := func(profile ProcessProfile) {
		if strings.TrimSpace(processProfileGroup(profile)) == "" &&
			len(processProfileRules(profile)) == 0 &&
			strings.TrimSpace(profile.Mode) == "" &&
			strings.TrimSpace(profile.Baseline) == "" {
			return
		}
		out = append(out, profile)
	}
	if doc.Process.Profile != nil {
		add(*doc.Process.Profile)
	}
	for _, profile := range doc.Process.Profiles {
		add(profile)
	}
	if doc.ProcessProfile != nil {
		add(*doc.ProcessProfile)
	}
	for _, profile := range doc.ProcessProfiles {
		add(profile)
	}
	if len(doc.Spec.ProcessRule) > 0 || doc.Spec.ProcessProfile != nil {
		add(processProfileFromNvSecurityRule(NvSecurityRuleDocument{
			Kind:     doc.Kind,
			Metadata: doc.Metadata,
			Spec:     doc.Spec,
		}))
	}
	for _, item := range doc.Items {
		if len(item.Spec.ProcessRule) > 0 || item.Spec.ProcessProfile != nil {
			add(processProfileFromNvSecurityRule(item))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return processProfileGroup(out[i]) < processProfileGroup(out[j])
	})
	return out
}

func collectDPISensors(doc SourceExport, category string) []DPISensor {
	candidates := collectDPISensorCandidates(doc, category, "")
	out := make([]DPISensor, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, candidate.Sensor)
	}
	return out
}

func collectDPISensorCandidates(doc SourceExport, category, docPath string) []dpiSensorCandidate {
	out := []dpiSensorCandidate{}
	add := func(sensor DPISensor, path string, cfgTypes ...string) {
		if strings.TrimSpace(sensor.Name) == "" && len(sensor.RuleList) == 0 {
			return
		}
		out = append(out, dpiSensorCandidate{
			Sensor:        sensor,
			SourcePath:    joinSourcePath(docPath, path),
			SourceCfgType: firstNonEmpty(append([]string{sensor.CfgType}, cfgTypes...)...),
			Federated:     cfgTypeFederated(append([]string{sensor.CfgType}, cfgTypes...)...),
		})
	}
	addRules := func(rules []DPIRule, path string, cfgTypes ...string) {
		if len(rules) == 0 {
			return
		}
		add(DPISensor{Name: "neuvector-" + category + "-sensor", RuleList: rules, CfgType: firstNonEmpty(cfgTypes...)}, path, cfgTypes...)
	}
	if category == "dlp" {
		if doc.DLP.Sensor != nil {
			add(*doc.DLP.Sensor, "dlp.sensor")
		}
		for i, sensor := range doc.DLP.Sensors {
			add(sensor, fmt.Sprintf("dlp.sensors[%d]", i))
		}
		for i, sensor := range doc.DLPSensors {
			add(sensor, fmt.Sprintf("dlp_sensors[%d]", i))
		}
		addRules(doc.DLP.Rules, "dlp.rules")
	} else {
		if doc.WAF.Sensor != nil {
			add(*doc.WAF.Sensor, "waf.sensor")
		}
		for i, sensor := range doc.WAF.Sensors {
			add(sensor, fmt.Sprintf("waf.sensors[%d]", i))
		}
		for i, sensor := range doc.WAFSensors {
			add(sensor, fmt.Sprintf("waf_sensors[%d]", i))
		}
		addRules(doc.WAF.Rules, "waf.rules")
	}

	kindCategory := dpiCategoryFromKind(doc.Kind)
	if kindCategory == category && doc.Spec.Sensor != nil {
		add(*doc.Spec.Sensor, "spec.sensor")
	}
	for i, item := range doc.Items {
		if dpiCategoryFromKind(item.Kind) == category && item.Spec.Sensor != nil {
			add(*item.Spec.Sensor, fmt.Sprintf("items[%d].spec.sensor", i))
		}
	}

	// REST /v1/dlp/sensors and /v1/waf/sensors both emit a top-level
	// {"sensors": [...]} envelope. When no kind is present, infer from the rule id
	// range/name; default to DLP because NeuVector's DLP endpoint is the more common
	// source for this ambiguous shape.
	if len(doc.Sensors) > 0 {
		inferred := inferDPICategory(doc.Sensors)
		if inferred == "" {
			inferred = "dlp"
		}
		if inferred == category {
			for i, sensor := range doc.Sensors {
				add(sensor, fmt.Sprintf("sensors[%d]", i))
			}
		}
	}
	if doc.Sensor != nil {
		inferred := inferDPICategory([]DPISensor{*doc.Sensor})
		if inferred == "" {
			inferred = firstNonEmpty(kindCategory, "dlp")
		}
		if inferred == category {
			add(*doc.Sensor, "sensor")
		}
	}
	return out
}

func collectGroups(doc SourceExport) []NVGroupConfig {
	out := []NVGroupConfig{}
	add := func(group NVGroupConfig) {
		if strings.TrimSpace(group.Name) == "" && len(group.Criteria) == 0 {
			return
		}
		out = append(out, group)
	}
	if doc.Group != nil {
		add(*doc.Group)
	}
	if doc.Config != nil {
		add(*doc.Config)
	}
	for _, group := range doc.Groups {
		add(group)
	}
	for _, group := range doc.Configs {
		add(group)
	}
	if isGroupDefinitionKind(doc.Kind) && !emptyGroupConfig(doc.Spec.Selector) {
		add(groupConfigFromSelector(doc.Spec.Selector))
	}
	if !emptyGroupConfig(doc.Spec.Target.Selector) {
		add(groupConfigFromSelector(doc.Spec.Target.Selector))
	}
	for _, rule := range doc.Spec.IngressRule {
		if !emptyGroupConfig(rule.Selector) {
			add(groupConfigFromSelector(rule.Selector))
		}
	}
	for _, rule := range doc.Spec.EgressRule {
		if !emptyGroupConfig(rule.Selector) {
			add(groupConfigFromSelector(rule.Selector))
		}
	}
	for _, item := range doc.Items {
		if isGroupDefinitionKind(item.Kind) && !emptyGroupConfig(item.Spec.Selector) {
			add(groupConfigFromSelector(item.Spec.Selector))
		}
		if !emptyGroupConfig(item.Spec.Target.Selector) {
			add(groupConfigFromSelector(item.Spec.Target.Selector))
		}
		for _, rule := range item.Spec.IngressRule {
			if !emptyGroupConfig(rule.Selector) {
				add(groupConfigFromSelector(rule.Selector))
			}
		}
		for _, rule := range item.Spec.EgressRule {
			if !emptyGroupConfig(rule.Selector) {
				add(groupConfigFromSelector(rule.Selector))
			}
		}
	}
	return out
}

func groupConfigFromSelector(selector GroupConfig) NVGroupConfig {
	return NVGroupConfig{
		Name:        firstNonEmpty(selector.Name, selector.OriginalName),
		Comment:     selector.Comment,
		CfgType:     selector.CfgType,
		PolicyMode:  selector.PolicyMode,
		ProfileMode: selector.ProfileMode,
		Learned:     selector.Learned,
		Criteria:    selector.Criteria,
	}
}

func emptyGroupConfig(group GroupConfig) bool {
	return strings.TrimSpace(group.Name) == "" &&
		strings.TrimSpace(group.OriginalName) == "" &&
		strings.TrimSpace(group.Comment) == "" &&
		len(group.Criteria) == 0
}

func isGroupDefinitionKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "nvgroupdefinition", "nvgroupdefinitionlist":
		return true
	default:
		return false
	}
}

func translateGroup(source NVGroupConfig) (TargetGroup, []UnsupportedObject) {
	name := strings.TrimSpace(source.Name)
	target := TargetGroup{
		Name:        name,
		Kind:        normalizeGroupKind(source),
		Comment:     strings.TrimSpace(source.Comment),
		CfgType:     normalizeGroupCfgType(source),
		PolicyMode:  normalizeGroupMode(source.PolicyMode),
		ProfileMode: normalizeGroupMode(source.ProfileMode),
		Imported: map[string]string{
			"source":       "neuvector",
			"source_group": name,
			"cfg_type":     strings.TrimSpace(source.CfgType),
		},
	}
	criteria, unsupported := translateGroupCriteria(name, source.Criteria)
	if len(unsupported) > 0 {
		return TargetGroup{}, unsupported
	}
	if len(criteria) == 0 {
		return TargetGroup{}, []UnsupportedObject{{
			Kind:       "group",
			Name:       name,
			Reason:     "NeuVector group has no supported selector criteria; importing it would match no workloads",
			Suggestion: "Add namespace, service+domain, id, cluster, or label criteria, then rerun the migration preview.",
			Source:     map[string]any{"group": name, "criteria": []NVGroupCriterion{}},
		}}
	}
	target.Criteria = criteria
	return target, nil
}

func translateGroupCriteria(groupName string, criteria []NVGroupCriterion) ([]TargetGroupCriterion, []UnsupportedObject) {
	out := []TargetGroupCriterion{}
	unsupported := []UnsupportedObject{}
	domains := []string{}
	services := []string{}
	for _, criterion := range criteria {
		key := strings.ToLower(strings.TrimSpace(criterion.Key))
		op, opOK := normalizeGroupCriterionOp(criterion.Op)
		value := strings.TrimSpace(criterion.Value)
		switch key {
		case "domain", "namespace":
			if key == "domain" && op == "eq" {
				domains = append(domains, value)
				continue
			}
			if opOK && value != "" {
				out = append(out, TargetGroupCriterion{Key: "namespace", Op: op, Value: value})
				continue
			}
		case "service":
			if op == "eq" && value != "" {
				services = append(services, value)
				continue
			}
		case "cluster", "id":
			if opOK && value != "" {
				out = append(out, TargetGroupCriterion{Key: key, Op: op, Value: value})
				continue
			}
		case "label", "lable":
			if converted, ok := translateGroupLabelCriterion(criterion, op, opOK); ok {
				out = append(out, converted)
				continue
			}
		default:
			if translatedKey, ok := translateGroupLabelKey(criterion.Key); ok && opOK && value != "" {
				out = append(out, TargetGroupCriterion{Key: translatedKey, Op: op, Value: value})
				continue
			}
		}
		unsupported = append(unsupported, unsupportedGroupCriterion(groupName, criterion))
	}
	if len(services) > 0 {
		serviceCriteria, serviceUnsupported := translateServiceDomainCriteria(groupName, services, domains)
		unsupported = append(unsupported, serviceUnsupported...)
		out = append(out, serviceCriteria...)
	} else {
		for _, domain := range normalizeStrings(domains) {
			out = append(out, TargetGroupCriterion{Key: "namespace", Op: "eq", Value: domain})
		}
	}
	if len(unsupported) > 0 {
		return nil, []UnsupportedObject{{
			Kind:       "group",
			Name:       groupName,
			Reason:     "NeuVector group contains selector criteria that Constellation cannot safely enforce; the group was not imported",
			Suggestion: "Create an equivalent Constellation group with supported namespace, service+domain, id, cluster, or label selectors before applying DLP/WAF bindings.",
			Source: map[string]any{
				"group":                groupName,
				"unsupported_criteria": unsupportedCriteriaSources(unsupported),
			},
		}}
	}
	return dedupeGroupCriteria(out), nil
}

func translateServiceDomainCriteria(groupName string, services, domains []string) ([]TargetGroupCriterion, []UnsupportedObject) {
	normalizedDomains := normalizeStrings(domains)
	out := []TargetGroupCriterion{}
	unsupported := []UnsupportedObject{}
	for _, rawService := range normalizeStrings(services) {
		service, domain := splitNeuVectorService(rawService)
		if domain == "" && len(normalizedDomains) == 1 {
			domain = normalizedDomains[0]
		}
		if domain == "" || service == "" {
			unsupported = append(unsupported, unsupportedGroupCriterion(groupName, NVGroupCriterion{Key: "service", Op: "=", Value: rawService}))
			continue
		}
		if len(normalizedDomains) > 0 && !stringInSlice(domain, normalizedDomains) {
			unsupported = append(unsupported, unsupportedGroupCriterion(groupName, NVGroupCriterion{Key: "service", Op: "=", Value: rawService}))
			continue
		}
		out = append(out, TargetGroupCriterion{Key: "id", Op: "eq", Value: domain + "/" + service})
	}
	return out, unsupported
}

func splitNeuVectorService(value string) (string, string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	idx := strings.LastIndex(value, ".")
	if idx <= 0 || idx == len(value)-1 {
		return value, ""
	}
	return value[:idx], value[idx+1:]
}

func normalizeGroupCriterionOp(op string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "", "=", "eq":
		return "eq", true
	case "contains":
		return "contains", true
	case "regex":
		return "regex", true
	case "prefix":
		return "prefix", true
	default:
		return strings.ToLower(strings.TrimSpace(op)), false
	}
}

func translateGroupLabelCriterion(criterion NVGroupCriterion, op string, opOK bool) (TargetGroupCriterion, bool) {
	if !opOK {
		return TargetGroupCriterion{}, false
	}
	key, value, ok := strings.Cut(strings.TrimSpace(criterion.Value), "=")
	if !ok || strings.TrimSpace(key) == "" || strings.TrimSpace(value) == "" {
		return TargetGroupCriterion{}, false
	}
	if op == "regex" && strings.ToLower(strings.TrimSpace(criterion.Op)) == "prefix" {
		value = "^" + regexp.QuoteMeta(strings.TrimSpace(value))
	}
	return TargetGroupCriterion{Key: "label." + strings.TrimSpace(key), Op: op, Value: strings.TrimSpace(value)}, true
}

func translateGroupLabelKey(key string) (string, bool) {
	key = strings.TrimSpace(key)
	lower := strings.ToLower(key)
	switch {
	case strings.HasPrefix(lower, "label."):
		return "label." + strings.TrimSpace(key[len("label."):]), strings.TrimSpace(key[len("label."):]) != ""
	case strings.HasPrefix(lower, "label/"):
		return strings.TrimSpace(key[len("label/"):]), strings.TrimSpace(key[len("label/"):]) != ""
	case strings.Contains(key, "/"):
		return key, true
	default:
		return "", false
	}
}

func unsupportedGroupCriterion(groupName string, criterion NVGroupCriterion) UnsupportedObject {
	return UnsupportedObject{
		Kind:       "group_criterion",
		Name:       groupName,
		Reason:     fmt.Sprintf("unsupported selector criterion %s %s %q", criterion.Key, criterion.Op, criterion.Value),
		Suggestion: "Use namespace, exact service+domain, id, cluster, or label selectors.",
		Source: map[string]any{
			"key":   criterion.Key,
			"op":    criterion.Op,
			"value": criterion.Value,
		},
	}
}

func unsupportedCriteriaSources(items []UnsupportedObject) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, item.Source)
	}
	return out
}

func dedupeGroupCriteria(criteria []TargetGroupCriterion) []TargetGroupCriterion {
	seen := map[string]bool{}
	out := []TargetGroupCriterion{}
	for _, criterion := range criteria {
		key := strings.TrimSpace(criterion.Key)
		op := strings.TrimSpace(criterion.Op)
		value := strings.TrimSpace(criterion.Value)
		if key == "" || value == "" {
			continue
		}
		if strings.ToLower(strings.TrimSpace(op)) == "prefix" {
			op = "regex"
			value = "^" + regexp.QuoteMeta(value)
		}
		id := key + "\x00" + op + "\x00" + value
		if seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, TargetGroupCriterion{Key: key, Op: op, Value: value})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		if out[i].Op != out[j].Op {
			return out[i].Op < out[j].Op
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func normalizeGroupKind(source NVGroupConfig) string {
	cfgType := strings.ToLower(strings.TrimSpace(source.CfgType))
	kind := strings.ToLower(strings.TrimSpace(source.Kind))
	switch {
	case source.Learned || cfgType == "learned" || kind == "learned":
		return "learned"
	case cfgType == "federal" || cfgType == "fed" || kind == "federated" || kind == "federal":
		return "federated"
	default:
		return "ground"
	}
}

func normalizeGroupCfgType(source NVGroupConfig) string {
	cfgType := strings.ToLower(strings.TrimSpace(source.CfgType))
	switch cfgType {
	case "learned":
		return "learned"
	case "federal", "fed":
		return "fed"
	default:
		return "user"
	}
}

func normalizeGroupMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "learn", "learning", "discover", "discovery":
		return "discover"
	case "protect", "enforce", "enforced":
		return "protect"
	default:
		return "monitor"
	}
}

func stringInSlice(value string, values []string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func translateNetworkRule(source NVNetworkRule) (TargetNetworkRule, []UnsupportedObject, bool) {
	name := networkRuleName(source)
	from := strings.TrimSpace(source.From)
	to := strings.TrimSpace(source.To)
	if from == "" || to == "" {
		return TargetNetworkRule{}, []UnsupportedObject{unsupportedNetworkRule(source, name,
			"NeuVector network rule is missing a from or to group",
			"Create matching source and destination groups in Constellation, then rerun the migration preview.")}, false
	}
	if source.Disable {
		return TargetNetworkRule{}, []UnsupportedObject{unsupportedNetworkRule(source, name,
			"NeuVector network rule is disabled",
			"Disabled rules are preserved as skipped migration rows; enable the rule in NeuVector or create it manually in Constellation if it should be active.")}, false
	}
	action, actionOK := normalizeNetworkAction(source.Action)
	if !actionOK || action != "allow" {
		return TargetNetworkRule{}, []UnsupportedObject{unsupportedNetworkRule(source, name,
			"NeuVector network rule action cannot be represented by Constellation group allow edges",
			"Review deny or unknown-action rules manually and model them with explicit runtime enforcement controls before applying.")}, false
	}
	if !networkRuleApplicationsSupported(source.Applications) {
		return TargetNetworkRule{}, []UnsupportedObject{unsupportedNetworkRule(source, name,
			"NeuVector network rule uses L7 application matching, but Constellation group edges only enforce L3/L4 ports",
			"Create an equivalent application-aware runtime policy manually, or remove the application predicate before importing the group edge.")}, false
	}
	ports, err := parseNetworkPorts(source.Ports)
	if err != nil {
		return TargetNetworkRule{}, []UnsupportedObject{unsupportedNetworkRule(source, name,
			"NeuVector network rule ports could not be converted safely: "+err.Error(),
			"Use 'any' or a comma-separated list of tcp/port, udp/port, sctp/port, icmp, or bare TCP ports.")}, false
	}
	priority := int(source.Priority)
	if priority == 0 && source.ID > 0 {
		priority = int(source.ID)
	}
	return TargetNetworkRule{
		Name:         name,
		FromGroup:    from,
		ToGroup:      to,
		Ports:        ports,
		Mode:         "monitor",
		Comment:      strings.TrimSpace(source.Comment),
		Priority:     priority,
		SourceAction: action,
		Imported: map[string]string{
			"source":       "neuvector",
			"source_id":    networkRuleSourceID(source),
			"source_from":  from,
			"source_to":    to,
			"source_ports": strings.TrimSpace(source.Ports),
		},
	}, nil, true
}

func normalizeNetworkAction(action string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "", "allow", "accept":
		return "allow", true
	case "deny", "drop", "reject", "block":
		return "deny", true
	default:
		return strings.ToLower(strings.TrimSpace(action)), false
	}
}

func networkRuleApplicationsSupported(applications []string) bool {
	for _, app := range applications {
		switch strings.ToLower(strings.TrimSpace(app)) {
		case "", "any":
			continue
		default:
			return false
		}
	}
	return true
}

func parseNetworkPorts(raw string) ([]TargetPortSpec, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return []TargetPortSpec{}, nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\t' || r == ' '
	})
	if len(parts) == 0 {
		return []TargetPortSpec{}, nil
	}
	out := make([]TargetPortSpec, 0, len(parts))
	for _, part := range parts {
		port, any, err := parseNetworkPort(part)
		if err != nil {
			return nil, err
		}
		if any {
			if len(parts) != 1 {
				return nil, fmt.Errorf("any cannot be mixed with specific ports")
			}
			return []TargetPortSpec{}, nil
		}
		out = append(out, port)
	}
	return dedupePortSpecs(out), nil
}

func parseNetworkPort(raw string) (TargetPortSpec, bool, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return TargetPortSpec{}, false, fmt.Errorf("empty port token")
	}
	if value == "any" {
		return TargetPortSpec{}, true, nil
	}
	if strings.Contains(value, "-") {
		return TargetPortSpec{}, false, fmt.Errorf("port ranges are not supported")
	}
	protocol := "tcp"
	portText := value
	if left, right, ok := cutAny(value, "/", ":"); ok {
		protocol = left
		portText = right
	}
	protocol, ok := normalizeNetworkProtocol(protocol)
	if !ok {
		return TargetPortSpec{}, false, fmt.Errorf("unsupported protocol %q", protocol)
	}
	if portText == "" {
		if protocol == "icmp" {
			return TargetPortSpec{Protocol: strings.ToUpper(protocol), Port: 0}, false, nil
		}
		return TargetPortSpec{}, false, fmt.Errorf("missing port for protocol %s", protocol)
	}
	if portText == protocol && protocol == "icmp" {
		return TargetPortSpec{Protocol: strings.ToUpper(protocol), Port: 0}, false, nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		if value == "icmp" {
			return TargetPortSpec{Protocol: "ICMP", Port: 0}, false, nil
		}
		return TargetPortSpec{}, false, fmt.Errorf("invalid port %q", portText)
	}
	if port <= 0 || port > 65535 {
		return TargetPortSpec{}, false, fmt.Errorf("port out of range")
	}
	return TargetPortSpec{Protocol: strings.ToUpper(protocol), Port: port}, false, nil
}

func normalizeNetworkProtocol(protocol string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "", "tcp":
		return "tcp", true
	case "udp":
		return "udp", true
	case "sctp":
		return "sctp", true
	case "icmp":
		return "icmp", true
	default:
		return strings.ToLower(strings.TrimSpace(protocol)), false
	}
}

func cutAny(value string, separators ...string) (string, string, bool) {
	best := -1
	for _, sep := range separators {
		if idx := strings.Index(value, sep); idx >= 0 && (best == -1 || idx < best) {
			best = idx
		}
	}
	if best < 0 {
		return "", "", false
	}
	return strings.TrimSpace(value[:best]), strings.TrimSpace(value[best+1:]), true
}

func mergeNetworkRule(base, next TargetNetworkRule) TargetNetworkRule {
	if next.Priority > 0 && (base.Priority == 0 || next.Priority < base.Priority) {
		base.Priority = next.Priority
	}
	if len(base.Ports) == 0 || len(next.Ports) == 0 {
		base.Ports = []TargetPortSpec{}
	} else {
		base.Ports = dedupePortSpecs(append(base.Ports, next.Ports...))
	}
	if base.Comment == "" {
		base.Comment = next.Comment
	} else if next.Comment != "" && next.Comment != base.Comment {
		base.Comment += "; " + next.Comment
	}
	return base
}

func dedupePortSpecs(ports []TargetPortSpec) []TargetPortSpec {
	seen := map[string]bool{}
	out := []TargetPortSpec{}
	for _, port := range ports {
		protocol, ok := normalizeNetworkProtocol(port.Protocol)
		if !ok {
			continue
		}
		spec := TargetPortSpec{Protocol: strings.ToUpper(protocol), Port: port.Port}
		key := spec.Protocol + "\x00" + strconv.Itoa(spec.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, spec)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func networkRuleName(rule NVNetworkRule) string {
	if rule.ID > 0 {
		return fmt.Sprintf("nv-network-%d", rule.ID)
	}
	if strings.TrimSpace(rule.Comment) != "" {
		return "nv-network-" + slug(rule.Comment)
	}
	from := slug(rule.From)
	to := slug(rule.To)
	if from != "" && to != "" {
		return "nv-network-" + from + "-to-" + to
	}
	return "nv-network-rule"
}

func networkRuleSourceID(rule NVNetworkRule) string {
	if rule.ID > 0 {
		return fmt.Sprintf("%d", rule.ID)
	}
	if rule.Priority > 0 {
		return fmt.Sprintf("priority:%d", rule.Priority)
	}
	return firstNonEmpty(rule.Comment, rule.From+"->"+rule.To)
}

func unsupportedNetworkRule(rule NVNetworkRule, name, reason, suggestion string) UnsupportedObject {
	return UnsupportedObject{
		Kind:       "network_rule",
		Name:       name,
		Reason:     reason,
		Suggestion: suggestion,
		Source: map[string]any{
			"id":           rule.ID,
			"from":         rule.From,
			"to":           rule.To,
			"ports":        rule.Ports,
			"action":       rule.Action,
			"applications": rule.Applications,
			"disable":      rule.Disable,
			"priority":     rule.Priority,
		},
	}
}

func translateDPISensor(candidate dpiSensorCandidate, category string, names map[string]int) ([]TargetDPIRule, []UnsupportedObject) {
	sensor := candidate.Sensor
	sensorName := firstNonEmpty(sensor.Name, "neuvector-"+category+"-sensor")
	out := make([]TargetDPIRule, 0, len(sensor.RuleList))
	unsupported := []UnsupportedObject{}
	for i, rule := range sensor.RuleList {
		rulePath := dpiRuleSourcePath(candidate.SourcePath, i)
		ruleName := firstNonEmpty(rule.Name, fmt.Sprintf("rule-%d", rule.ID), "rule")
		patterns, skipped := translateDPIPatternsDetailed(rule.Patterns, category, sensorName, ruleName, rulePath, candidate.SourceCfgType, rule.CfgType, candidate.Federated)
		unsupported = append(unsupported, skipped...)
		if len(patterns) == 0 {
			unsupported = append(unsupported, unsupportedDPIRule(candidate, category, sensorName, rule, ruleName, rulePath))
			continue
		}
		name := uniqueDPIRuleName(fmt.Sprintf("nv-%s-%s-%s", category, slug(sensorName), slug(ruleName)), names)
		sourceID := ruleName
		if rule.ID > 0 {
			sourceID = fmt.Sprintf("%s:%d", sourceID, rule.ID)
		}
		sourceCfgType := strings.TrimSpace(candidate.SourceCfgType)
		sourceRuleCfgType := strings.TrimSpace(rule.CfgType)
		federated := candidate.Federated || cfgTypeFederated(rule.CfgType)
		description := fmt.Sprintf("NeuVector %s sensor %s rule %s", strings.ToUpper(category), sensorName, ruleName)
		if rulePath != "" {
			description += fmt.Sprintf(" (source: %s)", rulePath)
		}
		imported := map[string]string{
			"source":             "neuvector",
			"source_sensor":      sensorName,
			"source_rule":        sourceID,
			"source_path":        rulePath,
			"source_sensor_path": candidate.SourcePath,
			"category":           category,
		}
		if sourceCfgType != "" {
			imported["source_cfg_type"] = sourceCfgType
		}
		if sourceRuleCfgType != "" {
			imported["source_rule_cfg_type"] = sourceRuleCfgType
		}
		if federated {
			imported["federated"] = "true"
		}
		out = append(out, TargetDPIRule{
			Name:              name,
			Category:          category,
			ApplyDir:          defaultDPIApplyDir(category),
			Severity:          defaultDPISeverity(category),
			Mode:              "monitor",
			Patterns:          patterns,
			Description:       description,
			SourceSensor:      sensorName,
			SourceGroups:      normalizeStrings(sensor.GroupList),
			SourcePath:        rulePath,
			SourceCfgType:     sourceCfgType,
			SourceRuleCfgType: sourceRuleCfgType,
			Federated:         federated,
			Imported:          imported,
		})
	}
	return out, unsupported
}

func translateDPIPatterns(patterns []DPICriterion, category string) []DPIPatternSpec {
	out, _ := translateDPIPatternsDetailed(patterns, category, "", "", "", "", "", false)
	return out
}

func translateDPIPatternsDetailed(patterns []DPICriterion, category, sensorName, ruleName, rulePath, sourceCfgType, sourceRuleCfgType string, federated bool) ([]DPIPatternSpec, []UnsupportedObject) {
	out := make([]DPIPatternSpec, 0, len(patterns))
	unsupported := []UnsupportedObject{}
	for i, pattern := range patterns {
		key := strings.ToLower(strings.TrimSpace(pattern.Key))
		patternPath := dpiPatternSourcePath(rulePath, i)
		if key != "" && key != "pattern" {
			unsupported = append(unsupported, unsupportedDPIPattern(category, sensorName, ruleName, patternPath, sourceCfgType, sourceRuleCfgType, federated, pattern, "unsupported pattern key", "Only NeuVector pattern criteria can be converted automatically. Recreate this selector manually if it changes matching semantics."))
			continue
		}
		value := strings.TrimSpace(pattern.Value)
		if value == "" {
			unsupported = append(unsupported, unsupportedDPIPattern(category, sensorName, ruleName, patternPath, sourceCfgType, sourceRuleCfgType, federated, pattern, "empty pattern value", "Add a non-empty pattern before importing or remove the empty NeuVector criterion."))
			continue
		}
		op := normalizeDPIOp(pattern.Op)
		if !supportedDPIOp(op) {
			unsupported = append(unsupported, unsupportedDPIPattern(category, sensorName, ruleName, patternPath, sourceCfgType, sourceRuleCfgType, federated, pattern, "unsupported pattern operator", "Use regex or not_regex in Constellation, or recreate this NeuVector criterion manually."))
			continue
		}
		if category == "dlp" {
			value = wildCardToRegexp(value)
		}
		out = append(out, DPIPatternSpec{
			Pattern: value,
			Op:      op,
			Context: normalizeDPIContext(pattern.Context),
		})
	}
	return out, unsupported
}

func translateDPIGroupBindings(groups []DPISensorGroup, category string) []TargetDPIBinding {
	out := make([]TargetDPIBinding, 0, len(groups))
	for _, group := range groups {
		name := strings.TrimSpace(group.Name)
		sourceSensors := normalizeDPISensorSettings(group.Sensors)
		if name == "" || len(sourceSensors) == 0 || !dpiGroupEnabled(group) {
			continue
		}
		out = append(out, TargetDPIBinding{
			SourceGroup:   name,
			Category:      category,
			SensorKind:    category,
			SourceSensors: sourceSensors,
			Imported: map[string]string{
				"source":        "neuvector",
				"source_group":  name,
				"source_sensor": strings.Join(sourceSensors, ","),
				"category":      category,
				"cfg_type":      strings.TrimSpace(group.CfgType),
			},
		})
	}
	return out
}

func unsupportedDPIRule(candidate dpiSensorCandidate, category, sensorName string, rule DPIRule, ruleName, rulePath string) UnsupportedObject {
	sourceCfgType := strings.TrimSpace(candidate.SourceCfgType)
	sourceRuleCfgType := strings.TrimSpace(rule.CfgType)
	federated := candidate.Federated || cfgTypeFederated(rule.CfgType)
	return UnsupportedObject{
		Kind:       "dpi_rule",
		Name:       firstNonEmpty(ruleName, sensorName, "neuvector-"+category+"-rule"),
		Reason:     "no supported patterns",
		Suggestion: "Add at least one supported pattern criterion, or recreate this NeuVector DLP/WAF rule manually.",
		Source: dpiUnsupportedSource(category, sensorName, ruleName, rulePath, sourceCfgType, sourceRuleCfgType, federated, map[string]any{
			"id":       rule.ID,
			"patterns": rule.Patterns,
		}),
	}
}

func unsupportedDPIPattern(category, sensorName, ruleName, patternPath, sourceCfgType, sourceRuleCfgType string, federated bool, pattern DPICriterion, reason, suggestion string) UnsupportedObject {
	return UnsupportedObject{
		Kind:       "dpi_pattern",
		Name:       firstNonEmpty(ruleName, sensorName, "neuvector-"+category+"-pattern"),
		Reason:     reason,
		Suggestion: suggestion,
		Source: dpiUnsupportedSource(category, sensorName, ruleName, patternPath, sourceCfgType, sourceRuleCfgType, federated, map[string]any{
			"key":     pattern.Key,
			"value":   pattern.Value,
			"op":      pattern.Op,
			"context": pattern.Context,
		}),
	}
}

func dpiUnsupportedSource(category, sensorName, ruleName, sourcePath, sourceCfgType, sourceRuleCfgType string, federated bool, extra map[string]any) map[string]any {
	source := map[string]any{
		"category":      category,
		"source_sensor": sensorName,
		"source_rule":   ruleName,
		"source_path":   sourcePath,
		"federated":     federated,
	}
	if trimmed := strings.TrimSpace(sourceCfgType); trimmed != "" {
		source["source_cfg_type"] = trimmed
	}
	if trimmed := strings.TrimSpace(sourceRuleCfgType); trimmed != "" {
		source["source_rule_cfg_type"] = trimmed
	}
	for key, value := range extra {
		source[key] = value
	}
	return source
}

func dpiDocumentPath(index, total int) string {
	if total <= 1 {
		return ""
	}
	return fmt.Sprintf("documents[%d]", index)
}

func joinSourcePath(prefix, path string) string {
	prefix = strings.TrimSpace(prefix)
	path = strings.TrimSpace(path)
	switch {
	case prefix == "":
		return path
	case path == "":
		return prefix
	default:
		return prefix + "." + path
	}
}

func dpiRuleSourcePath(sensorPath string, ruleIndex int) string {
	sensorPath = strings.TrimSpace(sensorPath)
	if sensorPath == "" {
		return fmt.Sprintf("rules[%d]", ruleIndex)
	}
	if strings.HasSuffix(sensorPath, ".rules") || strings.HasSuffix(sensorPath, "_rules") {
		return fmt.Sprintf("%s[%d]", sensorPath, ruleIndex)
	}
	return fmt.Sprintf("%s.rules[%d]", sensorPath, ruleIndex)
}

func dpiPatternSourcePath(rulePath string, patternIndex int) string {
	rulePath = strings.TrimSpace(rulePath)
	if rulePath == "" {
		return fmt.Sprintf("patterns[%d]", patternIndex)
	}
	return fmt.Sprintf("%s.patterns[%d]", rulePath, patternIndex)
}

func cfgTypeFederated(values ...string) bool {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "fed", "federal", "federated":
			return true
		}
	}
	return false
}

func normalizeDPISensorSettings(settings []DPISensorSetting) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(settings))
	for _, setting := range settings {
		name := strings.TrimSpace(setting.Name)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func dpiGroupEnabled(group DPISensorGroup) bool {
	return group.Status == nil || *group.Status
}

func dpiCategoryFromKind(kind string) string {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "nvdlpsecurityrule", "nvdlpsecurityrulelist":
		return "dlp"
	case "nvwafsecurityrule", "nvwafsecurityrulelist":
		return "waf"
	default:
		return ""
	}
}

func inferDPICategory(sensors []DPISensor) string {
	hasWAF, hasDLP := false, false
	for _, sensor := range sensors {
		if strings.Contains(strings.ToLower(sensor.Name), "waf") {
			hasWAF = true
		}
		if strings.Contains(strings.ToLower(sensor.Name), "dlp") {
			hasDLP = true
		}
		for _, rule := range sensor.RuleList {
			name := strings.ToLower(rule.Name)
			if rule.ID >= 40000 && rule.ID < 50000 || strings.Contains(name, "waf") {
				hasWAF = true
			}
			if rule.ID >= 20000 && rule.ID < 40000 || strings.Contains(name, "dlp") {
				hasDLP = true
			}
		}
	}
	switch {
	case hasWAF && !hasDLP:
		return "waf"
	case hasDLP && !hasWAF:
		return "dlp"
	default:
		return ""
	}
}

func uniqueDPIRuleName(base string, names map[string]int) string {
	base = strings.Trim(base, "-")
	if base == "" {
		base = "nv-dpi-rule"
	}
	names[base]++
	if names[base] == 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, names[base])
}

func defaultDPIApplyDir(category string) int16 {
	if category == "waf" {
		return 2
	}
	return 1
}

func defaultDPISeverity(category string) int16 {
	if category == "waf" {
		return 6
	}
	return 5
}

func normalizeDPIOp(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "", "regex", "regexcontainsany", "regexcontainsanyex":
		return "regex"
	case "!regex", "not_regex", "notregex", "not", "!regexcontainsany", "!regexcontainsanyex":
		return "not_regex"
	default:
		return strings.ToLower(strings.TrimSpace(op))
	}
}

func supportedDPIOp(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "regex", "not_regex":
		return true
	default:
		return false
	}
}

func normalizeDPIContext(context string) string {
	switch strings.ToLower(strings.TrimSpace(context)) {
	case "url":
		return "uri"
	case "head":
		return "header"
	default:
		return strings.ToLower(strings.TrimSpace(context))
	}
}

var dlpWildcardPattern = regexp.MustCompile(`(^|\pL|\pN|\s)(\?+|\*)`)

func wildCardToRegexp(pattern string) string {
	return dlpWildcardPattern.ReplaceAllStringFunc(pattern, func(match string) string {
		if len(match) == 1 {
			switch match[0] {
			case '*':
				return ".*"
			case '?':
				return "."
			default:
				return match
			}
		}
		if len(match) == 2 {
			switch match[1] {
			case '*':
				return string(match[0]) + ".*"
			case '?':
				if match[0] == '?' {
					return ".*"
				}
				return string(match[0]) + "."
			default:
				return match
			}
		}
		if match[1] == '?' {
			if match[0] == '?' {
				return ".*"
			}
			return string(match[0]) + ".*"
		}
		return match
	})
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

func processProfileFromNvSecurityRule(doc NvSecurityRuleDocument) ProcessProfile {
	group := groupNameFromSelector(doc.Spec.Target.Selector)
	if group == "" {
		group = groupNameFromSelector(doc.Spec.Selector)
	}
	if group == "" {
		group = strings.TrimSpace(doc.Metadata.Name)
	}
	mode := ""
	baseline := ""
	if doc.Spec.ProcessProfile != nil {
		if doc.Spec.ProcessProfile.Mode != nil {
			mode = *doc.Spec.ProcessProfile.Mode
		}
		if doc.Spec.ProcessProfile.Baseline != nil {
			baseline = *doc.Spec.ProcessProfile.Baseline
		}
	}
	if mode == "" && doc.Spec.Target.PolicyMode != nil {
		mode = *doc.Spec.Target.PolicyMode
	}
	return ProcessProfile{
		Group:       group,
		Name:        doc.Metadata.Name,
		Mode:        mode,
		Baseline:    baseline,
		Description: "",
		Process:     append([]ProcessProfileEntry(nil), doc.Spec.ProcessRule...),
	}
}

func translateProcessProfile(profile ProcessProfile) (TargetProcessProfile, []UnsupportedObject) {
	group := processProfileGroup(profile)
	rules := processProfileRules(profile)
	if strings.TrimSpace(group) == "" {
		return TargetProcessProfile{}, []UnsupportedObject{{
			Kind:       "process_profile",
			Name:       firstNonEmpty(strings.TrimSpace(profile.Name), "neuvector-process-profile"),
			Reason:     "NeuVector process profile is missing a target group",
			Suggestion: "Add a group name to the NeuVector process profile export or import the rules manually for each target workload.",
			Source:     map[string]any{"rules": len(rules), "mode": profile.Mode, "baseline": profile.Baseline},
		}}
	}
	converted := make([]TargetProcessProfileRule, 0, len(rules))
	unsupported := []UnsupportedObject{}
	seen := map[string]int{}
	for _, rule := range rules {
		target, skipped, ok := translateProcessProfileRule(profile, group, rule)
		if !ok {
			unsupported = append(unsupported, skipped)
			continue
		}
		key := target.Name + "\x00" + target.Path
		if idx, ok := seen[key]; ok {
			if converted[idx].Action != target.Action {
				unsupported = append(unsupported, unsupportedProcessRule(group, rule,
					"NeuVector process profile contains conflicting actions for the same name/path",
					"Split the process rules or resolve the action conflict before importing."))
				continue
			}
			converted[idx] = mergeProcessProfileRule(converted[idx], target)
			continue
		}
		seen[key] = len(converted)
		converted = append(converted, target)
	}
	sort.SliceStable(converted, func(i, j int) bool {
		if converted[i].Path != converted[j].Path {
			return converted[i].Path < converted[j].Path
		}
		return converted[i].Name < converted[j].Name
	})
	mode := normalizeProcessProfileMode(profile.Mode)
	if mode == "" && normalizeProcessProfileBaseline(profile.Baseline) == "basic" {
		mode = "monitor"
	}
	if mode == "" {
		mode = "monitor"
	}
	return TargetProcessProfile{
		Group:       group,
		Mode:        mode,
		Baseline:    normalizeProcessProfileBaseline(profile.Baseline),
		CfgType:     strings.TrimSpace(profile.CfgType),
		Description: fmt.Sprintf("NeuVector process profile %s", group),
		Rules:       converted,
		Imported:    map[string]string{"source": "neuvector", "source_id": group},
	}, unsupported
}

func translateProcessProfileRule(profile ProcessProfile, group string, rule ProcessProfileEntry) (TargetProcessProfileRule, UnsupportedObject, bool) {
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Path = strings.TrimSpace(rule.Path)
	rule.Action = strings.TrimSpace(rule.Action)
	if rule.Disabled || rule.Disable {
		return TargetProcessProfileRule{}, unsupportedProcessRule(group, rule,
			"NeuVector process rule is disabled",
			"Disabled process rules are preserved as skipped migration rows; enable the rule in NeuVector or create it manually in Constellation if it should be active."), false
	}
	if rule.Name == "" && rule.Path == "" {
		return TargetProcessProfileRule{}, unsupportedProcessRule(group, rule,
			"NeuVector process rule is missing a process name or path",
			"Add a process name or absolute path before importing this rule."), false
	}
	if rule.Name == "*" || rule.Path == "*" || rule.Path == "/*" {
		return TargetProcessProfileRule{}, unsupportedProcessRule(group, rule,
			"NeuVector wildcard process rule cannot be represented safely by Constellation process baselines",
			"Recreate this broad allow/deny rule manually after reviewing its blast radius."), false
	}
	action, ok := normalizeProcessRuleAction(rule.Action)
	if !ok {
		return TargetProcessProfileRule{}, unsupportedProcessRule(group, rule,
			"NeuVector process rule action cannot be represented by Constellation process baselines",
			"Only allow and deny process profile rules are imported automatically."), false
	}
	cfgType := strings.TrimSpace(rule.CfgType)
	if cfgType == "" {
		cfgType = strings.TrimSpace(profile.CfgType)
	}
	return TargetProcessProfileRule{
		Name:        rule.Name,
		Path:        rule.Path,
		User:        strings.TrimSpace(rule.User),
		SHA256:      strings.ToLower(strings.TrimSpace(rule.SHA256)),
		ParentName:  strings.TrimSpace(rule.ParentName),
		Action:      action,
		CfgType:     cfgType,
		UUID:        strings.TrimSpace(rule.UUID),
		AllowUpdate: rule.AllowFileUpdate,
		Enabled:     true,
		Description: processRuleDescription(group, rule),
	}, UnsupportedObject{}, true
}

func processProfileGroup(profile ProcessProfile) string {
	return firstNonEmpty(profile.Group, profile.Name)
}

func processProfileRules(profile ProcessProfile) []ProcessProfileEntry {
	out := make([]ProcessProfileEntry, 0, len(profile.ProcessList)+len(profile.Process)+len(profile.Rules))
	out = append(out, profile.ProcessList...)
	out = append(out, profile.Process...)
	out = append(out, profile.Rules...)
	return out
}

func normalizeProcessRuleAction(action string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return "allow", true
	case "deny", "alert":
		return "deny", true
	default:
		return "", false
	}
}

func normalizeProcessProfileMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "protect", "enforce", "enforced":
		return "enforce"
	case "learn", "learning", "discover", "discovery":
		return "learn"
	case "monitor", "evaluate", "evaluation":
		return "monitor"
	default:
		return ""
	}
}

func normalizeProcessProfileBaseline(baseline string) string {
	switch strings.ToLower(strings.TrimSpace(baseline)) {
	case "basic":
		return "basic"
	case "zero-drift", "zerodrift", "default", "shield":
		return "zero-drift"
	default:
		return ""
	}
}

func mergeProcessProfileRule(base, next TargetProcessProfileRule) TargetProcessProfileRule {
	if base.User == "" {
		base.User = next.User
	}
	if base.SHA256 == "" {
		base.SHA256 = next.SHA256
	}
	if base.ParentName == "" {
		base.ParentName = next.ParentName
	}
	if base.CfgType == "" {
		base.CfgType = next.CfgType
	}
	if base.UUID == "" {
		base.UUID = next.UUID
	}
	if next.AllowUpdate {
		base.AllowUpdate = true
	}
	if base.Description == "" {
		base.Description = next.Description
	}
	return base
}

func processRuleDescription(group string, rule ProcessProfileEntry) string {
	parts := []string{"NeuVector process profile", strings.TrimSpace(group)}
	if id := strings.TrimSpace(rule.UUID); id != "" {
		parts = append(parts, "rule "+id)
	}
	return strings.Join(parts, " ")
}

func unsupportedProcessRule(group string, rule ProcessProfileEntry, reason string, suggestion string) UnsupportedObject {
	name := firstNonEmpty(strings.TrimSpace(rule.Name), strings.TrimSpace(rule.Path), "neuvector-process-rule")
	return UnsupportedObject{
		Kind:       "process_profile",
		Name:       name,
		Reason:     reason,
		Suggestion: suggestion,
		Source: map[string]any{
			"group":  strings.TrimSpace(group),
			"name":   strings.TrimSpace(rule.Name),
			"path":   strings.TrimSpace(rule.Path),
			"action": strings.TrimSpace(rule.Action),
		},
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
	hostIPC             bool
	hostPID             bool
	requireReadOnlyRoot bool
	requireNonRoot      bool
	disallowLatestTag   bool
	disallowImplicitTag bool
	requireDigest       bool
	requireSignature    bool
	allowedRegistries   []string
	namespaces          []string
	vulnerabilityGate   string
	secretGate          bool
	misconfigGate       string
}

func translateAdmissionProfileRules(r AdmissionRule) []admission.AdmissionProfileRule {
	converted := convertedAdmissionCriteria{}
	unsupported := make([]AdmissionCriterion, 0)
	for _, c := range flattenAdmissionCriteria(r.Criteria) {
		if !converted.add(c) {
			unsupported = append(unsupported, c)
		}
	}

	out := []admission.AdmissionProfileRule{}
	if converted.enforceable() {
		name := profileRuleName(r, "")
		out = append(out, admission.AdmissionProfileRule{
			Name:        name,
			Description: profileRuleDescription(r, ""),
			Engine:      "constellation-admission",
			Category:    converted.category(),
			Mode:        admissionRuleMode(r),
			Enabled:     !admissionRuleDisabled(r),
			SpecYAML:    emitAdmissionProfileRuleYAML(r, converted, name),
		})
	}
	if len(unsupported) > 0 || !converted.enforceable() {
		reviewCriteria := unsupported
		if len(reviewCriteria) == 0 {
			reviewCriteria = r.Criteria
		}
		out = append(out, manualReviewAdmissionProfileRule(r, reviewCriteria))
	}
	return out
}

func (c *convertedAdmissionCriteria) add(crit AdmissionCriterion) bool {
	key := normalizeNeuVectorKey(criterionKey(crit))
	value := strings.ToLower(strings.TrimSpace(crit.Value))

	switch {
	case key == "namespace" || key == "domain":
		if values := exactCriterionValues(crit); len(values) > 0 {
			c.namespaces = append(c.namespaces, values...)
			return true
		}
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
	case key == "hostipc" || key == "shareipcwithhost":
		if criterionBoolTrue(crit) {
			c.hostIPC = true
			return true
		}
	case key == "sharenetwithhost":
		if criterionBoolTrue(crit) {
			c.hostNetwork = true
			return true
		}
	case key == "sharepidwithhost":
		if criterionBoolTrue(crit) {
			c.hostPID = true
			return true
		}
	case key == "runasprivileged":
		if criterionBoolTrue(crit) {
			c.privileged = true
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
		if values := exactCriterionValues(crit); len(values) > 0 {
			c.allowedRegistries = append(c.allowedRegistries, values...)
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
	return c.enforceable() || len(c.namespaces) > 0
}

func (c convertedAdmissionCriteria) enforceable() bool {
	return c.privileged ||
		c.hostNetwork ||
		c.hostIPC ||
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
		"action": admissionRuleAction(r),
	}
	if len(c.namespaces) > 0 {
		spec["match"].(map[string]any)["namespaces"] = normalizeStrings(c.namespaces)
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
	if c.hostIPC {
		conditions = append(conditions, map[string]any{"field": "spec.hostIPC", "equals": true})
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
			"key":   criterionKey(c),
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
	if admissionRuleDisabled(r) {
		return "monitor"
	}
	switch strings.ToLower(strings.TrimSpace(r.RuleMode)) {
	case "protect", "enforce":
		return "enforce"
	case "monitor":
		return "monitor"
	}
	if admissionRuleAction(r) == "allow" {
		return "enforce"
	}
	return "enforce"
}

func admissionRuleAction(r AdmissionRule) string {
	switch strings.ToLower(strings.TrimSpace(firstNonEmpty(r.Action, r.RuleType))) {
	case "allow", "except", "exception":
		return "allow"
	default:
		return "deny"
	}
}

func admissionRuleDisabled(r AdmissionRule) bool {
	return r.Disabled || r.Disable
}

func profileRuleName(r AdmissionRule, suffix string) string {
	base := fmt.Sprintf("nv-admission-%d", r.ID)
	if desc := firstNonEmpty(r.Desc, r.Comment); desc != "" {
		base = fmt.Sprintf("nv-%d-%s", r.ID, slug(desc))
	}
	if suffix != "" {
		return base + "-" + suffix
	}
	return base
}

func profileRuleDescription(r AdmissionRule, note string) string {
	desc := strings.TrimSpace(firstNonEmpty(r.Desc, r.Comment))
	if desc == "" {
		desc = fmt.Sprintf("NeuVector admission rule %d", r.ID)
	}
	if note == "" {
		return desc
	}
	return desc + " (" + note + ")"
}

func criterionKey(c AdmissionCriterion) string {
	return firstNonEmpty(c.Key, c.Name, c.Type)
}

func flattenAdmissionCriteria(criteria []AdmissionCriterion) []AdmissionCriterion {
	out := []AdmissionCriterion{}
	var walk func(AdmissionCriterion)
	walk = func(c AdmissionCriterion) {
		if criterionKey(c) != "" || c.Value != "" || c.Op != "" {
			out = append(out, c)
		}
		for _, sub := range c.SubCriteria {
			walk(sub)
		}
	}
	for _, c := range criteria {
		walk(c)
	}
	return out
}

func normalizeNeuVectorKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	replacer := strings.NewReplacer("_", "", "-", "", " ", "", ".", "")
	return replacer.Replace(s)
}

func exactCriterionValues(c AdmissionCriterion) []string {
	op := strings.ToLower(strings.TrimSpace(c.Op))
	if op == "regex" || op == "!regex" || strings.Contains(op, "regex") {
		return nil
	}
	raw := strings.TrimSpace(c.Value)
	if raw == "" || looksLikeRegex(raw) {
		return nil
	}
	out := []string{}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\t' }) {
		if item := strings.TrimSpace(part); item != "" {
			out = append(out, item)
		}
	}
	return normalizeStrings(out)
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
	return strings.ContainsAny(value, "*+?[]()|^$")
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
