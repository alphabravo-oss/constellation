package neuvector

import (
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/pkg/admission"
)

func TestConvertNativeAdmissionRulesMapsDenyAndException(t *testing.T) {
	raw := []byte(`rules:
  - id: 11
    comment: Allow platform namespace exception
    rule_type: exception
    disable: false
    criteria:
      - name: namespace
        op: containsAny
        value: kube-system, neuvector
      - name: runAsPrivileged
        op: =
        value: true
  - id: 12
    comment: Deny privileged from external registry
    rule_type: deny
    rule_mode: protect
    criteria:
      - name: runAsPrivileged
        op: =
        value: true
      - name: imageRegistry
        op: =
        value: registry.corp/
`)
	policies, err := Convert(raw)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("policy count=%d want 2: %+v", len(policies), policies)
	}

	exception := policies[0]
	if exception.Name != "nv-11-allow-platform-namespace-exception" ||
		exception.Mode != "enforce" ||
		!exception.Enabled ||
		!strings.Contains(exception.SpecYAML, "action: allow") ||
		!strings.Contains(exception.SpecYAML, "- kube-system") ||
		!strings.Contains(exception.SpecYAML, "- neuvector") {
		t.Fatalf("unexpected exception policy: %+v\n%s", exception, exception.SpecYAML)
	}
	rule, supported, err := admission.RuleFromYAML(exception.Name, exception.Name, exception.Description, exception.Mode, exception.SpecYAML)
	if err != nil {
		t.Fatalf("exception RuleFromYAML: %v\n%s", err, exception.SpecYAML)
	}
	if !supported || rule.Effect != admission.EffectAllow || rule.Mode != "enforce" {
		t.Fatalf("exception rule not active allow carve-out: supported=%v rule=%+v", supported, rule)
	}

	deny := policies[1]
	if deny.Name != "nv-12-deny-privileged-from-external-registry" ||
		deny.Mode != "enforce" ||
		deny.Category != "admission" ||
		!strings.Contains(deny.SpecYAML, "allowedRegistries") ||
		!strings.Contains(deny.SpecYAML, "registry.corp/") {
		t.Fatalf("unexpected deny policy: %+v\n%s", deny, deny.SpecYAML)
	}
	rule, supported, err = admission.RuleFromYAML(deny.Name, deny.Name, deny.Description, deny.Mode, deny.SpecYAML)
	if err != nil {
		t.Fatalf("deny RuleFromYAML: %v\n%s", err, deny.SpecYAML)
	}
	if !supported || rule.Effect != admission.EffectDeny {
		t.Fatalf("deny rule not supported deny: supported=%v rule=%+v", supported, rule)
	}
}

func TestConvertNativeAdmissionDisabledRuleIsMonitorDisabled(t *testing.T) {
	raw := []byte(`rules:
  - id: 13
    comment: Disabled host namespace rule
    rule_type: deny
    rule_mode: protect
    disable: true
    criteria:
      - name: shareNetWithHost
        op: =
        value: true
`)
	policies, err := Convert(raw)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("policy count=%d want 1", len(policies))
	}
	if policies[0].Enabled || policies[0].Mode != "monitor" {
		t.Fatalf("disabled rule should import disabled/monitor: %+v", policies[0])
	}
}

func TestConvertNativeAdmissionScopeOnlyExceptionRequiresManualReview(t *testing.T) {
	raw := []byte(`rules:
  - id: 14
    comment: Namespace-only exception
    rule_type: exception
    criteria:
      - name: namespace
        op: =
        value: kube-system
`)
	policies, err := Convert(raw)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("policy count=%d want 1", len(policies))
	}
	if policies[0].Engine != "manual-review" || policies[0].Enabled {
		t.Fatalf("scope-only exception must stay manual-review, got %+v", policies[0])
	}
	if !strings.Contains(policies[0].SpecYAML, "Namespace-only exception") && !strings.Contains(policies[0].SpecYAML, "namespace") {
		t.Fatalf("manual review spec lost source context: %s", policies[0].SpecYAML)
	}
}

func TestConvertDPIRulesFromDLPAndWAFSecurityRuleList(t *testing.T) {
	raw := []byte(`kind: List
items:
  - apiVersion: neuvector.com/v1
    kind: NvDlpSecurityRule
    metadata:
      name: pii-sensor
    spec:
      sensor:
        name: pii-sensor
        comment: PII detector
        rules:
          - name: ssn
            id: 20001
            patterns:
              - key: pattern
                op: regex
                value: "[0-9]{3}-[0-9]{2}-[0-9]{4}"
                context: body
  - apiVersion: neuvector.com/v1
    kind: NvWafSecurityRule
    metadata:
      name: waf-sensor
    spec:
      sensor:
        name: waf-sensor
        comment: WAF detector
        rules:
          - name: sql-injection
            id: 40001
            patterns:
              - key: pattern
                op: "!regex"
                value: "(?i)union select"
                context: url
`)
	rules, bindings, unsupported, err := ConvertDPIRules(raw)
	if err != nil {
		t.Fatalf("ConvertDPIRules: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("unexpected bindings: %+v", bindings)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", unsupported)
	}
	if len(rules) != 2 {
		t.Fatalf("rule count=%d want 2: %+v", len(rules), rules)
	}
	if rules[0].Category != "dlp" || rules[0].ApplyDir != 1 || rules[0].Mode != "monitor" {
		t.Fatalf("unexpected dlp rule: %+v", rules[0])
	}
	if rules[1].Category != "waf" || rules[1].ApplyDir != 2 || rules[1].Severity != 6 {
		t.Fatalf("unexpected waf rule: %+v", rules[1])
	}
	if rules[1].Patterns[0].Op != "not_regex" || rules[1].Patterns[0].Context != "uri" {
		t.Fatalf("waf pattern metadata not normalised: %+v", rules[1].Patterns[0])
	}
}

func TestConvertDPIRulesPreservesProvenanceAndUnsupportedPatternDetails(t *testing.T) {
	raw := []byte(`dlp_sensors:
  - name: pii-sensor
    cfg_type: federal
    groups:
      - nv.default.api
    rules:
      - name: pii-rule
        id: 20001
        cfg_type: federal
        patterns:
          - key: pattern
            op: regex
            value: "*secret?"
            context: body
          - key: file
            op: regex
            value: /etc/passwd
          - key: pattern
            op: contains
            value: token
          - key: pattern
            op: regex
            value: ""
`)
	rules, bindings, unsupported, err := ConvertDPIRules(raw)
	if err != nil {
		t.Fatalf("ConvertDPIRules: %v", err)
	}
	if len(bindings) != 0 {
		t.Fatalf("unexpected bindings: %+v", bindings)
	}
	if len(rules) != 1 {
		t.Fatalf("rule count=%d want 1: %+v", len(rules), rules)
	}
	rule := rules[0]
	if rule.SourcePath != "dlp_sensors[0].rules[0]" || rule.SourceCfgType != "federal" || rule.SourceRuleCfgType != "federal" || !rule.Federated {
		t.Fatalf("rule provenance not preserved: %+v", rule)
	}
	if got := rule.Imported["source_path"]; got != "dlp_sensors[0].rules[0]" {
		t.Fatalf("imported source_path=%q", got)
	}
	if got := rule.Imported["source_sensor_path"]; got != "dlp_sensors[0]" {
		t.Fatalf("imported source_sensor_path=%q", got)
	}
	if rule.Imported["federated"] != "true" || rule.Imported["source_cfg_type"] != "federal" || rule.Imported["source_rule_cfg_type"] != "federal" {
		t.Fatalf("imported cfg/federation metadata missing: %+v", rule.Imported)
	}
	if len(rule.SourceGroups) != 1 || rule.SourceGroups[0] != "nv.default.api" {
		t.Fatalf("source groups not preserved: %+v", rule.SourceGroups)
	}
	if !strings.Contains(rule.Description, "source: dlp_sensors[0].rules[0]") {
		t.Fatalf("description missing source path: %q", rule.Description)
	}
	if len(unsupported) != 3 {
		t.Fatalf("unsupported count=%d want 3: %+v", len(unsupported), unsupported)
	}
	wantReasons := map[string]string{
		"dlp_sensors[0].rules[0].patterns[1]": "unsupported pattern key",
		"dlp_sensors[0].rules[0].patterns[2]": "unsupported pattern operator",
		"dlp_sensors[0].rules[0].patterns[3]": "empty pattern value",
	}
	for _, item := range unsupported {
		if item.Kind != "dpi_pattern" {
			t.Fatalf("unsupported kind=%s want dpi_pattern: %+v", item.Kind, item)
		}
		path, _ := item.Source["source_path"].(string)
		if wantReasons[path] != item.Reason {
			t.Fatalf("unsupported provenance/reason mismatch for %q: %+v", path, item)
		}
		if item.Source["source_cfg_type"] != "federal" || item.Source["source_rule_cfg_type"] != "federal" || item.Source["federated"] != true {
			t.Fatalf("unsupported cfg/federation metadata missing: %+v", item.Source)
		}
		delete(wantReasons, path)
	}
	if len(wantReasons) != 0 {
		t.Fatalf("missing unsupported paths: %+v", wantReasons)
	}
}

func TestConvertDPIRulesPreservesGroupScopeBindingCandidates(t *testing.T) {
	raw := []byte(`dlp_groups:
  - name: nv.default.api
    status: true
    sensors:
      - name: pii-sensor
        action: deny
`)
	rules, bindings, unsupported, err := ConvertDPIRules(raw)
	if err != nil {
		t.Fatalf("ConvertDPIRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("unexpected rules: %+v", rules)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", unsupported)
	}
	if len(bindings) != 1 || bindings[0].SensorKind != "dlp" || bindings[0].SourceGroup != "nv.default.api" {
		t.Fatalf("missing group-scope binding candidate: %+v", bindings)
	}
	if len(bindings[0].SourceSensors) != 1 || bindings[0].SourceSensors[0] != "pii-sensor" {
		t.Fatalf("binding lost source sensor names: %+v", bindings[0])
	}
}

func TestConvertGroupsFromRESTAndCRDDefinitions(t *testing.T) {
	raw := []byte(`groups:
  - name: nv.api.default
    comment: API service
    cfg_type: user_created
    policy_mode: protect
    profile_mode: monitor
    criteria:
      - key: service
        op: "="
        value: api.default
      - key: domain
        op: "="
        value: default
      - key: label
        op: "="
        value: tier=backend
---
kind: NvGroupDefinition
spec:
  selector:
    name: nv.frontend.default
    comment: Frontend namespace
    criteria:
      - key: namespace
        op: "="
        value: default
      - key: label.app
        op: "="
        value: frontend
`)
	groups, unsupported, err := ConvertGroups(raw)
	if err != nil {
		t.Fatalf("ConvertGroups: %v", err)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported groups: %+v", unsupported)
	}
	if len(groups) != 2 {
		t.Fatalf("group count=%d want 2: %+v", len(groups), groups)
	}
	api := groups[0]
	if api.Name != "nv.api.default" || api.Kind != "ground" || api.CfgType != "user" || api.PolicyMode != "protect" {
		t.Fatalf("unexpected API group metadata: %+v", api)
	}
	if !hasGroupCriterion(api.Criteria, "id", "eq", "default/api") || !hasGroupCriterion(api.Criteria, "label.tier", "eq", "backend") {
		t.Fatalf("API group criteria not converted safely: %+v", api.Criteria)
	}
	frontend := groups[1]
	if frontend.Name != "nv.frontend.default" || !hasGroupCriterion(frontend.Criteria, "namespace", "eq", "default") || !hasGroupCriterion(frontend.Criteria, "label.app", "eq", "frontend") {
		t.Fatalf("CRD group criteria not converted: %+v", frontend)
	}
}

func TestConvertGroupsRejectsUnsupportedCriteria(t *testing.T) {
	raw := []byte(`groups:
  - name: nv.unsupported
    criteria:
      - key: container
        op: "!="
        value: api
      - key: address
        op: "="
        value: 10.0.0.1
  - name: nv.service-without-domain
    criteria:
      - key: service
        op: "="
        value: api
`)
	groups, unsupported, err := ConvertGroups(raw)
	if err != nil {
		t.Fatalf("ConvertGroups: %v", err)
	}
	if len(groups) != 0 {
		t.Fatalf("unsupported groups should be skipped, got %+v", groups)
	}
	if len(unsupported) != 2 {
		t.Fatalf("unsupported count=%d want 2: %+v", len(unsupported), unsupported)
	}
	for _, item := range unsupported {
		if item.Kind != "group" || !strings.Contains(item.Reason, "cannot safely enforce") {
			t.Fatalf("unexpected unsupported row: %+v", item)
		}
	}
}

func TestCountSourceObjectsMixedFixture(t *testing.T) {
	raw := []byte(`admission:
  rules:
    - id: 1001
      desc: Block latest
      criteria:
        - key: image_name
          op: regex
          value: latest
      action: deny
response:
  rules:
    - id: 2001
      event: process
      conditions: [process_baseline]
      actions: [alert]
groups:
  - name: nv.api.default
    criteria:
      - key: service
        op: "="
        value: api.default
      - key: domain
        op: "="
        value: default
file_profiles:
  - group: nv.api.default
    rules:
      - filter: /etc/passwd
        behavior: block_access
process_profiles:
  - group: nv.api.default
    process_list:
      - name: nginx
        path: /usr/sbin/nginx
        action: allow
dlp_sensors:
  - name: pii
    rules:
      - name: ssn
        patterns:
          - key: pattern
            value: "[0-9]{3}-[0-9]{2}-[0-9]{4}"
waf_sensors:
  - name: waf
    rules:
      - name: sql
        patterns:
          - key: pattern
            value: "(?i)union select"
dlp_groups:
  - name: nv.api.default
    status: true
    sensors:
      - name: pii
network_rules:
  - id: 3001
    from: nv.api.default
    to: nv.db.default
    ports: tcp/5432
    action: allow
`)
	counts, err := CountSourceObjects(raw)
	if err != nil {
		t.Fatalf("CountSourceObjects: %v", err)
	}
	if counts.Policies != 2 || counts.AdmissionRules != 1 || counts.ResponseRules != 1 ||
		counts.Groups != 1 || counts.FileProfiles != 1 || counts.ProcessProfiles != 1 ||
		counts.DPIRules != 2 || counts.DPIBindings != 1 || counts.NetworkRules != 1 ||
		counts.Total() != 9 {
		t.Fatalf("unexpected source counts: %+v total=%d", counts, counts.Total())
	}
	m := counts.Map()
	if m["policies"] != 2 || m["admission_rules"] != 1 || m["dpi_rules"] != 2 {
		t.Fatalf("unexpected source count map: %+v", m)
	}
}

func TestConvertNetworkRulesFromRESTAndCRD(t *testing.T) {
	raw := []byte(`policy:
  rules:
    - id: 1001
      comment: API to database
      from: nv.api.default
      to: nv.db.default
      ports: tcp/5432, udp/53
      action: allow
      priority: 20
---
kind: NvSecurityRule
metadata:
  name: nv-api-rule
spec:
  target:
    selector:
      name: nv.api.default
      criteria:
        - key: service
          op: "="
          value: api.default
        - key: domain
          op: "="
          value: default
  ingress:
    - name: frontend to api
      selector:
        name: nv.frontend.default
        criteria:
          - key: namespace
            op: "="
            value: default
      ports: "443"
      action: allow
      priority: 10
  egress:
    - name: api to cache
      selector:
        name: nv.cache.default
        criteria:
          - key: label
            op: "="
            value: app=cache
      ports: any
      action: allow
      priority: 30
`)
	rules, unsupported, err := ConvertNetworkRules(raw)
	if err != nil {
		t.Fatalf("ConvertNetworkRules: %v", err)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", unsupported)
	}
	if len(rules) != 3 {
		t.Fatalf("network rule count=%d want 3: %+v", len(rules), rules)
	}
	ingress := rules[0]
	if ingress.FromGroup != "nv.frontend.default" || ingress.ToGroup != "nv.api.default" || len(ingress.Ports) != 1 || ingress.Ports[0].Protocol != "TCP" || ingress.Ports[0].Port != 443 {
		t.Fatalf("CRD ingress rule not converted: %+v", ingress)
	}
	rest := rules[1]
	if rest.Name != "nv-network-1001" || rest.FromGroup != "nv.api.default" || rest.ToGroup != "nv.db.default" || len(rest.Ports) != 2 || rest.Ports[0].Protocol != "TCP" || rest.Ports[0].Port != 5432 || rest.Ports[1].Protocol != "UDP" || rest.Ports[1].Port != 53 {
		t.Fatalf("REST network rule not converted: %+v", rest)
	}
	egress := rules[2]
	if egress.FromGroup != "nv.api.default" || egress.ToGroup != "nv.cache.default" || len(egress.Ports) != 0 {
		t.Fatalf("CRD egress any-port rule not converted: %+v", egress)
	}
}

func TestConvertNetworkRulesRejectsUnsupportedSemantics(t *testing.T) {
	raw := []byte(`network_rules:
  - id: 1
    from: a
    to: b
    ports: tcp/80
    action: deny
  - id: 2
    from: a
    to: c
    ports: tcp/443
    action: allow
    disable: true
  - id: 3
    from: a
    to: d
    ports: tcp/8080
    action: allow
    applications: [HTTP]
  - id: 4
    from: a
    to: e
    ports: tcp/8000-8010
    action: allow
`)
	rules, unsupported, err := ConvertNetworkRules(raw)
	if err != nil {
		t.Fatalf("ConvertNetworkRules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("unsupported rules should not convert: %+v", rules)
	}
	if len(unsupported) != 4 {
		t.Fatalf("unsupported count=%d want 4: %+v", len(unsupported), unsupported)
	}
	for _, item := range unsupported {
		if item.Kind != "network_rule" || item.Name == "" || item.Reason == "" {
			t.Fatalf("bad unsupported row: %+v", item)
		}
	}
}

func TestConvertSkipsNetworkRulesInAdmissionPolicyPath(t *testing.T) {
	raw := []byte(`rules:
  - id: 1001
    comment: API to database
    from: nv.api.default
    to: nv.db.default
    ports: tcp/5432
    action: allow
`)
	policies, err := Convert(raw)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("network rules must not become admission policies: %+v", policies)
	}
}

func TestConvertProcessProfilesFromRESTAndCRD(t *testing.T) {
	raw := []byte(`process_profiles:
  - group: nv.api.default
    mode: protect
    baseline: zero-drift
    process_list:
      - name: nginx
        path: /usr/sbin/nginx
        action: allow
        allow_update: true
      - name: sh
        path: /bin/sh
        action: deny
        user: root
---
kind: NvSecurityRule
metadata:
  name: nv-worker-rule
spec:
  target:
    selector:
      name: nv.worker.default
  process_profile:
    baseline: basic
    mode: monitor
  process:
    - name: worker
      path: /app/worker
      action: allow
`)
	profiles, unsupported, err := ConvertProcessProfiles(raw)
	if err != nil {
		t.Fatalf("ConvertProcessProfiles: %v", err)
	}
	if len(unsupported) != 0 {
		t.Fatalf("unexpected unsupported: %+v", unsupported)
	}
	if len(profiles) != 2 {
		t.Fatalf("profile count=%d want 2: %+v", len(profiles), profiles)
	}
	api := profiles[0]
	if api.Group != "nv.api.default" || api.Mode != "enforce" || api.Baseline != "zero-drift" || len(api.Rules) != 2 {
		t.Fatalf("REST process profile not converted: %+v", api)
	}
	if api.Rules[0].Action != "deny" || api.Rules[1].Name != "nginx" || !api.Rules[1].AllowUpdate {
		t.Fatalf("REST process profile rules not normalized/sorted: %+v", api.Rules)
	}
	worker := profiles[1]
	if worker.Group != "nv.worker.default" || worker.Mode != "monitor" || worker.Baseline != "basic" || len(worker.Rules) != 1 || worker.Rules[0].Path != "/app/worker" {
		t.Fatalf("CRD process profile not converted: %+v", worker)
	}
}

func TestConvertProcessProfilesRejectsUnsafeRules(t *testing.T) {
	raw := []byte(`process_profile:
  group: nv.api.default
  mode: monitor
  process_list:
    - name: "*"
      path: /*
      action: deny
    - name: curl
      path: /usr/bin/curl
      action: quarantine
    - name: disabled
      path: /bin/disabled
      action: allow
      disable: true
    - name: duplicate
      path: /bin/dup
      action: allow
    - name: duplicate
      path: /bin/dup
      action: deny
`)
	profiles, unsupported, err := ConvertProcessProfiles(raw)
	if err != nil {
		t.Fatalf("ConvertProcessProfiles: %v", err)
	}
	if len(profiles) != 1 || len(profiles[0].Rules) != 1 || profiles[0].Rules[0].Name != "duplicate" || profiles[0].Rules[0].Action != "allow" {
		t.Fatalf("only first non-conflicting duplicate should convert: %+v", profiles)
	}
	if len(unsupported) != 4 {
		t.Fatalf("unsupported count=%d want 4: %+v", len(unsupported), unsupported)
	}
	for _, item := range unsupported {
		if item.Kind != "process_profile" || item.Name == "" || item.Reason == "" {
			t.Fatalf("bad unsupported row: %+v", item)
		}
	}
}

func hasGroupCriterion(criteria []TargetGroupCriterion, key, op, value string) bool {
	for _, criterion := range criteria {
		if criterion.Key == key && criterion.Op == op && criterion.Value == value {
			return true
		}
	}
	return false
}
