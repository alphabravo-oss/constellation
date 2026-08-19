// Compliance mappings — link every audit Action to the compliance controls
// it provides evidence for.
//
// Why this lives in pkg/audit and not in a separate package:
//
//	The audit log is the *evidence layer* of every framework we care about
//	(NIST SP 800-53, SOC 2, PCI DSS, ISO 27001). Procurement and ATO
//	reviewers ask one question — "show me your evidence for control AC-2" —
//	and the answer is "this query against audit_events". Keeping the
//	mapping table next to the Logger keeps the evidence claim honest:
//	whoever adds a new Action also has to decide what it's evidence *of*.
//
// Mapping policy:
//
//   - Match on prefix. Specific prefixes override general ones during a
//     ControlIDsFor() lookup, then we union the general mappings so an
//     action like "policy.create" inherits everything mapped to "policy."
//     plus any "policy.create"-specific overrides.
//
//   - Frameworks tracked: NIST SP 800-53 Rev 5, SOC 2 Trust Services
//     Criteria 2017 with 2022 revisions, PCI DSS v4.0, ISO/IEC 27001:2022.
//     Versions matter — auditors will check.
//
//   - We map *evidence*, not *compliance*. An audit row for AC-2 is one
//     piece of evidence that account-management events are being recorded;
//     it does NOT claim the system as a whole is AC-2 compliant. The
//     docs/compliance-mappings.md page spells out the distinction.
//
//   - We deliberately under-claim. A control is only listed if the audit
//     event genuinely demonstrates it. Stretch mappings (e.g. claiming
//     auth.logout as evidence for IR-4) are excluded — auditors penalise
//     them when they look closer.
package audit

import (
	"sort"
	"strings"
)

// Framework identifies a compliance framework. The string values are
// stable; they appear in API responses and CSV exports.
type Framework string

const (
	FrameworkNIST80053 Framework = "nist-sp-800-53-r5"
	FrameworkSOC2      Framework = "soc2-tsc-2017"
	FrameworkPCIDSSv4  Framework = "pci-dss-v4.0"
	FrameworkISO27001  Framework = "iso-27001-2022"
)

// ControlMapping ties one Action prefix to one control in one framework.
// Title is the human-readable control name as published by the framework
// authority — auditors expect to see these verbatim in reports.
type ControlMapping struct {
	Framework Framework `json:"framework"`
	ControlID string    `json:"control_id"`
	Title     string    `json:"title"`
}

// controlRule binds a set of Action prefixes to a set of mappings. The
// table is intentionally hand-written, not generated, because the
// per-action judgement call (does this action genuinely demonstrate the
// control?) cannot be automated.
type controlRule struct {
	prefixes []string
	mappings []ControlMapping
}

// rules is the full mapping table. Order is informational only —
// ControlIDsFor unions matches across rules. Keep rules grouped by
// audit-action family for legibility.
var rules = []controlRule{
	// -------------------------------------------------------------------
	// Identification & authentication.
	// -------------------------------------------------------------------
	{
		prefixes: []string{"auth.login."},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "AC-2", "Account Management"},
			{FrameworkNIST80053, "AC-7", "Unsuccessful Logon Attempts"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkNIST80053, "IA-2", "Identification and Authentication (Organizational Users)"},
			{FrameworkSOC2, "CC6.1", "Logical and physical access controls"},
			{FrameworkPCIDSSv4, "8.2", "User identification and authentication"},
			{FrameworkPCIDSSv4, "8.3", "Strong authentication"},
			{FrameworkPCIDSSv4, "10.2.1", "Log all individual user access"},
			{FrameworkISO27001, "A.5.16", "Identity management"},
			{FrameworkISO27001, "A.8.5", "Secure authentication"},
		},
	},
	{
		prefixes: []string{"auth.logout"},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "AC-11", "Device Lock / Session Termination"},
			{FrameworkNIST80053, "AC-12", "Session Termination"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC6.1", "Logical and physical access controls"},
			{FrameworkPCIDSSv4, "8.2.8", "Re-authenticate after idle session"},
		},
	},

	// -------------------------------------------------------------------
	// Account & access management. Group/role/service-account/RBAC.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"group.create", "group.update", "group.delete",
			"role_binding.create", "role_binding.delete",
			"service_account.create",
			"cluster-init-bundle.read", "cluster-init-bundle.revoke",
			"settings.user.update",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "AC-2", "Account Management"},
			{FrameworkNIST80053, "AC-3", "Access Enforcement"},
			{FrameworkNIST80053, "AC-5", "Separation of Duties"},
			{FrameworkNIST80053, "AC-6", "Least Privilege"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkNIST80053, "IA-5", "Authenticator Management"},
			{FrameworkSOC2, "CC6.1", "Logical and physical access controls"},
			{FrameworkSOC2, "CC6.2", "Authorization of new users"},
			{FrameworkSOC2, "CC6.3", "User access modifications and removal"},
			{FrameworkPCIDSSv4, "7.2", "Defined access control model"},
			{FrameworkPCIDSSv4, "7.3", "Access control system enforces privileges"},
			{FrameworkPCIDSSv4, "8.2.4", "Account management lifecycle"},
			{FrameworkISO27001, "A.5.15", "Access control"},
			{FrameworkISO27001, "A.5.18", "Access rights"},
		},
	},

	// -------------------------------------------------------------------
	// Findings — triage, suppression, risk acceptance.
	// These are the day-to-day evidence trail for risk-management controls.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"finding.suppress", "finding.accept_risk",
			"finding.comment", "finding.triage",
			"image.accept-risk", "image.accept-risk.revoke",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "CA-5", "Plan of Action and Milestones"},
			{FrameworkNIST80053, "CM-3", "Configuration Change Control"},
			{FrameworkNIST80053, "RA-5", "Vulnerability Monitoring and Scanning"},
			{FrameworkNIST80053, "RA-7", "Risk Response"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC4.2", "Evaluation and communication of deficiencies"},
			{FrameworkSOC2, "CC7.1", "Detection of system anomalies"},
			{FrameworkPCIDSSv4, "6.3.1", "Identify and prioritize security vulnerabilities"},
			{FrameworkPCIDSSv4, "11.4", "Internal and external penetration test management"},
			{FrameworkISO27001, "A.5.7", "Threat intelligence"},
			{FrameworkISO27001, "A.8.8", "Management of technical vulnerabilities"},
		},
	},

	// -------------------------------------------------------------------
	// Policy lifecycle (network policies, response rules, vulnerability
	// profiles, DLP, WAF). All represent configuration change events.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"policy.create", "policy.update", "policy.delete", "policy.bulk",
			"response_rule.", "response_rule_v2.",
			"vuln_profile.create", "vuln_profile.update", "vuln_profile.delete",
			"dlp_sensor.create", "dlp_sensor.update", "dlp_sensor.delete",
			"waf_group.create", "waf_group.update", "waf_group.delete",
			"attestation_trust_policy.",
			"routing.yaml.update", "settings.org.update",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "CM-3", "Configuration Change Control"},
			{FrameworkNIST80053, "CM-5", "Access Restrictions for Change"},
			{FrameworkNIST80053, "CM-6", "Configuration Settings"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkNIST80053, "AU-12", "Audit Record Generation"},
			{FrameworkSOC2, "CC8.1", "Authorization, design, development of changes"},
			{FrameworkPCIDSSv4, "6.5", "Changes to system components managed securely"},
			{FrameworkPCIDSSv4, "10.2", "Audit trails reconstruct events"},
			{FrameworkISO27001, "A.8.32", "Change management"},
			{FrameworkISO27001, "A.8.9", "Configuration management"},
		},
	},

	// -------------------------------------------------------------------
	// Quarantine — manual + auto add/lift on the admission deny list.
	// Combines incident-response evidence (IR-4) with config-change
	// evidence (CM-3) because every quarantine entry is both a runtime
	// response action AND a change to the cluster's effective policy.
	// -------------------------------------------------------------------
	{
		prefixes: []string{"quarantine.add", "quarantine.lift", "quarantine.auto"},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "IR-4", "Incident Handling"},
			{FrameworkNIST80053, "IR-5", "Incident Monitoring"},
			{FrameworkNIST80053, "CM-3", "Configuration Change Control"},
			{FrameworkNIST80053, "CM-5", "Access Restrictions for Change"},
			{FrameworkNIST80053, "SI-4", "System Monitoring"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC7.3", "Evaluation and communication of security events"},
			{FrameworkSOC2, "CC7.4", "Response to identified events"},
			{FrameworkPCIDSSv4, "12.10", "Incident response plan and procedures"},
			{FrameworkPCIDSSv4, "10.6", "Audit logs reviewed periodically"},
			{FrameworkISO27001, "A.5.24", "Information security incident management planning"},
			{FrameworkISO27001, "A.5.26", "Response to information security incidents"},
		},
	},

	// -------------------------------------------------------------------
	// Runtime detections — exec/file/DLP/WAF alerts, admission denies,
	// baseline transitions, drift detection. Hot incident-response path.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"runtime.alert.exec", "runtime.alert.waf", "runtime.alert.dlp",
			"admission.deny", "admission.monitor",
			"baseline.transition",
			"file_profile.",
			"gitops.drift.detected",
			"component.crashloop",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "SI-4", "System Monitoring"},
			{FrameworkNIST80053, "SI-3", "Malicious Code Protection"},
			{FrameworkNIST80053, "IR-4", "Incident Handling"},
			{FrameworkNIST80053, "IR-5", "Incident Monitoring"},
			{FrameworkNIST80053, "AU-6", "Audit Record Review, Analysis, and Reporting"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC7.2", "Monitoring of system components and operations"},
			{FrameworkSOC2, "CC7.3", "Evaluation and communication of security events"},
			{FrameworkSOC2, "CC7.4", "Response to identified events"},
			{FrameworkPCIDSSv4, "10.4", "Audit logs reviewed to identify anomalies"},
			{FrameworkPCIDSSv4, "10.7", "Failures of critical security control systems"},
			{FrameworkPCIDSSv4, "12.10", "Incident response plan and procedures"},
			{FrameworkISO27001, "A.5.24", "Information security incident management planning"},
			{FrameworkISO27001, "A.5.25", "Assessment and decision on information security events"},
			{FrameworkISO27001, "A.8.16", "Monitoring activities"},
		},
	},

	// -------------------------------------------------------------------
	// Receivers (alert sinks — Slack/PagerDuty/webhooks). Test fires and
	// secret rotations are critical for IR-4 evidence.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"receiver.create", "receiver.update", "receiver.delete",
			"receiver.rotate_secret", "receiver.test_fire",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "IR-6", "Incident Reporting"},
			{FrameworkNIST80053, "IR-4", "Incident Handling"},
			{FrameworkNIST80053, "AU-6", "Audit Record Review, Analysis, and Reporting"},
			{FrameworkNIST80053, "SI-4", "System Monitoring"},
			{FrameworkSOC2, "CC2.3", "Communication of internal and external responsibilities"},
			{FrameworkSOC2, "CC7.4", "Response to identified events"},
			{FrameworkISO27001, "A.5.24", "Information security incident management planning"},
		},
	},

	// -------------------------------------------------------------------
	// Backups & recovery.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"backup.start", "backup.complete", "backup.download",
			"backup.restore", "backup.verify",
			"backup.schedule.update", "backup.schedule.create", "backup.schedule.delete",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "CP-9", "System Backup"},
			{FrameworkNIST80053, "CP-10", "System Recovery and Reconstitution"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "A1.2", "Environmental protection, software, data backup, recovery"},
			{FrameworkSOC2, "CC9.1", "Identifies, selects, develops risk mitigation"},
			{FrameworkPCIDSSv4, "12.10.1", "Incident response plan includes recovery"},
			{FrameworkISO27001, "A.8.13", "Information backup"},
			{FrameworkISO27001, "A.5.29", "Information security during disruption"},
		},
	},

	// -------------------------------------------------------------------
	// Vulnerability scanning (registry sync, scan-jobs, cross-scan,
	// compliance scans). RA-5 territory.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"registry.create", "registry.update", "registry.delete",
			"registry.sync-now", "registry.sync.walker", "registry.test",
			"scan-job.enqueue", "scan-job.complete", "scan-job.fail",
			"attestation.verify",
			"cluster.cross-scan",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "RA-5", "Vulnerability Monitoring and Scanning"},
			{FrameworkNIST80053, "SI-2", "Flaw Remediation"},
			{FrameworkNIST80053, "SI-3", "Malicious Code Protection"},
			{FrameworkNIST80053, "SR-3", "Supply Chain Controls and Processes"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC7.1", "Detection of system anomalies"},
			{FrameworkPCIDSSv4, "6.3.1", "Identify and prioritize security vulnerabilities"},
			{FrameworkPCIDSSv4, "11.3", "External and internal vulnerabilities identified"},
			{FrameworkISO27001, "A.8.8", "Management of technical vulnerabilities"},
			{FrameworkISO27001, "A.8.7", "Protection against malware"},
		},
	},

	// -------------------------------------------------------------------
	// Compliance subsystem itself — scheduled assessments, custom
	// framework lifecycle, ingestion of external compliance scans.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"compliance.ingest",
			"compliance.schedule.create", "compliance.schedule.update",
			"compliance.schedule.delete", "compliance.schedule.run_now",
			"compliance.exemption.create", "compliance.exemption.revoke",
			"compliance.custom_framework.create",
			"compliance.custom_framework.delete",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "CA-2", "Control Assessments"},
			{FrameworkNIST80053, "CA-7", "Continuous Monitoring"},
			{FrameworkNIST80053, "PM-31", "Continuous Monitoring Strategy"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC4.1", "Evaluations of controls"},
			{FrameworkSOC2, "CC4.2", "Communication of deficiencies"},
			{FrameworkPCIDSSv4, "12.1", "Information security policy"},
			{FrameworkISO27001, "A.5.36", "Compliance with policies, rules, standards"},
		},
	},

	// -------------------------------------------------------------------
	// Federation — cross-tenant data sharing and identity broker events.
	// -------------------------------------------------------------------
	{
		prefixes: []string{
			"federation.",
			"fed_member.add",
		},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "AC-3", "Access Enforcement"},
			{FrameworkNIST80053, "AC-21", "Information Sharing"},
			{FrameworkNIST80053, "CA-3", "Information Exchange"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkSOC2, "CC6.6", "Logical access to data shared with external parties"},
			{FrameworkISO27001, "A.5.14", "Information transfer"},
		},
	},

	// -------------------------------------------------------------------
	// AI/agent actions — emerging guidance (NIST AI RMF, ISO 42001).
	// We log them; auditor framing is "AC-3 + AU-2 + emerging AI controls".
	// -------------------------------------------------------------------
	{
		prefixes: []string{"ai.query", "ai.tool"},
		mappings: []ControlMapping{
			{FrameworkNIST80053, "AC-3", "Access Enforcement"},
			{FrameworkNIST80053, "AU-2", "Event Logging"},
			{FrameworkNIST80053, "AU-12", "Audit Record Generation"},
			{FrameworkSOC2, "CC7.1", "Detection of system anomalies"},
			// NIST AI RMF and ISO 42001 mappings deliberately omitted at v1 —
			// see docs/compliance-mappings.md for the rationale.
		},
	},
}

// ControlIDsFor returns every compliance control mapping that applies to
// the given audit Action. Matches are unioned across all rules whose
// prefixes match. Order is stable: framework alpha, then control_id alpha.
// Returns an empty slice (never nil) when no rules match — auditors
// distinguish "no evidence" from "no mapping defined".
func ControlIDsFor(action string) []ControlMapping {
	if action == "" {
		return []ControlMapping{}
	}
	seen := make(map[string]struct{})
	out := make([]ControlMapping, 0, 8)
	for _, r := range rules {
		matched := false
		for _, p := range r.prefixes {
			if strings.HasPrefix(action, p) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for _, m := range r.mappings {
			key := string(m.Framework) + "|" + m.ControlID
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].ControlID < out[j].ControlID
	})
	return out
}

// ActionsFor returns every action prefix that maps to the given
// (framework, control_id) tuple. Used by the audit handler to translate
// `?control=AC-2&framework=nist-sp-800-53-r5` into an `action LIKE 'auth.%'
// OR action LIKE 'group.%' …` filter without round-tripping through
// every row in the table.
func ActionsFor(fw Framework, controlID string) []string {
	out := []string{}
	seen := make(map[string]struct{})
	for _, r := range rules {
		hit := false
		for _, m := range r.mappings {
			if m.Framework == fw && m.ControlID == controlID {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		for _, p := range r.prefixes {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// AllControls returns every distinct control mapping known to the table.
// Used by the /api/v1/compliance/control-mappings endpoint to let UIs
// render a "which controls do we cover?" tree.
func AllControls() []ControlMapping {
	seen := make(map[string]ControlMapping)
	for _, r := range rules {
		for _, m := range r.mappings {
			key := string(m.Framework) + "|" + m.ControlID
			seen[key] = m
		}
	}
	out := make([]ControlMapping, 0, len(seen))
	for _, m := range seen {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Framework != out[j].Framework {
			return out[i].Framework < out[j].Framework
		}
		return out[i].ControlID < out[j].ControlID
	})
	return out
}

// AllFrameworks returns every Framework constant we have mappings for.
// Stable order: alphabetical by framework string.
func AllFrameworks() []Framework {
	seen := map[Framework]struct{}{}
	for _, r := range rules {
		for _, m := range r.mappings {
			seen[m.Framework] = struct{}{}
		}
	}
	out := make([]Framework, 0, len(seen))
	for f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
