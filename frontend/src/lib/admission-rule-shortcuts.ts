import type { AdmissionCriterionOption } from "@/api/client";

export interface AdmissionCriterionRow {
  key: string;
  value: string;
}

export interface AdmissionRuleShortcut {
  id: string;
  name: string;
  description: string;
  mode: "monitor" | "enforce";
  criteria: AdmissionCriterionRow[];
}

export const ADMISSION_RISK_SHORTCUTS: AdmissionRuleShortcut[] = [
  {
    id: "privileged-workload",
    name: "Block privileged workload",
    description: "Privileged containers, root users, and privilege escalation.",
    mode: "enforce",
    criteria: [
      { key: "run_as_privileged", value: "" },
      { key: "run_as_root", value: "" },
      { key: "allow_privilege_escalation", value: "" },
    ],
  },
  {
    id: "host-namespace",
    name: "Block host namespace sharing",
    description: "Host network, PID, and IPC namespace access.",
    mode: "enforce",
    criteria: [
      { key: "host_network", value: "" },
      { key: "host_pid", value: "" },
      { key: "host_ipc", value: "" },
    ],
  },
  {
    id: "mutable-image",
    name: "Require immutable images",
    description: "Deny floating tags and images without digest pins.",
    mode: "enforce",
    criteria: [
      { key: "disallow_latest_tag", value: "" },
      { key: "require_digest", value: "" },
    ],
  },
  {
    id: "critical-cve-gate",
    name: "Block critical vulnerable images",
    description: "Critical CVEs, fixable high CVEs, and CVSS 9+.",
    mode: "monitor",
    criteria: [
      { key: "max_critical_cves", value: "0" },
      { key: "max_high_with_fix_cves", value: "0" },
      { key: "deny_cvss_at_score", value: "9.0" },
    ],
  },
  {
    id: "restricted-pss",
    name: "Enforce restricted PSS",
    description: "Kubernetes Pod Security Standard restricted profile.",
    mode: "monitor",
    criteria: [{ key: "pss_level", value: "restricted" }],
  },
];

export function admissionShortcutPayload(shortcut: AdmissionRuleShortcut, catalog: AdmissionCriterionOption[]) {
  const supported = new Set(catalog.map((option) => option.key));
  return {
    name: shortcut.name,
    mode: shortcut.mode,
    rows: shortcut.criteria.filter((criterion) => supported.has(criterion.key)),
  };
}

export function admissionShortcutAvailable(shortcut: AdmissionRuleShortcut, catalog: AdmissionCriterionOption[]) {
  const supported = new Set(catalog.map((option) => option.key));
  return shortcut.criteria.every((criterion) => supported.has(criterion.key));
}
