import axios, { type AxiosInstance } from "axios";

const STORAGE_TOKEN = "constellation.token";

const api: AxiosInstance = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem(STORAGE_TOKEN);
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      const sentAuth = Boolean(err.config?.headers?.Authorization);
      const url: string = err.config?.url || "";
      // Only treat as a real session expiry if the request carried our token AND
      // it was either /auth/me (the canonical session probe) or any non-auth API call.
      // Login attempts (/auth/login) returning 401 are user-typo events, not session expiry.
      const isLoginAttempt = url.includes("/auth/login");
      if (sentAuth && !isLoginAttempt) {
        localStorage.removeItem(STORAGE_TOKEN);
        if (!window.location.pathname.startsWith("/auth/login") && !window.location.pathname.startsWith("/login")) {
          window.location.href = "/auth/login";
        }
      }
    }
    return Promise.reject(err);
  },
);

export function setToken(t: string | null) {
  if (t) localStorage.setItem(STORAGE_TOKEN, t);
  else localStorage.removeItem(STORAGE_TOKEN);
}

export function getToken(): string | null {
  return localStorage.getItem(STORAGE_TOKEN);
}

export { api };

// --- typed endpoints (thin layer) ---

export async function downloadAPIFile(path: string, filename: string) {
  const response = await api.get(path, { responseType: "blob" });
  const blob = response.data instanceof Blob ? response.data : new Blob([response.data]);
  // Prefer the server-provided filename (Content-Disposition) when present.
  const cd = String(response.headers?.["content-disposition"] ?? "");
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(cd);
  const name = match ? decodeURIComponent(match[1].trim()) : filename;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Lifecycle = "open" | "triaged" | "in_progress" | "resolved" | "suppressed" | "accepted";
export type FindingKind =
  | "vulnerability" | "iac" | "license" | "cloud-config" | "drift"
  | "secret" | "signature" | "ml-model" | "compliance" | "runtime";

export interface Finding {
  id: string;
  kind: FindingKind;
  external_id?: string;
  title: string;
  severity: Severity;
  risk_score: number;
  lifecycle: Lifecycle;
  asset_id: string;
  cluster_id?: string;
  attack_techniques: string[];
  accepted_until?: string;
  first_seen_at: string;
  last_seen_at: string;
  canonical_engine?: string;
  engines?: EngineProvenance[];
  reconciliation?: ReconciliationSignal[];
  reconciliation_count?: number;
  package_name?: string;
  package_version?: string;
  package_ecosystem?: string;
  package_purl?: string;
  fixed_version?: string;
  affected_range?: AffectedRange;
  vulndb_bundle?: VulnDBBundleMetadata;
  cvss?: number;
  kev?: boolean;
  epss?: number;
}

export interface EngineProvenance {
  engine: string;
  confidence: number;
  role?: "canonical" | "evidence" | string;
}

export interface ReconciliationSignal {
  engine: string;
  field: string;
  canonical: string;
  evidence: string;
}

export interface AffectedRange {
  id?: number;
  source?: string;
  source_range_id?: string;
  namespace_kind?: string;
  namespace_name?: string;
  namespace_version?: string;
  version_scheme?: string;
  package_name?: string;
  package_purl?: string;
  package_cpe?: string;
  module_stream?: string;
  range_type?: string;
  introduced_version?: string;
  fixed_version?: string;
  last_affected_version?: string;
  range_expression?: string;
  events?: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }>;
  affected_status?: string;
  fix_state?: string;
}

export interface Comment {
  id: string;
  finding_id: string;
  author_id: string;
  body: string;
  created_at: string;
}

export interface CVERollup {
  cve: string;
  severity: Severity;
  risk_score: number;
  package?: string;
  fixed_version?: string;
  instances: number;
  affected_images: number;
  affected_clusters: number;
  images: string[];
  last_seen_at: string;
  cvss?: number;
  kev?: boolean;
  has_fix?: boolean;
}

export const findings = {
  list: (params: { kind?: FindingKind; lifecycle?: Lifecycle; cluster_id?: string; q?: string; limit?: number; offset?: number } = {}) =>
    api.get<{ findings: Finding[]; limit: number; offset: number; lifecycle_counts?: Record<Lifecycle, number> }>("/findings", { params }).then((r) => r.data),
  // NeuVector-style rollup: one row per CVE with its blast radius (affected images/clusters).
  byCVE: (params: { cluster_id?: string; lifecycle?: Lifecycle; limit?: number; offset?: number; fixable?: boolean; q?: string } = {}) =>
    api.get<{ cves: CVERollup[]; limit: number; offset: number; total: number }>("/findings/by-cve", { params: { ...params, fixable: params.fixable ? "true" : undefined, q: params.q || undefined } }).then((r) => r.data),
  get: (id: string) => api.get<Finding>(`/findings/${id}`).then((r) => r.data),
  triage:     (id: string, body: { assignee_id?: string; priority?: string }) =>
    api.post(`/findings/${id}/triage`, body).then((r) => r.data),
  suppress:   (id: string, body: { reason: string }) =>
    api.post(`/findings/${id}/suppress`, body).then((r) => r.data),
  acceptRisk: (id: string, body: { reason: string; approver_id?: string; accepted_until: string }) =>
    api.post(`/findings/${id}/accept-risk`, body).then((r) => r.data),
  listComments: (id: string) =>
    api.get<{ comments: Comment[] }>(`/findings/${id}/comments`).then((r) => r.data),
  addComment:   (id: string, body: { body: string }) =>
    api.post<Comment>(`/findings/${id}/comments`, body).then((r) => r.data),
};

export const sbom = {
  spdx:      (assetID: string) => `${api.defaults.baseURL}/sbom/spdx/${assetID}`,
  cyclonedx: (assetID: string) => `${api.defaults.baseURL}/sbom/cyclonedx/${assetID}`,
  mbom:      (assetID: string) => `${api.defaults.baseURL}/sbom/mbom/${assetID}`,
  // Authenticated downloads (these routes require a Bearer token, so they must go
  // through the axios client, not a plain <a href>/window.open which sends no header).
  downloadSpdx:      (assetID: string) => downloadAPIFile(`/sbom/spdx/${assetID}`, `sbom-${assetID}-spdx.json`),
  downloadCyclonedx: (assetID: string) => downloadAPIFile(`/sbom/cyclonedx/${assetID}`, `sbom-${assetID}-cyclonedx.json`),
  downloadMbom:      (assetID: string) => downloadAPIFile(`/sbom/mbom/${assetID}`, `sbom-${assetID}-mbom.json`),
};

export interface Asset {
  id: string;
  kind: string;
  name: string;
  digest?: string;
  labels: Record<string, string>;
  ai_workload: boolean;
  criticality: string;
  finding_count: number;
  critical_findings: number;
  high_findings: number;
  open_findings: number;
  sbom_count: number;
  image_signed?: boolean;
  registry?: string;
  repository?: string;
  tag?: string;
  size_bytes?: number;
  first_seen_at: string;
  last_seen_at: string;
}

export interface AssetFinding {
  id: string;
  kind: FindingKind;
  external_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  lifecycle: Lifecycle;
  last_seen_at: string;
  image_scan_result_id?: string;
  finding_key?: string;
}

export interface AssetImageDetail {
  registry: string;
  repository: string;
  tag: string;
  digest: string;
  layers: Array<{ digest: string; size?: number }>;
  architectures: string[];
  size_bytes?: number;
  signed: boolean;
  signature_info: Record<string, string>;
  pulled_at: string;
}

export interface AssetSBOM {
  id: string;
  format: string;
  sha256: string;
  created_at: string;
}

export interface ImageAcceptance {
  id: string;
  image_digest: string;
  rationale: string;
  approver_id: string;
  accepted_until: string;
  created_at: string;
  revoked_at?: string;
  status: "active" | "revoked" | "expired";
}

export interface AssetDetail {
  asset: Asset;
  image?: AssetImageDetail;
  image_scan_result?: ImageScanResult;
  findings: AssetFinding[];
  sboms: AssetSBOM[];
  image_acceptances: ImageAcceptance[];
}

export const assets = {
  list: (params: { limit?: number; offset?: number; cluster_id?: string } = {}) =>
    api.get<{ assets: Asset[]; limit: number; offset: number }>("/assets", { params }).then((r) => r.data),
  get: (id: string) => api.get<AssetDetail>(`/assets/${id}`).then((r) => r.data),
  createImageAcceptance: (id: string, body: { rationale: string; accepted_until: string }) =>
    api.post<{ id: string; image_acceptances: ImageAcceptance[] }>(`/assets/${id}/image-acceptances`, body).then((r) => r.data),
  revokeImageAcceptance: (assetID: string, acceptanceID: string) =>
    api.post<{ status: string; image_acceptances: ImageAcceptance[] }>(`/assets/${assetID}/image-acceptances/${acceptanceID}/revoke`).then((r) => r.data),
};

export interface HostVulnerability {
  node: string;
  cluster_id?: string;
  package_name: string;
  package_version: string;
  vuln_id: string;
  aliases?: string[];
  severity?: string;
  summary?: string;
  references?: string;
  fixed_version?: string;
  source: string;
  observed_at: string;
}

export interface NodeSummary {
  node: string;
  cluster_id: string;
  os_id?: string;
  os_version_id?: string;
  kernel_release?: string;
  arch?: string;
  cni_name?: string;
  cri_runtime?: string;
  btf_present?: boolean;
  nfqueue_capable?: boolean;
  package_count: number;
  package_source?: string;
  container_count: number;
  process_count: number;
  cis_profile?: string;
  cis_passed: number;
  cis_failed: number;
  cis_warned: number;
  cis_skipped: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  open_vulns: number;
  runtime_agent_status: string;
  runtime_agent_version?: string;
  runtime_agent_last_seen_at?: string;
  scan_target_id?: string;
  scan_status: string;
  inventory_hash?: string;
  last_scanned_at?: string;
  host_facts_observed_at?: string;
  packages_observed_at?: string;
  containers_observed_at?: string;
  processes_observed_at?: string;
  cis_observed_at?: string;
  last_seen_at: string;
  coverage_gaps?: string[];
}

export interface NodeListSummary {
  nodes: number;
  runtime_agent_healthy: number;
  runtime_agent_stale: number;
  runtime_agent_missing: number;
  scan_completed: number;
  scan_gaps: number;
  critical_vulns: number;
  high_vulns: number;
  cis_failed: number;
}

export interface NodeListResponse {
  cluster_id: string;
  items: NodeSummary[];
  summary: NodeListSummary;
}

export interface NodeDetail {
  node: NodeSummary;
  facts?: unknown;
  packages?: unknown;
  containers?: unknown;
  processes?: unknown;
  cis?: unknown;
  vulnerabilities: HostVulnerability[];
}

export interface ContainerRow {
  node: string;
  id: string;
  name: string;
  namespace: string;
  pod_name: string;
  image: string;
  state: string;
  workload?: string;
  privileged: boolean;
  run_as_root: boolean;
  risk_score: number;
  critical: number;
  high: number;
}
export interface ContainerListResponse {
  cluster_id: string;
  items: ContainerRow[];
  summary: { total: number; running: number; privileged: number; run_as_root: number };
}
export const containers = {
  list: (clusterID: string) =>
    api.get<ContainerListResponse>(`/clusters/${encodeURIComponent(clusterID)}/containers`).then((r) => r.data),
};

export interface NetworkRule {
  id: number;
  comment: string;
  from: string;
  to: string;
  ports: string;
  action: "allow" | "deny";
  applications: string[];
  learned: boolean;
  disable: boolean;
  cfg_type: string;
  priority: number;
  match_counter: number;
  last_match_timestamp: number;
}
export interface NetworkRuleInput {
  from: string;
  to: string;
  ports?: string;
  applications?: string[];
  action?: "allow" | "deny";
  disable?: boolean;
  comment?: string;
  priority?: number;
}
export const networkRules = {
  list: (clusterID: string) =>
    api.get<{ cluster_id: string; rules: NetworkRule[]; summary: { total: number; allow: number; deny: number; learned: number; disabled: number } }>(`/clusters/${encodeURIComponent(clusterID)}/network-rules`).then((r) => r.data),
  upsert: (clusterID: string, body: NetworkRuleInput) =>
    api.put<{ ok: boolean; id: number; cfg_type: string }>(`/clusters/${encodeURIComponent(clusterID)}/network-rules`, body).then((r) => r.data),
  remove: (clusterID: string, from: string, to: string) =>
    api.delete(`/clusters/${encodeURIComponent(clusterID)}/network-rules?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`).then((r) => r.data),
};

export const nodes = {
  list: (clusterID: string) =>
    api.get<NodeListResponse>(`/clusters/${encodeURIComponent(clusterID)}/nodes`).then((r) => r.data),
  get: (clusterID: string, node: string) =>
    api.get<NodeDetail>(`/clusters/${encodeURIComponent(clusterID)}/nodes/${encodeURIComponent(node)}`).then((r) => r.data),
  scan: (scanTargetID: string) =>
    api.post(`/scan/host/${encodeURIComponent(scanTargetID)}`, {}).then((r) => r.data),
};

export interface Framework { id: string; name: string; category: string }
export interface ComplianceCheck {
  framework: string;
  control_id: string;
  title: string;
  description: string;
  status: "pass" | "fail" | "manual" | "not_applicable";
  effective_status: "pass" | "fail" | "manual" | "not_applicable" | "exempted";
  severity: string;
  evidence: string;
  evaluated_at: string;
  // Regulation cross-mapping: standard-id -> { profile, references[], description }.
  // e.g. { "pci-dss-4.0": { references: ["2.2.1"] }, "nist-800-190": {...} }.
  tags_v2?: Record<string, { profile?: string; references?: string[]; description?: string }>;
  exemption?: {
    id: string;
    reason: string;
    expires_at: string;
  };
}
export interface ComplianceSummary {
  framework: string;
  pass: number;
  fail: number;
  manual: number;
  not_applicable?: number;
  exempted?: number;
  total: number;
  pass_pct: number;
  effective_pass_pct?: number;
}
export interface ComplianceExemption {
  id: string;
  cluster_id?: string;
  framework: string;
  control_id: string;
  reason: string;
  approved_by?: string;
  expires_at: string;
  created_at: string;
  revoked_at?: string;
  status: "active" | "expired" | "revoked";
}
export interface ComplianceEvidenceItem {
  id: string;
  scope: "node" | "workload" | "kubernetes" | "cloud";
  source: string;
  framework: string;
  control_id: string;
  internal_id?: string;
  title: string;
  severity: string;
  status: "pass" | "fail" | "manual" | "not_applicable";
  effective_status: "pass" | "fail" | "manual" | "not_applicable" | "exempted";
  target_kind: string;
  target: string;
  cluster_id?: string;
  namespace?: string;
  evidence?: string;
  remediation?: string;
  observed_at: string;
  exemption?: {
    id: string;
    reason: string;
    expires_at: string;
  };
}
export interface ComplianceEvidenceSummary {
  pass: number;
  fail: number;
  manual: number;
  not_applicable: number;
  exempted: number;
  total: number;
  by_scope?: Record<string, Omit<ComplianceEvidenceSummary, "by_scope">>;
}
export interface ComplianceEvidenceResponse {
  items: ComplianceEvidenceItem[];
  summary: ComplianceEvidenceSummary;
}

// DB-backed compliance scheduling.
export interface ComplianceScheduleDelivery {
  kind: "email" | "s3" | "webhook" | "file";
  target?: string;
  bucket?: string;
  prefix?: string;
  endpoint?: string;
  receiver_id?: string;
  url?: string;
}
export interface ComplianceScheduleDB {
  id: string;
  org_id: string;
  cluster_id?: string;
  name: string;
  description: string;
  framework: string;
  cron_expression: string;
  timezone: string;
  enabled: boolean;
  delivery: ComplianceScheduleDelivery[];
  report_format: string;
  report_template: string;
  last_run_at?: string;
  next_run_at?: string;
  last_status?: string;
  last_artifact_uri?: string;
  last_error?: string;
  created_at: string;
  updated_at: string;
}
export interface ComplianceScheduleListDBResponse {
  schedules: ComplianceScheduleDB[];
  summary: { total: number; enabled: number; disabled: number };
  frameworks: string[];
  report_formats: string[];
}
export interface ComplianceRunDB {
  id: string;
  org_id: string;
  cluster_id?: string;
  schedule_id?: string;
  framework: string;
  started_at: string;
  completed_at?: string;
  status: string;
  summary: { pass?: number; fail?: number; manual?: number; total?: number };
  artifact_uri?: string;
  artifact_signature?: string;
  artifact_size_bytes?: number;
  triggered_by: string;
  error_message?: string;
}

export const compliance = {
  frameworks: () => api.get<{ frameworks: Framework[] }>("/compliance/frameworks").then((r) => r.data),
  checks:     (framework?: string, cluster_id?: string) =>
    api.get<{ checks: ComplianceCheck[] }>("/compliance/checks", { params: { framework, cluster_id } }).then((r) => r.data),
  summary:    (cluster_id?: string) =>
    api.get<{ frameworks: ComplianceSummary[] }>("/compliance/summary", { params: { cluster_id } }).then((r) => r.data),
  evidence: (params: { cluster_id?: string; scope?: string; framework?: string; namespace?: string; limit?: number } = {}) =>
    api.get<ComplianceEvidenceResponse>("/compliance/evidence", { params }).then((r) => r.data),
  nodeEvidence: (params: { cluster_id?: string; framework?: string; limit?: number } = {}) =>
    api.get<ComplianceEvidenceResponse>("/compliance/nodes", { params }).then((r) => r.data),
  workloadEvidence: (params: { cluster_id?: string; framework?: string; namespace?: string; limit?: number } = {}) =>
    api.get<ComplianceEvidenceResponse>("/compliance/workloads", { params }).then((r) => r.data),
  kubernetesEvidence: (params: { cluster_id?: string; framework?: string; limit?: number } = {}) =>
    api.get<ComplianceEvidenceResponse>("/compliance/kubernetes", { params }).then((r) => r.data),
  cloudEvidence: (params: { cluster_id?: string; framework?: string; limit?: number } = {}) =>
    api.get<ComplianceEvidenceResponse>("/compliance/cloud", { params }).then((r) => r.data),
  listExemptions: (params: { framework?: string; control_id?: string; cluster_id?: string } = {}) =>
    api.get<{ exemptions: ComplianceExemption[] }>("/compliance/exemptions", { params }).then((r) => r.data),
  createExemption: (body: { cluster_id?: string; framework: string; control_id: string; reason: string; expires_at: string }) =>
    api.post<{ id: string; exemptions: ComplianceExemption[] }>("/compliance/exemptions", body).then((r) => r.data),
  revokeExemption: (id: string) =>
    api.post<{ status: string; id: string }>(`/compliance/exemptions/${id}/revoke`).then((r) => r.data),
  listDBSchedules: (cluster_id?: string) =>
    api.get<ComplianceScheduleListDBResponse>("/compliance/schedules", { params: { cluster_id } }).then((r) => r.data),
  createSchedule: (body: {
    name: string;
    description?: string;
    cluster_id?: string;
    framework: string;
    cron_expression: string;
    timezone?: string;
    enabled?: boolean;
    delivery: ComplianceScheduleDelivery[];
    report_format?: string;
    report_template?: string;
  }) => api.post<ComplianceScheduleDB>("/compliance/schedules", body).then((r) => r.data),
  patchSchedule: (id: string, body: Partial<ComplianceScheduleDB>) =>
    api.patch<ComplianceScheduleDB>(`/compliance/schedules/${id}`, body).then((r) => r.data),
  deleteSchedule: (id: string) => api.delete(`/compliance/schedules/${id}`),
  runScheduleNow: (id: string) =>
    api.post<{ schedule: ComplianceScheduleDB; queued: boolean; message: string }>(`/compliance/schedules/${id}/run-now`).then((r) => r.data),
  scheduleRuns: (id: string, limit = 50) =>
    api.get<{ runs: ComplianceRunDB[] }>(`/compliance/schedules/${id}/runs`, { params: { limit } }).then((r) => r.data),
  runArtifactURL: (id: string) => `/api/v1/compliance/runs/${id}/artifact`,
  downloadRunArtifact: (id: string) =>
    downloadAPIFile(`/compliance/runs/${id}/artifact`, `compliance-run-${id}.json`),
};

export interface Deployment {
  id: string;
  cluster_id?: string;
  namespace: string;
  name: string;
  kind: string;
  labels: Record<string, string>;
  risk_score: number;
  risk_factors: Record<string, number>;
  finding_count: number;
  critical_count: number;
  high_count: number;
  image_refs?: string[];
  workload_ids?: string[];
  first_seen_at: string;
  last_seen_at: string;
}

export interface DeploymentImageEvidence {
  image_ref: string;
  image_ref_normalized: string;
  image_repository?: string;
  image_tag?: string;
  image_digest?: string;
  image_scan_result_id?: string;
  scanner_profile?: string;
  vulndb_bundle_version?: string;
  package_count: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  max_risk_score: number;
  last_scanned_at?: string;
  last_seen_at: string;
}

export interface DeploymentPackageEvidence {
  id: string;
  scan_target_id: string;
  target_ref: string;
  workload_id: string;
  node?: string;
  namespace?: string;
  pod_name?: string;
  pod_uid?: string;
  runtime?: string;
  distro?: string;
  distro_version?: string;
  source?: string;
  inventory_hash: string;
  package_count: number;
  container_count: number;
  payload: Record<string, unknown>;
  observed_at: string;
}

export interface DeploymentFinding {
  id: string;
  kind: FindingKind;
  external_id?: string;
  title: string;
  severity: Severity;
  risk_score: number;
  lifecycle: Lifecycle;
  target_type?: string;
  target_ref?: string;
  package_name?: string;
  package_version?: string;
  fixed_version?: string;
  last_seen_at: string;
}

export interface DeploymentNetworkFlow {
  id: string;
  src: string;
  dst: string;
  src_addr?: string;
  dst_addr?: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  l7_protocol?: string;
  verdict: string;
  source?: string;
  bytes: number;
  packets: number;
  sessions?: number;
  threat_id?: number;
  severity?: number;
  last_seen_at: string;
}

export interface QuarantineEntry {
  id: string;
  org_id: string;
  cluster_id: string;
  scope: "workload" | "image" | "namespace";
  match_key: string;
  reason: string;
  origin: "manual" | "auto" | string;
  source_kind?: string;
  source_id?: string;
  created_by?: string;
  created_at: string;
  expires_at?: string;
  lifted_at?: string;
  lifted_by?: string;
  lifted_reason?: string;
}

export interface DeploymentProcessBaseline {
  workload_id: string;
  control_workload_id: string;
  cluster_id?: string;
  mode: "learn" | "monitor" | "enforce";
  learned_processes_count: number;
  monitored_alerts_24h: number;
  enforced_blocks_24h: number;
  last_new_process_at?: string;
  learn_started_at?: string;
  monitor_started_at?: string;
  enforce_started_at?: string;
  transitions?: BaselineTransition[];
  processes: Array<{
    name: string;
    args: string[];
    path: string;
    observed_count: number;
    first_seen: string;
    last_seen: string;
  }>;
}

export interface DeploymentFileProfile {
  workload_id: string;
  control_workload_id: string;
  cluster_id?: string;
  mode: "learn" | "monitor" | "enforce";
  learned_paths_count: number;
  sensitive_path_count: number;
  rule_count: number;
  watched_file_count: number;
  monitored_alerts_24h: number;
  enforced_blocks_24h: number;
  last_new_path_at?: string;
  learn_started_at?: string;
  monitor_started_at?: string;
  enforce_started_at?: string;
  transitions?: BaselineTransition[];
  files: Array<{
    path: string;
    operation: string;
    comm?: string;
    flags: number;
    mode: number;
    observed_count: number;
    sensitive: boolean;
    first_seen: string;
    last_seen: string;
  }>;
  rules: FileProfileRule[];
  exceptions: FileProfileException[];
  watched_files: FileProfileWatch[];
}

export type DeploymentThreatKind = "file" | "dlp" | "waf";

export interface DeploymentThreatPivot {
  id: string;
  kind: DeploymentThreatKind;
  at: string;
  severity: Severity | "info" | string;
  verdict: string;
  title: string;
  message?: string;
  workload_id: string;
  node_id?: string;
  namespace?: string;
  container_id?: string;
  attack_techniques: string[];
  source_event_id?: string;
  runtime_threat_id?: string;
  rule?: {
    id?: string;
    name?: string;
    category: "file" | "dlp" | "waf" | "signature" | "builtin";
    mode?: "learn" | "monitor" | "enforce" | "disabled";
    group?: string;
    dp_rule_id?: number;
  };
  file?: {
    path?: string;
    flags?: number;
    mode?: number;
    pid?: number;
    comm?: string;
    operation?: string;
  };
  network?: {
    src_ip?: string;
    src_port?: number;
    dst_ip?: string;
    dst_port?: number;
    protocol?: string;
    direction?: "ingress" | "egress" | string;
  };
  has_packet: boolean;
}

export interface DeploymentFileRisk {
  image_scan_result_id: string;
  image_ref?: string;
  image_ref_normalized?: string;
  image_digest?: string;
  artifact_id: string;
  format: string;
  sha256: string;
  status?: string;
  reason?: string;
  error?: string;
  file_risk_count: number;
  truncated: boolean;
  created_at: string;
  findings: Array<{
    path: string;
    type?: string;
    mode?: string;
    uid?: number;
    gid?: number;
    size_bytes?: number;
    layer_index?: number;
    layer_digest?: string;
    link_name?: string;
    risk_types?: string[];
    severity?: string;
    reason?: string;
  }>;
}

export interface DeploymentComplianceEvidence {
  id: string;
  source: string;
  framework: string;
  control_id: string;
  internal_id?: string;
  title: string;
  severity: string;
  status: "pass" | "fail" | "manual" | "not_applicable";
  effective_status: "pass" | "fail" | "manual" | "not_applicable" | "exempted";
  target_kind: string;
  target: string;
  evidence?: string;
  remediation?: string;
  observed_at: string;
  exemption?: string;
}

export interface Violation {
  id: string;
  deployment_id?: string;
  policy_name: string;
  severity: string;
  kind: string;
  message: string;
  at: string;
  deployment?: { namespace: string; name: string; kind: string };
}

export interface DeploymentDetail extends Deployment {
  image_refs: string[];
  workload_ids: string[];
  images: DeploymentImageEvidence[];
  package_evidence: DeploymentPackageEvidence[];
  findings: DeploymentFinding[];
  runtime_events: RuntimeEvent[];
  threat_pivots: DeploymentThreatPivot[];
  file_risks: DeploymentFileRisk[];
  network_flows: DeploymentNetworkFlow[];
  network_policy?: NetworkPolicyLifecycle;
  quarantine?: QuarantineEntry | null;
  process_baseline?: DeploymentProcessBaseline | null;
  file_profile?: DeploymentFileProfile | null;
  compliance_evidence: DeploymentComplianceEvidence[];
  violations: Violation[];
}

export const deployments = {
  list: (params: { namespace?: string; cluster_id?: string; limit?: number } = {}) =>
    api.get<{ deployments: Deployment[] }>("/deployments", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<DeploymentDetail>(`/deployments/${id}`).then((r) => r.data),
};

export const quarantine = {
  list: (params: { cluster_id?: string; scope?: "workload" | "image" | "namespace"; include_lifted?: boolean; limit?: number } = {}) =>
    api.get<{ entries: QuarantineEntry[] }>("/quarantine", {
      params: { ...params, include_lifted: params.include_lifted ? 1 : undefined },
    }).then((r) => r.data.entries),
  create: (body: { cluster_id: string; scope: "workload" | "image" | "namespace"; match_key: string; reason: string; expires_in_hours?: number }) =>
    api.post<QuarantineEntry>("/quarantine", body).then((r) => r.data),
  lift: (id: string, body: { reason: string }) =>
    api.post<{ status: string }>(`/quarantine/${encodeURIComponent(id)}/lift`, body).then((r) => r.data),
};

export const violations = {
  list: (limit = 100) =>
    api.get<{ violations: Violation[] }>(`/violations`, { params: { limit } }).then((r) => r.data),
};

// Process Baseline lifecycle — NeuVector-style learn → monitor → enforce kanban.
export type BaselineMode = "learn" | "monitor" | "enforce";

export interface BaselineSummary {
  workload_id: string;
  cluster_id?: string;
  namespace: string;
  name: string;
  mode: BaselineMode;
  learned_processes_count: number;
  monitored_alerts_24h: number;
  enforced_blocks_24h: number;
  learn_started_at?: string;
  monitor_started_at?: string;
  enforce_started_at?: string;
  last_new_process_at?: string;
  top_processes?: string[];
}

export interface BaselineProcess {
  name: string;
  args: string[];
  path: string;
  observed_count: number;
  first_seen: string;
  last_seen: string;
}

export interface BaselineTransition {
  at: string;
  actor: string;
  from: BaselineMode | "";
  to: BaselineMode;
  reason: string;
}

export interface ProcessRule {
  rule_id: string;
  name: string;
  path: string;
  action: "allow" | "deny";
  user: string;
  allow_update: boolean;
  enabled: boolean;
  description: string;
  updated_at: string;
}
export interface ProcessRuleInput {
  name: string;
  path?: string;
  action?: "allow" | "deny";
  user?: string;
  allow_update?: boolean;
  enabled?: boolean;
  description?: string;
}

export interface BaselineDetail extends BaselineSummary {
  processes: BaselineProcess[];
  transitions: BaselineTransition[];
  rules: ProcessRule[];
}

export const baselines = {
  list: (params: { cluster_id?: string; namespace?: string } = {}) =>
    api
      .get<{ profiles: BaselineSummary[]; summary: { total: number; learn: number; monitor: number; enforce: number } }>(
        "/runtime/baselines",
        { params },
      )
      .then((r) => r.data),
  get: (workloadID: string, params: { cluster_id?: string } = {}) =>
    api
      .get<BaselineDetail>(`/runtime/baselines/${encodeURIComponent(workloadID)}`, { params })
      .then((r) => r.data),
  setMode: (workloadID: string, body: { mode: BaselineMode; reason?: string }, params: { cluster_id?: string } = {}) =>
    api
      .post<BaselineSummary>(`/runtime/baselines/${encodeURIComponent(workloadID)}/mode`, body, { params })
      .then((r) => r.data),
  createRule: (workloadID: string, body: ProcessRuleInput) =>
    api.post<ProcessRule>(`/runtime/baselines/${encodeURIComponent(workloadID)}/rules`, body).then((r) => r.data),
  updateRule: (workloadID: string, ruleID: string, body: ProcessRuleInput) =>
    api.put<ProcessRule>(`/runtime/baselines/${encodeURIComponent(workloadID)}/rules/${encodeURIComponent(ruleID)}`, body).then((r) => r.data),
  deleteRule: (workloadID: string, ruleID: string) =>
    api.delete(`/runtime/baselines/${encodeURIComponent(workloadID)}/rules/${encodeURIComponent(ruleID)}`).then((r) => r.data),
};

export interface FileProfileSummary {
  workload_id: string;
  cluster_id?: string;
  namespace: string;
  name: string;
  mode: BaselineMode;
  learned_paths_count: number;
  sensitive_path_count: number;
  rule_count: number;
  watched_file_count: number;
  monitored_alerts_24h: number;
  enforced_blocks_24h: number;
  learn_started_at?: string;
  monitor_started_at?: string;
  enforce_started_at?: string;
  last_new_path_at?: string;
  top_paths?: string[];
}

export type FileProfileRuleBehavior = "monitor_change" | "block_access";

export interface FileProfileRule {
  id: string;
  filter: string;
  path: string;
  regex: string;
  recursive: boolean;
  behavior: FileProfileRuleBehavior;
  applications: string[];
  enabled: boolean;
  description?: string;
  created_by?: string;
  updated_by?: string;
  created_at: string;
  updated_at: string;
}

export interface FileProfileException {
  id: string;
  rule_id?: string;
  filter: string;
  path: string;
  regex: string;
  recursive: boolean;
  applications: string[];
  enabled: boolean;
  description?: string;
  expires_at?: string;
  created_by?: string;
  updated_by?: string;
  created_at: string;
  updated_at: string;
}

export interface FileProfilePortableRule {
  id?: string;
  filter: string;
  path?: string;
  regex?: string;
  recursive: boolean;
  behavior: FileProfileRuleBehavior;
  applications: string[];
  enabled?: boolean;
  description?: string;
  source_id?: string;
  source_group?: string;
  cfg_type?: string;
}

export interface FileProfileBundle {
  schema_version: "constellation-file-profile-v1" | string;
  kind: "FileProfile" | string;
  workload_id: string;
  cluster_id?: string;
  namespace?: string;
  name?: string;
  mode: BaselineMode;
  exported_at: string;
  rules: FileProfilePortableRule[];
  exceptions?: Array<{
    id?: string;
    rule_id?: string;
    filter: string;
    path?: string;
    regex?: string;
    recursive: boolean;
    applications: string[];
    enabled?: boolean;
    description?: string;
    expires_at?: string;
  }>;
}

export interface FileProfileImportResponse {
  dry_run: boolean;
  replace: boolean;
  imported: number;
  deleted: number;
  mode: BaselineMode;
  cluster_id: string;
  target_workload_id: string;
  rules: FileProfilePortableRule[];
  exceptions?: FileProfileBundle["exceptions"];
  warnings?: string[];
}

export interface FileProfileFile {
  path: string;
  operation: string;
  comm?: string;
  flags: number;
  mode: number;
  observed_count: number;
  sensitive: boolean;
  first_seen: string;
  last_seen: string;
}

export interface FileProfileWatchFile {
  path: string;
  is_dir: boolean;
  container_id?: string;
  container_name?: string;
  pod_name?: string;
  pod_namespace?: string;
  size_bytes?: number;
}

export interface FileProfileWatch {
  node: string;
  rule_id: string;
  filter: string;
  path: string;
  regex: string;
  recursive: boolean;
  behavior: FileProfileRuleBehavior;
  applications: string[];
  profile_mode: BaselineMode;
  desired_protect: boolean;
  protect: boolean;
  enforcement_state: "synced" | "unsupported" | "enforced" | "error" | string;
  files: FileProfileWatchFile[];
  files_count: number;
  sensitive_count: number;
  bundle_fingerprint?: string;
  observed_at: string;
  updated_at: string;
}

export interface FileProfileDetail extends FileProfileSummary {
  files: FileProfileFile[];
  transitions: BaselineTransition[];
  rules: FileProfileRule[];
  exceptions: FileProfileException[];
  watched_files: FileProfileWatch[];
}

export const fileProfiles = {
  list: (params: { cluster_id?: string; namespace?: string } = {}) =>
    api
      .get<{ profiles: FileProfileSummary[]; summary: { total: number; learn: number; monitor: number; enforce: number } }>(
        "/runtime/file-profiles",
        { params },
      )
      .then((r) => r.data),
  get: (workloadID: string, params: { cluster_id?: string } = {}) =>
    api
      .get<FileProfileDetail>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}`, { params })
      .then((r) => r.data),
  exportBundle: (workloadID: string, params: { cluster_id?: string } = {}) =>
    api
      .get<FileProfileBundle>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/export`, { params })
      .then((r) => r.data),
  importBundle: (
    workloadID: string,
    body: { bundle: FileProfileBundle; mode?: BaselineMode; dry_run?: boolean; replace?: boolean; reason: string },
    params: { cluster_id?: string } = {},
  ) =>
    api
      .post<FileProfileImportResponse>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}:import`, body, { params })
      .then((r) => r.data),
  setMode: (workloadID: string, body: { mode: BaselineMode; reason?: string }, params: { cluster_id?: string } = {}) =>
    api
      .post<FileProfileSummary>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/mode`, body, { params })
      .then((r) => r.data),
  createRule: (
    workloadID: string,
    body: {
      filter: string;
      recursive?: boolean;
      behavior: FileProfileRuleBehavior;
      applications?: string[];
      enabled?: boolean;
      description?: string;
      reason: string;
    },
    params: { cluster_id?: string } = {},
  ) =>
    api
      .post<FileProfileRule>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/rules`, body, { params })
      .then((r) => r.data),
  updateRule: (
    workloadID: string,
    ruleID: string,
    body: {
      filter?: string;
      recursive?: boolean;
      behavior?: FileProfileRuleBehavior;
      applications?: string[];
      enabled?: boolean;
      description?: string;
      reason: string;
    },
    params: { cluster_id?: string } = {},
  ) =>
    api
      .put<FileProfileRule>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/rules/${encodeURIComponent(ruleID)}`, body, { params })
      .then((r) => r.data),
  deleteRule: (workloadID: string, ruleID: string, body: { reason: string }, params: { cluster_id?: string } = {}) =>
    api
      .delete<{ deleted: string }>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/rules/${encodeURIComponent(ruleID)}`, { data: body, params })
      .then((r) => r.data),
  createException: (
    workloadID: string,
    body: {
      rule_id?: string;
      filter: string;
      recursive?: boolean;
      applications?: string[];
      enabled?: boolean;
      description?: string;
      expires_at?: string;
      reason: string;
    },
    params: { cluster_id?: string } = {},
  ) =>
    api
      .post<FileProfileException>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/exceptions`, body, { params })
      .then((r) => r.data),
  updateException: (
    workloadID: string,
    exceptionID: string,
    body: {
      rule_id?: string;
      filter?: string;
      recursive?: boolean;
      applications?: string[];
      enabled?: boolean;
      description?: string;
      expires_at?: string;
      reason: string;
    },
    params: { cluster_id?: string } = {},
  ) =>
    api
      .put<FileProfileException>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/exceptions/${encodeURIComponent(exceptionID)}`, body, { params })
      .then((r) => r.data),
  deleteException: (workloadID: string, exceptionID: string, body: { reason: string }, params: { cluster_id?: string } = {}) =>
    api
      .delete<{ deleted: string }>(`/runtime/file-profiles/${encodeURIComponent(workloadID)}/exceptions/${encodeURIComponent(exceptionID)}`, { data: body, params })
      .then((r) => r.data),
};

export interface ClusterStats {
  critical_open: number;
  high_open: number;
  open_findings: number;
  total_findings: number;
}

export interface ClusterSummary {
  id: string;
  name: string;
  distro: string;
  cloud_provider: string;
  region: string;
  state: string;
  agent_version: string;
  deployments: number;
  max_risk: number;
  last_heartbeat_at?: string;
  /** Aggregated finding counts for the cluster picker tiles. */
  stats?: ClusterStats;
  /** Timestamp of the most recently-observed network flow in this cluster. */
  last_flow_at?: string;
  /** namespace/name string of the workload with the highest risk score. */
  top_workload?: string;
  top_workload_risk?: number;
  sensor_health?: { status: string; ready: number; total: number };
  upgrade?: { available: boolean; target_version: string; rollout_status: string; rollback_window: string };
  platform?: {
    kubernetes_git_version?: string;
    platform_provider?: string;
    observed_at?: string;
  };
}

export interface ClusterDetail {
  id: string;
  name: string;
  distro: string;
  cloud_provider: string;
  region: string;
  state: string;
  agent_version: string;
  last_heartbeat_at?: string;
}

export interface ClusterHealth {
  cluster_id: string;
  summary: {
    status: string;
    connected_sensors: number;
    expected_sensors: number;
    last_check_in: string;
    registration_state: string;
  };
  components: Array<{
    name: string;
    kind: string;
    status: string;
    version: string;
    desired: number;
    ready: number;
    last_seen_at: string;
  }>;
  registration: {
    bundle_id: string;
    expires_at: string;
    rotate_command: string;
    helm_command: string;
  };
  gates: Array<{ name: string; status: string; evidence: string }>;
}

export interface PlatformComponent {
  name: string;
  version: string;
  type?: string;
  source?: string;
  namespace?: string;
}

export interface PlatformPackage {
  ecosystem?: string;
  name?: string;
  version?: string;
  purl?: string;
  namespace_kind?: string;
  namespace_name?: string;
  namespace_version?: string;
}

export interface ClusterPlatformFacts {
  cluster_id: string;
  distro: string;
  kubernetes_git_version?: string;
  kubernetes_major?: string;
  kubernetes_minor?: string;
  platform_provider?: string;
  platform_version?: string;
  node_count: number;
  kubelet_versions?: Record<string, number>;
  components?: PlatformComponent[];
  observed_at: string;
  updated_at: string;
}

export interface PlatformFactsResponse {
  cluster_id: string;
  cluster_name: string;
  distro: string;
  status: string;
  facts?: ClusterPlatformFacts;
  scan_target?: {
    id: string;
    ref: string;
    source_type: string;
    source_ref?: string;
    platform?: string;
    inventory_hash?: string;
    last_seen_at: string;
  };
  evidence?: {
    id: string;
    inventory_hash: string;
    package_count: number;
    packages?: PlatformPackage[];
    observed_at: string;
  };
  latest_job?: {
    id: string;
    status: string;
    error?: string;
    package_count?: number;
    finding_count?: number;
    bundle_metadata?: {
      schema_version?: string;
      bundle_version?: string;
      producer?: string;
      media_type?: string;
      exported_at?: string;
      payload_hash?: string;
      record_count?: number;
    };
    requested_at: string;
    claimed_at?: string;
    finished_at?: string;
  };
  findings_summary: {
    open: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: Array<{
    id: string;
    external_id?: string;
    title: string;
    severity: string;
    risk_score: number;
    package_name?: string;
    package_version?: string;
    fixed_version?: string;
    source?: string;
    last_seen_at: string;
  }>;
}

export const clusters = {
  list: () => api.get<{ clusters: ClusterSummary[] }>("/clusters").then((r) => r.data),
  getOne: (id: string) => api.get<ClusterDetail>(`/clusters/${id}`).then((r) => r.data),
  health: (id: string) => api.get<ClusterHealth>(`/clusters/${id}/health`).then((r) => r.data),
  platformFacts: (id: string) => api.get<PlatformFactsResponse>(`/clusters/${id}/platform-facts`).then((r) => r.data),
  scanPlatform: (id: string) =>
    api
      .post<{ scan_target_id: string; scan_evidence_id: string; inventory_hash: string; scan_job_enqueued: boolean; scan_job_id?: string }>(
        `/clusters/${id}/platform-scan`,
      )
      .then((r) => r.data),
};

// Wave N1: cluster init-bundles (StackRox-style onboarding kits).
export interface ClusterInitBundleSummary {
  id: string;
  org_id: string;
  cluster_id: string;
  name: string;
  distro: string;
  region?: string;
  status: "active" | "expired" | "revoked";
  expires_at: string;
  revoked_at?: string;
  downloaded_at?: string;
  created_at: string;
  created_by?: string;
}

export interface ClusterInitBundleMint extends ClusterInitBundleSummary {
  yaml: string;
  server_url: string;
  import_url: string;
}

export interface CreateClusterInitBundleRequest {
  name: string;
  distro?: string;
  region?: string;
  ttl?: string;
}

export const clusterInitBundles = {
  list: () =>
    api
      .get<{ bundles: ClusterInitBundleSummary[] }>("/cluster-init-bundles")
      .then((r) => r.data.bundles),
  create: (req: CreateClusterInitBundleRequest) =>
    api.post<ClusterInitBundleMint>("/cluster-init-bundles", req).then((r) => r.data),
  get: (id: string) =>
    api.get<ClusterInitBundleMint>(`/cluster-init-bundles/${id}`).then((r) => r.data),
  rotate: (id: string) =>
    api.post<ClusterInitBundleMint>(`/cluster-init-bundles/${id}/rotate`).then((r) => r.data),
  revoke: (id: string) =>
    api.delete<{ status: string }>(`/cluster-init-bundles/${id}`).then((r) => r.data),
};

export interface VulnerabilityException {
  id: string;
  status: "pending" | "approved" | "expired" | "revoked" | "suppressed";
  title: string;
  reason: string;
  scope: {
    org_id: string;
    clusters: string[];
    namespaces: string[];
    workloads: string[];
    images: string[];
    environment: string;
    admission_scope: string;
  };
  cve_refs: string[];
  finding_refs: string[];
  requester: { id: string; name: string; email: string; team: string };
  approver?: { id: string; name: string; email: string; team: string };
  requested_at: string;
  approved_at?: string;
  expires_at: string;
  risk_acceptance: {
    severity: Severity;
    business_justification: string;
    compensating_controls: string[];
    review_cadence: string;
  };
  audit_events: Array<{ at: string; actor: string; action: string; message: string }>;
  policy_guard_ids: string[];
}

export interface VulnerabilityExceptionsResponse {
  exceptions: VulnerabilityException[];
  summary: { total: number; pending: number; approved: number; expired: number; revoked?: number; suppressed?: number };
  statuses: string[];
  workflow: Array<{ id: string; name: string; description: string; statuses: string[] }>;
  policy_guardrails: Array<{ id: string; name: string; description: string; applies_to: string[]; enforcement: string }>;
}

export const vulnerabilityExceptions = {
  list: () => api.get<VulnerabilityExceptionsResponse>("/vulnerability-exceptions").then((r) => r.data),
};

export interface SystemHealthHeartbeat {
  component: string;
  cluster_id?: string;
  cluster_name?: string;
  version: string;
  commit: string;
  commit_short: string;
  build_time?: string;
  hostname: string;
  uptime_seconds: number;
  restart_count: number;
  last_error?: string;
  metadata?: {
    max_concurrent?: number;
    active_jobs?: number;
    idle_capacity?: number;
    target_capacity?: Record<string, number>;
    active_jobs_by_target_type?: Record<string, number>;
    engines?: Record<string, boolean>;
    cache_dirs?: Record<string, string>;
    cache_health?: Record<string, ScannerCacheHealthEntry>;
    vulndb?: { enabled?: boolean; ready?: boolean; status?: string; path?: string; bundle_version?: string; payload_hash?: string; exported_at?: string; record_count?: number; error?: string };
  };
  last_seen_at: string;
  status: "healthy" | "degraded" | "stale" | "drift" | "crashlooping" | string;
  drift_reason?: string;
}

export interface SystemHealthClusterDrift {
  cluster_id?: string;
  cluster_name: string;
  total_components: number;
  healthy: number;
  degraded: number;
  stale: number;
  drift: number;
  crashlooping: number;
  control_commit: string;
  versions: Array<{ component: string; commit: string; count: number }>;
}

export interface SystemHealthCrashloopEvent {
  id: number;
  component: string;
  hostname: string;
  cluster_id?: string;
  prev_uptime_s: number;
  new_uptime_s: number;
  detected_at: string;
  reason?: string;
}

export interface SystemHealthLicense {
  kind: string;
  severity: "info" | "warning" | "critical" | "fatal" | string;
  issued_at?: string;
  expires_at?: string;
  days_to_expiry: number;
  message: string;
  signed_by?: string;
  customer_id?: string;
  seats?: number;
  banner_visible: boolean;
}

export interface SystemHealth {
  summary: {
    status: string;
    generated_at: string;
    components_total: number;
    components_by_status: Record<string, number>;
    active_incidents: number;
    open_actions: number;
    degraded_components: string[];
    healthy?: number;
    degraded?: number;
    stale?: number;
    drift?: number;
    crashlooping?: number;
  };
  components: Array<{
    id: string;
    name: string;
    domain: string;
    status: string;
    mode: string;
    owner: string;
    slo: string;
    last_checked: string;
    summary: string;
    signals: Array<{ name: string; status: string; value: string; threshold: string; evidence: string }>;
  }>;
  incidents: Array<{
    id: string;
    severity: string;
    status: string;
    component_ids: string[];
    started_at: string;
    summary: string;
    impact: string;
  }>;
  remediation_actions: Array<{
    id: string;
    priority: string;
    status: string;
    component_id: string;
    title: string;
    owner: string;
    due_at: string;
    steps: string[];
  }>;
  heartbeats?: SystemHealthHeartbeat[];
  version_drift?: SystemHealthClusterDrift[];
  crashloop_history?: SystemHealthCrashloopEvent[];
  license?: SystemHealthLicense;
  control_plane?: Record<string, string>;
}

export const systemHealth = {
  overview: () => api.get<SystemHealth>("/system-health").then((r) => r.data),
  cluster: (clusterId: string) =>
    api.get<{
      cluster_id: string;
      cluster_name: string;
      heartbeats: SystemHealthHeartbeat[];
      version_drift: SystemHealthClusterDrift;
      crashloop_history: SystemHealthCrashloopEvent[];
    }>(`/system-health/clusters/${clusterId}`).then((r) => r.data),
};

export interface ComponentInventorySummary {
  generated_at: string;
  components: number;
  total_instances: number;
  healthy: number;
  degraded: number;
  stale: number;
  drift: number;
  crashlooping: number;
  missing: number;
}

export type ComponentStatus = "healthy" | "degraded" | "stale" | "drift" | "crashlooping" | "missing" | "not-observed";

export interface ComponentRollup {
  component: string;
  display_name: string;
  role: string;
  scope: string;
  kind: string;
  expected: boolean;
  status: ComponentStatus;
  instances: number;
  healthy: number;
  degraded: number;
  stale: number;
  drift: number;
  crashlooping: number;
  missing: number;
  latest_version?: string;
  latest_commit?: string;
  latest_seen_at?: string;
  last_status_cause?: string;
}

export interface ComponentInstance {
  id: string;
  component: string;
  display_name: string;
  role: string;
  scope: string;
  kind: string;
  status: ComponentStatus;
  status_reason?: string;
  cluster_id?: string;
  cluster_name?: string;
  version?: string;
  commit?: string;
  commit_short?: string;
  build_time?: string;
  hostname: string;
  uptime_seconds: number;
  restart_count: number;
  last_error?: string;
  metadata?: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ComponentDiagnosticStatus {
  state: ComponentStatus;
  reason?: string;
  stale: boolean;
  drift: boolean;
  crashlooping: boolean;
  degraded: boolean;
  version?: string;
  commit?: string;
  commit_short?: string;
  uptime_seconds: number;
  restart_count: number;
  last_error?: string;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ComponentDiagnosticCheck {
  key: string;
  label: string;
  status: string;
  value?: unknown;
  reason?: string;
  evidence?: string;
  error?: string;
  observed_at?: string;
}

export interface ComponentDiagnosticCounter {
  key: string;
  label: string;
  value: unknown;
  unit?: string;
  window?: string;
  tone?: "neutral" | "success" | "warning" | "error" | string;
}

export interface ComponentDiagnosticConfig {
  key: string;
  label: string;
  value: unknown;
  evidence?: string;
}

export interface ComponentDiagnosticDebug {
  profiling_enabled: boolean;
  live_logs_enabled: boolean;
  support_bundle_enabled: boolean;
  notes?: string[];
}

export interface ComponentDiagnostics {
  component: ComponentInstance;
  generated_at: string;
  admin_gate: string;
  status: ComponentDiagnosticStatus;
  diagnostics: ComponentDiagnosticCheck[];
  counters: ComponentDiagnosticCounter[];
  config: ComponentDiagnosticConfig[];
  debug: ComponentDiagnosticDebug;
}

export interface ComponentInventoryResponse {
  summary: ComponentInventorySummary;
  rollups: ComponentRollup[];
  components: ComponentInstance[];
}

export const componentsInventory = {
  list: (params?: { cluster_id?: string; component?: string; status?: string; limit?: number }) =>
    api.get<ComponentInventoryResponse>("/components", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<{ component: ComponentInstance }>(`/components/${encodeURIComponent(id)}`).then((r) => r.data),
  diagnostics: (id: string) =>
    api.get<ComponentDiagnostics>(`/components/${encodeURIComponent(id)}/diagnostics`).then((r) => r.data),
};

export type NetworkFlowState = "ok" | "warn" | "denied" | "declared";

export interface NetworkWorkload {
  id: string;
  cluster_id?: string;
  cluster_name?: string;
  namespace: string;
  name: string;
  kind: string;
  risk_score: number;
  finding_count: number;
  /** Real per-severity open-finding counts from the deployments row. */
  critical_count?: number;
  high_count?: number;
}

export interface NetworkFlow {
  id: string;
  cluster_id?: string;
  src: string;
  dst: string;
  src_addr?: string;
  dst_addr?: string;
  src_port?: number;
  protocol: string;
  l7_protocol: string;
  dst_port: number;
  verdict: string;
  state: NetworkFlowState;
  traffic_scope?: string;
  bytes: number;
  packets: number;
  samples: number;
  last_seen_at: string;

  /** Provenance: 'dp' (NeuVector C data-plane, real on-wire metrics) wins
   *  over 'bpf' (legacy synthetic estimator) wins over 'synthetic' (seed).
   *  When the row is dp-sourced, the fields below are populated. */
  source?: "dp" | "bpf" | "synthetic" | "declared";

  /** dp-only: per-direction byte counts from DPI session tracker. Wave 4. */
  client_bytes?: number;
  server_bytes?: number;

  /** dp-only: count of distinct 5-tuple sessions aggregated into this bucket. */
  sessions?: number;

  /** dp-only: L7 application id (third_party/neuvector/dp/apis.h). 0 = unknown. */
  application_id?: number;

  /** dp-only: NeuVector signature ID if this flow tripped a threat detector. */
  threat_id?: number;
  /** dp-only: 1-9 severity scale; 0 / undefined when no threat. */
  severity?: number;

  /** Hubble-lane egress destination domain; empty on dp-only clusters. */
  fqdn?: string;
}

/** Wave 5: one DPI signature hit emitted by the NeuVector dp data-plane.
 *  Matches handler.RuntimeThreatRow exactly. The captured packet bytes are
 *  not surfaced in this list shape — fetch a per-id endpoint when drilling
 *  in (the table column is `packet bytea` server-side). */
export interface RuntimeThreat {
  id: string;
  org_id: string;
  cluster_id: string;
  node?: string;
  ep_mac?: string;
  workload_id?: string;
  namespace?: string;
  pod_name?: string;
  threat_id: number;
  /** Human-friendly upstream name, eg. "SQL_INJECTION", "SSL_HEARTBLEED". */
  threat_name?: string;
  /** 1..9 NeuVector severity scale. */
  severity: number;
  /** DP_THREAT_ACTION_* — usually 0 (log) in TAP mode. */
  action: number;
  application?: number;
  msg?: string;
  ip_proto?: number;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  pkt_len?: number;
  cap_len?: number;
  pkt_ingress: boolean;
  sess_ingress: boolean;
  /** When dp first observed the threat (host clock). */
  reported_at: string;
  /** When the API ingested the row. */
  at: string;
}

export interface NetworkRecentFlow {
  id: string;
  flow_id: string;
  cluster_id?: string;
  src: string;
  dst: string;
  src_addr?: string;
  dst_addr?: string;
  src_port?: number;
  protocol: string;
  l7_protocol: string;
  dst_port: number;
  verdict: string;
  state: NetworkFlowState;
  traffic_scope?: string;
  bytes: number;
  packets: number;
  observed_at: string;
}

export interface NetworkMap {
  summary: {
    window_hours: number;
    selected_cluster_id?: string;
    clusters?: Array<{ id: string; name: string; state: string }>;
    workloads: number;
    flows: number;
    recent_flows?: number;
    total_bytes?: number;
    total_packets?: number;
    allowed?: number;
    alerted?: number;
    blocked?: number;
  };
  workloads: NetworkWorkload[];
  flows: NetworkFlow[];
  recent_flows?: NetworkRecentFlow[];
}

/** Endpoint classification returned in NetworkConversations.node_kinds —
 *  mirrors the server's endpointKind (internal/handler/network/conversations.go). */
export type NetworkNodeKind = "workload" | "host" | "unmanaged" | "external";

/** Folded service-conversation graph from GET /network/conversations. Distinct
 *  from /network/map (raw flow rows): edges/conversations are aggregated by the
 *  server-side pkg/graph and each node carries a kind. */
export interface NetworkConversationEdge {
  from: string;
  to: string;
  attrs: {
    bytes: number;
    packets: number;
    protocol: string;
    port: number;
    last_seen: string;
    l7?: string;
    verdict?: string;
    severity?: number;
  };
}

export interface NetworkConversation {
  from: string;
  to: string;
  bytes: number;
  packets: number;
  edges: number;
  last_seen: string;
  severity?: number;
  verdict?: string;
  apps?: string[];
}

export interface NetworkConversations {
  conversations: NetworkConversation[];
  nodes: string[];
  node_kinds: Record<string, NetworkNodeKind>;
  edges: NetworkConversationEdge[];
  window_hours: number;
  source?: "live";
}

/** One live flow pushed over the /network/flows:stream SSE channel. Matches
 *  livegraph.Flow's JSON shape (pkg/livegraph/livegraph.go). */
export interface NetworkStreamFlow {
  cluster_id: string;
  src_workload: string;
  dst_workload: string;
  protocol: string;
  port: number;
  l7?: string;
  verdict?: string;
  severity?: number;
  bytes?: number;
  packets?: number;
  at: string;
}

export type NetworkPolicyMode = "discover" | "monitor" | "protect";

export interface NetworkPolicyLifecycle {
  id: string;
  cluster_id?: string;
  cluster_name?: string;
  workload: string;
  namespace: string;
  current_mode: NetworkPolicyMode;
  target_mode?: NetworkPolicyMode;
  reason: string;
  auto_applied: boolean;
  evaluated_at: string;
  generated_at?: string;
  candidate_hash?: string;
  approved_candidate_hash?: string;
  stale_reason?: string;
  candidate_stale: boolean;
  approval_status: string;
  last_applied_at?: string;
  rollback_available: boolean;
  applied_ref?: string;
  rollback_ref?: string;
  summary: {
    total_flows: number;
    unique_peers: number;
    unique_port_protocol: number;
    out_of_policy_alerts: number;
    new_tuples_last_24h: number;
    first_observation: string;
    last_observation: string;
  };
  tuple_preview: Array<{
    direction: string;
    peer: string;
    protocol: string;
    port: number;
    l7_protocol?: string;
    verdict: string;
    samples: number;
    bytes: number;
    packets: number;
    first_seen_at: string;
    last_seen_at: string;
    included: boolean;
    exclude_reason?: string;
  }>;
  preview: { engine: string; yaml: string; refs: Record<string, string>; manifests?: Record<string, string>; l7_protocols?: string[] };
  diff: { summary: string; added: string[]; removed: string[]; changed: string[] };
  audit_trail: Array<{ at: string; actor: string; action: string; message: string; action_id?: string; idempotency_key?: string }>;
  apply_statuses?: Array<{
    flavor: string;
    resource_ref?: string;
    desired_mode: string;
    approval_status: string;
    last_action: string;
    status: string;
    error?: string;
    candidate_hash?: string;
    applied_ref?: string;
    rollback_ref?: string;
    last_applied_at?: string;
    last_deleted_at?: string;
    updated_at: string;
  }>;
}

export interface NetworkPolicyActionResponse {
  policy: NetworkPolicyLifecycle;
  action: "approve" | "apply" | "demote" | "rollback";
  action_id?: string;
  idempotency_key?: string;
  idempotent?: boolean;
  stale_candidate?: boolean;
  expected_candidate_hash?: string;
  actual_candidate_hash?: string;
  persists: boolean;
  applies_live: boolean;
  message: string;
  next_mode: NetworkPolicyMode;
  rollback_ref?: string;
  rollback_refs: Record<string, string>;
}

export interface NetworkPolicyLifecycleResponse {
  items: NetworkPolicyLifecycle[];
  summary: {
    total: number;
    ready: number;
    discover: number;
    monitor: number;
    protect: number;
    rollback_ready: number;
    pending_approval: number;
    selected_cluster_id?: string;
  };
}

export const network = {
  map: (params: { hours?: number; namespace?: string; verdict?: string; cluster_id?: string } = {}) =>
    api.get<NetworkMap>("/network/map", { params }).then((r) => r.data),
  exposure: (params: { hours?: number; cluster_id?: string } = {}) =>
    api.get<ExposureResponse>("/network/exposure", { params }).then((r) => r.data),
  conversations: (params: { hours?: number; cluster_id?: string } = {}) =>
    api.get<NetworkConversations>("/network/conversations", { params }).then((r) => r.data),
  /** Subscribes to the GET /network/flows:stream SSE channel and invokes
   *  onFlow for each live flow. Returns an unsubscribe fn.
   *
   *  ponytail: implemented over fetch()+ReadableStream rather than the native
   *  EventSource. Ceiling: EventSource cannot send the Authorization bearer
   *  header that authMiddleware requires (auth is bearer-only, no cookie/query
   *  token), so a native EventSource would 401. fetch carries the same token
   *  the axios interceptor uses. No reconnect/backoff — the 10s poll on the
   *  page stays as the durable fallback. */
  streamFlows: (
    params: { cluster_id?: string } = {},
    onFlow: (flow: NetworkStreamFlow) => void,
  ): (() => void) => {
    const controller = new AbortController();
    const qs = new URLSearchParams();
    if (params.cluster_id) qs.set("cluster_id", params.cluster_id);
    const url = `/api/v1/network/flows:stream${qs.toString() ? `?${qs.toString()}` : ""}`;
    const token = getToken();
    void (async () => {
      try {
        const res = await fetch(url, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
          credentials: "include",
          signal: controller.signal,
        });
        if (!res.ok || !res.body) return;
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buf = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buf += decoder.decode(value, { stream: true });
          // SSE frames are separated by a blank line; comments (": ping") and
          // non-"flow" events are ignored.
          let sep: number;
          while ((sep = buf.indexOf("\n\n")) !== -1) {
            const frame = buf.slice(0, sep);
            buf = buf.slice(sep + 2);
            if (!frame.includes("event: flow")) continue;
            const dataLine = frame.split("\n").find((l) => l.startsWith("data:"));
            if (!dataLine) continue;
            try {
              onFlow(JSON.parse(dataLine.slice(5).trim()) as NetworkStreamFlow);
            } catch {
              /* skip malformed frame */
            }
          }
        }
      } catch {
        /* aborted or network error — caller falls back to the poll */
      }
    })();
    return () => controller.abort();
  },
  lifecycle: (params: { hours?: number; namespace?: string; verdict?: string; cluster_id?: string } = {}) =>
    api.get<NetworkPolicyLifecycleResponse>("/network/policies/lifecycle", { params }).then((r) => r.data),
  policyAction: (workload: string, action: "approve" | "apply" | "demote", body: { reason?: string; idempotency_key?: string; candidate_hash?: string } = {}, params: { cluster_id?: string } = {}) =>
    api.post<NetworkPolicyActionResponse>(`/network/policies/${encodeURIComponent(workload)}/${action}`, body, { params }).then((r) => r.data),
  rollbackPolicy: (workload: string, body: { rollback_ref: string; reason?: string; idempotency_key?: string }, params: { cluster_id?: string } = {}) =>
    api.post<NetworkPolicyActionResponse>(`/network/policies/${encodeURIComponent(workload)}/rollback`, body, { params }).then((r) => r.data),
};

/** Wave 5b: full row including the captured packet bytes (base64-encoded by
 *  the Go JSON encoder) and a parsed L7 preview when dp tripped on a
 *  recognised protocol. */
export interface RuntimeThreatDetail extends RuntimeThreat {
  /** base64-encoded packet bytes — up to ~2 KB from dp's DPLOG_MAX_PKT_LEN. */
  packet?: string;
  l7?: ThreatL7Preview;
}

export interface ThreatL7Preview {
  kind: "http" | "dns" | "tls" | "";
  http?: HTTPRequestPreview;
  dns?: DNSQueryPreview;
  tls?: TLSHelloPreview;
}
export interface HTTPRequestPreview {
  method: string;
  target: string;
  version?: string;
  headers?: Record<string, string>;
}
export interface DNSQueryPreview {
  qname?: string;
  qtype?: string;
}
export interface TLSHelloPreview {
  sni?: string;
  version?: string;
}

/** Wave C3: PCAP capture status and orchestration. */
export type PcapCaptureStatus = "pending" | "running" | "completed" | "failed" | "expired";

export interface PcapCapture {
  id: string;
  org_id: string;
  cluster_id: string;
  workload: string;
  namespace: string;
  requested_by: string;
  requested_at: string;
  duration_s: number;
  src_ip?: string;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  status: PcapCaptureStatus;
  claimed_by_node?: string;
  claimed_at?: string;
  completed_at?: string;
  error_message?: string;
  file_size_bytes?: number;
  sha256?: string;
  packet_count?: number;
  expires_at: string;
}

export const runtimePcap = {
  start: (body: {
    cluster_id: string;
    workload: string;
    namespace?: string;
    duration_s?: number;
    src_ip?: string;
    dst_ip?: string;
    dst_port?: number;
    protocol?: string;
  }) => api.post<PcapCapture>("/runtime-pcap/start", body).then((r) => r.data),
  list: (params: { cluster_id?: string; workload?: string; status?: PcapCaptureStatus } = {}) =>
    api.get<{ captures: PcapCapture[] }>("/runtime-pcap", { params }).then((r) => r.data.captures),
  get: (id: string) =>
    api.get<PcapCapture>(`/runtime-pcap/${encodeURIComponent(id)}`).then((r) => r.data),
  downloadURL: (id: string) =>
    `${api.defaults.baseURL ?? ""}/runtime-pcap/${encodeURIComponent(id)}/download`,
  download: (id: string) =>
    downloadAPIFile(`/runtime-pcap/${encodeURIComponent(id)}/download`, `capture-${id}.pcap`),
  remove: (id: string) =>
    api.delete<{ deleted: string }>(`/runtime-pcap/${encodeURIComponent(id)}`).then((r) => r.data),
};

/** Wave C4: DLP regex rules — user-authored PCRE patterns dp scans payloads for. */
export type DLPMode = "monitor" | "enforce" | "disabled";

export type DLPCategory = "dlp" | "signature";

export interface DLPRule {
  id: string;
  dp_rule_id: number;
  org_id: string;
  cluster_id: string;
  name: string;
  /** Wave D4: distinguishes DLP rules from custom DPI signatures. Both
   *  feed dp's hyperscan engine via the same RPC; the category just shapes
   *  defaults (dlp → egress only; signature → both directions). */
  category: DLPCategory;
  apply_dir: number; // 1=egress, 2=ingress, 3=both
  severity: number; // 1..9
  mode: DLPMode;
  patterns: string[];
  description?: string;
  version: number;
  created_at: string;
  updated_at: string;
}

export const runtimeDLP = {
  list: (cluster_id: string) =>
    api.get<{ rules: DLPRule[] }>("/runtime-dlp-rules", { params: { cluster_id } })
      .then((r) => r.data.rules),
  get: (id: string) =>
    api.get<DLPRule>(`/runtime-dlp-rules/${encodeURIComponent(id)}`).then((r) => r.data),
  create: (body: { cluster_id: string; name: string; severity: number; mode?: DLPMode; patterns: string[]; description?: string }) =>
    api.post<DLPRule>("/runtime-dlp-rules", body).then((r) => r.data),
  update: (id: string, body: { patterns?: string[]; severity?: number; description?: string }) =>
    api.put<DLPRule>(`/runtime-dlp-rules/${encodeURIComponent(id)}`, body).then((r) => r.data),
  promote: (id: string) =>
    api.post<DLPRule>(`/runtime-dlp-rules/${encodeURIComponent(id)}/promote`).then((r) => r.data),
  demote: (id: string) =>
    api.post<DLPRule>(`/runtime-dlp-rules/${encodeURIComponent(id)}/demote`).then((r) => r.data),
  disable: (id: string) =>
    api.post<DLPRule>(`/runtime-dlp-rules/${encodeURIComponent(id)}/disable`).then((r) => r.data),
  remove: (id: string) =>
    api.delete<{ deleted: string }>(`/runtime-dlp-rules/${encodeURIComponent(id)}`).then((r) => r.data),
};

/** Wave D4: Custom DPI signatures. Backed by the same runtime_dlp_rules
 *  table but filtered/stamped to category='signature'. */
export const runtimeSignatures = {
  list: (cluster_id: string) =>
    api.get<{ signatures: DLPRule[] }>("/runtime-signatures", { params: { cluster_id } })
      .then((r) => r.data.signatures),
  get: (id: string) =>
    api.get<DLPRule>(`/runtime-signatures/${encodeURIComponent(id)}`).then((r) => r.data),
  create: (body: { cluster_id: string; name: string; severity: number; mode?: DLPMode; patterns: string[]; description?: string; apply_dir?: number }) =>
    api.post<DLPRule>("/runtime-signatures", body).then((r) => r.data),
  update: (id: string, body: { patterns?: string[]; severity?: number; description?: string }) =>
    api.put<DLPRule>(`/runtime-signatures/${encodeURIComponent(id)}`, body).then((r) => r.data),
  promote: (id: string) =>
    api.post<DLPRule>(`/runtime-signatures/${encodeURIComponent(id)}/promote`).then((r) => r.data),
  demote: (id: string) =>
    api.post<DLPRule>(`/runtime-signatures/${encodeURIComponent(id)}/demote`).then((r) => r.data),
  disable: (id: string) =>
    api.post<DLPRule>(`/runtime-signatures/${encodeURIComponent(id)}/disable`).then((r) => r.data),
  remove: (id: string) =>
    api.delete<{ deleted: string }>(`/runtime-signatures/${encodeURIComponent(id)}`).then((r) => r.data),
};

/** Wave B1: runtime_policies — per-workload dp policy bundles. */
export type RuntimePolicyMode = "monitor" | "enforce" | "disabled";

export interface RuntimePolicy {
  id: string;
  dp_policy_id: number;
  org_id: string;
  cluster_id: string;
  workload: string;
  namespace: string;
  name: string;
  mode: RuntimePolicyMode;
  def_action: number;
  apply_dir: number;
  rules: RuntimePolicyRule[] | string; // server returns JSONB; we deserialize lazily
  version: number;
  created_at: string;
  updated_at: string;
}

export interface RuntimePolicyRule {
  id: number;
  ingress: boolean;
  sip: string;          // source IP (Go net.IP encodes as a string)
  dip: string;          // dest IP
  sipr?: string;        // source IP range upper bound
  dipr?: string;        // dest IP range upper bound
  port: number;         // dest port
  portr?: number;       // dest port range upper bound
  proto: number;        // 6=TCP, 17=UDP, 0=any
  action: number;       // PolicyAction* (2=allow, 6=violate, 7=deny)
  fqdn?: string;
  apps?: Array<{ app: number; action: number; rid: number }>;
}

/** Wave B2/B3: result shape from /match-stats and /simulate.  */
export interface PolicyMatchStats {
  window_hours: number;
  workload: string;
  total: number;
  allow: number;
  monitor: number;
  deny: number;
  default: number;
  samples?: Record<string, Array<{
    src: string;
    dst: string;
    dst_port: number;
    protocol: string;
    l7_protocol?: string;
    bytes: number;
    last_seen_at: string;
  }>>;
}

export const runtimePolicies = {
  list: (cluster_id: string) =>
    api.get<{ policies: RuntimePolicy[] }>("/runtime-policies", { params: { cluster_id } })
      .then((r) => r.data.policies),
  get: (id: string) =>
    api.get<RuntimePolicy>(`/runtime-policies/${encodeURIComponent(id)}`).then((r) => r.data),
  create: (body: {
    cluster_id: string; workload: string; namespace: string; name: string;
    mode?: RuntimePolicyMode; rules?: RuntimePolicyRule[];
    def_action?: number; apply_dir?: number;
  }) =>
    api.post<RuntimePolicy>("/runtime-policies", body).then((r) => r.data),
  update: (id: string, body: {
    rules?: RuntimePolicyRule[]; def_action?: number; apply_dir?: number; name?: string;
  }) =>
    api.put<RuntimePolicy>(`/runtime-policies/${encodeURIComponent(id)}`, body).then((r) => r.data),
  promote: (id: string) =>
    api.post<RuntimePolicy>(`/runtime-policies/${encodeURIComponent(id)}/promote`).then((r) => r.data),
  demote: (id: string) =>
    api.post<RuntimePolicy>(`/runtime-policies/${encodeURIComponent(id)}/demote`).then((r) => r.data),
  disable: (id: string) =>
    api.post<RuntimePolicy>(`/runtime-policies/${encodeURIComponent(id)}/disable`).then((r) => r.data),
  remove: (id: string) =>
    api.delete<{ deleted: string }>(`/runtime-policies/${encodeURIComponent(id)}`).then((r) => r.data),
  /** Wave B2: counts what the SAVED policy currently matches over hours. */
  matchStats: (id: string, hours: number = 24) =>
    api.get<PolicyMatchStats>(`/runtime-policies/${encodeURIComponent(id)}/match-stats`, { params: { hours } })
      .then((r) => r.data),
  /** Wave B3: counts what a CANDIDATE rule set would match — preview before save. */
  simulate: (id: string, body: { rules: RuntimePolicyRule[]; def_action?: number; as_mode?: RuntimePolicyMode }, hours: number = 24) =>
    api.post<PolicyMatchStats>(`/runtime-policies/${encodeURIComponent(id)}/simulate`, body, { params: { hours } })
      .then((r) => r.data),
  /** Wave B4: synthesise rules from observed flows. Preview only. */
  generate: (body: GeneratePolicyRequest) =>
    api.post<GeneratePolicyResponse>("/runtime-policies:generate", body).then((r) => r.data),
  /** Wave B4: same as generate(), but persist the result as a new monitor-mode policy. */
  applyGenerated: (body: GeneratePolicyRequest & { name: string }) =>
    api.post<RuntimePolicy>("/runtime-policies:apply-generated", body).then((r) => r.data),
};

export interface GeneratePolicyRequest {
  cluster_id: string;
  workload: string;
  namespace?: string;
  hours?: number;
  allow_dns?: boolean;
  default_deny?: boolean;
}

export interface GeneratePolicyResponse {
  window_hours: number;
  workload: string;
  flows_seen: number;
  flows_kept: number;
  threats_excluded: number;
  rules: RuntimePolicyRule[];
  def_action: number;
  apply_dir: number;
  yaml: { native: string; cilium: string; calico: string };
  summary: string[];
}

/** Wave 5: DPI threats from the NeuVector dp data-plane. */
export const runtimeThreats = {
  list: (params: { hours?: number; severity_min?: number; cluster_id?: string; workload_id?: string; category?: "dlp" | "waf" } = {}) =>
    api.get<{ threats: RuntimeThreat[] }>("/runtime-threats", { params }).then((r) => r.data.threats),
  get: (id: string) =>
    api.get<RuntimeThreatDetail>(`/runtime-threats/${encodeURIComponent(id)}`).then((r) => r.data),
};

// B1 — Unified incident timeline. Merges DPI threats + runtime events +
// network violations + audit into one time-ordered investigation stream.
export type TimelineSource = "dpi_threat" | "runtime_event" | "network_violation" | "audit";

export interface TimelineItem {
  source: TimelineSource;
  id: string;
  severity: Severity;
  at: string;
  title: string;
  workload_id?: string;
  namespace?: string;
  cluster_id?: string;
  ref?: string;
}

export interface TimelineResponse {
  items: TimelineItem[];
  limit: number;
  offset: number;
  has_more: boolean;
  from: string;
  to: string;
}

export const securityTimeline = {
  list: (
    params: {
      type?: string; // comma list of TimelineSource
      severity?: string; // comma list of Severity
      from?: string;
      to?: string;
      limit?: number;
      offset?: number;
      cluster_id?: string;
    } = {},
  ) => api.get<TimelineResponse>("/security/timeline", { params }).then((r) => r.data),
};

// B8 — Score what-if / prediction.
export interface ScoreSnapshot {
  score: number;
  grade: "good" | "fair" | "poor";
  counts: { critical: number; high: number; medium: number; low: number; info: number };
  total: number;
}

export interface ScorePredictResponse {
  current: ScoreSnapshot;
  projected: ScoreSnapshot;
  delta: number;
  resolved: number;
}

export const scorePredict = {
  predict: (
    body: { resolve_finding_ids?: string[]; resolve_severities?: string[] },
    params: { cluster_id?: string } = {},
  ) => api.post<ScorePredictResponse>("/security/score/predict", body, { params }).then((r) => r.data),
};

export interface CoverageItem {
  id: string;
  domain: string;
  feature: string;
  reference: string[];
  decision: string;
  status: string;
  ux_surface: string;
  evidence: string;
  next_milestone: string;
  enterprise_notes: string;
}

export const coverage = {
  list: () => api.get<{ items: CoverageItem[] }>("/coverage").then((r) => r.data),
};

export interface RuntimeOverview {
  modes: Array<{ id: string; label: string; blocks: boolean; description: string }>;
  subsystems: Array<{ id: string; name: string; status: string; mode: string; evidence: string }>;
  rules: Array<{ id: string; name: string; source: string; severity: string; techniques: string[]; mode: string; event_count: number; affected_workloads: number; last_triggered_at?: string }>;
  summary: {
    window_hours: number;
    events: number;
    alerts: number;
    blocks: number;
    quarantines: number;
    affected_workloads: number;
    techniques: number;
  };
  recent_events: Array<{
    id: string;
    at: string;
    cluster_id: string;
    cluster_name?: string;
    workload_id: string;
    rule_id?: string;
    rule_name?: string;
    source: string;
    kind: string;
    severity: Severity;
    verdict: string;
    attack_techniques: string[];
    message: string;
  }>;
  workloads: Array<{
    workload_id: string;
    events: number;
    alerts: number;
    blocks: number;
    highest_severity: Severity | "info";
    last_seen_at: string;
    sources: string[];
    techniques: string[];
  }>;
}

export interface IntegrationsOverview {
  receivers: Array<{ id: string; name: string; kind: string; status: string; testable: boolean }>;
  routing: { status: string; group_by: string[]; inhibition: string; default_route: string };
  report_jobs: Array<{ id: string; name: string; format: string; status: string }>;
}

export interface MigrationOverview {
  sources: Array<{ id: string; name: string; status: string; imports: string[] }>;
  workflow: Array<{ step: number; name: string; state: string }>;
}

export interface MigrationPreview {
  summary: {
    source: string;
    total: number;
    create: number;
    update: number;
    enforce: number;
    monitor: number;
    enabled: number;
    file_profiles: number;
    engines: Record<string, number>;
    categories: Record<string, number>;
    read_only: boolean;
    rollback_hint: string;
  };
  policies: Array<{
    name: string;
    description: string;
    engine: string;
    category: string;
    enabled: boolean;
    mode: string;
    spec_yaml: string;
    imported_from?: Record<string, string>;
    diff_action: "create" | "update";
  }>;
  file_profiles: Array<{
    group: string;
    mode: string;
    cfg_type?: string;
    description?: string;
    rules: FileProfilePortableRule[];
    imported_from?: Record<string, string>;
    diff_action: "create" | "update";
  }>;
  rollback_bundle: string;
}

export interface OnboardingOverview {
  install_methods: Array<{ id: string; name: string; status: string; command: string }>;
  health_gates: Array<{ name: string; status: string }>;
}

export const enterprise = {
  runtime: (params: { hours?: number; cluster_id?: string } = {}) => api.get<RuntimeOverview>("/runtime/overview", { params }).then((r) => r.data),
  integrations: () => api.get<IntegrationsOverview>("/integrations").then((r) => r.data),
  migration: () => api.get<MigrationOverview>("/migration/sources").then((r) => r.data),
  migrationPreview: (body: { source: string; export: string }) =>
    api.post<MigrationPreview>("/migration/preview", body).then((r) => r.data),
  onboarding: () => api.get<OnboardingOverview>("/onboarding").then((r) => r.data),
};

export type ResponseRuleMode = "learn" | "monitor" | "enforce";

export interface ResponseRule {
  id: string;
  name: string;
  description: string;
  event_type: string;
  match: string;
  actions: string[];
  mode: ResponseRuleMode;
  default_mode: ResponseRuleMode;
  enabled: boolean;
  default_enabled: boolean;
  severity: Severity;
  source: string;
  override_reason?: string;
  updated_at?: string;
  managed: boolean;
  drifted: boolean;
}

export interface ResponseRulesSummary {
  total: number;
  enabled: number;
  monitor: number;
  enforce: number;
  disabled: number;
  managed: number;
}

export interface ResponseRulePreview {
  rule_id: string;
  current_mode: ResponseRuleMode;
  next_mode: ResponseRuleMode;
  current_enabled: boolean;
  next_enabled: boolean;
  actions: string[];
  persists: boolean;
  requires_privileged_agent: boolean;
  impact: string;
  warnings: string[];
}

export const responseRules = {
  list: () =>
    api.get<{ rules: ResponseRule[]; summary: ResponseRulesSummary }>("/response-rules").then((r) => r.data),
  preview: (id: string, body: { mode?: ResponseRuleMode; enabled?: boolean; reason?: string }) =>
    api.post<{ preview: ResponseRulePreview }>(`/response-rules/${encodeURIComponent(id)}/preview`, body).then((r) => r.data),
  update: (id: string, body: { mode?: ResponseRuleMode; enabled?: boolean; reason: string }) =>
    api.patch<{ rule: ResponseRule; preview: ResponseRulePreview }>(`/response-rules/${encodeURIComponent(id)}`, body).then((r) => r.data),
};

export interface AccessControlUser {
  id: string;
  name: string;
  email: string;
  status: string;
  auth_provider_id: string;
  roles: string[];
  last_login_at: string;
  mfa_enabled: boolean;
}

export interface AccessControlRole {
  id: string;
  name: string;
  description: string;
  type: string;
  permissions: string[];
}

export interface AccessControlBinding {
  id: string;
  subject_id: string;
  subject_type: string;
  role_id: string;
  scopes: Array<{ kind: string; values: string[]; inherited: boolean }>;
  granted_by: string;
  granted_at: string;
  expires_at?: string;
}

export interface AccessControlProvider {
  id: string;
  name: string;
  type: string;
  status: string;
  domains: string[];
  login_url: string;
  scim_enabled: boolean;
  last_sync_at: string;
}

export interface AccessControlServiceAccount {
  id: string;
  name: string;
  description: string;
  status: string;
  owner: string;
  roles: string[];
  scopes: string[];
  last_used_at: string;
  created_at: string;
}

export interface AccessControlAPIToken {
  id: string;
  name: string;
  service_account_id: string;
  status: string;
  scopes: string[];
  last_used_at: string;
  expires_at: string;
  created_at: string;
}

export interface AccessControlPermissionMatrixRow {
  domain: string;
  permissions: string[];
  roles: string[];
  notes: string;
}

export interface AccessControlGuardrail {
  id: string;
  name: string;
  status: string;
  severity: string;
  description: string;
  applies_to: string[];
  evidence: string;
}

export interface AccessControlOverview {
  summary: {
    generated_at: string;
    users_total: number;
    users_by_status: Record<string, number>;
    roles_total: number;
    role_bindings_total: number;
    auth_providers_total: number;
    service_accounts_total: number;
    api_tokens_total: number;
    active_guardrails_total: number;
  };
  users: AccessControlUser[];
  roles: AccessControlRole[];
  role_bindings: AccessControlBinding[];
  auth_providers: AccessControlProvider[];
  service_accounts: AccessControlServiceAccount[];
  api_tokens: AccessControlAPIToken[];
  permission_matrix: AccessControlPermissionMatrixRow[];
  guardrails: AccessControlGuardrail[];
}

export const accessControl = {
  overview: () => api.get<AccessControlOverview>("/access-control").then((r) => r.data),
};

export interface IntegrationInstance {
  id: string;
  name: string;
  type: string;
  status: string;
  owner: string;
  environment: string;
  endpoint: string;
  secret_ref: string;
  last_verified_at: string;
  supported_events: string[];
}

export interface IntegrationRoutingRule {
  id: string;
  name: string;
  priority: number;
  enabled: boolean;
  event_types: string[];
  severity: string[];
  scope: string[];
  receiver_ids: string[];
  throttle: string;
  dedupe_window: string;
  escalation_after?: string;
}

export interface IntegrationDeliveryHistory {
  id: string;
  event_type: string;
  severity: string;
  status: string;
  receiver_id: string;
  routing_rule_id: string;
  created_at: string;
  delivered_at?: string;
  attempts: number;
  latency_ms: number;
  trace_id: string;
  error?: string;
  artifacts: string[];
}

export interface IntegrationReceiverHealth {
  receiver_id: string;
  status: string;
  last_success_at: string;
  last_failure_at?: string;
  p95_latency_ms: number;
  success_rate_24h: number;
  rate_limit_reset_at?: string;
  recent_errors: string[];
  recommended_action: string;
}

export interface IntegrationRetryStats {
  receiver_id: string;
  queued_retries: number;
  retry_rate_24h: string;
  max_attempts: number;
  backoff_policy: string;
  dead_letters_open: number;
  dead_letters_24h: number;
  oldest_dead_letter_at?: string;
}

export interface IntegrationAction {
  id: string;
  label: string;
  integration_ids: string[];
  read_only_preview: boolean;
  requires_role: string;
  guardrail_ids: string[];
}

export interface IntegrationGuardrail {
  id: string;
  name: string;
  description: string;
  enforced: boolean;
}

export interface IntegrationDeliveryOverview {
  summary: {
    generated_at: string;
    integration_instances_total: number;
    integration_instances_by_type: Record<string, number>;
    healthy_receivers: number;
    degraded_receivers: number;
    deliveries_24h: number;
    failed_deliveries_24h: number;
    dead_letters_open: number;
  };
  integration_instances: IntegrationInstance[];
  routing_rules: IntegrationRoutingRule[];
  delivery_history: IntegrationDeliveryHistory[];
  receiver_health: IntegrationReceiverHealth[];
  retry_stats: IntegrationRetryStats[];
  testable_actions: IntegrationAction[];
  guardrails: IntegrationGuardrail[];
}

export interface IntegrationTestPreview {
  integration_instance: IntegrationInstance;
  action: IntegrationAction;
  preview_delivery: IntegrationDeliveryHistory;
  receiver_health: IntegrationReceiverHealth;
  guardrails: IntegrationGuardrail[];
  persists_delivery: boolean;
  sends_notification: boolean;
  message: string;
}

export const integrationDeliveries = {
  overview: () => api.get<IntegrationDeliveryOverview>("/integration-deliveries").then((r) => r.data),
  testPreview: (id: string, action = "send-test-notification") =>
    api.post<IntegrationTestPreview>("/integration-deliveries/test", null, { params: { id, action } }).then((r) => r.data),
};

export interface ConnectorCoverageOverview {
  summary: {
    generated_at: string;
    registry_connectors_total: number;
    registry_connectors_ready: number;
    cloud_connectors_total: number;
    cloud_connectors_ready: number;
    images_observed: number;
    images_scanned: number;
    images_unscanned: number;
    cloud_resources_observed: number;
    cloud_resources_assessed: number;
    queued_scans: number;
    credential_rotations_due: number;
  };
  registry_connectors: Array<{
    id: string;
    name: string;
    provider: string;
    status: string;
    endpoint: string;
    auth_mode: string;
    repositories: number;
    images_observed: number;
    images_scanned: number;
    last_scan_at: string;
    next_scan_at: string;
    credential_age: string;
    rotation_due_at: string;
    supported_checks: string[];
    notes: string;
  }>;
  cloud_connectors: Array<{
    id: string;
    name: string;
    provider: string;
    status: string;
    account: string;
    regions: string[];
    auth_mode: string;
    resources_observed: number;
    resources_assessed: number;
    findings_open: number;
    last_assessment_at: string;
    next_assessment_at: string;
    credential_age: string;
    rotation_due_at: string;
    controls: string[];
    notes: string;
  }>;
  configs: ConnectorConfig[];
  scan_coverage: Array<{
    scope: string;
    observed: number;
    scanned: number;
    unscanned: number;
    critical_gaps: number;
    last_covered_at: string;
    recommended_fix: string;
  }>;
  scanner_pools: Array<{
    id: string;
    name: string;
    status: string;
    desired_workers: number;
    ready_workers: number;
    active_jobs: number;
    idle_capacity: number;
    queue_depth: number;
    stale_leases: number;
    p95_duration: string;
    capacity: string;
    queue_by_target_type?: ScanQueueMetric[];
    scanners?: Array<{
      instance_id?: string;
      hostname: string;
      cluster_id?: string;
      cluster_name?: string;
      status: string;
      last_seen_at: string;
      max_concurrent: number;
      active_jobs: number;
      idle_capacity: number;
      target_capacity?: Record<string, number>;
      active_jobs_by_target_type?: Record<string, number>;
      cache_health?: Record<string, ScannerCacheHealthEntry>;
      vulndb_status?: string;
      vulndb_bundle_version?: string;
      vulndb_error?: string;
    }>;
  }>;
  recent_jobs: Array<{
    id: string;
    source: string;
    target_type: string;
    target_ref: string;
    image_ref?: string;
    status: string;
    requested_at: string;
    finished_at?: string;
    findings: number;
    error?: string;
  }>;
  guardrails: Array<{ id: string; name: string; description: string; status: string }>;
}

export interface ScannerCacheHealthEntry {
  path?: string;
  configured?: boolean;
  present?: boolean;
  is_dir?: boolean;
  writable?: boolean;
  status?: string;
  error?: string;
  free_bytes?: number;
  record_count?: number;
  record_size_bytes?: number;
  records_truncated?: boolean;
}

export interface ScannerCacheStat {
  scanner_id: string;
  hostname: string;
  cluster_id?: string;
  cluster_name?: string;
  status: string;
  last_seen_at: string;
  record_count: number;
  record_size_bytes: number;
  cache_misses: number;
  cache_hits: number;
  caches: Array<ScannerCacheHealthEntry & { name: string }>;
}

export interface ScannerCacheData {
  scanner_id: string;
  hostname: string;
  cluster_id?: string;
  cluster_name?: string;
  status: string;
  last_seen_at: string;
  record_size_bytes: number;
  cache_misses: number;
  cache_hits: number;
  cache_records: Array<{ cache: string; layer: string; size: number; ref_count: number; ref_last?: string }>;
}

export interface ConnectorConfig {
  id?: string;
  connector_id: string;
  connector_type: "registry" | "cloud";
  provider: string;
  display_name: string;
  endpoint: string;
  auth_mode: string;
  owner: string;
  scan_cadence: string;
  rotation_due_at?: string;
  credential_ref?: string;
  credential_present: boolean;
  credential_fingerprint?: string;
  last_test_status: string;
  last_test_at?: string;
  updated_at?: string;
}

export interface ConnectorCheckPreview {
  connector_id: string;
  connector_type: string;
  status: string;
  message: string;
  persists_secrets: boolean;
  starts_scan: boolean;
  rotates_credential: boolean;
  guardrails: Array<{ id: string; name: string; description: string; status: string }>;
}

export interface ConnectorConfigTestResult {
  config: ConnectorConfig;
  status: string;
  message: string;
  persists_secrets: boolean;
  starts_scan: boolean;
  rotates_credential: boolean;
  guardrails: Array<{ id: string; name: string; description: string; status: string }>;
}

export interface ScanJob {
  id: string;
  org_id?: string;
  target_id: string;
  target_type: string;
  target_ref: string;
  target_cluster_id?: string;
  source_type?: string;
  source_ref?: string;
  image_ref?: string;
  inventory_hash?: string;
  platform?: string;
  registry_id?: string;
  image_digest?: string;
  enqueue_reason?: string;
  registry_policy_hash?: string;
  vulndb_bundle_version?: string;
  status: string;
  worker_id?: string;
  error?: string;
  attempt_count: number;
  max_attempts: number;
  package_count?: number;
  finding_count?: number;
  bundle_metadata?: VulnDBBundleMetadata;
  requested_at: string;
  claimed_at?: string;
  lease_expires_at?: string;
  next_attempt_at?: string;
  last_attempt_at?: string;
  last_error_at?: string;
  finished_at?: string;
}

export interface ScanQueueMetric {
  target_type: string;
  pending: number;
  retry_delayed: number;
  exhausted: number;
  running: number;
  stale_running: number;
  paused: number;
  canceled: number;
  failed: number;
  completed_last_hour: number;
  oldest_pending_seconds: number;
}

export interface ImpactedWorkload {
  cluster_id: string;
  deployment_id: string;
  workload_id: string;
  namespace: string;
  name: string;
  kind: string;
  image_ref: string;
  image_ref_normalized: string;
  image_repository?: string;
  image_tag?: string;
  image_digest?: string;
  risk_score: number;
  finding_count: number;
  critical_count: number;
  high_count: number;
  last_seen_at: string;
}

export interface ScanTargetImpacts {
  target_id: string;
  target_type: string;
  target_ref: string;
  target_cluster_id?: string;
  image_ref?: string;
  image_digest?: string;
  impacted_count: number;
  impacted_workloads: ImpactedWorkload[];
}

export interface ImageScanResult {
  id: string;
  asset_id?: string;
  scan_target_id?: string;
  last_scan_job_id?: string;
  source_type?: string;
  source_ref?: string;
  scan_target_metadata?: Record<string, unknown>;
  image_ref: string;
  image_ref_normalized: string;
  image_repository: string;
  image_tag?: string;
  image_digest: string;
  platform?: string;
  scanner_profile: string;
  vulndb_bundle_version?: string;
  vulndb_bundle_hash?: string;
  bundle_metadata?: VulnDBBundleMetadata;
  package_count: number;
  layer_count: number;
  secret_count: number;
  file_risk_count: number;
  image_signed: boolean;
  signature_status?: string;
  finding_count: number;
  severity_counts: Record<string, number>;
  max_risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  impacted_count: number;
  first_seen_at: string;
  last_scanned_at: string;
  updated_at: string;
}

export interface ImageScanFinding {
  id: string;
  image_scan_result_id: string;
  finding_key: string;
  external_id?: string;
  title: string;
  description?: string;
  severity: Severity;
  risk_score: number;
  canonical_engine?: string;
  engines?: EngineProvenance[];
  reconciliation?: ReconciliationSignal[];
  reconciliation_count?: number;
  package_ecosystem?: string;
  package_name?: string;
  package_version?: string;
  package_purl?: string;
  fixed_version?: string;
  affected_range?: AffectedRange;
  cvss_base?: number;
  cvss_vector?: string;
  epss_probability?: number;
  kev_listed?: boolean;
  aliases?: string[];
  references?: string[];
  detail?: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ImageScanResultDetail {
  image_scan_result: ImageScanResult;
  findings: ImageScanFinding[];
  impacted_workloads: ImpactedWorkload[];
}

export interface ImageScanAffectedWorkloads {
  image_scan_result_id: string;
  image_ref: string;
  image_ref_normalized: string;
  image_repository: string;
  image_tag?: string;
  image_digest: string;
  affected_count: number;
  affected_workloads: ImpactedWorkload[];
}

export interface ScanPackage {
  ecosystem?: string;
  name?: string;
  version?: string;
  purl?: string;
  cpes?: string[];
  licenses?: string[];
  namespace_kind?: string;
  namespace_name?: string;
  namespace_version?: string;
  arch?: string;
  repository?: string;
  image_repository?: string;
  image_tag?: string;
  base_image?: string;
  module_stream?: string;
  locations?: ScanPackageLocation[];
}

export interface ScanPackageLocation {
  path?: string;
  access_path?: string;
  real_path?: string;
  layer_id?: string;
  layer_digest?: string;
}

export interface ImagePackageLayer {
  layer_index?: number;
  layer_digest?: string;
  layer_media_type?: string;
  layer_size_bytes?: number;
  package_count: number;
  packages: ScanPackage[];
}

export interface ImageScanPackageInventory {
  schema_version: string;
  image_ref: string;
  image_digest: string;
  platform?: string;
  scanner_profile: string;
  package_count: number;
  packages: ScanPackage[];
  vulndb_bundle?: VulnDBBundleMetadata;
}

export interface ImageScanPackageInventoryResponse {
  image_scan_result_id: string;
  format: "constellation-package-inventory-v1";
  sha256: string;
  package_count: number;
  created_at: string;
  package_inventory: ImageScanPackageInventory;
  package_layers?: ImagePackageLayer[];
  layer_package_count?: number;
  unattributed_package_count?: number;
}

export interface ImageSecretFinding {
  engine?: string;
  rule_id?: string;
  category?: string;
  severity?: string;
  title?: string;
  target?: string;
  path?: string;
  start_line?: number;
  end_line?: number;
  match_sha256?: string;
  match_redacted?: string;
}

export interface ImageSecretScan {
  schema_version?: string;
  image_ref?: string;
  image_digest?: string;
  platform?: string;
  scanner_profile?: string;
  secret_count?: number;
  secrets?: ImageSecretFinding[];
  vulndb_bundle?: VulnDBBundleMetadata;
}

export interface ImageSecretsResponse {
  image_scan_result_id: string;
  format: "constellation-image-secrets-v1";
  sha256: string;
  secret_count: number;
  created_at: string;
  secret_scan: ImageSecretScan;
}

export interface ImageLayerDescriptor {
  index?: number;
  media_type?: string;
  digest?: string;
  diff_id?: string;
  size_bytes?: number;
  created_by?: string;
  command?: string;       // Dockerfile-style instruction (RUN/ADD/COPY…)
  in_base_image?: boolean; // base OS layer vs application layer
  package_count?: number;
  annotations?: Record<string, string>;
}

export interface ImageLayerMetadata {
  schema_version?: string;
  image_ref?: string;
  image_digest?: string;
  platform?: string;
  scanner_profile?: string;
  layer_count?: number;
  layers?: ImageLayerDescriptor[];
  architectures?: string[];
  manifest_digest?: string;
  index_digest?: string;
  media_type?: string;
  config_digest?: string;
  config_media_type?: string;
  config_size_bytes?: number;
  selected_platform?: string;
  total_size_bytes?: number;
  status?: string;
  reason?: string;
  error?: string;
  vulndb_bundle?: VulnDBBundleMetadata;
}

export interface ImageLayersResponse {
  image_scan_result_id: string;
  format: "constellation-image-layers-v1";
  sha256: string;
  layer_count: number;
  created_at: string;
  layer_metadata: ImageLayerMetadata;
}

export interface ImageFileRiskFinding {
  path: string;
  type?: string;
  mode?: string;
  uid?: number;
  gid?: number;
  size_bytes?: number;
  layer_index?: number;
  layer_digest?: string;
  link_name?: string;
  risk_types?: string[];
  severity?: string;
  reason?: string;
}

export interface ImageFileRiskReport {
  schema_version?: string;
  image_ref?: string;
  image_digest?: string;
  platform?: string;
  scanner_profile?: string;
  file_risk_count?: number;
  findings?: ImageFileRiskFinding[];
  manifest_digest?: string;
  entry_count?: number;
  max_findings?: number;
  truncated?: boolean;
  status?: string;
  reason?: string;
  error?: string;
  vulndb_bundle?: VulnDBBundleMetadata;
}

export interface ImageFileRisksResponse {
  image_scan_result_id: string;
  format: "constellation-image-file-risk-v1";
  sha256: string;
  file_risk_count: number;
  created_at: string;
  file_risk: ImageFileRiskReport;
}

export interface ImageSignatureResult {
  image_ref?: string;
  status?: string;
  signed?: boolean;
  trusted?: boolean;
  identity?: string;
  issuer?: string;
  rekor_log?: string;
  attestations?: string[];
  reason?: string;
  error?: string;
}

export interface ImageSignatureScan {
  schema_version?: string;
  image_ref?: string;
  image_digest?: string;
  platform?: string;
  scanner_profile?: string;
  signature?: ImageSignatureResult;
  status?: string;
  signed?: boolean;
  trusted?: boolean;
  vulndb_bundle?: VulnDBBundleMetadata;
}

export interface ImageSignatureResponse {
  image_scan_result_id: string;
  format: "constellation-image-signature-v1";
  sha256: string;
  created_at: string;
  signature_scan: ImageSignatureScan;
}

export interface ServerlessFunction {
  id: string;
  function_ref: string;
  function_name?: string;
  provider?: string;
  account_id?: string;
  region?: string;
  runtime?: string;
  version?: string;
  architecture?: string;
  role?: string;
  handler?: string;
  package_type?: string;
  layers?: string[];
  source_type: string;
  source_ref?: string;
  inventory_hash?: string;
  package_count: number;
  permission_status?: string;
  permission_level?: string;
  permission_analysis?: Record<string, unknown>;
  latest_evidence_id?: string;
  latest_observed_at?: string;
  latest_job_id?: string;
  latest_job_status?: string;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  last_seen_at: string;
  metadata?: Record<string, unknown>;
}

export interface ServerlessEvidence {
  id: string;
  inventory_hash: string;
  package_count: number;
  observed_at: string;
  runtime?: string;
  provider?: string;
  account_id?: string;
  region?: string;
  version?: string;
  architecture?: string;
  packages?: ScanPackage[];
}

export interface ServerlessJob {
  id: string;
  status: string;
  error?: string;
  package_count: number;
  finding_count: number;
  requested_at: string;
  claimed_at?: string;
  finished_at?: string;
}

export interface ServerlessFinding {
  id: string;
  kind: string;
  external_id?: string;
  title: string;
  severity: Severity;
  risk_score: number;
  lifecycle: string;
  detail?: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
}

export interface ServerlessFunctionDetail {
  serverless_function: ServerlessFunction;
  latest_evidence?: ServerlessEvidence | null;
  jobs: ServerlessJob[];
  findings: ServerlessFinding[];
}

export interface RepositoryScan {
  id: string;
  repository_ref: string;
  repository_url?: string;
  source_type: string;
  source_ref?: string;
  commit_sha?: string;
  branch?: string;
  path?: string;
  workflow?: string;
  run_id?: string;
  inventory_hash?: string;
  package_count: number;
  latest_evidence_id?: string;
  latest_observed_at?: string;
  latest_job_id?: string;
  latest_job_status?: string;
  latest_attestation?: RepositoryAttestationSummary;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  last_seen_at: string;
  metadata?: Record<string, unknown>;
}

export interface RepositoryAttestationSummary {
  id: string;
  subject_kind: "image" | "repository";
  subject_digest: string;
  predicate_type: string;
  payload_sha256: string;
  verification_status: "trusted" | "untrusted" | "unsigned" | "error" | "unverified";
  trusted: boolean;
  trust_policy_id?: string;
  verification_reason?: string;
  signer_identity?: string;
  signer_issuer?: string;
  observed_at: string;
  expires_at?: string;
}

export interface RepositoryAttestation extends RepositoryAttestationSummary {
  scan_target_id: string;
  scan_job_id?: string;
  scan_evidence_id?: string;
  image_scan_result_id?: string;
  target_type: string;
  target_ref: string;
  source_type: string;
  source_ref?: string;
  subject_ref: string;
  repository_ref?: string;
  repository_url?: string;
  commit_sha?: string;
  branch?: string;
  workflow?: string;
  run_id?: string;
  run_attempt?: string;
  ci_provider?: string;
  format: string;
  verified_at?: string;
  created_at: string;
  metadata?: Record<string, unknown>;
  payload?: unknown;
  envelope?: unknown;
  signature?: unknown;
}

export interface RepositoryAttestationVerification {
  id: string;
  attestation_id: string;
  trust_policy_id?: string;
  trust_policy_name?: string;
  status: "trusted" | "untrusted" | "unsigned" | "error" | "unverified";
  trusted: boolean;
  reason?: string;
  error?: string;
  signer_identity?: string;
  signer_issuer?: string;
  subject_ref?: string;
  subject_digest?: string;
  predicate_type?: string;
  payload_sha256?: string;
  require_rekor: boolean;
  policy_snapshot?: unknown;
  verifier_metadata?: unknown;
  verified_by?: string;
  auto_verified: boolean;
  verified_at: string;
}

export interface RepositoryAttestationTrustPolicy {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  auto_verify: boolean;
  subject_kind: "image" | "repository";
  source_types: string[];
  repository_ref_patterns: string[];
  source_ref_patterns: string[];
  predicate_types: string[];
  allowed_identities: string[];
  allowed_issuers: string[];
  require_rekor: boolean;
  verifier_mode: "keyless" | "public-key";
  public_key_pem?: string;
  created_at: string;
  updated_at: string;
}

export type RepositoryAttestationTrustPolicyInput = Omit<RepositoryAttestationTrustPolicy, "id" | "created_at" | "updated_at">;

export interface RepositoryEvidence {
  id: string;
  inventory_hash: string;
  package_count: number;
  observed_at: string;
  repository_ref?: string;
  repository_url?: string;
  commit_sha?: string;
  branch?: string;
  path?: string;
  workflow?: string;
  run_id?: string;
  packages?: ScanPackage[];
}

export interface RepositoryJob {
  id: string;
  status: string;
  error?: string;
  package_count: number;
  finding_count: number;
  requested_at: string;
  claimed_at?: string;
  finished_at?: string;
}

export interface RepositoryFinding {
  id: string;
  kind: string;
  external_id?: string;
  title: string;
  severity: Severity;
  risk_score: number;
  lifecycle: string;
  detail?: Record<string, unknown>;
  first_seen_at: string;
  last_seen_at: string;
}

export interface RepositoryScanDetail {
  repository_scan: RepositoryScan;
  latest_evidence?: RepositoryEvidence | null;
  jobs: RepositoryJob[];
  findings: RepositoryFinding[];
}

export const connectorCoverage = {
  overview: () => api.get<ConnectorCoverageOverview>("/connector-coverage").then((r) => r.data),
  testPreview: (id: string, type = "registry") =>
    api.post<ConnectorCheckPreview>("/connector-coverage/test", null, { params: { id, type } }).then((r) => r.data),
  saveConfig: (body: Omit<ConnectorConfig, "id" | "credential_present" | "credential_fingerprint" | "last_test_status" | "last_test_at" | "updated_at">) =>
    api.post<{ config: ConnectorConfig }>("/connector-coverage/configs", body).then((r) => r.data),
  testConfig: (id: string) => api.post<ConnectorConfigTestResult>(`/connector-coverage/configs/${id}/test`).then((r) => r.data),
  cacheStat: (scannerId: string) =>
    api.get<ScannerCacheStat>(`/scanner-cache/${encodeURIComponent(scannerId)}/stat`).then((r) => r.data),
  cacheData: (scannerId: string) =>
    api.get<ScannerCacheData>(`/scanner-cache/${encodeURIComponent(scannerId)}/data`).then((r) => r.data),
};

export const scanJobs = {
  list: (params?: { cluster_id?: string; target_type?: string; status?: string }) =>
    api.get<{ jobs: ScanJob[]; queue_metrics?: ScanQueueMetric[] }>("/scan-jobs", { params }).then((r) => r.data),
  enqueue: (body: { target_type: string; target_ref: string; platform?: string; target_cluster_id?: string; source_type?: string; source_ref?: string; max_attempts?: number }) =>
    api.post<{ id: string; status: string }>("/scan-jobs", body).then((r) => r.data),
};

export const scanTargets = {
  impactedWorkloads: (id: string) =>
    api.get<ScanTargetImpacts>(`/scan-targets/${encodeURIComponent(id)}/impacted-workloads`).then((r) => r.data),
};

export const imageScanResults = {
  list: (params?: { cluster_id?: string; image_digest?: string; digest?: string; q?: string; limit?: number; offset?: number }) =>
    api.get<{ image_scan_results: ImageScanResult[]; limit: number; offset: number }>("/image-scan-results", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<ImageScanResultDetail>(`/image-scan-results/${encodeURIComponent(id)}`).then((r) => r.data),
  packages: (id: string) =>
    api.get<ImageScanPackageInventoryResponse>(`/image-scan-results/${encodeURIComponent(id)}/packages`).then((r) => r.data),
  layers: (id: string) =>
    api.get<ImageLayersResponse>(`/image-scan-results/${encodeURIComponent(id)}/layers`).then((r) => r.data),
  secrets: (id: string) =>
    api.get<ImageSecretsResponse>(`/image-scan-results/${encodeURIComponent(id)}/secrets`).then((r) => r.data),
  fileRisks: (id: string) =>
    api.get<ImageFileRisksResponse>(`/image-scan-results/${encodeURIComponent(id)}/file-risks`).then((r) => r.data),
  signature: (id: string) =>
    api.get<ImageSignatureResponse>(`/image-scan-results/${encodeURIComponent(id)}/signature`).then((r) => r.data),
  affectedWorkloads: (id: string) =>
    api.get<ImageScanAffectedWorkloads>(`/image-scan-results/${encodeURIComponent(id)}/affected-workloads`).then((r) => r.data),
  downloadPackages: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/packages`, `constellation-image-${id}-packages.json`),
  downloadLayers: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/layers`, `constellation-image-${id}-layers.json`),
  downloadSecrets: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/secrets`, `constellation-image-${id}-secrets.json`),
  downloadFileRisks: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/file-risks`, `constellation-image-${id}-file-risks.json`),
  downloadSignature: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/signature`, `constellation-image-${id}-signature.json`),
  downloadSPDX: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/sbom/spdx`, `constellation-image-${id}-spdx-2.3.json`),
  downloadCycloneDX: (id: string) =>
    downloadAPIFile(`/image-scan-results/${encodeURIComponent(id)}/sbom/cyclonedx`, `constellation-image-${id}-cyclonedx-1.6.json`),
};

export const serverlessFunctions = {
  list: (params?: { q?: string; provider?: string; account_id?: string; region?: string; limit?: number; offset?: number }) =>
    api.get<{ serverless_functions: ServerlessFunction[]; limit: number; offset: number }>("/serverless-functions", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<ServerlessFunctionDetail>(`/serverless-functions/${encodeURIComponent(id)}`).then((r) => r.data),
};

export const repositoryScans = {
  list: (params?: { q?: string; branch?: string; workflow?: string; limit?: number; offset?: number }) =>
    api.get<{ repository_scans: RepositoryScan[]; limit: number; offset: number }>("/repository-scans", { params }).then((r) => r.data),
  get: (id: string) =>
    api.get<RepositoryScanDetail>(`/repository-scans/${encodeURIComponent(id)}`).then((r) => r.data),
  attestations: (id: string) =>
    api.get<{ attestations: RepositoryAttestation[] }>(`/repository-scans/${encodeURIComponent(id)}/attestations`).then((r) => r.data),
};

export const repositoryScanAttestations = {
  get: (id: string) =>
    api.get<{ attestation: RepositoryAttestation }>(`/repository-scan-attestations/${encodeURIComponent(id)}`).then((r) => r.data),
  verifications: (id: string) =>
    api.get<{ verifications: RepositoryAttestationVerification[] }>(`/repository-scan-attestations/${encodeURIComponent(id)}/verifications`).then((r) => r.data),
  verify: (id: string, body?: { policy_id?: string }) =>
    api.post<{ ok: boolean; policy: RepositoryAttestationTrustPolicy; attestation: RepositoryAttestation; reason?: string; error?: string }>(
      `/repository-scan-attestations/${encodeURIComponent(id)}:verify`,
      body ?? {},
    ).then((r) => r.data),
  download: (id: string) =>
    downloadAPIFile(`/repository-scan-attestations/${encodeURIComponent(id)}/export`, `constellation-repository-attestation-${id}.json`),
};

export const repositoryScanAttestationTrustPolicies = {
  list: () =>
    api.get<{ policies: RepositoryAttestationTrustPolicy[] }>("/repository-scan-attestation-trust-policies").then((r) => r.data),
  create: (body: RepositoryAttestationTrustPolicyInput) =>
    api.post<{ policy: RepositoryAttestationTrustPolicy }>("/repository-scan-attestation-trust-policies", body).then((r) => r.data),
  update: (id: string, body: Partial<RepositoryAttestationTrustPolicyInput>) =>
    api.patch<{ policy: RepositoryAttestationTrustPolicy }>(`/repository-scan-attestation-trust-policies/${encodeURIComponent(id)}`, body).then((r) => r.data),
  remove: (id: string) =>
    api.delete<void>(`/repository-scan-attestation-trust-policies/${encodeURIComponent(id)}`).then((r) => r.data),
  verifyPending: (id: string, body?: { limit?: number }) =>
    api.post<{ policy: RepositoryAttestationTrustPolicy; verified: number; trusted: number; verification_run: Array<{ id: string; trusted: boolean; status: string; reason?: string; error?: string }> }>(
      `/repository-scan-attestation-trust-policies/${encodeURIComponent(id)}:verify-pending`,
      body ?? {},
    ).then((r) => r.data),
};

export interface Policy {
  id: string;
  name: string;
  description: string;
  engine: string;
  category: string;
  enabled: boolean;
  mode: "monitor" | "enforce";
  version: number;
  spec_yaml: string;
}

export interface AdmissionProfileRule {
  name: string;
  description: string;
  engine: string;
  category: string;
  mode: "monitor" | "enforce";
  enabled: boolean;
  spec_yaml: string;
}

export interface AdmissionProfile {
  id: string;
  name: string;
  description: string;
  failure_policy: "Ignore" | "Fail";
  namespace_selector?: Record<string, unknown>;
  rules: AdmissionProfileRule[];
}

export interface AdmissionProfileBundle {
  api_version: string;
  kind: string;
  profile: AdmissionProfile;
}

export interface AdmissionProfileImportPolicy {
  policy_name: string;
  rule_name: string;
  description: string;
  engine: string;
  category: string;
  mode: "monitor" | "enforce";
  enabled: boolean;
  spec_yaml: string;
}

export interface AdmissionProfileImportResponse {
  profile_id: string;
  dry_run: boolean;
  imported: number;
  ids?: string[];
  policies: AdmissionProfileImportPolicy[];
}

export interface PolicySimulation {
  decision: "allow" | "warn" | "deny";
  enforcement_mode: "none" | "monitor" | "enforce";
  workload: {
    kind: string;
    name: string;
    namespace: string;
    images: string[];
    labels: Record<string, string>;
    privileged: boolean;
    run_as_root: boolean;
    latest_tag: boolean;
    unsigned_image: boolean;
  };
  matches: Array<{
    policy_id: string;
    policy_name: string;
    category: string;
    engine: string;
    mode: string;
    action: string;
    severity: string;
    reason: string;
    evidence: string[];
    evidence_details?: Array<{
      kind: string;
      label: string;
      href?: string;
      image: {
        container?: string;
        role?: string;
        ref?: string;
        digest?: string;
      };
      scan_result?: {
        id: string;
        image_ref?: string;
        image_digest?: string;
        source_type?: string;
        source_ref?: string;
        last_scanned_at?: string;
        vulndb_bundle_version?: string;
        vulndb_bundle_hash?: string;
        package_count: number;
        finding_count: number;
      };
      finding?: {
        id?: string;
        key?: string;
        external_id?: string;
        title?: string;
        severity?: string;
        risk_score?: number;
        canonical_engine?: string;
        package_ecosystem?: string;
        package_name?: string;
        package_version?: string;
        package_purl?: string;
        fixed_version?: string;
      };
      artifact?: {
        id?: string;
        type?: string;
        format?: string;
        status?: string;
        identity?: string;
        path?: string;
        severity?: string;
        title?: string;
        rule_id?: string;
        risk_types?: string[];
        count?: number;
      };
    }>;
    remediation: string;
  }>;
  guardrails: Array<{ id: string; name: string; status: string; description: string }>;
  admission_review: {
    dry_run: boolean;
    persists_decision: boolean;
    sends_webhook: boolean;
    reviewed_at: string;
    source: string;
  };
  cluster_resources: Array<{
    id: string;
    label: string;
    namespace: string;
    kind: string;
    last_seen_at: string;
    manifest: string;
    description: string;
  }>;
}

export const policies = {
  list:   (params: { cluster_id?: string } = {}) =>
    api.get<{ policies: Policy[] }>("/policies", { params }).then((r) => r.data),
  admissionProfiles: () =>
    api.get<{ profiles: AdmissionProfile[] }>("/policies/admission-profiles").then((r) => r.data),
  exportAdmissionProfile: (profile: string) =>
    api.get<AdmissionProfileBundle>(`/policies/admission-profiles/${profile}/export`).then((r) => r.data),
  importAdmissionProfile: (body: { profile_id?: string; bundle?: AdmissionProfileBundle; mode?: "monitor" | "enforce"; enabled?: boolean; dry_run?: boolean }) =>
    api.post<AdmissionProfileImportResponse>("/policies/admission-profiles:import", body).then((r) => r.data),
  update: (id: string, body: Partial<Policy>) =>
    api.patch<Policy>(`/policies/${id}`, body).then((r) => r.data),
  create: (body: Partial<Policy>) =>
    api.post<Policy>("/policies", body).then((r) => r.data),
  delete: (id: string) =>
    api.delete<{ status: string }>(`/policies/${id}`).then((r) => r.data),
  bulk: (operations: Array<{ op: string; id?: string; body?: unknown }>) =>
    api.post<{ results: Array<{ op: string; id?: string; status: string; error?: string }> }>(
      "/policies:bulk",
      { operations },
    ).then((r) => r.data),
  simulate: (body: { manifest?: string; cluster_resource_id?: string }, params: { cluster_id?: string } = {}) =>
    api.post<PolicySimulation>("/policies/simulate", body, { params }).then((r) => r.data),
  admissionState: (params: { cluster_id?: string } = {}) =>
    api.get<AdmissionState>("/policies/admission/state", { params }).then((r) => r.data),
  updateAdmissionState: (body: Partial<AdmissionStateInput>, params: { cluster_id?: string } = {}) =>
    api.patch<AdmissionState>("/policies/admission/state", body, { params }).then((r) => r.data),
  assess: (body: { image: string; namespace?: string; labels?: Record<string, string> }, params: { cluster_id?: string } = {}) =>
    api.post<AdmissionAssessResult>("/policies/assess", body, { params }).then((r) => r.data),
  admissionRules: (params: { cluster_id?: string } = {}) =>
    api.get<{ rules: AdmissionRuleRow[]; total: number }>("/policies/admission/rules", { params }).then((r) => r.data),
  admissionOptions: () =>
    api.get<AdmissionOptions>("/policies/admission/options").then((r) => r.data),
  createAdmissionRule: (body: { name: string; mode: string; criteria: Array<{ key: string; value: string }> }, params: { cluster_id?: string } = {}) =>
    api.post<{ id: string; spec_yaml: string }>("/policies/admission/rules", body, { params }).then((r) => r.data),
};

export interface AdmissionCriterionOption {
  key: string;
  label: string;
  value_type: "none" | "int" | "float" | "csv" | "severity" | "pss";
  placeholder?: string;
  help: string;
}
export interface AdmissionOptions {
  criteria: AdmissionCriterionOption[];
  rule_modes: string[];
  severities: string[];
  pss_levels: string[];
}

export interface AdmissionRuleRow {
  id: string;
  name: string;
  enabled: boolean;
  mode: string;
  action: string;
  category: string;
  criteria: string[];
}

export interface AdmissionState {
  cluster_id: string;
  enabled: boolean;
  mode: "monitor" | "protect";
  default_action: "allow" | "deny";
  failure_policy: "ignore" | "fail";
  updated_at?: string;
}
export interface AdmissionStateInput {
  enabled: boolean;
  mode: "monitor" | "protect";
  default_action: "allow" | "deny";
  failure_policy: "ignore" | "fail";
}
export interface AdmissionAssessResult {
  image: string;
  namespace: string;
  decision: string;
  enforcement_mode: string;
  matches: Array<{ rule_id?: string; policy_name?: string; action?: string; reason?: string; [k: string]: unknown }>;
}

// ---------- New endpoints (Wave B) ----------
export interface DashboardSummary {
  generated_at: string;
  findings_by_severity: Record<string, number>;
  findings_total: number;
  open_findings: number;
  accepted_risks: number;
  highest_risk: number;
  assets_total: number;
  scan_queue_depth: number;
  recent_activity: Array<{
    at: string;
    action: string;
    target_kind: string;
    target_id: string;
    actor_id?: string;
  }>;
  posture: {
    security_score: number;                     // RISK score 0-100 (higher = worse), NV model
    score_breakdown: Record<string, number>;    // protection_mode / exposure / privileged / root / admission / vulnerabilities
    vulns_by_location: Record<string, number>;  // image / host / platform
    vuln_signals: Record<string, number>;       // kev / fixable / high_epss / corroborated
    hardening: Record<string, number>;          // workloads / privileged / host_network / run_as_root / exposed
    enforcement: Record<string, number>;        // groups / discover / monitor / protect
    top_vulnerable: Array<{ namespace: string; name: string; critical: number; high: number }>;
  };
}

export interface ExposedService {
  workload: string;
  namespace: string;
  name: string;
  external_peers: number;
  protocols: string[];
  ports: number[];
  sessions: number;
  critical: number;
  high: number;
  risk_score: number;
}
export interface ExposureResponse { ingress: ExposedService[]; egress: ExposedService[] }

export const dashboard = {
  summary: (params: { cluster_id?: string } = {}) =>
    api.get<DashboardSummary>("/dashboard/summary", { params }).then((r) => r.data),
};

export const settingsApi = {
  getOrg: () => api.get<{ settings: Record<string, unknown> }>("/settings/org").then((r) => r.data),
  patchOrg: (patch: Record<string, unknown>) =>
    api.patch<{ settings: Record<string, unknown> }>("/settings/org", patch).then((r) => r.data),
  getUser: () => api.get<{ settings: Record<string, unknown> }>("/settings/user").then((r) => r.data),
  patchUser: (patch: Record<string, unknown>) =>
    api.patch<{ settings: Record<string, unknown> }>("/settings/user", patch).then((r) => r.data),
};

export const systemConfigApi = {
  get: () =>
    api.get<{ config: Record<string, unknown>; revision: number }>("/system/config").then((r) => r.data),
  patch: (body: Record<string, unknown>) =>
    api.patch<{ config: Record<string, unknown>; revision: number }>("/system/config", body).then((r) => r.data),
  refreshScanner: () =>
    api.post<{ refresh_now: number; revision: number }>("/scanner/refresh", {}).then((r) => r.data),
};

// A1: org password + session/idle policy (GET/PUT /auth/security-policy).
export interface SecurityPolicy {
  min_length: number;
  min_classes: number;
  max_age_days: number;
  history_depth: number;
  session_timeout_minutes: number;
  idle_timeout_minutes: number;
  revision: number;
}

export const securityPolicyApi = {
  get: () => api.get<SecurityPolicy>("/auth/security-policy").then((r) => r.data),
  put: (body: SecurityPolicy) => api.put<SecurityPolicy>("/auth/security-policy", body).then((r) => r.data),
};

// SSO / IdP config (LDAP / SAML / OIDC) — full CRUD via /auth-servers.
export interface AuthServerConfig {
  // LDAP
  url?: string; bind_dn?: string; bind_password?: string; base_dn?: string;
  user_filter?: string; group_attribute?: string; email_attribute?: string;
  // SAML
  idp_metadata_xml?: string; entity_id?: string; acs_url?: string; sp_cert_pem?: string; sp_key_pem?: string;
  // OIDC
  issuer_url?: string; client_id?: string; client_secret?: string; redirect_url?: string; scopes?: string[];
}

export interface AuthServer {
  id?: string;
  type: string; // ldap | saml | oidc
  name: string;
  enabled: boolean;
  auth_order: number;
  config: AuthServerConfig;
  role_mapping: { rules: Record<string, string>; default: string };
  revision?: number;
}

export const authServersApi = {
  list: () => api.get<{ auth_servers: AuthServer[] }>("/auth-servers").then((r) => r.data.auth_servers),
  create: (body: Omit<AuthServer, "id" | "revision">) =>
    api.post<AuthServer>("/auth-servers", body).then((r) => r.data),
  update: (id: string, body: AuthServer) =>
    api.put<AuthServer>(`/auth-servers/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/auth-servers/${id}`).then((r) => r.data),
};

export interface Receiver {
  id: string;
  name: string;
  kind: string;
  endpoint: string;
  secret_ref?: string;
  owner?: string;
  environment: string;
  status: string;
  status_message?: string;
  supported_events: string[];
  config: Record<string, unknown>;
  last_verified_at?: string;
  created_at: string;
  rate_per_min: number;
  template_id: string;
  paused: boolean;
}

export interface ReceiverDelivery {
  id: string;
  receiver_id: string;
  event_type: string;
  severity: string;
  status: string;
  attempts: number;
  latency_ms: number;
  trace_id?: string;
  error?: string;
  artifacts: string[];
  routing_rule_id?: string;
  created_at: string;
  delivered_at?: string;
  idempotency_key?: string;
  final_state?: string;
  next_retry_at?: string;
  signed_at?: string;
}

export const receivers = {
  list: () => api.get<{ receivers: Receiver[]; delivery_history: ReceiverDelivery[] }>(
    "/integrations/receivers",
  ).then((r) => r.data),
  create: (body: Partial<Receiver>) =>
    api.post<{ id: string; secret_key: string }>("/integrations/receivers", body).then((r) => r.data),
  patch: (id: string, body: Partial<Receiver>) =>
    api.patch<{ status: string }>(`/integrations/receivers/${id}`, body).then((r) => r.data),
  delete: (id: string) =>
    api.delete<{ status: string }>(`/integrations/receivers/${id}`).then((r) => r.data),
  // Wave N3 endpoints.
  testFire: (id: string) =>
    api.post<{ delivery_id: string; idempotency_key: string }>(
      `/integrations/receivers/${id}/test-fire`,
    ).then((r) => r.data),
  pause: (id: string) =>
    api.post<{ status: string; paused: boolean }>(`/integrations/receivers/${id}/pause`).then((r) => r.data),
  unpause: (id: string) =>
    api.post<{ status: string; paused: boolean }>(`/integrations/receivers/${id}/unpause`).then((r) => r.data),
  rotateSecret: (id: string) =>
    api.post<{ secret_key: string }>(`/integrations/receivers/${id}/rotate-secret`).then((r) => r.data),
  deliveries: (id: string, limit = 50) =>
    api.get<{ deliveries: ReceiverDelivery[] }>(
      `/integrations/receivers/${id}/deliveries`,
      { params: { limit } },
    ).then((r) => r.data),
};

export const routing = {
  get: () => api.get<{ yaml: string; revision: number; updated_at: string }>("/routing.yaml").then((r) => r.data),
  put: (yaml: string) => api.post<{ status: string }>("/routing.yaml", { yaml }).then((r) => r.data),
};

export const forensics = {
  get: (snapshotID: string) =>
    api.get<{
      id: string;
      trigger: string;
      payload_sha256: string;
      size_bytes: number;
      captured_at: string;
      cluster_id?: string;
      deployment_id?: string;
      pod_name?: string;
      namespace?: string;
    }>(`/forensics/${snapshotID}`).then((r) => r.data),
};

export const scanJobsAdmin = {
  pause: (id: string) => api.post<{ status: string }>(`/scan-jobs/${id}/pause`).then((r) => r.data),
  resume: (id: string) => api.post<{ status: string }>(`/scan-jobs/${id}/resume`).then((r) => r.data),
  retry: (id: string) => api.post<{ status: string }>(`/scan-jobs/${id}/retry`).then((r) => r.data),
  cancel: (id: string) => api.post<{ status: string }>(`/scan-jobs/${id}/cancel`).then((r) => r.data),
};

export const accessControlAdmin = {
  createRoleBinding: (body: {
    subject_id: string;
    subject_type: string;
    role_id: string;
    scopes: Array<{ kind: string; values: string[]; inherited: boolean }>;
    expires_at?: string;
  }) => api.post<{ id: string }>("/access-control/role-bindings", body).then((r) => r.data),
  deleteRoleBinding: (id: string) =>
    api.delete<{ status: string }>(`/access-control/role-bindings/${id}`).then((r) => r.data),
  createServiceAccount: (body: {
    name: string;
    description?: string;
    owner?: string;
    scopes?: string[];
    roles?: string[];
  }) => api.post<{ id: string }>("/access-control/service-accounts", body).then((r) => r.data),
};

export const clustersAdmin = {
  crossScan: (clusterID: string, platform?: string) =>
    api.post<{ images_seen: number; jobs_enqueued: number; job_ids: string[] }>(
      `/clusters/${clusterID}/cross-scan`,
      { platform: platform ?? "" },
    ).then((r) => r.data),
};

export interface CVEResult {
  cve_id: string;
  title?: string;
  description?: string;
  cvss_base?: number;
  cvss_vector?: string;
  kev_listed: boolean;
  kev_added?: string;
  epss_probability?: number;
  epss_updated_at?: string;
  aliases: string[];
  affected?: unknown;
  sources: string[];
  published_at?: string;
  modified_at?: string;
}

export interface CVESearchParams {
  q?: string;
  limit?: number;
  offset?: number;
  kev?: boolean;
  epss_gt?: number;
  cvss_gt?: number;
  severity?: Severity;
  source?: string;
  sort?: string;
  dir?: "asc" | "desc";
}

export interface CVEStats {
  total: number;
  kev_listed: number;
  epss_gt_50: number;
  cvss_gt_70: number;
  has_cvss: number;
  latest_published_at?: string;
  oldest_published_at?: string;
  by_severity?: Array<{ severity: string; count: number }>;
  by_source?: Array<{ source: string; count: number }>;
}

export interface CVEBundleStatus {
  available: boolean;
  version?: string;
  oci_ref?: string;
  sha256?: string;
  record_count?: number;
  row_count?: number;
  signed?: boolean;
  imported_at?: string;
  published_at?: string;
  signer_identity?: string;
}

export interface CVEAffectedPackage {
  finding_id: string;
  package_ecosystem?: string;
  package_name?: string;
  package_version?: string;
  package_purl?: string;
  fixed_version?: string;
  severity: Severity;
  risk_score: number;
}

export interface CVEAffectedImage {
  image_scan_result_id: string;
  asset_id?: string;
  image_ref: string;
  image_ref_normalized: string;
  image_repository: string;
  image_tag?: string;
  image_digest: string;
  platform?: string;
  scanner_profile: string;
  vulndb_bundle_version?: string;
  vulndb_bundle_hash?: string;
  finding_count: number;
  max_risk_score: number;
  severity_counts: Record<string, number>;
  packages: CVEAffectedPackage[];
  last_seen_at: string;
  last_scanned_at: string;
}

export interface CVEAffectedWorkload {
  cluster_id: string;
  cluster_name?: string;
  deployment_id: string;
  workload_id: string;
  namespace: string;
  name: string;
  kind: string;
  image_ref: string;
  image_ref_normalized: string;
  image_repository?: string;
  image_tag?: string;
  image_digest?: string;
  finding_count: number;
  max_risk_score: number;
  critical_count: number;
  high_count: number;
  last_seen_at: string;
}

export interface CVEAffectedCluster {
  cluster_id: string;
  name?: string;
  workload_count: number;
  finding_count: number;
  max_risk_score: number;
}

export interface CVEAffectedSummary {
  image_count: number;
  workload_count: number;
  cluster_count: number;
  finding_count: number;
  max_risk_score: number;
}

export interface CVEAffectedResponse {
  cve_id: string;
  summary: CVEAffectedSummary;
  images: CVEAffectedImage[];
  workloads: CVEAffectedWorkload[];
  clusters: CVEAffectedCluster[];
}

export const cve = {
  search: (qOrParams: string | CVESearchParams = "") => {
    const params: Record<string, unknown> = typeof qOrParams === "string"
      ? { q: qOrParams }
      : {
          q: qOrParams.q ?? "",
          limit: qOrParams.limit,
          offset: qOrParams.offset,
          kev: qOrParams.kev ? "true" : undefined,
          epss_gt: qOrParams.epss_gt,
          cvss_gt: qOrParams.cvss_gt,
          severity: qOrParams.severity,
          source: qOrParams.source,
          sort: qOrParams.sort,
          dir: qOrParams.dir,
        };
    return api.get<{ results: CVEResult[]; limit: number; offset: number }>(`/cve/search`, { params }).then((r) => r.data);
  },
  bundle: () => api.get<CVEBundleStatus>(`/cve/bundle/status`).then((r) => r.data),
  stats:  () => api.get<CVEStats>(`/cve/stats`).then((r) => r.data),
  affected: (id: string, clusterId?: string) =>
    api.get<CVEAffectedResponse>(`/cve/${encodeURIComponent(id)}/affected`, { params: clusterId ? { cluster_id: clusterId } : undefined }).then((r) => r.data),
};

// ----- Wave D: Response Rules V2 (NeuVector-style condition catalog) ------

export type RRV2EventType = "admission" | "runtime" | "scan" | "compliance" | "*";
export type RRV2CondType = "name" | "level" | "cve_critical" | "proc" | "event_type";
export type RRV2ActionKind = "notify" | "quarantine" | "isolate" | "ticket";

export interface RRV2Condition { type: RRV2CondType; op?: string; value: string; }
export interface RRV2Action { kind: RRV2ActionKind; target?: string; params?: Record<string,string>; }
export interface RRV2Selector { cluster?: string; namespace?: string; labels?: Record<string,string>; }

export interface ResponseRuleV2 {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  event_type: RRV2EventType;
  conditions: RRV2Condition[];
  actions: RRV2Action[];
  workload_match: RRV2Selector;
  created_at?: string;
  updated_at?: string;
}

export const responseRulesV2 = {
  list:   (params: { cluster_id?: string } = {}) =>
    api.get<{ rules: ResponseRuleV2[] }>("/response-rules-v2", { params }).then((r) => r.data),
  create: (body: Omit<ResponseRuleV2, "id"|"priority"|"created_at"|"updated_at">, params: { cluster_id?: string } = {}) =>
    api.post<{ id: string }>("/response-rules-v2", body, { params }).then((r) => r.data),
  update: (id: string, body: Omit<ResponseRuleV2, "id"|"priority"|"created_at"|"updated_at">) =>
    api.put<{ id: string }>(`/response-rules-v2/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/response-rules-v2/${id}`).then((r) => r.data),
  reorder: (orderedIds: string[]) =>
    api.patch<{ ok: boolean; count: number }>("/response-rules-v2:reorder", { ordered_ids: orderedIds }).then((r) => r.data),
};

// ----- Wave D: Vulnerability Profiles ------

export type VPEntryAction = "suppress" | "escalate";

export interface VPEntry {
  name: string;
  name_regex?: string;
  images?: string[];
  action: VPEntryAction;
  days_to_fix?: number;
  severity_floor?: string;
  score_floor?: number;
  reserved?: string;
  recent_days?: number;
  comment?: string;
}

export interface VulnProfile {
  id: string;
  name: string;
  description: string;
  active: boolean;
  entries: VPEntry[];
  domain_scope: { clusters?: string[]; namespaces?: string[] };
  created_at?: string;
  updated_at?: string;
}

export const vulnProfiles = {
  list:   (params: { cluster_id?: string } = {}) =>
    api.get<{ profiles: VulnProfile[] }>("/vuln-profiles", { params }).then((r) => r.data),
  create: (body: Omit<VulnProfile, "id"|"created_at"|"updated_at">, params: { cluster_id?: string } = {}) =>
    api.post<{ id: string }>("/vuln-profiles", body, { params }).then((r) => r.data),
  update: (id: string, body: Omit<VulnProfile, "id"|"created_at"|"updated_at">) =>
    api.put<{ id: string }>(`/vuln-profiles/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/vuln-profiles/${id}`).then((r) => r.data),
};

// ----- Wave D: Groups ------

export type GroupKind = "learned" | "ground" | "federated";
export type GroupMode = "discover" | "monitor" | "protect";
export type GroupOp = "eq" | "contains" | "regex";

export interface GroupCriterion { key: string; value: string; op: GroupOp; }
export interface Group {
  id: string;
  name: string;
  kind: GroupKind;
  comment: string;
  criteria: GroupCriterion[];
  members: string[];
  learned_from: string;
  cfg_type: string;
  policy_mode: GroupMode;
  profile_mode: GroupMode;
  created_at?: string;
  updated_at?: string;
}

export const groupsApi = {
  list:   (params: { cluster_id?: string } = {}) =>
    api.get<{ groups: Group[] }>("/groups", { params }).then((r) => r.data),
  create: (body: Omit<Group, "id"|"created_at"|"updated_at">, params: { cluster_id?: string } = {}) =>
    api.post<{ id: string }>("/groups", body, { params }).then((r) => r.data),
  update: (id: string, body: Omit<Group, "id"|"created_at"|"updated_at">) =>
    api.put<{ id: string }>(`/groups/${id}`, body).then((r) => r.data),
  delete: (id: string) => api.delete(`/groups/${id}`).then((r) => r.data),
};

// ----- Wave D: Federation ------

export type FedState = "standalone" | "master" | "joint";

export interface FedMembership {
  state: FedState;
  master_id?: string;
  cluster_name?: string;
  revision: number;
  updated_at?: string;
}

export interface FedMember {
  id: string;
  cluster_id: string;
  name: string;
  role: "master" | "joint";
  endpoint: string;
  status: string;
  last_sync_at?: string;
  revision: number;
}

export const federation = {
  state:    () => api.get<FedMembership>("/federation/state").then((r) => r.data),
  transition: (action: "promote" | "demote" | "join" | "leave", master_id?: string, cluster_name?: string) =>
    api.post<FedMembership>("/federation/state", { action, master_id, cluster_name }).then((r) => r.data),
  members:  () => api.get<{ members: FedMember[] }>("/federation/members").then((r) => r.data),
  addMember: (body: Omit<FedMember,"id"|"last_sync_at">) =>
    api.post<FedMember>("/federation/members", body).then((r) => r.data),
  sync:     (since = 0) => api.get<{ revisions: unknown[]; since: number }>("/federation/sync", { params: { since } }).then((r) => r.data),
};

// The DLP sensor-CRUD surface and the earlier WAF rule-group CRUD were removed:
// they never reached the dataplane. DPI Signatures (runtimeSignaturesApi) are
// the authoritative DPI/L7/WAF ruleset; code-seeded runtime_dlp_rules cover DLP.

// RuntimeEvent is one row from the live runtime-events feed (POST /api/v1/events:bulk by
// the per-node runtime-agent DaemonSet). Distinct from RuntimeOverview.recent_events which
// joins with rule metadata for the legacy curated view; this is the raw stream the Runtime
// page surfaces alongside the curated evidence.
export interface RuntimeEvent {
  id: string;
  at: string;
  kind: string;
  source: string;
  severity: Severity | "info";
  verdict: string;
  node_id: string;
  workload_id: string;
  namespace?: string;
  container_id?: string;
  attack_techniques: string[];
  payload: Record<string, unknown>;
}

export const runtimeEvents = {
  list: (params: { limit?: number; kind?: string; severity?: Severity; workload?: string; cluster_id?: string } = {}) =>
    api.get<{ events: RuntimeEvent[]; limit: number }>("/events", { params }).then((r) => r.data),
};

export const auth = {
  login: (email: string, password: string) =>
    api.post<{ token: string; expires_at: string }>(`/auth/login`, { email, password }).then((r) => r.data),
  me:    () => api.get<{ user_id: string; org_id: string; email: string; roles: string[] }>("/auth/me").then((r) => r.data),
  logout: () => api.post(`/auth/logout`).then((r) => r.data),
  oidcStart: () => api.get<{ authorize_url: string }>(`/auth/oidc/start`).then((r) => r.data),
};

// --------- API tokens (Personal Access Tokens) ---------
//
// Backed by /api/v1/api-tokens. Raw token values are returned ONLY on create / rotate.
// The list / detail endpoints never include the raw value, only the SHA-256 metadata.

export interface ApiTokenDTO {
  id: string;
  name: string;
  scopes: string[];
  attached_to_kind: "user" | "service-account";
  attached_to_id: string;
  attached_to_label?: string;
  status: "active" | "expired" | "revoked";
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  revoked_at?: string;
}

export interface ApiTokenCreateResponse {
  id: string;
  name: string;
  scopes: string[];
  raw_token: string;
  hint?: string;
}

export interface VerbInfo {
  name: string;
  description: string;
  category: string;
  user_grantable: boolean;
}

export const apiTokens = {
  list: () => api.get<{ tokens: ApiTokenDTO[] }>("/api-tokens").then((r) => r.data.tokens),
  get: (id: string) => api.get<ApiTokenDTO>(`/api-tokens/${id}`).then((r) => r.data),
  create: (body: { name: string; scopes: string[]; expires_at?: string; attached_to?: string }) =>
    api.post<ApiTokenCreateResponse>("/api-tokens", body).then((r) => r.data),
  rotate: (id: string) =>
    api.post<ApiTokenCreateResponse>(`/api-tokens/${id}/rotate`, {}).then((r) => r.data),
  revoke: (id: string) => api.delete<{ status: string }>(`/api-tokens/${id}`).then((r) => r.data),
  verbCatalog: () => api.get<{ verbs: VerbInfo[] }>("/rbac/verbs").then((r) => r.data.verbs),
};

// --------- Container registries (Wave N2) ---------
//
// Backed by /api/v1/registries. auth_secret is server-side AES-256-GCM-sealed
// and never returned by any endpoint — has_secret is the boolean the UI uses
// to indicate "creds already saved, leave the field blank to keep them".

export type RegistryKind =
  | "docker-hub" | "ghcr" | "ecr" | "gcr" | "acr"
  | "quay" | "harbor" | "gitlab" | "jfrog";

export type RegistryAuthKind =
  | "static" | "aws-iam-role" | "gcp-service-account" | "azure-managed-id" | "none";

export type RegistryCadence = "manual" | "hourly" | "6h" | "daily" | "weekly";

export type RegistrySyncStatus = "ok" | "failed" | "partial" | "";

export interface RegistryScanPolicy {
  include_repos: string[];
  exclude_repos: string[];
  tag_selection: "all" | "latest";
  max_age?: string;
  rescan_interval?: string;
  block_promotion_threshold: string;
}

export interface RegistryDTO {
  id: string;
  org_id: string;
  name: string;
  kind: RegistryKind;
  endpoint: string;
  auth_kind: RegistryAuthKind;
  has_secret: boolean;
  scan_cadence: RegistryCadence;
  image_globs: string[];
  scan_policy: RegistryScanPolicy;
  last_sync_at?: string;
  last_sync_status?: RegistrySyncStatus;
  last_sync_error?: string;
  images_seen: number;
  created_at: string;
  updated_at: string;
}

export interface RegistryImageRow {
  id: string;
  repository: string;
  tags: string[];
  digests: Record<string, string>;
  last_pushed_at?: string;
  first_seen_at: string;
  last_seen_at: string;
  scanned: boolean;
  finding_count: number;
  last_scanned_at?: string;
  critical: number;
  high: number;
}

export interface RegistryTestResult {
  ok: boolean;
  images_visible?: number;
  error?: string;
}

export interface RegistrySyncResult {
  registry_id: string;
  status: "ok" | "failed" | "partial";
  images_seen: number;
  scan_jobs_enqueued: number;
  error?: string;
}

export interface RegistryCreateBody {
  name: string;
  kind: RegistryKind;
  endpoint: string;
  auth_kind: RegistryAuthKind;
  credentials?: Record<string, string>;
  scan_cadence?: RegistryCadence;
  image_globs?: string[];
  scan_policy?: RegistryScanPolicy;
}

export interface RegistryUpdateBody {
  name?: string;
  endpoint?: string;
  auth_kind?: RegistryAuthKind;
  credentials?: Record<string, string>;
  scan_cadence?: RegistryCadence;
  image_globs?: string[];
  scan_policy?: RegistryScanPolicy;
}

export const registries = {
  list:   () => api.get<{ registries: RegistryDTO[] }>("/registries").then((r) => r.data.registries),
  get:    (id: string) => api.get<RegistryDTO>(`/registries/${id}`).then((r) => r.data),
  create: (body: RegistryCreateBody) =>
    api.post<{ id: string }>("/registries", body).then((r) => r.data),
  update: (id: string, body: RegistryUpdateBody) =>
    api.patch<void>(`/registries/${id}`, body).then((r) => r.data),
  remove: (id: string) => api.delete<void>(`/registries/${id}`).then((r) => r.data),
  test:   (id: string) => api.post<RegistryTestResult>(`/registries/${id}/test`).then((r) => r.data),
  syncNow:(id: string) => api.post<RegistrySyncResult>(`/registries/${id}/sync-now`).then((r) => r.data),
  images: (id: string, params: { q?: string; limit?: number; offset?: number } = {}) =>
    api.get<{ images: RegistryImageRow[]; total: number; limit: number; offset: number }>(`/registries/${id}/images`, { params: { ...params, q: params.q || undefined } }).then((r) => r.data),
};

// Wave N5 — Backup / Restore.
export interface BackupSummary {
  id: string;
  mode: string;
  status: "running" | "succeeded" | "failed";
  started_at: string;
  finished_at?: string;
  size_bytes: number;
  sha256?: string;
  signed: boolean;
  signer_identity?: string;
  format_version?: string;
  s3_uri?: string;
  tables_included?: string[];
  error?: string;
}

export interface BackupSchedule {
  cron_expr: string;
  enabled: boolean;
  s3_bucket?: string;
  s3_prefix?: string;
  s3_endpoint?: string;
  sign_mode: "static-key" | "keyless" | "none";
  last_run_at?: string;
  last_status?: string;
  next_run_at?: string;
}

export interface BackupManifestDTO {
  format_version: string;
  org_id: string;
  org_name: string;
  generated_at: string;
  generated_by?: string;
  source_instance?: string;
  tables: Array<{ name: string; rows: number; sha256: string; bytes: number }>;
  root_hash: string;
  signer_identity?: string;
}

// ---------- VulnDB (host-vulnerability bundle mgmt) ----------

export interface VulnDBBundleMetadata {
  schema_version?: string;
  bundle_version?: string;
  producer?: string;
  media_type?: string;
  exported_at?: string;
  payload_hash?: string;
  record_count?: number;
}

export interface VulnDBStatus {
  path: string;
  status_path?: string;
  manual_upload_enabled: boolean;
  present: boolean;
  size_bytes?: number;
  modified_at?: string;
  bundle?: VulnDBBundleMetadata;
  importer?: {
    installed_at: string;
    source_kind: string;
    source_ref?: string;
    store_path: string;
    bundle: VulnDBBundleMetadata;
    tables?: Record<string, number>;
    trust: {
      require_signatures: boolean;
      signature_mode?: string;
      oci_signature_verified?: boolean;
      max_age?: string;
    };
  };
  importer_status_error?: string;
  last_loaded_at?: string;
  scanner_consumers?: Array<{
    hostname: string;
    cluster_id?: string;
    cluster_name?: string;
    status: string;
    last_seen_at: string;
    path?: string;
    ready: boolean;
    enabled: boolean;
    bundle_version?: string;
    payload_hash?: string;
    exported_at?: string;
    record_count?: number;
    error?: string;
  }>;
}

export interface VulnDBImportResponse {
  path: string;
  bundle: VulnDBBundleMetadata;
  record_count: number;
  tables: Record<string, number>;
  imported: boolean;
  rescan?: VulnDBRescanResponse;
  rescan_error?: string;
}

export interface VulnDBRescanResponse {
  bundle_version: string;
  payload_hash?: string;
  jobs_enqueued: number;
  target_counts: Array<{
    target_type: string;
    jobs_enqueued: number;
  }>;
}

export const vulndbApi = {
  status: () => api.get<VulnDBStatus>("/vulndb/status").then((r) => r.data),
  // Server expects multipart/form-data with two file fields:
  // "manifest" (manifest.json) and "payload" (bundle.jsonl.gz). The UI
  // builds the FormData and sets Content-Type from the body — leaving
  // axios to compute the multipart boundary.
  import: (manifest: File, payload: File) => {
    const fd = new FormData();
    fd.append("manifest", manifest);
    fd.append("payload", payload);
    return api.post<VulnDBImportResponse>("/vulndb:import", fd).then((r) => r.data);
  },
  rescan: () => api.post<VulnDBRescanResponse>("/vulndb:rescan").then((r) => r.data),
};

export const backupsApi = {
  list: () => api.get<{ backups: BackupSummary[] }>("/backups").then((r) => r.data.backups),
  get: (id: string) => api.get<BackupSummary>(`/backups/${id}`).then((r) => r.data),
  create: (body: { sign_mode?: string }) =>
    api.post<{ id: string; status: string }>("/backups", body).then((r) => r.data),
  downloadURL: (id: string) => `/api/v1/backups/${id}/download`,
  download: (id: string) => downloadAPIFile(`/backups/${id}/download`, `backup-${id}.tar.gz`),
  verify: (file: File) =>
    api.post<BackupManifestDTO>("/backups/verify", file, {
      headers: { "Content-Type": "application/octet-stream" },
    }).then((r) => r.data),
  restore: (file: File, opts: { on_conflict?: "skip" | "overwrite"; allow_unverified?: boolean }) =>
    api.post(`/backups/restore`, file, {
      params: opts,
      headers: { "Content-Type": "application/octet-stream" },
    }).then((r) => r.data),
  getSchedule: () => api.get<BackupSchedule>("/backups/schedule").then((r) => r.data),
  putSchedule: (s: BackupSchedule) =>
    api.post<BackupSchedule>("/backups/schedule", s).then((r) => r.data),
};
