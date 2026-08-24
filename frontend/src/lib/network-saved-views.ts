import type { SavedViewBase } from "@/hooks/useSavedViews";

export const NETWORK_SAVED_VIEW_SCHEMA_VERSION = 1;
export const NETWORK_SAVED_VIEW_KIND = "constellation.networkActivity.savedViews";

export const NETWORK_SAVED_WORKSPACE_TABS = ["map", "conversations", "sessions", "pcap", "rules", "threats"] as const;
export const NETWORK_SAVED_VERDICTS = ["", "allow", "alert", "block"] as const;
export const NETWORK_SAVED_VERDICT_GROUPS = ["allow", "alert", "block"] as const;
export const NETWORK_SAVED_NODE_KINDS = ["workload", "host", "unmanaged", "external"] as const;
export const NETWORK_SAVED_SCOPE_MODES = ["both", "internal", "external"] as const;

export type NetworkSavedWorkspaceTab = (typeof NETWORK_SAVED_WORKSPACE_TABS)[number];
export type NetworkSavedVerdict = (typeof NETWORK_SAVED_VERDICTS)[number];
export type NetworkSavedVerdictGroup = (typeof NETWORK_SAVED_VERDICT_GROUPS)[number];
export type NetworkSavedNodeKind = (typeof NETWORK_SAVED_NODE_KINDS)[number];
export type NetworkSavedScopeMode = (typeof NETWORK_SAVED_SCOPE_MODES)[number];

export interface NetworkSavedViewSnapshot {
  schema_version: typeof NETWORK_SAVED_VIEW_SCHEMA_VERSION;
  workspace_tab: NetworkSavedWorkspaceTab;
  hours: number;
  namespace: string;
  group: string;
  verdict: NetworkSavedVerdict;
  verdicts_visible: Record<NetworkSavedVerdictGroup, boolean>;
  protocols: string[];
  namespaces: string[];
  hide_kube_system: boolean;
  hidden_kinds: NetworkSavedNodeKind[];
  scope_mode: NetworkSavedScopeMode;
  session_filters: NetworkSessionSavedFilters;
  pcap_filters: NetworkPcapSavedFilters;
}

export interface NetworkSessionSavedFilters {
  protocol: string;
  application: string;
  port: string;
  peer: string;
  workload: string;
  node: string;
}

export interface NetworkPcapSavedFilters {
  status: string;
  workload: string;
  duration_s: number;
  protocol: string;
  src_ip: string;
  dst_ip: string;
  dst_port: string;
  bpf_filter: string;
  interface: string;
  file_count: string;
  file_size_mb: string;
}

export interface NetworkSavedView extends SavedViewBase {
  cluster_id: string;
  saved_at: string;
  filters: NetworkSavedViewSnapshot;
}

export interface NetworkSavedViewsExportBundle {
  schema_version: typeof NETWORK_SAVED_VIEW_SCHEMA_VERSION;
  kind: typeof NETWORK_SAVED_VIEW_KIND;
  cluster_id: string;
  exported_at: string;
  views: NetworkSavedView[];
}

export function networkActivitySavedViewsStorageKey(clusterID: string, userID = "local") {
  return `constellation:network-activity:saved-views:${clusterID || "unscoped"}:${userID || "local"}`;
}

export function buildNetworkSavedViewSnapshot(input: {
  workspaceTab: NetworkSavedWorkspaceTab;
  hours: number;
  namespace: string;
  group?: string;
  verdict: string;
  verdictsVisible: Record<NetworkSavedVerdictGroup, boolean>;
  protocolFilter: Iterable<string>;
  namespaceFilter: Iterable<string>;
  hideKubeSystem: boolean;
  hiddenKinds: Iterable<string>;
  scopeMode: NetworkSavedScopeMode;
  sessionFilters?: Partial<NetworkSessionSavedFilters>;
  pcapFilters?: Partial<NetworkPcapSavedFilters>;
}): NetworkSavedViewSnapshot {
  return {
    schema_version: NETWORK_SAVED_VIEW_SCHEMA_VERSION,
    workspace_tab: normalizeWorkspaceTab(input.workspaceTab),
    hours: normalizeHours(input.hours),
    namespace: input.namespace.trim(),
    group: normalizeTextFilter(input.group),
    verdict: normalizeVerdict(input.verdict),
    verdicts_visible: normalizeVerdictsVisible(input.verdictsVisible),
    protocols: normalizeTokenList(Array.from(input.protocolFilter), { upper: true }),
    namespaces: normalizeTokenList(Array.from(input.namespaceFilter)),
    hide_kube_system: input.hideKubeSystem,
    hidden_kinds: normalizeNodeKinds(Array.from(input.hiddenKinds)),
    scope_mode: normalizeScopeMode(input.scopeMode),
    session_filters: normalizeSessionSavedFilters(input.sessionFilters),
    pcap_filters: normalizePcapSavedFilters(input.pcapFilters),
  };
}

export function normalizeNetworkSavedViewSnapshot(value: unknown): NetworkSavedViewSnapshot | null {
  if (!isRecord(value)) return null;
  return {
    schema_version: NETWORK_SAVED_VIEW_SCHEMA_VERSION,
    workspace_tab: normalizeWorkspaceTab(value.workspace_tab),
    hours: normalizeHours(value.hours),
    namespace: typeof value.namespace === "string" ? value.namespace.trim() : "",
    group: normalizeTextFilter(value.group),
    verdict: normalizeVerdict(value.verdict),
    verdicts_visible: normalizeVerdictsVisible(value.verdicts_visible),
    protocols: normalizeTokenList(Array.isArray(value.protocols) ? value.protocols : [], { upper: true }),
    namespaces: normalizeTokenList(Array.isArray(value.namespaces) ? value.namespaces : []),
    hide_kube_system: typeof value.hide_kube_system === "boolean" ? value.hide_kube_system : true,
    hidden_kinds: normalizeNodeKinds(Array.isArray(value.hidden_kinds) ? value.hidden_kinds : ["unmanaged"]),
    scope_mode: normalizeScopeMode(value.scope_mode),
    session_filters: normalizeSessionSavedFilters(value.session_filters),
    pcap_filters: normalizePcapSavedFilters(value.pcap_filters),
  };
}

export function normalizeNetworkSavedView(value: unknown, clusterID?: string): NetworkSavedView | null {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") return null;
  const filters = normalizeNetworkSavedViewSnapshot(value.filters);
  if (!filters) return null;
  return {
    id: value.id,
    name: value.name.trim() || "Imported view",
    cluster_id: clusterID ?? (typeof value.cluster_id === "string" ? value.cluster_id : ""),
    saved_at: typeof value.saved_at === "string" ? value.saved_at : new Date(0).toISOString(),
    filters,
  };
}

export function parseNetworkSavedViewsImport(text: string, clusterID: string): NetworkSavedView[] {
  const parsed = JSON.parse(text) as unknown;
  const views = Array.isArray(parsed)
    ? parsed
    : isRecord(parsed) && Array.isArray(parsed.views)
      ? parsed.views
      : [];
  return views
    .map((view) => normalizeNetworkSavedView(view, clusterID))
    .filter((view): view is NetworkSavedView => Boolean(view));
}

export function mergeNetworkSavedViews(
  current: NetworkSavedView[],
  imported: NetworkSavedView[],
  makeID: () => string = defaultNetworkSavedViewID,
): NetworkSavedView[] {
  const usedIDs = new Set(current.map((view) => view.id));
  const next = imported.map((view) => {
    if (!usedIDs.has(view.id)) {
      usedIDs.add(view.id);
      return view;
    }
    const id = makeID();
    usedIDs.add(id);
    return { ...view, id };
  });
  return [...current, ...next];
}

export function buildNetworkSavedViewsExport(
  clusterID: string,
  views: NetworkSavedView[],
  exportedAt = new Date().toISOString(),
): NetworkSavedViewsExportBundle {
  return {
    schema_version: NETWORK_SAVED_VIEW_SCHEMA_VERSION,
    kind: NETWORK_SAVED_VIEW_KIND,
    cluster_id: clusterID,
    exported_at: exportedAt,
    views,
  };
}

export function suggestNetworkSavedViewName(snapshot: NetworkSavedViewSnapshot, groupLabel?: string) {
  const tab = snapshot.workspace_tab[0].toUpperCase() + snapshot.workspace_tab.slice(1);
  const ns = groupLabel || snapshot.group || snapshot.namespace || (snapshot.namespaces.length === 1 ? snapshot.namespaces[0] : "all namespaces");
  const verdict = snapshot.verdict || "all verdicts";
  return `${tab} ${snapshot.hours}h ${ns} ${verdict}`;
}

function defaultNetworkSavedViewID() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return `network-view-${crypto.randomUUID()}`;
  }
  return `network-view-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function normalizeHours(value: unknown) {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 24;
}

function normalizeWorkspaceTab(value: unknown): NetworkSavedWorkspaceTab {
  return NETWORK_SAVED_WORKSPACE_TABS.includes(value as NetworkSavedWorkspaceTab)
    ? (value as NetworkSavedWorkspaceTab)
    : "map";
}

function normalizeVerdict(value: unknown): NetworkSavedVerdict {
  return NETWORK_SAVED_VERDICTS.includes(value as NetworkSavedVerdict)
    ? (value as NetworkSavedVerdict)
    : "";
}

function normalizeScopeMode(value: unknown): NetworkSavedScopeMode {
  return NETWORK_SAVED_SCOPE_MODES.includes(value as NetworkSavedScopeMode)
    ? (value as NetworkSavedScopeMode)
    : "both";
}

function normalizeVerdictsVisible(value: unknown): Record<NetworkSavedVerdictGroup, boolean> {
  const record = isRecord(value) ? value : {};
  return {
    allow: typeof record.allow === "boolean" ? record.allow : true,
    alert: typeof record.alert === "boolean" ? record.alert : true,
    block: typeof record.block === "boolean" ? record.block : true,
  };
}

function normalizeSessionSavedFilters(value: unknown): NetworkSessionSavedFilters {
  const record = isRecord(value) ? value : {};
  return {
    protocol: normalizeSessionProtocol(record.protocol),
    application: normalizeTextFilter(record.application),
    port: normalizePortFilter(record.port),
    peer: normalizeTextFilter(record.peer),
    workload: normalizeTextFilter(record.workload),
    node: normalizeTextFilter(record.node),
  };
}

function normalizePcapSavedFilters(value: unknown): NetworkPcapSavedFilters {
  const record = isRecord(value) ? value : {};
  return {
    status: normalizePcapStatus(record.status),
    workload: normalizeTextFilter(record.workload),
    duration_s: normalizePcapDuration(record.duration_s),
    protocol: normalizePcapProtocol(record.protocol),
    src_ip: normalizeTextFilter(record.src_ip),
    dst_ip: normalizeTextFilter(record.dst_ip),
    dst_port: normalizePortFilter(record.dst_port),
    bpf_filter: normalizeTextFilter(record.bpf_filter, 1024),
    interface: normalizeTextFilter(record.interface, 15),
    file_count: normalizePcapFileCount(record.file_count),
    file_size_mb: normalizePcapFileSizeMB(record.file_size_mb),
  };
}

function normalizeSessionProtocol(value: unknown) {
  if (typeof value !== "string") return "";
  const protocol = value.trim().toLowerCase();
  return ["", "tcp", "udp", "icmp", "icmpv6"].includes(protocol) || /^proto-\d{1,3}$/.test(protocol)
    ? protocol
    : "";
}

function normalizePcapStatus(value: unknown) {
  if (typeof value !== "string") return "";
  const status = value.trim().toLowerCase();
  return ["", "pending", "running", "completed", "failed", "expired"].includes(status) ? status : "";
}

function normalizePcapProtocol(value: unknown) {
  if (typeof value !== "string") return "";
  const protocol = value.trim().toLowerCase();
  return ["", "tcp", "udp", "icmp"].includes(protocol) ? protocol : "";
}

function normalizePcapDuration(value: unknown) {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return 30;
  return Math.min(300, Math.max(5, Math.floor(n)));
}

function normalizePcapFileCount(value: unknown) {
  const text = typeof value === "number" ? String(value) : typeof value === "string" ? value.trim() : "";
  if (!text) return "";
  const n = Number(text);
  return Number.isInteger(n) && n >= 1 && n <= 20 ? String(n) : "";
}

function normalizePcapFileSizeMB(value: unknown) {
  const text = typeof value === "number" ? String(value) : typeof value === "string" ? value.trim() : "";
  if (!text) return "";
  const n = Number(text);
  return Number.isInteger(n) && n >= 1 && n <= 100 ? String(n) : "";
}

function normalizePortFilter(value: unknown) {
  const text = typeof value === "number" ? String(value) : typeof value === "string" ? value.trim() : "";
  if (!text) return "";
  const n = Number(text);
  return Number.isInteger(n) && n > 0 && n <= 65535 ? String(n) : "";
}

function normalizeTextFilter(value: unknown, maxLen = 128) {
  return typeof value === "string" ? value.trim().slice(0, maxLen) : "";
}

function normalizeNodeKinds(values: unknown[]): NetworkSavedNodeKind[] {
  const selected = new Set(values.filter((value): value is NetworkSavedNodeKind =>
    NETWORK_SAVED_NODE_KINDS.includes(value as NetworkSavedNodeKind),
  ));
  return NETWORK_SAVED_NODE_KINDS.filter((kind) => selected.has(kind));
}

function normalizeTokenList(values: unknown[], options: { upper?: boolean } = {}) {
  const seen = new Set<string>();
  values.forEach((value) => {
    if (typeof value !== "string") return;
    const token = options.upper ? value.trim().toUpperCase() : value.trim();
    if (token) seen.add(token);
  });
  return Array.from(seen).sort((a, b) => a.localeCompare(b));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}
