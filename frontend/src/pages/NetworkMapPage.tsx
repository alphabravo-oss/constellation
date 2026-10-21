import { NetworkEnforcementStatus } from "./NetworkEnforcementStatus";
import { NetworkPeerEvidence } from "./NetworkPeerEvidence";
import { StreamsTab, PcapWorkspaceTab, ThreatMaximum } from "./NetworkSecondaryInventory";
export { StreamsTab, PcapWorkspaceTab } from "./NetworkSecondaryInventory";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { createContext, useContext, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate, useRouter } from "@tanstack/react-router";
import {
  Background,
  Controls,
  MarkerType,
  type Edge,
  type Node,
  ReactFlow,
  ReactFlowProvider,
  useNodesState,
  useEdgesState,
  useReactFlow,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import * as Dialog from "@radix-ui/react-dialog";
import * as RadixTabs from "@radix-ui/react-tabs";
import {
  Activity,
  Filter,
  ShieldAlert,
  Waypoints,
  Eye,
  EyeOff,
  Radio,
  Lock,
  X,
  TriangleAlert,
  CircleCheck,
  Ban,
  ChevronUp,
  ChevronDown,
  Table2,
} from "lucide-react";


import { Button } from "@/components/ui/button";
import { FilterLabel, InventoryMoreFilters } from "./inventory-workspace";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { PageHeader } from "@/components/ui/page";
import { StatusPill } from "@/components/ui/status-pill";
import { Sparkline } from "@/components/ui/sparkline";
import { EmptyState } from "@/components/ui/empty-state";
import { useNetworkRoute } from "@/hooks/useNetworkRoute";
import { NETWORK_VIEW_PARAM, networkViewHref, networkViewSnapshotFromParams } from "@/lib/network-saved-view-route";
import { NetworkSavedViewsControl } from "@/components/NetworkSavedViewsControl";
import { Collapse } from "@/components/ui/collapse";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { policyActionAvailable } from "./network-secondary";
import { ErrorState } from "@/components/ui/states";
import { useCluster } from "@/hooks/useCluster";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";
import { cn } from "@/lib/cn";
import { fmtBytes } from "@/lib/format";
import { isPlatformNamespace, isPlatformResource, namespaceFromWorkloadID } from "@/lib/platform-components";
import {
  buildNetworkSavedViewSnapshot,
  type NetworkPcapSavedFilters,
  type NetworkSessionSavedFilters,
  type NetworkSavedViewSnapshot,
} from "@/lib/network-saved-views";
import { toast } from "sonner";
import { DataTable, type Column } from "@/components/ui/data-table";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { ScanInventoryExport } from "./inventory-workspace";
import { conversationsValid, sessionsValid, threatsValid, conversationSorts, sessionSorts, threatSorts } from "@/lib/network-inventory";
import type { TableSort } from "@/components/ui/data-table";
import type { ReactNode } from "react";
import { Pager } from "@/components/ui/pager";

import {
  groupsApi,
  network,
  policies,
  runtimeThreats,
  type NetworkConversation,
  type NetworkConversationFilters,
  type NetworkFlow,
  type NetworkFlowState,
  type NetworkNodeKind,
  type NetworkPolicyLifecycle,
  type NetworkPolicyMode,
  type NetworkRecentFlow,
  type NetworkSession,
  type NetworkSessionsResponse,
  type NetworkSessionKillResponse,
  type NetworkWorkload,
  type RuntimeThreat,
  type RuntimeThreatDetail,
} from "@/api/client";
import { Select } from "@/components/ui/form";

const STATE_COLOR: Record<NetworkFlowState, string> = {
  ok: "var(--color-status-success)",
  warn: "var(--color-status-warning)",
  denied: "var(--color-status-error)",
  declared: "var(--color-muted-foreground)",
};

// L2 verdict-to-state mapping used by the new chip filters and the
// top-right legend pinned on top of the canvas.
const VERDICT_GROUPS = ["allow", "alert", "block"] as const;
// Endpoint kinds shown as legend visibility toggles. `unmanaged` (bare
// in-cluster IPs that didn't resolve to a workload) is hidden by default so the
// graph stays focused on real workloads, NeuVector-style.
const NODE_KINDS = ["workload", "host", "unmanaged", "external"] as const;

// severityLabel maps the dp 1..9 threat severity scale to a human band, so the
// UI never shows a bare number the operator has to decode.
function severityLabel(n: number): string {
  if (n >= 8) return "Critical";
  if (n >= 6) return "High";
  if (n >= 4) return "Medium";
  if (n >= 1) return "Low";
  return "Info";
}

// threatActionLabel decodes DP_THREAT_ACTION_* into what actually happened to
// the packet — the actionability signal. In TAP/monitor mode (the common case)
// action is 0: the threat was DETECTED but traffic was NOT blocked.
function threatActionLabel(action: number): string {
  switch (action) {
    case 0:
      return "detected (log-only)";
    case 2:
    case 3:
      return "blocked";
    case 4:
      return "connection reset";
    default:
      return "detected";
  }
}

function threatCategoryLabel(threatID: number): string {
  if (threatID >= 40000 && threatID < 50000) return "waf";
  if (threatID >= 20000 && threatID < 40000) return "dlp";
  return "ips";
}
type VerdictGroup = (typeof VERDICT_GROUPS)[number];
type NetworkWorkspaceTab = "map" | "conversations" | "sessions" | "pcap" | "rules" | "threats";

const NETWORK_WORKSPACE_TABS: Array<{
  id: NetworkWorkspaceTab;
  label: string;
  nvLabel: string;
}> = [
  { id: "map", label: "Map", nvLabel: "Map" },
  { id: "conversations", label: "Conversations", nvLabel: "Conversations" },
  { id: "sessions", label: "Sessions", nvLabel: "Sessions" },
  { id: "pcap", label: "PCAP", nvLabel: "Sniffer" },
  { id: "rules", label: "Rules", nvLabel: "Policy" },
  { id: "threats", label: "Threats", nvLabel: "Threats" },
];

const VERDICT_TO_STATE: Record<VerdictGroup, NetworkFlowState> = {
  allow: "ok",
  alert: "warn",
  block: "denied",
};

const VERDICT_LABEL: Record<VerdictGroup, string> = {
  allow: "Allow",
  alert: "Alert",
  block: "Block",
};

const VERDICT_ICON: Record<VerdictGroup, typeof CircleCheck> = {
  allow: CircleCheck,
  alert: TriangleAlert,
  block: Ban,
};

type ScopeMode = "both" | "internal" | "external";

const EMPTY_WORKLOADS: NetworkWorkload[] = [];
const EMPTY_FLOWS: NetworkFlow[] = [];
const EMPTY_SESSIONS: NetworkSession[] = [];
const EMPTY_LIFECYCLE_ITEMS: NetworkPolicyLifecycle[] = [];
const EMPTY_THREATS: RuntimeThreat[] = [];
const EMPTY_CONVERSATIONS: NetworkConversation[] = [];
const EMPTY_NODE_KINDS: Record<string, NetworkNodeKind> = {};
const EMPTY_SESSION_FILTERS: NetworkSessionSavedFilters = {
  protocol: "",
  application: "",
  port: "",
  peer: "",
  workload: "",
  node: "",
};
const EMPTY_PCAP_FILTERS: NetworkPcapSavedFilters = {
  status: "",
  workload: "",
  duration_s: 30,
  protocol: "",
  src_ip: "",
  dst_ip: "",
  dst_port: "",
  bpf_filter: "",
  interface: "",
  file_count: "",
  file_size_mb: "",
};

const NetworkViewContext = createContext<{ clusterID: string; snapshot: NetworkSavedViewSnapshot } | null>(null);

export function NetworkMapPage() {
  return (
    <ReactFlowProvider>
      <NetworkMapInner />
    </ReactFlowProvider>
  );
}

function NetworkMapInner() {
  const router = useRouter();
  const pathname = useLocation({ select: location => location.pathname });
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const { params: routeParams, update: updateRoute, hours, setHours, namespace, setNamespace, groupFilter, setGroupFilter, verdict, setVerdict, selectedFlowID, setSelectedFlowID, selectedWorkloadID, setSelectedWorkloadID, workspaceTab, setWorkspaceTab, conversationPage, setConversationPage } = useNetworkRoute();
  const conversationScope = useMemo(() => ({ from: routeParams.get("from") || undefined, to: routeParams.get("to") || undefined, verdict_group: (routeParams.get("verdict_group") || undefined) as "blocked" | undefined }), [routeParams]);
  // B1: cluster scoping. We're mounted under /clusters/:id/network, so the
  // active cluster comes from the route param via useCluster() — NOT from a
  // query string (normal sidebar nav has none, which previously yielded an
  // empty unscoped map). The hooks/useCluster.ts contract requires every
  // fetch on this page to thread this cluster_id.
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const registryFetching=useIsFetching({queryKey:["clusters"],exact:true});
  const clusterFetching=useIsFetching({queryKey:["cluster",clusterId],exact:true});
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !registryFetching && !clusterFetching && clusterCacheReady(queryClient,clusterId);
  const clusterID = clusterId ?? "";
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const currentOwner = useRef(owner); currentOwner.current = owner;
  const [live, setLive] = useState(true);

  // ───── L2 chip-filter state ─────
  // Verdict toggles default to all on. Toggling a verdict hides edges of that
  // verdict; this maps to canvas color legend clicks too.
  const [verdictsVisible, setVerdictsVisible] = useState<Record<VerdictGroup, boolean>>({
    allow: true,
    alert: true,
    block: true,
  });
  const [protocolFilter, setProtocolFilter] = useState<Set<string>>(() => new Set());
  const [namespaceFilter, setNamespaceFilter] = useState<Set<string>>(() => new Set());
  const [platformPreference, setPlatformPreference] = usePlatformComponentVisibility();
  const hidePlatformComponents = routeParams.has("hide_platform") ? routeParams.get("hide_platform") !== "false" : platformPreference;
  const setHidePlatformComponents = useCallback((value: boolean) => {
    setPlatformPreference(value);
    updateRoute({ hide_platform: String(value) }, false, true);
  }, [setPlatformPreference, updateRoute]);
  const [hiddenKinds, setHiddenKinds] = useState<Set<NetworkNodeKind>>(() => new Set<NetworkNodeKind>(["unmanaged"]));
  const [scopeMode, setScopeMode] = useState<ScopeMode>("both");
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [sessionFilters, setSessionFilters] = useState<NetworkSessionSavedFilters>(() => ({ ...EMPTY_SESSION_FILTERS }));
  const pageFor = (name: string) => Math.max(0, Number(routeParams.get(name) || "1") - 1);
  const sessionPage = pageFor("session_page"), threatPage = pageFor("threat_page");
  const setSessionPage = (page: number) => updateRoute({ session_page: page ? String(page + 1) : null });
  const setThreatPage = (page: number) => updateRoute({ threat_page: page ? String(page + 1) : null });
  const sortFor = (name: string, fallback: string): TableSort => ({ id: routeParams.get(`${name}_sort`) || fallback, dir: (routeParams.get(`${name}_order`) || "desc") as "asc" | "desc" });
  const conversationSort = sortFor("conversation", "last_seen"), sessionSort = sortFor("session", "bytes"), threatSort = sortFor("threat", "at");
  const changeSort = (name: string) => (next: TableSort | null) => updateRoute({ [`${name}_sort`]: next?.id ?? null, [`${name}_order`]: next?.dir ?? null, [`${name}_page`]: null });
  const routeValid = (name: string, sort: TableSort, allowed: string[]) => allowed.includes(sort.id) && ["asc", "desc"].includes(sort.dir) && (!routeParams.has(`${name}_page`) || /^\d+$/.test(routeParams.get(`${name}_page`)!) && Number(routeParams.get(`${name}_page`)) >= 1 && Number(routeParams.get(`${name}_page`)) <= INVENTORY_MAX_PAGE);
  const [pcapFilters, setPcapFilters] = useState<NetworkPcapSavedFilters>(() => ({ ...EMPTY_PCAP_FILTERS }));
  const groupsQ = useQuery({
    queryKey: ["groups", clusterID],
    queryFn: () => groupsApi.list({ cluster_id: clusterID || undefined }),
    enabled: scopeReady,
    staleTime: 30_000,
  });
  const groupOptions = useMemo(() => groupsQ.data?.groups ?? [], [groupsQ.data?.groups]);
  const selectedGroup = useMemo(
    () => groupOptions.find((group) => group.id === groupFilter || group.name === groupFilter) ?? null,
    [groupOptions, groupFilter],
  );
  const effectiveGroupFilter = selectedGroup?.id ?? groupFilter;
  const selectedGroupLabel = selectedGroup?.name ?? "";
  const sessionQueryParams = useMemo(() => {
    const port = Number(sessionFilters.port);
    return {
      group: effectiveGroupFilter || undefined,
      protocol: sessionFilters.protocol || undefined,
      application: sessionFilters.application || undefined,
      port: Number.isInteger(port) && port > 0 ? port : undefined,
      peer: sessionFilters.peer || undefined,
      workload: sessionFilters.workload || undefined,
      node: sessionFilters.node || undefined,
    };
  }, [effectiveGroupFilter, sessionFilters]);
  const sharedTrafficFilters = useMemo(() => ({
    port: sessionQueryParams.port,
    peer: sessionQueryParams.peer,
    application: sessionQueryParams.application,
  }), [sessionQueryParams.port, sessionQueryParams.peer, sessionQueryParams.application]);
  // URL-backed group changes already reset pages through useNetworkRoute.
  // Track only local traffic inputs here so Back can restore a group's page.
  const trafficSignature = JSON.stringify({ ...sessionQueryParams, group: undefined });
  const previousTrafficSignature = useRef(trafficSignature);
  useEffect(() => {
    if (previousTrafficSignature.current !== trafficSignature) {
      previousTrafficSignature.current = trafficSignature;
      updateRoute({}, true, true);
    }
  }, [trafficSignature, updateRoute]);

  const savedViewSnapshot = useMemo(
    () => buildNetworkSavedViewSnapshot({
      workspaceTab,
      hours,
      namespace,
      group: groupFilter,
      verdict,
      verdictsVisible,
      protocolFilter,
      namespaceFilter,
      hidePlatformComponents,
      hiddenKinds,
      scopeMode,
      sessionFilters,
      pcapFilters: { ...pcapFilters, q: routeParams.get("pcap_q") ?? undefined, namespace: routeParams.get("pcap_namespace") ?? undefined, node: routeParams.get("pcap_node") ?? undefined },
      conversationFilters: conversationScope,
    }),
    [workspaceTab, hours, namespace, groupFilter, verdict, verdictsVisible, protocolFilter, namespaceFilter, hidePlatformComponents, hiddenKinds, scopeMode, sessionFilters, pcapFilters, conversationScope, routeParams],
  );

  const restoredContext = useRef<string | null>(null);
  const pendingRestore = useRef<string | null>(null);
  const applySavedViewSnapshot = useCallback((snapshot: NetworkSavedViewSnapshot, restoring = false) => {
    const serialized = JSON.stringify(snapshot);
    restoredContext.current = serialized;
    pendingRestore.current = serialized;
    updateRoute({ tab: snapshot.workspace_tab === "map" ? null : snapshot.workspace_tab, hours: snapshot.hours === 24 ? null : String(snapshot.hours), namespace: snapshot.namespace, group: snapshot.group, verdict: snapshot.verdict, ...(!restoring ? { flow: null, workload: null } : {}), [NETWORK_VIEW_PARAM]: serialized, hide_platform: String(snapshot.hide_platform_components), from: snapshot.conversation_filters?.from ?? null, to: snapshot.conversation_filters?.to ?? null, verdict_group: snapshot.conversation_filters?.verdict_group ?? null, pcap_q: snapshot.pcap_filters.q ?? null, pcap_namespace: snapshot.pcap_filters.namespace ?? null, pcap_node: snapshot.pcap_filters.node ?? null }, restoring, !restoring);
    if (restoring) { const port = Number(snapshot.session_filters.port); previousTrafficSignature.current = JSON.stringify({ protocol: snapshot.session_filters.protocol || undefined, application: snapshot.session_filters.application || undefined, port: Number.isInteger(port) && port > 0 ? port : undefined, peer: snapshot.session_filters.peer || undefined, workload: snapshot.session_filters.workload || undefined, node: snapshot.session_filters.node || undefined }); }
    setVerdictsVisible(snapshot.verdicts_visible);
    setProtocolFilter(new Set(snapshot.protocols));
    setNamespaceFilter(new Set(snapshot.namespaces));
    setPlatformPreference(snapshot.hide_platform_components);
    setHiddenKinds(new Set(snapshot.hidden_kinds));
    setScopeMode(snapshot.scope_mode);
    setSessionFilters(snapshot.session_filters);
    setPcapFilters(snapshot.pcap_filters);
    setPopoverOpen(false);
  }, [updateRoute, setPlatformPreference]);
  const restoreContext = routeParams.get(NETWORK_VIEW_PARAM);
  useEffect(() => {
    // Router search updates can arrive before the outgoing workspace unmounts.
    // Consume carried filters only on the workspace, never on its form routes.
    if (router.latestLocation.pathname.replace(/\/$/, "") !== `/clusters/${encodeURIComponent(clusterID)}/network`) return;
    if (!restoreContext) { restoredContext.current = null; return; }
    if (restoredContext.current === restoreContext) return;
    const snapshot = networkViewSnapshotFromParams(new URLSearchParams({ [NETWORK_VIEW_PARAM]: restoreContext }));
    if (!snapshot) return;
    applySavedViewSnapshot(snapshot, true);
  }, [restoreContext, applySavedViewSnapshot, pathname, clusterID, router]);
  useEffect(() => {
    if (router.latestLocation.pathname.replace(/\/$/, "") !== `/clusters/${encodeURIComponent(clusterID)}/network`) return;
    if (restoreContext && !networkViewSnapshotFromParams(new URLSearchParams({ [NETWORK_VIEW_PARAM]: restoreContext }))) return;
    const serialized = JSON.stringify(savedViewSnapshot);
    // Wait for the incoming snapshot to reach local state before writing it.
    // Otherwise the outgoing render's defaults could overwrite restored filters.
    if (pendingRestore.current && pendingRestore.current !== serialized) return;
    pendingRestore.current = null;
    if (restoreContext === serialized) return;
    restoredContext.current = serialized;
    updateRoute({ [NETWORK_VIEW_PARAM]: serialized }, true, false);
  }, [savedViewSnapshot, restoreContext, updateRoute, pathname, clusterID, router]);

  const q = useQuery({
    queryKey: ["network-map", hours, clusterID, namespace, effectiveGroupFilter, verdict, sharedTrafficFilters],
    queryFn: () => network.map({ hours, cluster_id: clusterID || undefined, namespace: namespace || undefined, group: effectiveGroupFilter || undefined, verdict: verdict || undefined, ...sharedTrafficFilters }),
    enabled: scopeReady,
    refetchInterval: live ? 10_000 : false,
  });
  // NET-1: folded service-conversation graph. Distinct from /network/map (raw
  // flow rows) — it carries node_kinds (workload|host|unmanaged|external) so we
  // can badge off-cluster endpoints the raw map can't classify. Cluster-scoped
  // via useCluster() like every other query on this page.
  const conversationRequest = { hours, cluster_id: clusterID, namespace: namespace || undefined, group: effectiveGroupFilter || undefined, verdict: verdict || undefined, ...sharedTrafficFilters, ...conversationScope, limit: 100, offset: conversationPage * 100, sort: conversationSort.id, order: conversationSort.dir, hide_platform: hidePlatformComponents };
  const conversationKey = ["network-conversations", owner, conversationRequest];
  const conversationRouteValid = routeValid("conversation", conversationSort, conversationSorts);
  const conversationsQ = useQuery({
    queryKey: conversationKey,
    queryFn: async () => { const data = await network.conversations(conversationRequest); if (!conversationsValid(data, conversationRequest)) throw new Error("Conversation scope or totals could not be confirmed."); return data; },
    enabled: scopeReady && !!owner && conversationRouteValid,
    refetchInterval: live ? 10_000 : false,
  });
  const conversationsAvailable = scopeReady && !!owner && conversationRouteValid && conversationsQ.isSuccess && !conversationsQ.isFetching && conversationsValid(conversationsQ.data, conversationRequest);
  const nodeKinds = conversationsQ.data?.node_kinds ?? EMPTY_NODE_KINDS;
  const lifecycleQ = useQuery({
    queryKey: ["network-policy-lifecycle", hours, clusterID, namespace, effectiveGroupFilter, verdict],
    queryFn: () => network.lifecycle({ hours, cluster_id: clusterID || undefined, namespace: namespace || undefined, group: effectiveGroupFilter || undefined, verdict: verdict || undefined }),
    enabled: scopeReady,
    refetchInterval: live ? 10_000 : false,
  });
  // Wave 6: recent DPI threats from the runtime-agent's dp data-plane. Drives
  // the threats card pinned to the bottom-right of the canvas. We pull the
  // same window as the flow query so the two views stay coherent, and use a
  // longer refetch interval (15s) since threats are append-only and don't
  // need the 10s flow cadence.
  const threatRequest = { hours, cluster_id: clusterID, namespace: namespace || undefined, group: effectiveGroupFilter || undefined, port: sharedTrafficFilters.port, peer: sharedTrafficFilters.peer, application: sharedTrafficFilters.application, limit: 100, offset: threatPage * 100, sort: threatSort.id, order: threatSort.dir, hide_platform: hidePlatformComponents };
  const threatKey = ["runtime-threats", owner, threatRequest];
  const threatRouteValid = routeValid("threat", threatSort, threatSorts);
  const threatsQ = useQuery({
    queryKey: threatKey,
    queryFn: async () => { const data = await runtimeThreats.page(threatRequest); if (!threatsValid(data, threatRequest)) throw new Error("Threat scope or totals could not be confirmed."); return data; },
    enabled: scopeReady && !!owner && threatRouteValid,
    refetchInterval: live ? 10_000 : false,
  });
  const sessionRequest = { cluster_id: clusterID, ...sessionQueryParams, limit: 100, offset: sessionPage * 100, sort: sessionSort.id, order: sessionSort.dir, hide_platform: hidePlatformComponents };
  const sessionKey = ["network-sessions", owner, sessionRequest];
  const sessionRouteValid = routeValid("session", sessionSort, sessionSorts);
  const sessionsQ = useQuery({
    queryKey: sessionKey,
    queryFn: async () => { const data = await network.sessions(sessionRequest); if (!sessionsValid(data, sessionRequest)) throw new Error("Session scope or totals could not be confirmed."); return data; },
    enabled: scopeReady && !!owner && sessionRouteValid,
    refetchInterval: live ? 5_000 : false,
  });
  const sessionsAvailable = scopeReady && !!owner && sessionRouteValid && sessionsQ.isSuccess && !sessionsQ.isFetching && sessionsValid(sessionsQ.data, sessionRequest);
  const exportReady = (key: unknown[]) => { const state = queryClient.getQueryState(key); if (!scopeReady || currentOwner.current !== owner || !clusterCacheReady(queryClient, clusterID) || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated) throw new Error("Refresh the inventory before exporting."); };
  const sessionContext = JSON.stringify(sessionKey);
  const currentSessionContext = useRef(sessionContext); currentSessionContext.current = sessionContext;
  const [lastSessionKill, setLastSessionKill] = useState<NetworkSessionKillResponse | null>(null);
  // DPI toggle: weak-TLS version detection (SSLv3/TLS1.0/1.1). Applied live by the agent.
  const dpiSettingsQ = useQuery({
    queryKey: ["dpi-threat-settings", clusterID],
    queryFn: () => policies.dpiThreatSettings({ cluster_id: clusterID || undefined }),
    enabled: scopeReady,
  });
  // NV session-kill: queue a dp ctrl_clear_session; agent executes on its next snapshot.
  const killSessionMut = useMutation({
    mutationFn: async ({ id, node, context, cluster, key }: { id: number; node: string; context: string; cluster: string; key: unknown[] }) => {
      const state = queryClient.getQueryState<NetworkSessionsResponse>(key);
      if (currentSessionContext.current !== context || !clusterCacheReady(queryClient, cluster) || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !sessionsValid(state.data, sessionRequest) || !state.data?.sessions.some(row => row.id === id && row.node === node && row.cluster_id === cluster)) throw new Error("Refresh sessions before terminating this connection.");
      return network.killSession(id, { cluster_id: cluster, node });
    },
    onSuccess: (result, request) => {
      if (request.context !== currentSessionContext.current) return;
      setLastSessionKill(result);
      const audit = result.audit_id ? ` Audit #${result.audit_id}.` : "";
      toast.success(`Session ${result.session_id} kill queued on ${result.node || "node"}.${audit}`);
    },
    onError: () => toast.error("Failed to queue session kill"),
  });
  const workloads = q.data?.workloads ?? EMPTY_WORKLOADS;
  const platformWorkloads = useMemo(() => new Map(workloads.map((workload) => [
    workload.id,
    isPlatformResource(workload.platform_role, workload.namespace),
  ])), [workloads]);
  const isPlatformWorkload = useCallback(
    (workloadID: string | undefined) => (workloadID ? platformWorkloads.get(workloadID) : undefined) ?? isPlatformNamespace(namespaceFromWorkloadID(workloadID)),
    [platformWorkloads],
  );
  const isPlatformEndpoint = useCallback(
    (workloadID: string | undefined, platformRole: string | undefined) => platformRole == null
      ? isPlatformWorkload(workloadID)
      : isPlatformResource(platformRole, namespaceFromWorkloadID(workloadID)),
    [isPlatformWorkload],
  );
  const flowsRaw = q.data?.flows ?? EMPTY_FLOWS;
  const liveFlows = q.data?.recent_flows ?? [];
  const sessions = sessionsAvailable ? sessionsQ.data!.sessions : EMPTY_SESSIONS;
  const sessionsTotal = sessionsAvailable ? sessionsQ.data!.total : 0;
  const sessionsHasMore = sessionsAvailable ? sessionsQ.data!.has_more : false;
  // Cluster list was used by the dropped select; URL-driven now.
  // const clusters = q.data?.summary.clusters ?? [];
  const lifecycleAvailable=scopeReady&&lifecycleQ.isSuccess&&!lifecycleQ.isError&&lifecycleQ.data?.summary.selected_cluster_id===clusterID&&lifecycleQ.data.items.every(item=>item.cluster_id===clusterID);
  const lifecycleItemsRaw = lifecycleAvailable ? lifecycleQ.data!.items : EMPTY_LIFECYCLE_ITEMS;
  const lifecycleItems = useMemo(
    () => hidePlatformComponents ? lifecycleItemsRaw.filter((item) => !isPlatformResource(item.platform_role,item.namespace)) : lifecycleItemsRaw,
    [hidePlatformComponents, lifecycleItemsRaw],
  );
  const threatsAvailable = scopeReady && !!owner && threatRouteValid && threatsQ.isSuccess && !threatsQ.isFetching && threatsValid(threatsQ.data, threatRequest);
  const threats = threatsAvailable ? threatsQ.data!.threats : EMPTY_THREATS;
  const conversations = conversationsAvailable ? conversationsQ.data!.conversations : EMPTY_CONVERSATIONS;
  const platformWorkloadCount = useMemo(
    () => workloads.filter((item) => isPlatformResource(item.platform_role, item.namespace)).length,
    [workloads],
  );

  // Drop self-loops (workload→workload) up front; they clutter the canvas and
  // are usually intra-pod retries.
  const flowsNoSelf = useMemo(() => flowsRaw.filter((f) => f.src !== f.dst), [flowsRaw]);

  // Union of protocols / namespaces observed in the *current* flow window
  // drives the chip menus. Kept stable across renders for keyboard tab order.
  const observedProtocols = useMemo(() => {
    const s = new Set<string>();
    flowsNoSelf.forEach((f) => {
      if (f.l7_protocol) s.add(f.l7_protocol.toUpperCase());
      if (f.protocol) s.add(f.protocol.toUpperCase());
    });
    return Array.from(s);
  }, [flowsNoSelf]);
  const namespaces = useMemo(() => Array.from(new Set(workloads.map((w) => w.namespace))).sort(), [workloads]);

  // Workload→namespace lookup so we can derive flow→namespace classification
  // without joining on every filter pass.
  const workloadNS = useMemo(() => {
    const m = new Map<string, string>();
    workloads.forEach((w) => m.set(w.id, w.namespace));
    return m;
  }, [workloads]);

  const flowProtocols = useCallback((f: NetworkFlow) => {
    const tags = [f.l7_protocol, f.protocol].filter(Boolean).map((s) => s.toUpperCase());
    return new Set(tags);
  }, []);

  const isExternal = useCallback((f: NetworkFlow) => f.src.startsWith("external/") || f.dst.startsWith("external/"), []);
  const isPlatformFlow = useCallback(
    (f: NetworkFlow) => {
      return isPlatformEndpoint(f.src, f.src_platform_role) || isPlatformEndpoint(f.dst, f.dst_platform_role);
    },
    [isPlatformEndpoint],
  );

  // Apply L2 chip filters on top of the server-side filters (which only
  // know about hours / cluster / namespace / verdict). This pass runs against
  // the in-memory flow list so chip toggles feel instant.
  const flows = useMemo(() => {
    return flowsNoSelf.filter((f) => {
      const vg = verdictGroupFromState(f.state, f.verdict);
      if (vg && !verdictsVisible[vg]) return false;
      if (hidePlatformComponents && isPlatformFlow(f)) return false;
      if (scopeMode === "external" && !isExternal(f)) return false;
      if (scopeMode === "internal" && isExternal(f)) return false;
      if (protocolFilter.size > 0) {
        const tags = flowProtocols(f);
        let any = false;
        protocolFilter.forEach((p) => {
          if (tags.has(p)) any = true;
        });
        if (!any) return false;
      }
      if (namespaceFilter.size > 0) {
        const srcNS = workloadNS.get(f.src) ?? "";
        const dstNS = workloadNS.get(f.dst) ?? "";
        if (!namespaceFilter.has(srcNS) && !namespaceFilter.has(dstNS)) return false;
      }
      if (hiddenKinds.size > 0) {
        const srcKind = nodeKinds[f.src];
        const dstKind = nodeKinds[f.dst];
        if ((srcKind && hiddenKinds.has(srcKind)) || (dstKind && hiddenKinds.has(dstKind))) return false;
      }
      return true;
    });
  }, [flowsNoSelf, verdictsVisible, hidePlatformComponents, scopeMode, protocolFilter, namespaceFilter, workloadNS, isPlatformFlow, isExternal, flowProtocols, hiddenKinds, nodeKinds]);

  // Hide nodes that have no visible edges once chip filters are applied so the
  // canvas declutters in lockstep.
  const visibleWorkloadIDs = useMemo(() => {
    const s = new Set<string>();
    flows.forEach((f) => {
      s.add(f.src);
      s.add(f.dst);
    });
    return s;
  }, [flows]);
  const visibleWorkloads = useMemo(
    () => workloads.filter((w) =>
      (!hidePlatformComponents || !isPlatformResource(w.platform_role, w.namespace))
      && (flowsNoSelf.length === 0 || visibleWorkloadIDs.has(w.id)),
    ),
    [flowsNoSelf.length, hidePlatformComponents, workloads, visibleWorkloadIDs],
  );

  const selectedFlow = flows.find((f) => f.id === selectedFlowID) ?? null;
  const selectedWorkload = visibleWorkloads.find((w) => w.id === selectedWorkloadID) ?? null;
  // Mutually-exclusive inspectors — NeuVector-style:
  //   - edge click  -> FlowInspector popover (selectedFlow is set)
  //   - node click  -> Workload panel       (selectedWorkload is set)
  //   - either one  -> CollapsiblePolicyLifecycle expands IFF an explicit
  //                    workload is selected (NOT auto-derived from flow.src)
  // Closing the modal clears both, returning the page to the empty-selection
  // baseline where the lifecycle chip stays collapsed.
  const selectedLifecycle =
    selectedWorkloadID
      ? lifecycleItems.find((item) => item.workload === selectedWorkloadID) ?? null
      : null;

  // Compute the spread-out auto-layout, then hold positions in local state so
  // (a) user drags stick across the 10s refetch, and (b) only newly-arrived
  // nodes pick up a fresh auto-layout slot. clusterID change resets the layout.
  const layout = useMemo(() => layoutGraph(visibleWorkloads, flows, selectedFlowID, nodeKinds), [visibleWorkloads, flows, selectedFlowID, nodeKinds]);
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>(layout.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>(layout.edges);

  // Reset layout when the user explicitly changes cluster (positions become meaningless)
  useEffect(() => { setNodes(layout.nodes); }, [clusterID]); // eslint-disable-line react-hooks/exhaustive-deps

  // Merge layout updates while preserving any user-dragged positions for nodes we already know
  useEffect(() => {
    setNodes((prev) => {
      const prevById = new Map(prev.map((n) => [n.id, n]));
      return layout.nodes.map((n) => {
        const existing = prevById.get(n.id);
        return existing ? { ...n, position: existing.position } : n;
      });
    });
  }, [layout.nodes, setNodes]);

  useEffect(() => { setEdges(layout.edges); }, [layout.edges, setEdges]);

  // NET-1: subscribe to the live flow SSE stream. Each pushed flow means a new
  // edge was observed, so we coalesce arrivals into a debounced refetch of the
  // map + conversation graph — the canvas updates within ~1s of live traffic
  // instead of waiting on the 10s poll. The poll stays as the durable fallback
  // (the SSE channel is lossy under backpressure and only registered when the
  // hot graph is enabled server-side). Scoped to the active cluster.
  useEffect(() => {
    if (!live || !clusterID) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const unsubscribe = network.streamFlows({ cluster_id: clusterID }, () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        void queryClient.invalidateQueries({ queryKey: ["network-map"] });
        void queryClient.invalidateQueries({ queryKey: ["network-conversations"] });
      }, 1_000);
    });
    return () => {
      if (timer) clearTimeout(timer);
      unsubscribe();
    };
  }, [live, clusterID, queryClient]);

  const activeInventory = workspaceTab === "conversations" ? conversationsQ : workspaceTab === "sessions" ? sessionsQ : workspaceTab === "threats" ? threatsQ : q;
  const lastUpdated = workspaceTab === "pcap" ? "" : activeInventory.isSuccess && activeInventory.dataUpdatedAt ? `Updated ${new Date(activeInventory.dataUpdatedAt).toLocaleTimeString()}` : "not loaded";

  const selectFlow = useCallback(
    (flowID: string) => {
      updateRoute({ flow: flowID, workload: null });
    },
    [updateRoute],
  );

  const toggleVerdict = (g: VerdictGroup) =>
    setVerdictsVisible((prev) => ({ ...prev, [g]: !prev[g] }));

  const toggleKind = (k: NetworkNodeKind) =>
    setHiddenKinds((prev) => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k);
      else next.add(k);
      return next;
    });

  const toggleProtocol = (p: string) =>
    setProtocolFilter((prev) => {
      const next = new Set(prev);
      if (next.has(p)) next.delete(p);
      else next.add(p);
      return next;
    });

  const toggleNamespace = (ns: string) =>
    setNamespaceFilter((prev) => {
      const next = new Set(prev);
      if (next.has(ns)) next.delete(ns);
      else next.add(ns);
      return next;
    });

  // Keyboard step-through: arrow up/down on an open inspector cycles flows
  // in render order so reviewers can audit a list without dropping back to the
  // canvas.
  const stepFlow = useCallback(
    (delta: number) => {
      if (!selectedFlowID || flows.length === 0) return;
      const idx = flows.findIndex((f) => f.id === selectedFlowID);
      if (idx < 0) return;
      const next = (idx + delta + flows.length) % flows.length;
      setSelectedFlowID(flows[next].id);
    },
    [flows, selectedFlowID, setSelectedFlowID],
  );

  useEffect(() => {
    if (!popoverOpen) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "ArrowUp") {
        e.preventDefault();
        stepFlow(-1);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        stepFlow(1);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [popoverOpen, stepFlow]);

  // Map metrics describe only the currently loaded, visible map sample.
  const workloadCount = visibleWorkloads.length;
  // The existing single-IP action emits a Cilium policy. Gates the
  // "Block IP" affordance — on flannel/native it can't apply, so we hide it.
  const denyCapable = !!q.data?.summary.cni?.toLowerCase().includes("cilium");
  const flowCount = flows.length;
  const volume = fmtBytes(flows.reduce((total, flow) => total + flow.bytes, 0));
  const blocked = flows.filter((f) => f.state === "denied").length;

  // B2: canvas-level states. A successful fetch with zero workloads AND zero
  // flows means nothing was tapped in the window (no runtime-agent dp data).
  const noData = q.isSuccess && workloads.length === 0 && flowsRaw.length === 0;
  const noVisibleData = q.isSuccess && !noData && visibleWorkloads.length === 0 && flows.length === 0;

  if (!scopeReady) return <div className="space-y-4"><PageHeader title="Network map" description="Observed traffic, live connections and network security evidence." />{clusterLoading ? <p role="status">Resolving cluster…</p> : <ErrorState title="The selected cluster could not be resolved." error={clusterError} action={<Button onClick={() => { void queryClient.invalidateQueries({ queryKey: ["clusters"] }); void queryClient.invalidateQueries({ queryKey: ["cluster", clusterId] }); }}>Retry cluster</Button>} />}</div>;

  return (
    <NetworkViewContext.Provider value={{ clusterID, snapshot: savedViewSnapshot }}>
    <div className="flex min-h-[calc(100vh-72px)] flex-col gap-4" data-testid="network-activity-page">
      <PageHeader
        title="Network map"
        description="Observed traffic, live connections and network security evidence."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <StatusPill label={live ? "Live" : "Paused"} tone={live ? "success" : "neutral"} />
            <Button size="sm" variant="ghost" onClick={() => setLive((c) => !c)}>{live ? "Pause" : "Resume"}</Button>
            <Button size="sm" onClick={() => { if (workspaceTab === "pcap") { void queryClient.invalidateQueries({ queryKey: ["pcap-captures", clusterID] }); return; } void q.refetch(); void conversationsQ.refetch(); void lifecycleQ.refetch(); void threatsQ.refetch(); void sessionsQ.refetch(); }}>Refresh</Button>
          </div>
        }
      />
      {restoreContext && !networkViewSnapshotFromParams(routeParams) && <ErrorState title="The saved network context is invalid. URL filters remain active." action={<Button onClick={() => updateRoute({ [NETWORK_VIEW_PARAM]: null }, true)}>Discard invalid context</Button>} />}
      <VerdictBanner status={workspaceTab !== "pcap" && activeInventory.isError ? "degraded" : "info"}
        title={workspaceTab === "conversations" ? !conversationsAvailable ? conversationsQ.isFetching ? "Loading conversations" : "Conversation evidence unavailable" : `${conversationsQ.data!.total} matching directed pairs`
          : workspaceTab === "sessions" ? !sessionsAvailable ? sessionsQ.isFetching ? "Loading sessions" : "Session evidence unavailable" : `${sessionsTotal} matching live sessions`
          : workspaceTab === "threats" ? !threatsAvailable ? threatsQ.isFetching ? "Loading threats" : "Threat evidence unavailable" : `${threatsQ.data!.total} matching threats`
          : workspaceTab === "pcap" ? "Capture request ledger" : q.isError ? "Network map evidence unavailable" : "Inspect observed network activity"}
        detail={workspaceTab === "pcap" ? "The ledger reports retained capture requests. A request does not establish a completed capture; its matching counts, files and refresh status appear below." : workspaceTab === "map" ? "The map loads up to 300 rolled-up flows and 50 recent flow events. Narrow filters to inspect more. Missing traffic does not prove a workload is protected."
          : workspaceTab === "sessions" ? "Totals cover all matching sessions reported in the last five minutes. Missing sessions do not establish agent coverage or protection."
          : workspaceTab === "conversations" ? "Totals cover all matching directed pairs in retained hourly rollups for this window. Missing traffic does not prove a workload is protected."
          : "Reported evidence is limited by its source coverage. Missing activity does not prove a workload is protected."}
        numbers={workspaceTab === "map" ? [
          { label: "workloads", value: q.isSuccess ? workloadCount : "—", title: "Visible workloads" },
          { label: "flows", value: q.isSuccess ? flowCount : "—", title: "Visible map flows" },
          { label: "volume", value: q.isSuccess ? volume : "—", title: "Map flow volume" },
          { label: "blocked", value: q.isSuccess ? blocked : "—", tone: blocked > 0 ? "error" : "default", title: "Blocked map flows" },
        ] : undefined} />
      {workspaceTab === "map" && <div className="sr-only" data-testid="network-map-summary">
        <span>Visible workloads {q.isSuccess ? workloadCount : "—"}</span> <span>Visible map flows {q.isSuccess ? flowCount : "—"}</span> <span>Map flow volume {q.isSuccess ? volume : "—"}</span> <span>Blocked map flows {q.isSuccess ? blocked : "—"}</span>
        <span>Platform workloads {platformWorkloadCount}</span> <span data-testid="netstat-threats">Loaded threats {threatsAvailable ? threats.length : "—"}</span>
      </div>}
      <RadixTabs.Root
        value={workspaceTab}
        onValueChange={(value) => setWorkspaceTab(value as NetworkWorkspaceTab)}
        className="flex min-h-0 flex-1 flex-col gap-2"
        data-testid="network-workspace-tabs"
      >
        <RadixTabs.List
          className="flex items-center gap-6 overflow-x-auto border-b border-border"
          aria-label="Network workspace"
          data-testid="network-workspace-tab-list"
        >
          {NETWORK_WORKSPACE_TABS.map((tab) => (
            <RadixTabs.Trigger
              key={tab.id}
              value={tab.id}
              className={cn(
                "relative -mb-px inline-flex items-center gap-2 whitespace-nowrap border-b-2 border-transparent pb-3 pt-1 text-sm font-medium text-muted-foreground transition-colors",
                "hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring data-[state=active]:border-foreground data-[state=active]:text-foreground",
              )}
              data-testid={`network-workspace-tab-${tab.id}`}
            >
              <span>{tab.label}</span>
            </RadixTabs.Trigger>
          ))}
        </RadixTabs.List>

      {/* L2 filter chip bar — replaces the legacy select bar except the
          server-side (hours/cluster/namespace/verdict) selects which still
          drive the API queries. */}
      {/* Single-row filter strip. Cluster comes from the URL (we're inside
          /clusters/:id/network). Verdict + namespace are chips, not selects.
          Power-user controls collapse into the "More" dropdown. */}
      <div className="flex flex-nowrap items-center gap-2 overflow-x-auto pb-0.5" data-testid="network-filter-bar">
        {["map", "conversations", "sessions", "threats"].includes(workspaceTab) && <>
        {workspaceTab !== "sessions" && <Select
          className="h-9 shrink-0"
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
          aria-label="Traffic window"
          data-testid="network-window-select"
        >
          <option value={1}>Last hour</option>
          <option value={24}>Last 24 hours</option>
          <option value={168}>Last 7 days</option>
        </Select>}
        {(workspaceTab === "map" || workspaceTab === "conversations") && <Select
          className="h-9 shrink-0"
          value={verdict}
          onChange={(e) => setVerdict(e.target.value)}
          aria-label="Verdict filter"
          data-testid="network-verdict-select"
        >
          <option value="">All verdicts</option>
          <option value="allow">Allow</option>
          <option value="alert">Alert</option>
          <option value="deny">Deny</option>
          <option value="block">Block</option>
        </Select>}
        {workspaceTab !== "sessions" && <Select
          className="h-9 max-w-48 shrink-0"
          value={namespace}
          onChange={(e) => setNamespace(e.target.value)}
          aria-label="Namespace filter"
          data-testid="network-namespace-select"
        >
          <option value="">All namespaces</option>
          {namespaces.map((ns) => (
            <option key={ns} value={ns}>{ns}</option>
          ))}
          {namespace && !namespaces.includes(namespace) && (
            <option value={namespace}>{namespace}</option>
          )}
        </Select>}
        <InventoryMoreFilters count={[sessionFilters.port, sessionFilters.peer, sessionFilters.application, groupFilter].filter(Boolean).length + (protocolFilter.size ? 1 : 0) + (namespaceFilter.size ? 1 : 0) + (scopeMode !== "both" ? 1 : 0)}>
          <div className="grid grid-cols-3 gap-2">
            <FilterLabel label="Port">
        <input
          className="h-9 w-full rounded-md border border-input bg-background px-3 font-mono text-sm"
          aria-label="Traffic port"
          data-testid="network-traffic-port"
          placeholder="Port"
          inputMode="numeric"
          value={sessionFilters.port}
          onChange={(event) => setSessionFilters((current) => ({ ...current, port: event.target.value.replace(/[^\d]/g, "").slice(0, 5) }))}
        />
            </FilterLabel>
            <FilterLabel label="Peer">
        <input
          className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
          aria-label="Traffic peer"
          data-testid="network-traffic-peer"
          placeholder="Peer"
          value={sessionFilters.peer}
          onChange={(event) => setSessionFilters((current) => ({ ...current, peer: event.target.value }))}
        />
            </FilterLabel>
            <FilterLabel label="App or ID">
        <input
          className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
          aria-label="Traffic application"
          data-testid="network-traffic-application"
          title="Application names use source-specific protocol or port hints; numeric IDs filter DPI threats"
          placeholder="App / ID"
          value={sessionFilters.application}
          onChange={(event) => setSessionFilters((current) => ({ ...current, application: event.target.value }))}
        />
            </FilterLabel>
          </div>
          <FilterLabel label="Group">
        <Select
          className="w-full"
          value={selectedGroup?.id ?? groupFilter}
          onChange={(e) => setGroupFilter(e.target.value)}
          aria-label="Group filter"
          data-testid="network-group-select"
        >
          <option value="">{groupsQ.isPending ? "Loading groups" : "All groups"}</option>
          {groupOptions.map((group) => (
            <option key={group.id} value={group.id}>
              {group.name} ({(group.members ?? []).length})
            </option>
          ))}
          {groupFilter && !groupOptions.some((group) => group.id === groupFilter || group.name === groupFilter) && (
            <option value={groupFilter}>{groupFilter}</option>
          )}
        </Select>
          </FilterLabel>
          {workspaceTab === "map" && <div className="space-y-1.5"><p className="text-meta font-medium text-muted-foreground">Map verdicts and protocols</p><div className="flex flex-wrap items-center gap-1.5">
        {workspaceTab === "map" && <>
        <Chip
          active={verdictsVisible.allow && verdictsVisible.alert && verdictsVisible.block}
          onClick={() => setVerdictsVisible({ allow: true, alert: true, block: true })}
          data-testid="netchip-verdict-all"
        >All</Chip>
        {VERDICT_GROUPS.map((g) => (
          <Chip key={g} active={verdictsVisible[g]} tone={g} onClick={() => toggleVerdict(g)} data-testid={`netchip-verdict-${g}`}>
            {VERDICT_LABEL[g]}
          </Chip>
        ))}
        {observedProtocols.slice(0, 6).map((p) => (
          <Chip key={p} active={protocolFilter.has(p)} onClick={() => toggleProtocol(p)} data-testid={`netchip-proto-${p}`}>
            {p}
          </Chip>
        ))}
        <NamespaceMultiSelect
          namespaces={namespaces}
          selected={namespaceFilter}
          onToggle={toggleNamespace}
          onClear={() => setNamespaceFilter(new Set())}
        />
        </>}
          </div></div>}
        {workspaceTab === "map" && <div className="flex rounded-md border border-border p-0.5" data-testid="netchip-scope">
          {(["both", "internal", "external"] as ScopeMode[]).map((m) => (
            <button
              key={m}
              type="button"
              className={cn(
                "h-7 flex-1 rounded-sm px-2 text-meta transition-colors",
                scopeMode === m ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
              )}
              onClick={() => setScopeMode(m)}
              data-testid={`netchip-scope-${m}`}
            >
              {m === "external" ? "External" : m === "internal" ? "Internal" : "Both"}
            </button>
          ))}
        </div>}
        </InventoryMoreFilters>
        </>}
        <span className="ml-auto" />
        <NetworkSavedViewsControl
          clusterID={clusterID}
          snapshot={savedViewSnapshot}
          groupLabel={selectedGroupLabel}
          onApply={applySavedViewSnapshot}
        />
        {["map", "conversations", "sessions", "threats"].includes(workspaceTab) && <span className="shrink-0 whitespace-nowrap text-meta text-muted-foreground" data-testid="network-last-updated">{lastUpdated}</span>}
      </div>
        <RadixTabs.Content value="map" className="flex min-h-0 flex-1 flex-col outline-none" data-testid="network-workspace-panel-map">
      {/* ReactFlow needs a definite height inside this scrolling workspace.
          The L2 edge-popover is the single inspector now (no right rail). */}
      <div className="relative h-[max(460px,calc(100vh-330px))] min-h-[420px] rounded-lg border border-border bg-card" data-testid="network-map">
        {/* B2: loading / error / empty states before the ReactFlow canvas. */}
        {q.isLoading ? (
          <div className="flex h-full items-center justify-center" data-testid="network-map-loading">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Radio className="h-4 w-4 animate-pulse" aria-hidden />
              <span>Loading traffic map…</span>
            </div>
          </div>
        ) : q.isError ? (
          <div className="flex h-full items-center justify-center" data-testid="network-map-error">
            <EmptyState
              icon={<TriangleAlert className="h-8 w-8" aria-hidden />}
              title="Couldn’t load the traffic map"
              hint={(q.error as Error | null)?.message ?? "The network map request failed."}
              action={
                <Button size="sm" variant="outline" onClick={() => void q.refetch()} data-testid="network-map-retry">
                  Retry
                </Button>
              }
            />
          </div>
        ) : noData ? (
          <div className="flex h-full items-center justify-center" data-testid="network-map-empty">
            <EmptyState
              icon={<Waypoints className="h-8 w-8" aria-hidden />}
              title="No traffic observed"
              hint={`No flows in the last ${hours}h for this cluster. Confirm the runtime-agent DaemonSet is running with dp.enabled — flows are tapped from the data-plane. Note that Cilium eBPF CNIs may bypass this tap and won’t be observed here.`}
              action={
                clusterID ? (
                  <a
                    href={`/clusters/${clusterID}/health`}
                    className="text-link text-sm"
                    data-testid="network-map-empty-health-link"
                  >
                    View cluster health →
                  </a>
                ) : undefined
              }
            />
          </div>
        ) : noVisibleData ? (
          <div className="flex h-full items-center justify-center" data-testid="network-map-filtered-empty">
            <EmptyState
              icon={<EyeOff className="h-8 w-8" aria-hidden />}
              title="No traffic matches this view"
              hint="Platform components or the active network filters are hiding all observed workloads and flows. Collection and protection remain active."
              action={
                hidePlatformComponents ? (
                  <Button size="sm" onClick={() => setHidePlatformComponents(false)}>
                    Include system workloads
                  </Button>
                ) : undefined
              }
            />
          </div>
        ) : (
        <>
        <CanvasInner
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onSelectFlow={(id) => {
            selectFlow(id);
            setPopoverOpen(true);
          }}
          onSelectWorkload={(id) => {
            setSelectedWorkloadID(id);
            setSelectedFlowID(null);
          }}
        />
        {/* Top-right overlay stack: the verdict legend and the DPI threats card
            share one flex column so the card always sits below the legend and
            never overlaps it, regardless of how tall the legend grows. */}
        <div className="absolute right-3 top-3 z-10 flex flex-col items-end gap-2">
        <div
          className="flex flex-col gap-1 rounded-md border border-border bg-card/95 p-2 text-micro shadow-[var(--elev-2)] backdrop-blur"
          data-testid="network-verdict-legend"
        >
          <div className="px-1 text-micro  text-muted-foreground">Legend</div>
          {VERDICT_GROUPS.map((g) => {
            const Icon = VERDICT_ICON[g];
            const state = VERDICT_TO_STATE[g];
            const on = verdictsVisible[g];
            return (
              <button
                key={g}
                type="button"
                onClick={() => toggleVerdict(g)}
                data-testid={`network-legend-${g}`}
                className={cn(
                  "flex items-center gap-2 rounded px-1.5 py-0.5 text-left transition-colors",
                  on ? "text-foreground" : "text-muted-foreground line-through opacity-60",
                  "hover:bg-accent",
                )}
                aria-pressed={on}
              >
                <span
                  aria-hidden
                  className="h-2 w-2 rounded-full"
                  style={{ background: STATE_COLOR[state] }}
                />
                <Icon className="h-3 w-3" style={{ color: STATE_COLOR[state] }} />
                <span>{VERDICT_LABEL[g]}</span>
              </button>
            );
          })}
          {/* Freshness legend — solid = recent observation, dashed = stale.
              Visible until the BPF agent's uploader writes into network_flows. */}
          <div className="mt-1 border-t border-border/60 pt-1 text-micro text-muted-foreground">
            <div className="flex items-center gap-1.5"><span aria-hidden className="h-px w-4 bg-muted-foreground" /> <span>fresh ≤ 5 min</span></div>
            <div className="flex items-center gap-1.5"><span aria-hidden className="h-px w-4 bg-muted-foreground/40" style={{ borderTop: "1px dashed currentColor", background: "transparent" }} /> <span>stale (~total)</span></div>
          </div>
          {/* Endpoint-kind visibility toggles. `unmanaged` (unresolved in-cluster
              IPs / infra noise) is hidden by default; click to show. */}
          <div className="mt-1 border-t border-border/60 pt-1">
            <div className="px-1 text-micro  text-muted-foreground">Endpoints</div>
            {NODE_KINDS.map((k) => {
              const on = !hiddenKinds.has(k);
              return (
                <button
                  key={k}
                  type="button"
                  onClick={() => toggleKind(k)}
                  data-testid={`network-kind-${k}`}
                  className={cn(
                    "flex w-full items-center gap-2 rounded px-1.5 py-0.5 text-left capitalize transition-colors hover:bg-accent",
                    on ? "text-foreground" : "text-muted-foreground line-through opacity-60",
                  )}
                  aria-pressed={on}
                >
                  {on ? <Eye className="h-3 w-3" aria-hidden /> : <EyeOff className="h-3 w-3" aria-hidden />}
                  <span>{k}</span>
                </button>
              );
            })}
          </div>
        </div>
        {/* Wave 6: recent DPI threats from dp. Pinned top-right below the
            legend. Only renders when we have at least one threat in the
            current window — keeps the canvas uncluttered when nothing's
            happening. Clicking a threat tries to pivot to the matching flow
            on the canvas. */}
        <ThreatsCard
          threats={threats}
          flows={flows}
          weakTLS={scopeReady&&!dpiSettingsQ.isError&&dpiSettingsQ.data?.cluster_id===clusterID?dpiSettingsQ.data.weak_tls_enabled:undefined}
          settingsUnavailable={dpiSettingsQ.isError}
          settingsLoading={dpiSettingsQ.isPending}
          settingsHref={scopeReady?`/clusters/${clusterID}/network/settings/dpi?${new URLSearchParams({back:routeParams.toString()})}`:undefined}
          onPivot={(flowID) => {
            selectFlow(flowID);
            setPopoverOpen(true);
          }}
        />
        </div>
        {/* Live sessions (NV RESTSession) — bottom-left collapsible card fed by the
            runtime-agent's dp ctrl_list_session snapshot. Sits above the netpol status bar. */}
        <div className="absolute bottom-14 left-3 z-10 space-y-2">
          <EnforcementCard clusterID={clusterID} />
          <LiveSessionsCard sessions={sessions} total={sessionsTotal} hasMore={sessionsHasMore} loading={sessionsQ.isPending}
            onKill={(id, node) => killSessionMut.mutate({ id, node, context: sessionContext, cluster: clusterID, key: sessionKey })} killing={killSessionMut.isPending} lastKill={lastSessionKill} />
        </div>
        {/* Selected-workload mini panel — bottom-right floating, only when a
            workload (not an edge) is selected. Edge selection opens the
            FlowInspectorPopover overlay instead. */}
        {selectedWorkload && (
          <div className="absolute bottom-3 right-3 z-10 max-w-[300px] rounded-md border border-border bg-card/95 p-3 shadow-[var(--elev-2)] backdrop-blur" data-testid="network-workload-panel">
            <WorkloadDrilldown
              workload={selectedWorkload}
              flows={flows}
              clusterID={clusterID}
              hours={hours}
              denyCapable={denyCapable}
              hidePlatform={hidePlatformComponents}
              onSelectFlow={(id) => { selectFlow(id); setPopoverOpen(true); }}
            />
            <div className="mt-2 flex items-center justify-between">
              {selectedWorkload.kind !== "External" && clusterID ? (
                <div className="flex items-center gap-1.5">
                  <button
                    type="button"
                    title="Cut this workload off the network with a default-deny NetworkPolicy (CNI-enforced)"
                    onClick={() => navigate({ href: networkActionHref(clusterID, "isolate", selectedWorkload.id) })}
                    className="inline-flex items-center gap-1 rounded border border-[color:var(--color-severity-critical)] px-2 py-0.5 text-micro font-medium text-[color:var(--color-severity-critical)] hover:bg-[color:color-mix(in_oklab,var(--color-severity-critical)_12%,transparent)] disabled:opacity-40"
                  >
                    <Lock className="h-3 w-3" /> Isolate
                  </button>
                  <button
                    type="button"
                    title="Add to the admission-webhook deny list (blocks re-admission / reschedule)"
                    onClick={() => navigate({ href: networkActionHref(clusterID, "quarantine", selectedWorkload.id) })}
                    className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-micro font-medium text-muted-foreground hover:bg-muted disabled:opacity-40"
                  >
                    <Ban className="h-3 w-3" /> Quarantine
                  </button>
                </div>
              ) : <span />}
              <button
                type="button"
                onClick={() => setSelectedWorkloadID(null)}
                className="text-micro text-muted-foreground hover:text-foreground"
              >
                close
              </button>
            </div>
          </div>
        )}
        {/* Policy-lifecycle bottom-left — collapsed chip by default; expands
            when clicked OR when a workload is selected. */}
        <CollapsiblePolicyLifecycle
          item={selectedLifecycle}
          items={lifecycleItems}
          available={lifecycleAvailable}
          loading={lifecycleQ.isPending}
          refreshing={lifecycleQ.isFetching}
          onRetry={()=>void lifecycleQ.refetch()}
          onSelect={(workload) => {
            setSelectedWorkloadID(workload);
            setSelectedFlowID(null);
          }}

        />
        </>
        )}
      </div>

      {/* Edge inspector popup — centered Dialog with tabs. Closing the
          dialog clears the underlying flow selection so the page returns
          to baseline (no panels open) — matches NeuVector's behaviour. */}
      <FlowInspectorPopover
        open={popoverOpen && !!selectedFlow}
        flow={selectedFlow}
        sourceFilters={{ namespace: namespace || undefined, group: effectiveGroupFilter || undefined, verdict: verdict || undefined, ...sharedTrafficFilters, hide_platform: hidePlatformComponents }}
        clusterID={clusterID}
        hours={hours}
        denyCapable={denyCapable}
        recentFlows={liveFlows}
        threats={threats}
        lifecycle={lifecycleItems}
        onOpenChange={(o) => {
          setPopoverOpen(o);
          if (!o) setSelectedFlowID(null);
        }}
        onStep={stepFlow}
      />
        </RadixTabs.Content>

        <RadixTabs.Content value="conversations" className="min-h-0 flex-1 overflow-auto outline-none" data-testid="network-workspace-panel-conversations">
          <div className="mb-3 space-y-2 rounded-md border border-border bg-card p-3" data-testid="network-conversation-filters">
            <p className="text-xs text-muted-foreground">Conversation filters match exact directed endpoints before server pagination. Other traffic filters above also apply.</p>
            <div className="flex flex-wrap items-end gap-3">
              <label className="text-xs">From<input aria-label="Conversation from" className="mt-1 block rounded border border-input bg-background p-2" value={conversationScope.from ?? ""} onChange={event => updateRoute({ from: event.target.value }, true, true)} /></label>
              <label className="text-xs">To<input aria-label="Conversation to" className="mt-1 block rounded border border-input bg-background p-2" value={conversationScope.to ?? ""} onChange={event => updateRoute({ to: event.target.value }, true, true)} /></label>
              <label className="text-xs">Outcome<Select aria-label="Conversation outcome" className="mt-1 block rounded border border-input bg-background p-2" value={conversationScope.verdict_group ?? ""} onChange={event => updateRoute({ verdict_group: event.target.value }, false, true)}><option value="">All outcomes</option><option value="blocked">Denied or blocked</option></Select></label>
              <Button onClick={() => updateRoute({ from: null, to: null, verdict_group: null }, false, true)}>Clear conversation filters</Button>
            </div>
          </div>
          {!conversationRouteValid ? <ErrorState title="Choose supported conversation sorting and page values." action={<Button onClick={() => changeSort("conversation")(null)}>Reset sorting and page</Button>} /> : !conversationsAvailable ? conversationsQ.isFetching ? <p role="status">Loading conversations…</p> : <ErrorState title="Conversations could not be loaded or refreshed." error={conversationsQ.error} action={<Button onClick={() => void conversationsQ.refetch()}>Retry conversations</Button>} /> : <NetworkConversationsWorkspaceTab
            conversations={conversations}
            total={conversationsQ.data!.total!}
            summary={conversationsQ.data!.summary!}
            sort={conversationSort} onSort={changeSort("conversation")}
            matchingExport={<ScanInventoryExport context={JSON.stringify(conversationKey)} disabled={!conversationsAvailable} download={shouldDownload => { exportReady(conversationKey); return network.conversationsCSV(conversationRequest, () => { if (!shouldDownload()) return false; exportReady(conversationKey); return true; }); }} />}
            page={conversationPage}
            onPage={setConversationPage}
            loading={conversationsQ.isPending}
            hours={hours}
            onSelect={(conversation) => updateRoute({ inspect_from: conversation.from, inspect_to: conversation.to, stream_page: null })}
          />}
          {routeParams.get("inspect_from") && routeParams.get("inspect_to") && <section className="mt-4 space-y-3 rounded-md border border-border bg-card p-4" data-testid="network-conversation-detail">
            <div className="flex flex-wrap items-start justify-between gap-2"><h2 className="break-all text-sm font-semibold">{routeParams.get("inspect_from")} → {routeParams.get("inspect_to")}</h2><Button onClick={() => updateRoute({ inspect_from: null, inspect_to: null })}>Close conversation</Button></div>
            <p className="text-xs text-muted-foreground">Matching retained streams for this filtered directed pair and time window.</p>
            <StreamsTab from={routeParams.get("inspect_from")!} to={routeParams.get("inspect_to")!} clusterID={clusterID} hours={hours} active sourceFilters={conversationRequest} />
          </section>}
        </RadixTabs.Content>

        <RadixTabs.Content value="sessions" className="min-h-0 flex-1 overflow-auto outline-none" data-testid="network-workspace-panel-sessions">
          {!sessionRouteValid ? <ErrorState title="Choose supported session sorting and page values." action={<Button onClick={() => changeSort("session")(null)}>Reset sorting and page</Button>} /> : !sessionsAvailable ? sessionsQ.isFetching ? <p role="status">Loading sessions…</p> : <ErrorState title="Sessions could not be loaded or refreshed for this scope." error={sessionsQ.error} action={<Button onClick={() => void sessionsQ.refetch()}>Retry sessions</Button>} /> : <NetworkSessionsWorkspaceTab
            sessions={sessions}
            summary={sessionsQ.data!.summary!}
            sort={sessionSort} onSort={changeSort("session")}
            matchingExport={<ScanInventoryExport context={JSON.stringify(sessionKey)} disabled={!sessionsAvailable} download={shouldDownload => { exportReady(sessionKey); return network.sessionsCSV(sessionRequest, () => { if (!shouldDownload()) return false; exportReady(sessionKey); return true; }); }} />}
            total={sessionsTotal}
            hasMore={sessionsHasMore}
            page={sessionPage}
            onPage={setSessionPage}
            filters={sessionFilters}
            loading={sessionsQ.isPending}
            killing={killSessionMut.isPending}
            lastKill={lastSessionKill}
            onFiltersChange={setSessionFilters}
            onKill={(id, node) => killSessionMut.mutate({ id, node, context: sessionContext, cluster: clusterID, key: sessionKey })}
          />}
        </RadixTabs.Content>

        <RadixTabs.Content value="pcap" className="min-h-0 flex-1 overflow-auto outline-none" data-testid="network-workspace-panel-pcap">
          <PcapWorkspaceTab
            autoRefresh={live}
            clusterID={clusterID}
            groupFilter={effectiveGroupFilter}
            filters={pcapFilters}
            snapshot={savedViewSnapshot}
            onFiltersChange={setPcapFilters}
          />
        </RadixTabs.Content>

        <RadixTabs.Content value="rules" className="min-h-0 flex-1 overflow-auto outline-none" data-testid="network-workspace-panel-rules">
          <NetworkRulesWorkspaceTab
            items={lifecycleItems}
            selectedWorkload={selectedWorkloadID}
            onSelect={setSelectedWorkloadID}
            available={lifecycleAvailable}
            loading={lifecycleQ.isPending}
            refreshing={lifecycleQ.isFetching}
            onRetry={()=>void lifecycleQ.refetch()}
          />
        </RadixTabs.Content>

        <RadixTabs.Content value="threats" className="min-h-0 flex-1 overflow-auto outline-none" data-testid="network-workspace-panel-threats">
          {!threatRouteValid ? <ErrorState title="Choose supported threat sorting and page values." action={<Button onClick={() => changeSort("threat")(null)}>Reset sorting and page</Button>} /> : !threatsAvailable ? threatsQ.isFetching ? <p role="status">Loading threat evidence…</p> : <ErrorState title="Threat evidence could not be loaded or refreshed for the selected cluster." error={threatsQ.error} action={<Button onClick={() => void threatsQ.refetch()}>Retry threats</Button>} /> : <NetworkThreatsWorkspaceTab
            threats={threats}
            total={threatsQ.data!.total}
            summary={threatsQ.data!.summary!}
            sort={threatSort} onSort={changeSort("threat")}
            matchingExport={<ScanInventoryExport context={JSON.stringify(threatKey)} disabled={!threatsAvailable} download={shouldDownload => { exportReady(threatKey); return runtimeThreats.exportCSV(threatRequest, () => { if (!shouldDownload()) return false; exportReady(threatKey); return true; }); }} />}
            page={threatPage}
            onPage={setThreatPage}
            weakTLS={scopeReady&&!dpiSettingsQ.isError&&dpiSettingsQ.data?.cluster_id===clusterID?dpiSettingsQ.data.weak_tls_enabled:undefined}
            settingsUnavailable={dpiSettingsQ.isError}
            settingsLoading={dpiSettingsQ.isPending}
            settingsHref={scopeReady?`/clusters/${clusterID}/network/settings/dpi?${new URLSearchParams({back:routeParams.toString()})}`:undefined}
            onPivot={(threat) => {
              const flow = flows.find(
                (f) =>
                  f.dst_port === threat.dst_port &&
                  f.protocol.toLowerCase() === ipProtoName(threat.ip_proto).toLowerCase() &&
                  (f.threat_id ?? 0) === threat.threat_id,
              );
              if (flow) {
                setWorkspaceTab("map");
                selectFlow(flow.id);
                setPopoverOpen(true);
              }
            }}
          />}
        </RadixTabs.Content>
      </RadixTabs.Root>
    </div>
    </NetworkViewContext.Provider>
  );
}

function NetworkConversationsWorkspaceTab({
  conversations, summary, sort, onSort, matchingExport,
  total,
  page,
  onPage,
  loading,
  hours,
  onSelect,
}: {
  conversations: NetworkConversation[];
  summary: Record<string, number>; sort: TableSort; onSort: (sort: TableSort | null) => void; matchingExport: ReactNode;
  total: number;
  page: number;
  onPage: (page: number) => void;
  loading: boolean;
  hours: number;
  onSelect: (conversation: NetworkConversation) => void;
}) {
  const rows = conversations;
  const totals = summary;
  const columns = useMemo<Column<NetworkConversation>[]>(() => [
    { id: "severity", header: "Severity", kind: "count", sort: () => 0, cell: row => row.severity ?? 0 },
    { id: "from", header: "From", kind: "name", wrap: true, code: true, minSize: 192, cell: (row) => <span className="font-mono">{row.from}</span>, exportValue: (row) => row.from, sort: (a, b) => a.from.localeCompare(b.from) },
    { id: "from_platform_role", header: "From role", kind: "text", wrap: true, size: 144, minSize: 120, maxSize: 184, exportHeader: "from_platform_role", cell: (row) => row.from_platform_role ?? "", exportValue: (row) => row.from_platform_role ?? "" },
    { id: "to", header: "To", kind: "text", code: true, wrap: true, size: 224, minSize: 192, maxSize: 320, cell: (row) => <span className="font-mono">{row.to}</span>, exportValue: (row) => row.to, sort: (a, b) => a.to.localeCompare(b.to) },
    { id: "to_platform_role", header: "To role", kind: "text", wrap: true, size: 144, minSize: 120, maxSize: 184, exportHeader: "to_platform_role", cell: (row) => row.to_platform_role ?? "", exportValue: (row) => row.to_platform_role ?? "" },
    { id: "apps", exportValue: row => JSON.stringify(row.apps ?? []), header: "Apps", kind: "text", wrap: true, size: 176, minSize: 144, maxSize: 240, cell: (row) => <span className="text-muted-foreground">{(row.apps ?? []).slice(0, 4).join(", ") || "-"}</span>, sort: (a, b) => (a.apps ?? []).join(",").localeCompare((b.apps ?? []).join(",")) },
    { id: "bytes", exportValue: row => row.bytes, header: "Volume", kind: "bytes", size: 128, minSize: 112, maxSize: 160, cell: (row) => <span className="font-mono">{formatBytes(row.bytes)}</span>, sort: (a, b) => a.bytes - b.bytes, numeric: true },
    { id: "packets", exportValue: row => row.packets, header: "Packets", kind: "count", cell: (row) => <span className="font-mono">{row.packets.toLocaleString()}</span>, sort: (a, b) => a.packets - b.packets, numeric: true },
    { id: "edges", exportValue: row => row.edges, header: "Streams", kind: "count", cell: (row) => <span className="font-mono">{row.edges.toLocaleString()}</span>, sort: (a, b) => a.edges - b.edges, numeric: true },
    { id: "verdict", exportValue: row => row.verdict ?? "", header: "Verdict", kind: "status", cell: (row) => <span className={cn("rounded px-1.5 py-0.5 text-micro ", ["deny", "denied", "block", "blocked"].includes(row.verdict ?? "") ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]" : "bg-muted text-muted-foreground")}>{row.verdict || "allow"}</span>, sort: (a, b) => (a.verdict ?? "allow").localeCompare(b.verdict ?? "allow") },
    { id: "last_seen", exportValue: row => row.last_seen, header: "Last seen", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (row) => <button type="button" className="text-left text-muted-foreground hover:text-foreground" onClick={() => onSelect(row)} data-testid="network-conversation-open">{formatDateTime(row.last_seen)}</button>, sort: (a, b) => Date.parse(a.last_seen) - Date.parse(b.last_seen) },
  ], [onSelect]);
  return (
    <section className="space-y-3" data-testid="network-conversations-tab">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-card px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatPill icon={<Table2 className="h-3 w-3" />} label="pairs" value={total} />
          <StatPill icon={<Activity className="h-3 w-3" />} label="streams" value={totals.edges} />
          <StatPill icon={<Activity className="h-3 w-3" />} label="volume" value={formatBytes(totals.bytes)} />
          <StatPill icon={<Ban className="h-3 w-3" />} label="blocked" value={totals.blocked} tone={totals.blocked > 0 ? "critical" : "neutral"} />
        </div>
        {matchingExport}
      </div>
      <DataTable rows={loading ? [] : rows} columns={columns} onRowClick={onSelect} rowKey={(row) => row.row_id!} manualSorting sort={sort} onSortChange={onSort} pagination={false} preferencesKey="network-conversations" defaultHiddenColumnIds={["severity"]} exportFileName={`network-conversations-${hours}h-page`} exportLabel="Export this page CSV" testId="network-conversations-table" emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">{loading ? "Loading conversations..." : "No conversations in this window."}</div>} />
      <p className="text-xs text-muted-foreground">Metrics cover all matching conversations.</p>
      {!rows.length && page > 0 && <Button onClick={() => onPage(0)}>First page</Button>}
      <Pager page={page} pageSize={100} total={total} rowsOnPage={rows.length} onPage={onPage} />
    </section>
  );
}

function NetworkSessionsWorkspaceTab({
  sessions, summary, sort, onSort, matchingExport,
  total,
  hasMore,
  page,
  onPage,
  filters,
  loading,
  killing,
  lastKill,
  onFiltersChange,
  onKill,
}: {
  sessions: NetworkSession[];
  summary: Record<string, number>; sort: TableSort; onSort: (sort: TableSort | null) => void; matchingExport: ReactNode;
  total: number;
  hasMore: boolean;
  page: number;
  onPage: (page: number) => void;
  filters: NetworkSessionSavedFilters;
  loading: boolean;
  killing: boolean;
  lastKill: NetworkSessionKillResponse | null;
  onFiltersChange: (filters: NetworkSessionSavedFilters) => void;
  onKill: (id: number, node: string) => void;
}) {
  const rows = sessions;
  const totals = { inBytes: summary.client_bytes, outBytes: summary.server_bytes, threats: summary.threats };
  const hasFilters = Object.values(filters).some(Boolean);
  const visibleRows = rows;
  const updateFilter = (key: keyof NetworkSessionSavedFilters, value: string) => {
    onFiltersChange({ ...filters, [key]: value });
  };
  return (
    <section className="space-y-3" data-testid="network-sessions-tab">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-card px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatPill icon={<Activity className="h-3 w-3" />} label="sessions" value={total} />
          <StatPill icon={<Activity className="h-3 w-3" />} label="client" value={formatBytes(totals.inBytes)} />
          <StatPill icon={<Activity className="h-3 w-3" />} label="server" value={formatBytes(totals.outBytes)} />
          <StatPill icon={<ShieldAlert className="h-3 w-3" />} label="threats" value={totals.threats} tone={totals.threats > 0 ? "critical" : "neutral"} />
        </div>
        {matchingExport}
      </div>
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-border bg-card px-3 py-2" data-testid="network-session-filters">
        <Filter className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
        <Select
          className="h-7 rounded border border-input bg-card px-2 text-micro text-mono outline-none focus:border-[color:var(--color-primary)]"
          value={filters.protocol}
          onChange={(event) => updateFilter("protocol", event.target.value)}
          aria-label="Session protocol"
          data-testid="network-session-filter-protocol"
        >
          <option value="">Protocol</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
          <option value="icmpv6">ICMPv6</option>
        </Select>
        <input
          className="h-7 w-24 rounded border border-input bg-card px-2 text-micro outline-none placeholder:text-muted-foreground focus:border-[color:var(--color-primary)]"
          value={filters.application}
          onChange={(event) => updateFilter("application", event.target.value)}
          placeholder="App"
          aria-label="Session application"
          data-testid="network-session-filter-application"
        />
        <input
          className="h-7 w-20 rounded border border-input bg-card px-2 text-micro text-mono outline-none placeholder:text-muted-foreground focus:border-[color:var(--color-primary)]"
          value={filters.port}
          onChange={(event) => updateFilter("port", event.target.value.replace(/[^\d]/g, "").slice(0, 5))}
          inputMode="numeric"
          placeholder="Port"
          aria-label="Session port"
          data-testid="network-session-filter-port"
        />
        <input
          className="h-7 w-36 rounded border border-input bg-card px-2 text-micro text-mono outline-none placeholder:text-muted-foreground focus:border-[color:var(--color-primary)]"
          value={filters.peer}
          onChange={(event) => updateFilter("peer", event.target.value)}
          placeholder="Peer IP"
          aria-label="Session peer"
          data-testid="network-session-filter-peer"
        />
        <input
          className="h-7 w-44 rounded border border-input bg-card px-2 text-micro text-mono outline-none placeholder:text-muted-foreground focus:border-[color:var(--color-primary)]"
          value={filters.workload}
          onChange={(event) => updateFilter("workload", event.target.value)}
          placeholder="Workload"
          aria-label="Session workload"
          data-testid="network-session-filter-workload"
        />
        <input
          className="h-7 w-28 rounded border border-input bg-card px-2 text-micro text-mono outline-none placeholder:text-muted-foreground focus:border-[color:var(--color-primary)]"
          value={filters.node}
          onChange={(event) => updateFilter("node", event.target.value)}
          placeholder="Node"
          aria-label="Session node"
          data-testid="network-session-filter-node"
        />
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={!hasFilters}
          onClick={() => onFiltersChange({ ...EMPTY_SESSION_FILTERS })}
          data-testid="network-session-filters-clear"
        >
          <X className="h-3.5 w-3.5" aria-hidden />
          Clear
        </Button>
      </div>
      {(hasMore || page > 0) && (
        <div className="text-xs text-muted-foreground" data-testid="network-sessions-truncated">
          Page {page + 1} of {Math.ceil(total / 100)} · Totals cover all matching live sessions.
        </div>
      )}
      {lastKill && (
        <div
          className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-[color:var(--color-status-success)]/40 bg-[color-mix(in_oklab,var(--color-status-success)_10%,transparent)] px-3 py-2 text-xs"
          data-testid="network-session-kill-result"
        >
          <div className="min-w-0">
            <div className="flex items-center gap-1.5 font-medium text-foreground">
              <CircleCheck className="h-3.5 w-3.5 text-[color:var(--color-status-success)]" aria-hidden />
              <span>Kill queued for session {lastKill.session_id}</span>
            </div>
            <div className="mt-0.5 truncate text-micro text-muted-foreground">
              {sessionKillTargetLabel(lastKill)} on {lastKill.node || "unknown node"} at {formatKillRequestedAt(lastKill.requested_at)}
              {lastKill.expires_at && <> · Delivery expires {formatKillRequestedAt(lastKill.expires_at)}</>}
            </div>
          </div>
          {lastKill.audit_id ? (
            <span className="rounded border border-border bg-card px-2 py-0.5 text-micro text-mono text-muted-foreground" data-testid="network-session-kill-audit">
              audit #{lastKill.audit_id}
            </span>
          ) : null}
        </div>
      )}
      <div className="overflow-hidden rounded-md border border-border bg-card">
        <DataTable<NetworkSession>
          testId="network-sessions-table"
          className="rounded-none border-0"
          rows={loading ? [] : visibleRows}
          rowKey={(row) => row.row_id!}
          pagination={false} manualSorting sort={sort} onSortChange={onSort}
          preferencesKey="network-sessions" exportFileName="network-sessions-page" exportLabel="Export this page CSV"
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">{loading ? "Loading sessions..." : "No live sessions reported."}</div>}
          defaultHiddenColumnIds={["bytes", "packets", "idle", "severity", "observed", "node", "protocol"]}
          columns={[
            { id: "bytes", header: "Total bytes", kind: "bytes", sort: () => 0, cell: row => fmtBytes(row.client_bytes + row.server_bytes), exportValue: row => row.client_bytes + row.server_bytes },
            { id: "packets", header: "Packets", kind: "count", sort: () => 0, cell: row => row.client_pkts + row.server_pkts },
            { id: "idle", header: "Idle", kind: "age", sort: () => 0, cell: row => row.idle },
            { id: "severity", header: "Severity", kind: "count", sort: () => 0, cell: row => row.severity },
            { id: "observed", header: "Observed", kind: "date", sort: () => 0, cell: row => formatDateTime(row.updated_at ?? ""), exportValue: row => row.updated_at },
            { id: "node", header: "Node", kind: "name", sort: () => 0, cell: row => row.node },
            { id: "protocol", header: "Protocol", kind: "text", sort: () => 0, cell: row => row.ip_proto },
            { id: "platform_role", header: "Platform role", kind: "text", cell: row => row.platform_role || "Not classified", exportValue: row => row.platform_role },
            { id: "client", sort: () => 0, header: "Client", kind: "id", size: 180, cell: (row) => `${row.client_ip}:${row.client_port}` },
            { id: "server", sort: () => 0, header: "Server", kind: "id", size: 180, cell: (row) => `${row.server_ip}:${row.server_port}` },
            { id: "workload", sort: () => 0, header: "Workload", kind: "name", code: true, cell: (row) => row.workload_id || "-" },
            { id: "application", sort: () => 0, header: "App", kind: "text", size: 120, cell: (row) => row.application || row.ip_proto },
            { id: "state", sort: () => 0, header: "State", kind: "status", cell: (row) => <>{row.client_state || row.server_state || row.ip_proto}{row.threat_id ? <span className="ml-1 text-[color:var(--color-status-error)]" title={`threat ${row.threat_id}`}>!</span> : null}</> },
            { id: "client_bytes", exportValue: row => row.client_bytes, sort: () => 0, header: "Client bytes", kind: "bytes", cell: (row) => formatBytes(row.client_bytes) },
            { id: "server_bytes", exportValue: row => row.server_bytes, sort: () => 0, header: "Server bytes", kind: "bytes", cell: (row) => formatBytes(row.server_bytes) },
            { id: "age", exportValue: row => row.age, sort: () => 0, header: "Age", kind: "age", numeric: true, cell: (row) => `${row.age}s` },
            { id: "actions", header: "", kind: "actions", size: 48, minSize: 48, maxSize: 48, cell: (row) => <Button size="icon" variant="ghost" disabled={killing} onClick={() => { if (window.confirm(`Terminate session ${row.id} on ${row.node}?`)) onKill(row.id, row.node); }} title="Kill session" data-testid="network-session-kill"><X className="h-3.5 w-3.5" aria-hidden /></Button> },
          ]}
        />
      </div>
      {!rows.length && page > 0 && <Button onClick={() => onPage(0)}>First page</Button>}
      <Pager page={page} pageSize={100} total={total} rowsOnPage={visibleRows.length} onPage={onPage} />
    </section>
  );
}

function sessionKillTargetLabel(kill: NetworkSessionKillResponse) {
  const target = kill.target;
  if (!target) return "Queued for agent pickup";
  const client = [target.client_ip, target.client_port ? `:${target.client_port}` : ""].filter(Boolean).join("");
  const server = [target.server_ip, target.server_port ? `:${target.server_port}` : ""].filter(Boolean).join("");
  const proto = target.application || target.ip_proto || "session";
  const workload = target.workload_id ? `${target.workload_id} ` : "";
  return `${workload}${proto} ${client || "client"} -> ${server || "server"}`;
}

function formatKillRequestedAt(value?: string) {
  if (!value) return "queued";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "queued";
  return d.toLocaleTimeString();
}

export function NetworkRulesWorkspaceTab({
  items,
  selectedWorkload,
  onSelect,
  available,
  loading,
  refreshing,
  onRetry,
}: {
  items: NetworkPolicyLifecycle[];
  selectedWorkload: string | null;
  onSelect: (value: string) => void;
  available: boolean;
  loading: boolean;
  refreshing: boolean;
  onRetry: () => void;
}) {
  const selected = selectedWorkload
    ? (items.find((item) => item.workload === selectedWorkload) ?? null)
    : null;
  const columns: Column<NetworkPolicyLifecycle>[] = [
    {
      id: "workload",
      header: "Workload",
      kind: "name",
      cell: (r) => (
        <button
          type="button"
          onClick={() => onSelect(r.workload)}
          className="text-primary hover:underline"
        >
          {r.workload}
        </button>
      ),
      exportValue: (r) => r.workload,
    },
    {
      id: "platform_role",
      header: "Platform role",
      kind: "text",
      exportHeader: "platform_role",
      cell: (r) => r.platform_role || "Not classified",
      exportValue: (r) => r.platform_role ?? "",
    },
    {
      id: "mode",
      header: "Configured mode",
      kind: "status",
      cell: (r) => <ModeBadge mode={r.current_mode} />,
      exportValue: (r) => r.current_mode,
    },
    {
      id: "approval",
      header: "Approval",
      kind: "status",
      cell: (r) => r.approval_status,
      exportValue: (r) => r.approval_status,
    },
    {
      id: "flows",
      header: "Observed flow rows",
      kind: "count",
      cell: (r) => r.summary.total_flows,
      exportValue: (r) => r.summary.total_flows,
    },
    {
      id: "peers",
      header: "Observed peers",
      kind: "count",
      cell: (r) => r.summary.unique_peers,
      exportValue: (r) => r.summary.unique_peers,
    },
  ];
  return (
    <section className="space-y-5" data-testid="network-rules-tab">
      <p className="text-sm text-muted-foreground">
        Policy candidates use seven days of retained flow evidence. Namespace
        and group restrict workloads; map hours and verdict filters do not
        change the policy source.
      </p>
      {!available ? (
        loading ? (
          <p role="status">Loading lifecycle evidence…</p>
        ) : (
          <ErrorState
            title="Could not load current lifecycle evidence for this cluster."
            action={<Button onClick={onRetry}>Retry</Button>}
          />
        )
      ) : (
        <>
          {refreshing && (
            <p role="status" className="text-sm text-muted-foreground">
              Refreshing policy evidence… Actions are paused.
            </p>
          )}
          <DataTable
            rows={items}
            columns={columns}
            rowKey={(r) => `${r.cluster_id}/${r.workload}`}
            rowTestId={() => "network-rules-workload-row"}
            testId="network-lifecycle-table"
            preferencesKey="network-policy-lifecycle"
            exportFileName="network-lifecycle.csv"
            exportLabel="Export returned policy evidence"
            emptyState={
              <p>
                No policy candidates returned for the current source window and
                filters.
              </p>
            }
          />
          {selectedWorkload && !selected && (
            <ErrorState title="The selected workload policy is unavailable in the current result. Select another policy explicitly." />
          )}
          <PolicyLifecyclePanel
            item={selected}
            items={items}
            onSelect={onSelect}
            available={available}
            loading={loading}
            refreshing={refreshing}
            onRetry={onRetry}
          />
        </>
      )}
    </section>
  );
}

export function NetworkThreatsWorkspaceTab({
  threats, summary, sort, onSort, matchingExport,
  total,
  page,
  onPage,
  weakTLS,
  settingsUnavailable,
  settingsLoading,
  settingsHref,
  onPivot,
}: {
  threats: RuntimeThreat[];
  summary?: Record<string, number>; sort?: TableSort; onSort?: (sort: TableSort | null) => void; matchingExport?: ReactNode;
  total: number;
  page: number;
  onPage: (page: number) => void;
  weakTLS: boolean|undefined;
  settingsUnavailable:boolean;
  settingsLoading:boolean;
  settingsHref:string|undefined;
  onPivot: (threat: RuntimeThreat) => void;
}) {
  const [drilldownID, setDrilldownID] = useState<string | null>(null);
  const rows = threats;
  const critical = summary?.critical ?? 0;
  const blocked = summary?.blocked ?? 0;
  const visibleThreats = rows;
  return (
    <section className="space-y-3" data-testid="network-threats-tab">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border bg-card px-3 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <StatPill icon={<ShieldAlert className="h-3 w-3" />} label="threats" value={total} tone={total > 0 ? "critical" : "neutral"} />
          <StatPill icon={<TriangleAlert className="h-3 w-3" />} label="critical" value={critical} tone={critical > 0 ? "critical" : "neutral"} />
          <StatPill icon={<Ban className="h-3 w-3" />} label="blocked" value={blocked} tone={blocked > 0 ? "critical" : "neutral"} />
        </div>
        <WeakTLSStatus configured={weakTLS} unavailable={settingsUnavailable} loading={settingsLoading} href={settingsHref} testId="network-threats-weak-tls"/>
      </div>
      {matchingExport}
      <div className="overflow-hidden rounded-md border border-border bg-card">
        <DataTable<RuntimeThreat>
          testId="network-threats-table"
          className="rounded-none border-0"
          rows={visibleThreats}
          rowKey={(row) => row.id}
          pagination={false} manualSorting sort={sort} onSortChange={onSort}
          preferencesKey="network-threats"
          exportFileName="network-loaded-threat-page"
          exportLabel="Export this page CSV"
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No DPI threats in this window.</div>}
          defaultHiddenColumnIds={["at", "node", "signature"]}
          columns={[
            { id: "at", header: "Observed", kind: "date", sort: () => 0, cell: row => formatDateTime(row.at), exportValue: row => row.at },
            { id: "node", header: "Node", kind: "name", sort: () => 0, cell: row => row.node || "Not reported" },
            { id: "signature", header: "Signature ID", kind: "count", sort: () => 0, cell: row => row.threat_id },
            { id: "threat", header: "Threat", kind: "name", exportValue: (row) => row.threat_name || row.msg || `signature ${row.threat_id}`, cell: (row) => <><button type="button" className="block max-w-full truncate text-left font-medium hover:text-[color:var(--color-primary)]" onClick={() => setDrilldownID(row.id)} data-testid="network-threats-open" title={row.threat_name || row.msg || `signature ${row.threat_id}`}>{row.threat_name || row.msg || `signature ${row.threat_id}`}</button>{row.msg && <div className="truncate text-xs text-muted-foreground" title={row.msg}>{row.msg}</div>}</> },
            { id: "workload", sort: () => 0, header: "Workload", kind: "name", code: true, cell: (row) => row.workload_id || row.namespace || "Not reported", exportValue: (row) => row.workload_id ?? "" },
            { id: "platform_role", header: "Platform role", kind: "text", exportHeader: "platform_role", cell: (row) => row.platform_role || "Not classified", exportValue: (row) => row.platform_role ?? "" },
            { id: "category", sort: () => 0, header: "Category", kind: "text", size: 140, cell: (row) => threatCategoryLabel(row.threat_id) },
            { id: "flow", header: "Flow", kind: "id", size: 260, maxSize: 360, cell: (row) => `${row.src_ip}:${row.src_port} -> ${row.dst_ip}:${row.dst_port}` },
            { id: "severity", sort: () => 0, header: "Severity", kind: "status", cell: (row) => severityLabel(row.severity) },
            { id: "action", sort: () => 0, header: "Action", kind: "status", cell: (row) => threatActionLabel(row.action) },
            { id: "reported", exportValue: row => row.reported_at, sort: () => 0, header: "Reported", kind: "date", cell: (row) => formatDateTime(row.reported_at || row.at) },
            { id: "actions", header: "", kind: "actions", exportable: false, cell: (row) => <Button size="sm" variant="outline" onClick={() => onPivot(row)} data-testid="network-threats-pivot">Pivot</Button> },
          ]}
        />
      </div>
      <p className="text-xs text-muted-foreground">Metrics cover all matching threats.</p>
      {!rows.length && page > 0 && <Button onClick={() => onPage(0)}>First page</Button>}
      <Pager page={page} pageSize={100} total={total} rowsOnPage={visibleThreats.length} onPage={onPage} />
      {drilldownID && <ThreatDrilldownDialog id={drilldownID} onClose={() => setDrilldownID(null)} />}
    </section>
  );
}

// ───── Helper: classify a flow into one of the three verdict chips. ─────
function verdictGroupFromState(state: NetworkFlowState, verdict: string): VerdictGroup | null {
  if (state === "ok") return "allow";
  if (state === "warn") return "alert";
  if (state === "denied") return "block";
  const v = verdict.toLowerCase();
  if (v === "allow") return "allow";
  if (v === "alert") return "alert";
  if (v === "block" || v === "deny") return "block";
  return null;
}

// Reusable filter chip — kept small to match the FilterChip ui component, but
// the existing FilterChip has slightly different semantics (removable).
function Chip({
  active,
  onClick,
  children,
  tone,
  ...rest
}: {
  active?: boolean;
  onClick?: () => void;
  children: React.ReactNode;
  tone?: VerdictGroup;
  "data-testid"?: string;
}) {
  const toneColor = tone ? STATE_COLOR[VERDICT_TO_STATE[tone]] : undefined;
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "inline-flex h-6 items-center gap-1 rounded border px-2 text-micro text-mono whitespace-nowrap transition-colors",
        active
          ? "border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] text-[color:var(--color-primary)]"
          : "border-border bg-card text-muted-foreground hover:bg-accent",
      )}
      data-testid={rest["data-testid"]}
      aria-pressed={active}
    >
      {tone && (
        <span aria-hidden className="h-1.5 w-1.5 rounded-full" style={{ background: toneColor }} />
      )}
      {children}
    </button>
  );
}

function NamespaceMultiSelect({
  namespaces,
  selected,
  onToggle,
  onClear,
}: {
  namespaces: string[];
  selected: Set<string>;
  onToggle: (ns: string) => void;
  onClear: () => void;
}) {
  const [open, setOpen] = useState(false);
  const label = selected.size === 0 ? "All" : selected.size === 1 ? Array.from(selected)[0] : `${selected.size} selected`;
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "inline-flex h-6 items-center gap-1 rounded border px-2 text-micro text-mono whitespace-nowrap transition-colors",
          selected.size > 0
            ? "border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] text-[color:var(--color-primary)]"
            : "border-border bg-card text-muted-foreground hover:bg-accent",
        )}
        data-testid="netchip-namespace"
      >
        {label}
        <ChevronDown className="h-3 w-3" />
      </button>
      {open && (
        <div
          className="absolute left-0 top-7 z-20 max-h-72 w-56 overflow-auto rounded-md border border-border bg-card p-1 shadow-[var(--elev-2)]"
          data-testid="netchip-namespace-menu"
        >
          <button
            type="button"
            className="block w-full rounded px-2 py-1 text-left text-micro text-muted-foreground hover:bg-accent"
            onClick={() => { onClear(); }}
          >
            Clear
          </button>
          {namespaces.map((ns) => {
            const on = selected.has(ns);
            return (
              <button
                key={ns}
                type="button"
                onClick={() => onToggle(ns)}
                className={cn(
                  "block w-full rounded px-2 py-1 text-left text-micro transition-colors",
                  on ? "bg-accent text-foreground" : "text-muted-foreground hover:bg-accent/60",
                )}
                aria-pressed={on}
              >
                {on ? "● " : "○ "} {ns}
              </button>
            );
          })}
          {namespaces.length === 0 && <div className="px-2 py-2 text-micro text-muted-foreground">No namespaces in window</div>}
        </div>
      )}
    </div>
  );
}

// The canvas needs to live below the ReactFlowProvider AND have access to
// useReactFlow() to call fitBounds, so it's split into its own child.
function CanvasInner({
  nodes,
  edges,
  onNodesChange,
  onEdgesChange,
  onSelectFlow,
  onSelectWorkload,
}: {
  nodes: Node[];
  edges: Edge[];
  onNodesChange: Parameters<typeof ReactFlow>[0]["onNodesChange"];
  onEdgesChange: Parameters<typeof ReactFlow>[0]["onEdgesChange"];
  onSelectFlow: (id: string) => void;
  onSelectWorkload: (id: string) => void;
}) {
  const rf = useReactFlow();
  const handleEdgeClick = useCallback(
    (_: React.MouseEvent, edge: Edge) => {
      onSelectFlow(edge.id);
      // Smooth zoom-to-conversation: fit a bounding box around src + dst nodes.
      const src = rf.getNode(edge.source);
      const dst = rf.getNode(edge.target);
      if (src && dst) {
        // Use the auto-layout positions (and assume the standard ~220 node
        // width / ~70 height) to size the bounds box.
        const NW = 240;
        const NH = 80;
        const x = Math.min(src.position.x, dst.position.x) - 60;
        const y = Math.min(src.position.y, dst.position.y) - 60;
        const x2 = Math.max(src.position.x, dst.position.x) + NW + 60;
        const y2 = Math.max(src.position.y, dst.position.y) + NH + 60;
        rf.fitBounds(
          { x, y, width: x2 - x, height: y2 - y },
          { padding: 0.2, duration: 200 },
        );
      }
    },
    [rf, onSelectFlow],
  );
  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      fitView
      // Tighter padding so the initial fitView zooms IN closer; nodes are big
      // enough now that breathing room above 0.1 padding is unnecessary.
      fitViewOptions={{ padding: 0.1, minZoom: 0.5, maxZoom: 1.0 }}
      minZoom={0.2}
      maxZoom={2.5}
      proOptions={{ hideAttribution: true }}
      nodesDraggable
      nodesConnectable={false}
      onNodeClick={(_, node) => onSelectWorkload(node.id)}
      onEdgeClick={handleEdgeClick}
    >
      <Background gap={16} size={1} color="var(--color-border)" />
      {/* Themed react-flow controls. Default position (bottom-left) was
          getting buried under the lifecycle chip; the version of react-flow
          we ship doesn't accept the `position` prop reliably so we override
          position in CSS via .constellation-rf-controls instead. */}
      <Controls showInteractive={false} className="constellation-rf-controls" />
    </ReactFlow>
  );
}

// ───── Flow inspector popover (edge-click target). ─────
function FlowInspectorPopover({
  open,
  flow,
  clusterID,
  hours,
  denyCapable,
  sourceFilters,
  recentFlows,
  threats,
  lifecycle,
  onOpenChange,
  onStep,
}: {
  open: boolean;
  flow: NetworkFlow | null;
  clusterID: string;
  hours: number;
  denyCapable: boolean;
  sourceFilters: NetworkConversationFilters;
  recentFlows: NetworkRecentFlow[];
  threats: RuntimeThreat[];
  lifecycle: NetworkPolicyLifecycle[];
  onOpenChange: (open: boolean) => void;
  onStep: (delta: number) => void;
}) {
  const navigate = useNavigate();
  const [tab, setTab] = useState("flow");

  // History sparkline: bin observed samples for this flow_id into 12 buckets.
  const sparkData = useMemo(() => {
    if (!flow) return [] as number[];
    const samples = recentFlows.filter((r) => r.flow_id === flow.id);
    if (samples.length === 0) return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    const sortedSamples = [...samples].sort((a, b) => new Date(a.observed_at).getTime() - new Date(b.observed_at).getTime());
    const buckets = new Array(12).fill(0);
    const first = new Date(sortedSamples[0].observed_at).getTime();
    const last = new Date(sortedSamples[sortedSamples.length - 1].observed_at).getTime();
    const span = Math.max(1, last - first);
    sortedSamples.forEach((s) => {
      const t = new Date(s.observed_at).getTime();
      const idx = Math.min(11, Math.floor(((t - first) / span) * 12));
      buckets[idx] += s.bytes;
    });
    return buckets;
  }, [flow, recentFlows]);

  if (!flow) return null;
  const verdictColor = STATE_COLOR[flow.state];
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-background/30 backdrop-blur-[1px] data-[state=open]:animate-in data-[state=open]:fade-in-0"
          data-testid="network-inspector-overlay"
        />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 flex h-[520px] w-[480px] -translate-x-1/2 -translate-y-1/2 flex-col rounded-lg border border-border bg-card shadow-[var(--elev-3)] focus:outline-none"
          data-testid="network-flow-inspector"
          aria-describedby={undefined}
        >
          {/* Severity bar (verdict color) */}
          <div className="h-1 w-full rounded-t-lg" style={{ background: verdictColor }} aria-hidden />
          <header className="flex items-start justify-between gap-2 border-b border-border px-4 py-3">
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-display text-sm font-semibold tracking-tight" data-testid="network-flow-inspector-title">
                <span className="break-all text-mono">{shortName(flow.src)}</span>
                <span className="mx-1.5 text-muted-foreground">→</span>
                <span className="break-all text-mono">{shortName(flow.dst)}</span>
              </Dialog.Title>
              <div className="mt-0.5 flex items-center gap-2 text-micro text-muted-foreground">
                <span style={{ color: verdictColor }}>● {flow.verdict}</span>
                <span>·</span>
                <span>{formatProtocol(flow)}</span>
                <span>·</span>
                <span>{formatBytes(flow.bytes)}</span>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => onStep(-1)}
                className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                aria-label="Previous flow"
                data-testid="network-flow-inspector-prev"
              >
                <ChevronUp className="h-4 w-4" />
              </button>
              <button
                type="button"
                onClick={() => onStep(1)}
                className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                aria-label="Next flow"
                data-testid="network-flow-inspector-next"
              >
                <ChevronDown className="h-4 w-4" />
              </button>
              <Dialog.Close
                aria-label="Close inspector"
                className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                data-testid="network-flow-inspector-close"
              >
                <X className="h-4 w-4" />
              </Dialog.Close>
            </div>
          </header>
          <RadixTabs.Root value={tab} onValueChange={setTab} className="flex flex-1 flex-col overflow-hidden">
            <RadixTabs.List className="flex border-b border-border px-2" data-testid="network-flow-inspector-tabs">
              {[
                { v: "flow", l: "Flow" },
                { v: "peers", l: "Peer IPs" },
                { v: "streams", l: "Streams" },
                { v: "threat", l: "Threat" },
                { v: "policy", l: "Policy" },
                { v: "history", l: "History" },
              ].map((t) => (
                <RadixTabs.Trigger
                  key={t.v}
                  value={t.v}
                  className={cn(
                    "relative -mb-px px-3 py-2 text-xs text-muted-foreground border-b-2 border-transparent",
                    "data-[state=active]:text-foreground data-[state=active]:border-[color:var(--color-primary)]",
                    "hover:text-foreground transition-colors",
                  )}
                  data-testid={`network-flow-inspector-tab-${t.v}`}
                >
                  {t.l}
                </RadixTabs.Trigger>
              ))}
            </RadixTabs.List>
            <div className="flex-1 overflow-y-auto px-4 py-3">
              <RadixTabs.Content value="flow" className="outline-none">
                <FlowTab flow={flow} threats={threats} />
              </RadixTabs.Content>
              <RadixTabs.Content value="peers" className="outline-none">
                <EdgePeersTab flow={flow} clusterID={clusterID} hours={hours} denyCapable={denyCapable} hidePlatform={sourceFilters.hide_platform ?? false} active={tab === "peers"} />
              </RadixTabs.Content>
              <RadixTabs.Content value="streams" className="outline-none">
                <StreamsTab flow={flow} clusterID={clusterID} hours={hours} active={tab === "streams"} sourceFilters={sourceFilters} />
              </RadixTabs.Content>
              <RadixTabs.Content value="threat" className="outline-none">
                <ThreatTab flow={flow} threats={threats} />
              </RadixTabs.Content>
              <RadixTabs.Content value="policy" className="outline-none">
                <PolicyTab flow={flow} lifecycle={lifecycle} />
              </RadixTabs.Content>
              <RadixTabs.Content value="history" className="outline-none">
                <HistoryTab data={sparkData} samples={recentFlows.filter((r) => r.flow_id === flow.id)} />
              </RadixTabs.Content>
            </div>
          </RadixTabs.Root>
          <footer className="flex items-center gap-2 border-t border-border px-4 py-3" data-testid="network-flow-inspector-footer">
            <Button
              size="sm"
              variant="primary"
              onClick={() => navigate({ href: networkActionHref(clusterID, "approve-policy", flow.src === "external" || flow.src.startsWith("external/") ? flow.dst : flow.src, { flow: flow.id }) })}
              data-testid="network-flow-inspector-convert"
            >
              Review network policy
            </Button>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// matchFlowThreats returns the real DPI threats from the page's threats list
// that belong to this conversation. A match requires the same signature id
// (threat_id) AND an endpoint overlap: either the threat's src/dst IP lines up
// with the flow's addresses, or the L4 destination port matches. flow.threat_id
// of 0 means dp never tripped a detector on this flow, so there is nothing to
// correlate.
function matchFlowThreats(flow: NetworkFlow, threats: RuntimeThreat[]): RuntimeThreat[] {
  const tid = flow.threat_id ?? 0;
  if (tid === 0) return [];
  return threats.filter((t) => {
    if (t.threat_id !== tid) return false;
    const addrMatch =
      (!!flow.src_addr && (t.src_ip === flow.src_addr || t.dst_ip === flow.src_addr)) ||
      (!!flow.dst_addr && (t.src_ip === flow.dst_addr || t.dst_ip === flow.dst_addr));
    const portMatch = flow.dst_port > 0 && t.dst_port === flow.dst_port;
    return addrMatch || portMatch;
  });
}

// appName ports cmd/constellation-runtime-agent/dp_flow.go's dpAppToL7 id→name
// map so the flow inspector shows a protocol name instead of a raw dp
// application id. Unknown ids fall back to "app <id>".
const DP_APP_NAMES: Record<number, string> = {
  1001: "HTTP",
  1002: "SSL",
  1003: "SSH",
  1004: "DNS",
  1005: "DHCP",
  1006: "NTP",
  1007: "TFTP",
  1008: "Echo",
  1009: "RTSP",
  1010: "SIP",
  1011: "MQTT",
  1012: "Syslog",
  2001: "MySQL",
  2002: "Redis",
  2003: "PostgreSQL",
  2004: "MongoDB",
  2005: "Kafka",
  2006: "Couchbase",
  2007: "Cassandra",
  2008: "Oracle-TNS",
  2009: "MSSQL-TDS",
  2010: "ZooKeeper",
  2011: "Spark",
  2012: "gRPC",
};

function appName(id: number): string {
  return DP_APP_NAMES[id] ?? `app ${id}`;
}

// Authoring keeps the selected target and return context in a dedicated URL.
function networkActionHref(clusterID: string, action: string, workload: string, extra: Record<string, string> = {}) {
  const params = new URLSearchParams({ workload, ...extra });
  const back = new URLSearchParams(window.location.search).toString();
  if (back) params.set("back", back);
  return `/clusters/${encodeURIComponent(clusterID)}/network/actions/${action}?${params}`;
}

// EnforcementCard lists active block/isolate actions with a lift (✕) control — the
// mirror of LiveSessionsCard, but for durable CNI policy rather than one connection.
function EnforcementCard({ clusterID }: { clusterID: string }) {
  const queryClient = useQueryClient();
  const q = useQuery({
    queryKey: ["network-enforcement", clusterID],
    queryFn: () => network.enforcement.list({ cluster_id: clusterID || undefined }),
    refetchInterval: 20_000,
  });
  const lift = useMutation({
    mutationFn: (id: string) => network.enforcement.lift(id),
    onSuccess: () => { toast.success("Removal requested. Waiting for the applier to confirm."); void queryClient.invalidateQueries({ queryKey: ["network-enforcement", clusterID] }); },
    onError: () => toast.error("Failed to lift"),
  });
  const actions = q.data ?? [];
  if (q.isError) return <p role="alert" className="rounded border border-border bg-card p-3 text-sm">Enforcement status could not be loaded. Refresh before assuming policies have been removed.</p>;
  if (actions.length === 0) return null;
  return (
    <div className="rounded-md border border-border bg-card/95 p-3 shadow-[var(--elev-1)]" data-testid="network-enforcement-card">
      <div className="mb-2 flex items-center gap-1.5 text-xs font-semibold">
        <Ban className="h-3.5 w-3.5 text-[color:var(--color-severity-critical)]" /> Enforcement requests ({actions.length})
      </div>
      <ul className="max-h-56 space-y-1 overflow-auto pr-1">
        {actions.map((a) => (
          <li key={a.id} className="flex items-center justify-between gap-2 rounded border border-border/60 p-1.5 text-micro">
            <div className="min-w-0">
              <div className="flex items-center gap-1">
                <span className="rounded bg-muted px-1 text-micro  text-muted-foreground">{a.kind === "isolate" ? "isolate" : "block"}</span>
                <span className="truncate text-mono font-medium">{a.kind === "isolate" ? shortName(a.target) : `${a.workload ? shortName(a.workload) + " ✕ " : ""}${a.target}`}</span>
              </div>
              <div className="mt-0.5 break-words text-micro text-muted-foreground">
                <NetworkEnforcementStatus action={a} />
                {a.reason ? ` · ${a.reason}` : ""}
              </div>
            </div>
            {a.state !== "lifting" && (
              <button type="button" title="Lift this enforcement" disabled={lift.isPending} onClick={() => lift.mutate(a.id)}
                className="shrink-0 rounded p-0.5 text-muted-foreground hover:text-[color:var(--color-severity-critical)] disabled:opacity-40">
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

// EdgePeersTab expands a clicked edge into the individual peer IPs behind it. The map folds
// all external peers into one "external" node, so a workload→external line is a single edge;
// this lists every real IP that edge represents (the whole point of "click the line to
// external and see the IPs").
function EdgePeersTab({ flow, clusterID, hours, denyCapable, hidePlatform, active }: { flow: NetworkFlow; clusterID: string; hours: number; denyCapable: boolean; hidePlatform: boolean; active: boolean }) {
  const aggregate = (id: string) => id === "external" || id.startsWith("external/");
  const workload = aggregate(flow.src) ? flow.dst : flow.src;
  const direction = aggregate(flow.src) ? "ingress" : "egress";
  if (aggregate(workload)) return <p className="text-xs text-muted-foreground">Select an edge with a workload endpoint to list peer IPs.</p>;
  return <NetworkPeerEvidence clusterID={clusterID} workload={workload} hours={hours} hidePlatform={hidePlatform} active={active} direction={direction} externalOnly={aggregate(flow.src) || aggregate(flow.dst)} testId="network-edge-peers" blockHref={denyCapable ? peer => networkActionHref(clusterID, "block-ip", workload, { ip: peer.peer_ip, direction }) : undefined} />;
}

function FlowTab({ flow, threats }: { flow: NetworkFlow; threats: RuntimeThreat[] }) {
  // Wave 6: surface dp-sourced fields when present. Source 'dp' means the
  // metrics came from real on-wire DPI inspection (NeuVector data-plane);
  // 'bpf' means our legacy port-heuristic estimator. Everything below the
  // verdict row is dp-only and conditionally rendered.
  const fromDP = flow.source === "dp";
  const hasThreat = (flow.threat_id ?? 0) > 0;
  // Resolve the raw signature id to a human name via the matching runtime
  // threat row when one is on the page; fall back to the bare id otherwise.
  const matchedThreat = matchFlowThreats(flow, threats)[0];
  return (
    <div className="space-y-3" data-testid="network-flow-tab">
      {fromDP && (
        <div
          className="flex items-center gap-2 rounded border border-border bg-card/60 px-2 py-1.5 text-micro text-muted-foreground"
          data-testid="network-flow-tab-source-dp"
        >
          <Radio className="h-3.5 w-3.5 text-[color:var(--color-status-success)]" aria-hidden />
          <span>
            Live DPI capture · real on-wire bytes from <span className="text-mono text-foreground">dp</span>
          </span>
        </div>
      )}
      <dl className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Bytes" value={formatBytes(flow.bytes)} />
        {fromDP && (flow.sessions ?? 0) > 0 && (
          <Field label="Sessions" value={(flow.sessions as number).toLocaleString()} />
        )}
        {!fromDP && <Field label="Packets" value={flow.packets.toLocaleString()} />}
        <Field label="Protocol" value={flow.protocol} />
        <Field label="L7" value={flow.l7_protocol || "—"} />
        <Field label="Source" value={formatEndpoint(flow.src_addr, flow.src_port)} />
        <Field label="Source platform role" value={flow.src_platform_role || "Not classified"} />
        <Field label="Destination" value={formatEndpoint(flow.dst_addr, flow.dst_port)} />
        <Field label="Destination platform role" value={flow.dst_platform_role || "Not classified"} />
        {typeof flow.fqdn === "string" && flow.fqdn !== "" && <Field label="FQDN" value={flow.fqdn} />}
        {fromDP && (flow.client_bytes ?? 0) > 0 && (
          <Field label="Client→Server" value={formatBytes(flow.client_bytes as number)} />
        )}
        {fromDP && (flow.server_bytes ?? 0) > 0 && (
          <Field label="Server→Client" value={formatBytes(flow.server_bytes as number)} />
        )}
        <Field label="Scope" value={flow.traffic_scope ?? trafficScopeLabel(flow)} />
        <Field label="Samples" value={flow.samples.toLocaleString()} />
        <Field label="Last seen" value={new Date(flow.last_seen_at).toLocaleString()} />
        <Field label="Verdict" value={flow.verdict} tone={flow.state} />
        <div><dt className="text-micro text-muted-foreground">Signature maximum</dt><dd><ThreatMaximum id={flow.threat_id} complete={flow.threat_id_complete} /></dd></div>
      </dl>
      {hasThreat && (
        <div
          className="rounded border border-[color:var(--color-status-error)] bg-card/60 p-2 text-micro"
          data-testid="network-flow-tab-threat"
        >
          <div className="mb-1 flex items-center gap-1.5 text-[color:var(--color-status-error)]">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
            <span className="font-semibold">DPI threat detected</span>
          </div>
          <dl className="grid grid-cols-2 gap-1 text-muted-foreground">
            <Field
              label="Threat"
              value={matchedThreat?.threat_name || matchedThreat?.msg || flow.threat_name || `signature ${flow.threat_id}`}
            />
            {(flow.severity ?? 0) > 0 && <Field label="Severity" value={severityLabel(flow.severity as number)} />}
            {(flow.application_id ?? 0) > 0 && (
              <Field label="App" value={appName(flow.application_id as number)} />
            )}
          </dl>
        </div>
      )}
    </div>
  );
}

// ThreatTab correlates the selected flow with the page's real DPI threat list
// (runtimeThreats.list). No inference — a threat only shows when dp actually
// tripped a signature on this conversation. Clicking "View packet detail"
// opens the existing ThreatDrilldownDialog for the full packet + L7 dump.
function ThreatTab({ flow, threats }: { flow: NetworkFlow; threats: RuntimeThreat[] }) {
  const [drilldownID, setDrilldownID] = useState<string | null>(null);
  const matched = matchFlowThreats(flow, threats);
  if (matched.length === 0) {
    if (flow.threat_id_complete !== true && !(flow.threat_id && flow.threat_id > 0)) {
      return <div className="text-xs" data-testid="network-threat-tab"><ThreatMaximum id={flow.threat_id} complete={flow.threat_id_complete} /></div>;
    }
    // The flow carries a threat_id (dp flagged it) but the packet-level runtime_threats row
    // isn't loaded — it aged out of the window or was purged. Be honest: name the threat
    // rather than implying nothing happened.
    if ((flow.threat_id ?? 0) > 0) {
      return (
        <div className="space-y-2" data-testid="network-threat-tab">
          <div className="rounded-md border border-[color:var(--color-status-error)]/50 bg-muted/40 p-2 text-xs">
            <div className="flex items-center gap-1.5 font-medium text-[color:var(--color-status-error)]">
              <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
              {flow.threat_name || `signature ${flow.threat_id}`}
            </div>
            <p className="mt-1 text-micro leading-tight text-muted-foreground">
              dp flagged this signature on the conversation, but the packet-level detail is no
              longer retained (older than the threat window or cleared). The signature id and
              name above are from the flow record.
              {flow.threat_id_complete !== true && <span className="block"><ThreatMaximum id={flow.threat_id} complete={flow.threat_id_complete} /></span>}
            </p>
          </div>
        </div>
      );
    }
    return (
      <div className="space-y-2" data-testid="network-threat-tab">
        <p className="text-xs text-muted-foreground">No DPI threat detected on this conversation.</p>
      </div>
    );
  }
  return (
    <div className="space-y-2" data-testid="network-threat-tab">
      <ul className="space-y-1.5">
        {matched.map((t) => (
          <li
            key={t.id}
            className="rounded-md border border-[color:var(--color-status-error)] bg-muted/40 p-2 text-xs"
            data-testid="network-threat-item"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-1.5 font-medium text-[color:var(--color-status-error)]">
                <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
                {t.threat_name || t.msg || `signature ${t.threat_id}`}
              </span>
              <span className="text-micro text-muted-foreground">
                {severityLabel(t.severity)} · {threatActionLabel(t.action)}
              </span>
            </div>
            {t.msg && (
              <div className="mt-1 text-micro text-muted-foreground">{t.msg}</div>
            )}
            <div className="mt-1 text-mono text-micro text-muted-foreground">
              {formatEndpoint(t.src_ip, t.src_port)} → {formatEndpoint(t.dst_ip, t.dst_port)}
            </div>
            <div className="mt-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => setDrilldownID(t.id)}
                data-testid="network-threat-view-packet"
              >
                View packet detail
              </Button>
            </div>
          </li>
        ))}
      </ul>
      {drilldownID && <ThreatDrilldownDialog id={drilldownID} onClose={() => setDrilldownID(null)} />}
    </div>
  );
}

// PolicyTab renders the REAL generated policy for this flow's workload, taken
// from the network policy lifecycle (network.lifecycle → item.preview.yaml and
// item.tuple_preview). It matches the lifecycle item by workload (flow.src, or
// flow.dst as a fallback). No synthesized YAML — if generation hasn't run for
// the workload there is nothing real to show.
function PolicyTab({ flow, lifecycle }: { flow: NetworkFlow; lifecycle: NetworkPolicyLifecycle[] }) {
  const item =
    lifecycle.find((it) => it.workload === flow.src) ??
    lifecycle.find((it) => it.workload === flow.dst);
  if (!item) {
    return (
      <div className="space-y-2" data-testid="network-policy-tab">
        <p className="text-xs text-muted-foreground">
          No generated policy for this workload yet — run policy generation.
        </p>
      </div>
    );
  }
  const yaml = item.preview.yaml;
  const tuples = item.tuple_preview ?? [];
  return (
    <div className="space-y-3" data-testid="network-policy-tab">
      <div className="flex items-center gap-2 text-micro">
        <span className="text-muted-foreground">Generated policy for</span>
        <span className="text-mono text-foreground">{item.workload}</span>
        <span className="rounded px-1.5 py-0.5 text-mono bg-muted text-muted-foreground">
          {item.preview.engine || "cilium"}
        </span>
      </div>
      {tuples.length > 0 && (
        <ul className="space-y-1" data-testid="network-policy-tuples">
          {tuples.map((t, i) => (
            <li
              key={`${t.direction}-${t.peer}-${t.protocol}-${t.port}-${i}`}
              className={cn(
                "flex items-center justify-between gap-2 rounded border px-2 py-1 text-micro",
                t.included
                  ? "border-border bg-card"
                  : "border-[color:var(--color-status-warning)]/40 bg-muted/40 text-muted-foreground",
              )}
            >
              <span className="text-mono">
                {t.direction} · {shortName(t.peer)} · {t.protocol}/{t.port}
              </span>
              <span className="text-micro">
                {t.included ? t.verdict : `excluded: ${t.exclude_reason || "n/a"}`}
              </span>
            </li>
          ))}
        </ul>
      )}
      {yaml && (
        <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 text-micro leading-tight">{yaml}</pre>
      )}
    </div>
  );
}

function HistoryTab({ data, samples }: { data: number[]; samples: NetworkRecentFlow[] }) {
  const max = Math.max(...data, 1);
  return (
    <div className="space-y-3" data-testid="network-history-tab">
      <div>
        <div className="text-micro  text-muted-foreground">Bytes / 24h (binned)</div>
        <div className="mt-2 rounded-md border border-border bg-muted/30 p-3">
          <Sparkline data={data} width={420} height={64} strokeWidth={1.5} />
          <div className="mt-1 flex items-center justify-between text-micro text-muted-foreground">
            <span>peak {formatBytes(max)}</span>
            <span>{samples.length} samples</span>
          </div>
        </div>
      </div>
      <div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="text-micro  text-muted-foreground">
            Recent samples · preview up to 8 of {samples.length} returned for this flow
          </div>
          <Button
            size="sm"
            variant="outline"
            disabled={samples.length === 0}
            onClick={() => downloadCsv(
              "network-selected-flow-returned-samples.csv",
              ["cluster_id", "src", "src_platform_role", "dst", "dst_platform_role", "observed_at", "bytes", "packets", "verdict"],
              samples.map(sample => [sample.cluster_id ?? "", sample.src, sample.src_platform_role ?? "", sample.dst, sample.dst_platform_role ?? "", sample.observed_at, String(sample.bytes), String(sample.packets), sample.verdict]),
            )}
          >Export returned samples</Button>
        </div>
        <ul className="mt-2 space-y-1 text-micro">
          {samples.slice(0, 8).map((s) => (
            <li key={s.id} className="flex items-center justify-between rounded border border-border bg-card px-2 py-1">
              <span className="text-mono">{new Date(s.observed_at).toLocaleTimeString()}</span>
              <span>{formatBytes(s.bytes)} · {s.packets} pkts</span>
            </li>
          ))}
          {samples.length === 0 && <li className="text-muted-foreground">No recent samples</li>}
        </ul>
      </div>
    </div>
  );
}



// FlowDrilldown is kept for accessibility / fallback when the popover is
// dismissed without changing the selected flow (e.g. user closed the dialog
// but still wants the data visible in the right rail).

function WorkloadDrilldown({ workload, flows, clusterID, hours, denyCapable, hidePlatform, onSelectFlow }: { workload: NetworkWorkload; flows: NetworkFlow[]; clusterID: string; hours: number; denyCapable: boolean; hidePlatform: boolean; onSelectFlow: (flowID: string) => void }) {
  const [tab, setTab] = useState<"ingress" | "egress" | "peers">("egress");
  const related = flows.filter((f) => f.src === workload.id || f.dst === workload.id);
  const ingressFlows = related.filter((f) => f.dst === workload.id);
  const egressFlows = related.filter((f) => f.src === workload.id);
  const visibleFlows = tab === "ingress" ? ingressFlows : egressFlows;
  return (
    <div className="space-y-4" data-testid="network-workload-detail">
      <div>
        <h2 className="text-sm font-semibold">{workload.name}</h2>
        <p className="mt-1 break-all text-xs text-muted-foreground">{workload.kind} · {workload.namespace}</p>
      </div>
      <dl className="grid grid-cols-2 gap-2 text-sm">
        <Field label="Risk" value={`${workload.risk_score}`} />
        <Field label="Findings" value={`${workload.finding_count}`} />
        <Field label="Ingress" value={`${ingressFlows.length}`} />
        <Field label="Egress" value={`${egressFlows.length}`} />
      </dl>
      <div>
        <div className="mb-2 flex gap-1" data-testid="network-detail-tabs">
          <button
            type="button"
            className={`rounded-md px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${tab === "ingress" ? "bg-accent text-foreground" : "bg-muted text-muted-foreground"}`}
            onClick={() => setTab("ingress")}
            data-testid="network-workload-ingress-tab"
          >
            Ingress
          </button>
          <button
            type="button"
            className={`rounded-md px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${tab === "egress" ? "bg-accent text-foreground" : "bg-muted text-muted-foreground"}`}
            onClick={() => setTab("egress")}
            data-testid="network-workload-egress-tab"
          >
            Egress
          </button>
          <button
            type="button"
            className={`rounded-md px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${tab === "peers" ? "bg-accent text-foreground" : "bg-muted text-muted-foreground"}`}
            onClick={() => setTab("peers")}
            data-testid="network-workload-peers-tab"
            title="Every individual peer IP (incl. external) this workload talked to"
          >
            Peers
          </button>
        </div>
        {tab === "peers" ? (
          <NetworkPeerEvidence clusterID={clusterID} workload={workload.id} hours={hours} hidePlatform={hidePlatform} active testId="network-workload-peers" blockHref={denyCapable ? peer => networkActionHref(clusterID, "block-ip", workload.id, { ip: peer.peer_ip, direction: peer.direction }) : undefined} />
        ) : (
        <ul className="max-h-72 space-y-2 overflow-auto pr-1 text-sm">
          {visibleFlows.map((f) => (
            <li key={f.id}>
              <button
                type="button"
                className="w-full rounded-md border border-border p-2 text-left hover:bg-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                onClick={() => onSelectFlow(f.id)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") onSelectFlow(f.id);
                }}
                data-testid="network-related-flow-row"
              >
                <div className="font-medium">{shortName(f.src)} {"->"} {shortName(f.dst)}</div>
                <div className="text-xs text-muted-foreground">{formatBytes(f.bytes)} · {formatProtocol(f)} · {f.verdict}</div>
              </button>
            </li>
          ))}
          {visibleFlows.length === 0 && <li className="text-xs text-muted-foreground">No observed traffic in this direction.</li>}
        </ul>
        )}
      </div>
    </div>
  );
}

export function WeakTLSStatus({
  configured,
  unavailable,
  loading,
  href,
  testId,
}: {
  configured: boolean | undefined;
  unavailable: boolean;
  loading: boolean;
  href?: string;
  testId: string;
}) {
  return (
    <div className="space-y-1 text-xs" data-testid={testId}>
      <p>
        Weak-TLS detection:{" "}
        {unavailable
          ? "unavailable"
          : loading
            ? "loading"
            : configured == null
              ? "unknown"
              : `configured ${configured ? "on" : "off"}`}
      </p>
      <p className="text-muted-foreground">
        Agent adoption is not reported here.
      </p>
      {href && (
        <a href={href} className="text-primary hover:underline">
          Review weak-TLS settings
        </a>
      )}
    </div>
  );
}
function PolicyLifecyclePanel({
  item,
  items,
  onSelect,
  available,
  loading,
  refreshing,
  onRetry,
}: {
  item: NetworkPolicyLifecycle | null;
  items: NetworkPolicyLifecycle[];
  onSelect: (value: string) => void;
  available: boolean;
  loading: boolean;
  refreshing: boolean;
  onRetry: () => void;
}) {
  const context = useContext(NetworkViewContext);
  const search = useLocation({ select: (l) => l.searchStr });
  if (!available)
    return (
      <ErrorState
        title={
          loading
            ? "Loading policy lifecycle evidence…"
            : "Current policy lifecycle evidence is unavailable."
        }
        action={<Button onClick={onRetry}>Retry</Button>}
      />
    );
  if (!item)
    return (
      <section data-testid="network-policy-lifecycle">
        <p className="text-sm text-muted-foreground">
          Select a reported workload to inspect its configured policy,
          candidate, and applier evidence.
        </p>
        {items.length > 0 && (
          <Select
            aria-label="Select workload policy"
            value=""
            onChange={(e) => onSelect(e.target.value)}
            className="mt-3 w-full rounded border border-border bg-background p-2"
          >
            <option value="">Choose a workload</option>
            {items.map((p) => (
              <option key={p.workload} value={p.workload}>
                {p.workload}
              </option>
            ))}
          </Select>
        )}
      </section>
    );
  const params = new URLSearchParams(search);
  const actions = [
    "approve-policy",
    "apply-policy",
    "demote-policy",
    "rollback-policy",
  ].filter((action) => policyActionAvailable(action, item));
  const labels: Record<string, string> = {
    "approve-policy": "Approve candidate",
    "apply-policy": "Apply policy",
    "demote-policy": "Demote policy",
    "rollback-policy": "Roll back policy",
  };
  const actionURL = (action: string) =>
    `/clusters/${encodeURIComponent(context?.clusterID ?? item.cluster_id ?? "")}/network/actions/${action}?${new URLSearchParams({ workload: item.workload, hours: params.get("hours") || "24", back: params.toString() })}`;
  const latest = [...(item.apply_statuses ?? [])].sort((a, b) =>
    b.updated_at.localeCompare(a.updated_at),
  )[0];
  const tuples = item.tuple_preview.map((r, key) => ({ ...r, key }));
  const audit = item.audit_trail.map((r, key) => ({ ...r, key }));
  const tupleColumns: Column<(typeof tuples)[number]>[] = [
    {
      id: "direction",
      header: "Direction",
      kind: "status",
      cell: (r) => r.direction,
      exportValue: (r) => r.direction,
    },
    {
      id: "peer",
      header: "Peer",
      kind: "name",
      cell: (r) => r.peer,
      exportValue: (r) => r.peer,
    },
    {
      id: "platform-role",
      header: "Platform role",
      kind: "status",
      cell: (r) => r.peer_platform_role === "core" ? "Core" : r.peer_platform_role === "" ? "Unclassified" : "Not reported",
      exportValue: (r) => r.peer_platform_role ?? "",
    },
    {
      id: "protocol",
      header: "Protocol",
      kind: "text",
      cell: (r) => `${r.l7_protocol || ""} ${r.protocol}/${r.port}`,
      exportValue: (r) => `${r.protocol}/${r.port}`,
    },
    {
      id: "samples",
      header: "Observations",
      kind: "count",
      cell: (r) => r.samples,
      exportValue: (r) => r.samples,
    },
    {
      id: "included",
      header: "Candidate treatment",
      kind: "status",
      cell: (r) => (r.included ? "included" : r.exclude_reason || r.verdict),
      exportValue: (r) =>
        r.included ? "included" : r.exclude_reason || r.verdict,
    },
  ];
  return (
    <section
      className="space-y-4 rounded border border-border bg-card p-4"
      data-testid="network-policy-lifecycle"
    >
      <h2 className="text-sm font-semibold">
        Network policy · {item.workload}
      </h2>
      <div
        className="flex flex-wrap items-center gap-3"
        data-testid="network-policy-action-bar"
      >
        <ModeBadge mode={item.current_mode} />
        <span>{item.approval_status}</span>
        <span className="text-sm text-muted-foreground">
          Configured state; deployment requires separate applier evidence.
        </span>
      </div>
      <p className="text-sm">{item.reason}</p>
      <p
        className="text-xs text-muted-foreground"
        data-testid="network-policy-apply-status"
      >
        {latest
          ? `Last reported applier: ${latest.flavor} · ${latest.last_action} ${latest.status} · ${latest.updated_at}${latest.error ? ` · ${latest.error}` : ""}`
          : "No applier report is available for this policy."}
      </p>
      <div className="flex flex-wrap gap-3">
        {actions.map((action) => (
          <a
            key={action}
            href={!refreshing ? actionURL(action) : undefined}
            aria-disabled={refreshing}
            className="rounded border border-border px-3 py-2 text-sm text-primary"
            data-testid={`network-policy-${action.split("-")[0]}`}
          >
            {labels[action]}
          </a>
        ))}
      </div>
      <Collapse label="Advanced: candidate and observed tuples">
        <p className="break-all font-mono text-xs">
          Candidate {item.candidate_hash || "unavailable"} · approved{" "}
          {item.approved_candidate_hash || "none"} · generated{" "}
          {item.generated_at || "not reported"}
        </p>
        <DataTable
          rows={tuples}
          columns={tupleColumns}
          rowKey={(r) => r.key}
          preferencesKey="network-policy-tuples"
          testId="network-policy-tuple-preview"
          sourceLimit={12}
          exportFileName="network-policy-observed-tuples.csv"
          exportLabel="Export returned tuple preview"
          emptyState={<p>No observed tuples returned.</p>}
        />
      </Collapse>
      <Collapse label="Advanced: current manifest and differences">
        <div data-testid="network-policy-preview">
          {Object.entries(
            item.preview.manifests && Object.keys(item.preview.manifests).length > 0 ? item.preview.manifests : {
              [item.preview.engine]: item.preview.yaml,
            },
          ).map(([name, yaml]) => (
            <div key={name}>
              <p className="text-sm font-medium">{name}</p>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
                {yaml}
              </pre>
            </div>
          ))}
        </div>
        <p className="mt-3 text-sm">{item.diff.summary}</p>
        <ul>
          {[...item.diff.added, ...item.diff.changed, ...item.diff.removed].map(
            (value, index) => (
              <li key={index} className="text-xs">
                {value}
              </li>
            ),
          )}
        </ul>
        {item.rollback_ref && (
          <p className="mt-3 break-all text-sm">
            Stored rollback reference: {item.rollback_ref}. Historical bundle
            contents are not supplied for a preview.
          </p>
        )}
      </Collapse>
      <Collapse label="Advanced: returned policy audit">
        <DataTable
          rows={audit}
          columns={[
            {
              id: "at",
              header: "At",
              kind: "date",
              cell: (r) => r.at,
              exportValue: (r) => r.at,
            },
            {
              id: "action",
              header: "Action",
              kind: "status",
              cell: (r) => r.action,
              exportValue: (r) => r.action,
            },
            {
              id: "message",
              header: "Record",
              kind: "name",
              wrap: true,
              cell: (r) => r.message,
              exportValue: (r) => r.message,
            },
            {
              id: "actor",
              header: "Actor",
              kind: "id",
              cell: (r) => r.actor,
              exportValue: (r) => r.actor,
            },
          ]}
          rowKey={(r) => r.key}
          testId="network-policy-audit-trail"
          preferencesKey="network-policy-audit"
          exportFileName="network-policy-audit.csv"
          emptyState={<p>No policy audit records returned.</p>}
        />
      </Collapse>
    </section>
  );
}

function ModeBadge({ mode }: { mode: NetworkPolicyMode }) {
  const cls = mode === "protect"
    ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
    : mode === "monitor"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : "bg-[color:var(--color-status-info)]/15 text-[color:var(--color-status-info)]";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`} data-testid="network-policy-mode">{mode}</span>;
}

function Field({ label, value, tone }: { label: string; value: string; tone?: NetworkFlowState }) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 font-medium" style={tone ? { color: STATE_COLOR[tone] } : undefined}>{value}</dd>
    </div>
  );
}

function layoutGraph(
  workloads: NetworkWorkload[],
  flows: NetworkFlow[],
  selectedFlowID: string | null,
  nodeKinds: Record<string, NetworkNodeKind> = {},
): { nodes: Node[]; edges: Edge[] } {
  // Topology-driven tier assignment: compute longest distance from a source
  // (node with no inbound edges) so the layout spreads across multiple rows
  // naturally. Sinks (only inbound) end up at the bottom; sources at the top.
  // Falls back to a static-heuristic tier for any isolated node.
  const incoming = new Map<string, Set<string>>();
  const outgoing = new Map<string, Set<string>>();
  for (const w of workloads) {
    incoming.set(w.id, new Set());
    outgoing.set(w.id, new Set());
  }
  for (const f of flows) {
    if (f.src === f.dst) continue;
    if (!incoming.has(f.dst)) incoming.set(f.dst, new Set());
    if (!outgoing.has(f.src)) outgoing.set(f.src, new Set());
    incoming.get(f.dst)!.add(f.src);
    outgoing.get(f.src)!.add(f.dst);
  }
  const tierFor = (w: NetworkWorkload): number => {
    // Static overrides for common topology landmarks
    if (w.kind === "External" || w.namespace === "external") return 5;
    if (w.namespace.includes("ingress")) return 0;
    if (w.namespace === "kube-system") return 1;
    // BFS distance from any source (node with zero inbound edges)
    const sources = workloads.filter((x) => (incoming.get(x.id)?.size ?? 0) === 0).map((x) => x.id);
    if (sources.length === 0) return 2;
    const dist = new Map<string, number>(sources.map((s) => [s, 0]));
    const queue = [...sources];
    while (queue.length) {
      const cur = queue.shift()!;
      const d = dist.get(cur)!;
      for (const next of outgoing.get(cur) ?? []) {
        if (!dist.has(next) || dist.get(next)! < d + 1) {
          dist.set(next, d + 1);
          queue.push(next);
        }
      }
    }
    // Clamp to 0..4 so the static external tier (5) still reads as "far right"
    return Math.min(4, dist.get(w.id) ?? 2);
  };
  void tierFor; // kept for future flow-aware layout variants
  // Radial cluster layout, NeuVector-style:
  //   - workloads bucket by namespace
  //   - each namespace gets a slot on a big circle
  //   - inside the namespace slot, members tile in a small grid
  // This spreads ~20 workloads across a 1500×900-ish canvas instead of
  // squeezing them into one horizontal line. The user can still drag any node;
  // useNodesState in the caller preserves positions across the 10s refetch.
  const NODE_W = 260;
  const NODE_H = 96;
  const GRID_GAP_X = 32;
  const GRID_GAP_Y = 32;
  const RADIUS_X = 700;   // ellipse-x for namespace centers
  const RADIUS_Y = 420;   // ellipse-y for namespace centers
  const CENTER_X = 800;
  const CENTER_Y = 480;

  // 1. Bucket by namespace, sorted alphabetically for stable layout.
  const byNs = new Map<string, NetworkWorkload[]>();
  for (const w of workloads) {
    const k = w.namespace || "default";
    if (!byNs.has(k)) byNs.set(k, []);
    byNs.get(k)!.push(w);
  }
  const namespaces = Array.from(byNs.keys()).sort();
  const slotPos = new Map<string, { cx: number; cy: number }>();

  if (namespaces.length === 1) {
    // Single namespace: just center the cluster.
    slotPos.set(namespaces[0], { cx: CENTER_X, cy: CENTER_Y });
  } else {
    namespaces.forEach((ns, i) => {
      const angle = (i / namespaces.length) * Math.PI * 2 - Math.PI / 2; // start at top
      slotPos.set(ns, {
        cx: CENTER_X + Math.cos(angle) * RADIUS_X,
        cy: CENTER_Y + Math.sin(angle) * RADIUS_Y,
      });
    });
  }

  const nodes: Node[] = workloads.map((w) => {
    const peers = byNs.get(w.namespace || "default") ?? [];
    const idx = peers.findIndex((p) => p.id === w.id);
    // Lay peers out in a small N×N grid centered on the namespace slot.
    const cols = Math.max(1, Math.ceil(Math.sqrt(peers.length)));
    const col = idx % cols;
    const row = Math.floor(idx / cols);
    const gridW = cols * NODE_W + (cols - 1) * GRID_GAP_X;
    const gridH = Math.ceil(peers.length / cols) * NODE_H + (Math.ceil(peers.length / cols) - 1) * GRID_GAP_Y;
    const slot = slotPos.get(w.namespace || "default") ?? { cx: CENTER_X, cy: CENTER_Y };
    return {
      id: w.id,
      data: { label: <NodeLabel workload={w} kind={nodeKinds[w.id]} /> },
      position: {
        x: slot.cx - gridW / 2 + col * (NODE_W + GRID_GAP_X),
        y: slot.cy - gridH / 2 + row * (NODE_H + GRID_GAP_Y),
      },
      style: {
        background: "var(--color-card)",
        border: "1px solid var(--color-border)",
        borderRadius: 10,
        padding: 14,
        fontSize: 14,
        color: "var(--color-foreground)",
        width: NODE_W,
      },
    };
  });

  // L2: log-scale stroke width 1–3px (formula: 1 + log10(1 + bytes/maxBytes * 100) * 0.7).
  // Selected edge bumps to 3.5px and gets a drop-shadow.
  //
  // Wave 6 — three things changed here:
  //   1. dp-sourced flows are NEVER stale: dp emits per (EPMAC, 5-tuple) on
  //      every report cycle, so a last_seen_at older than 5min means dp has
  //      genuinely stopped seeing the conversation. BPF-synthetic flows keep
  //      the old "stale after 5min" heuristic because their estimator only
  //      fires on connect events, not throughout the connection.
  //   2. Flows with `threat_id` get a red threat outline that overrides the
  //      verdict color. dp set the threat_id because a signature fired on the
  //      wire — that's louder than the policy verdict and we want it visible.
  //   3. The edge label includes an "L7" chip when dp's DPI parsers identified
  //      a real application layer (vs the port-number guess).
  const now = Date.now();
  const FRESH_MS = 5 * 60_000;
  const maxBytes = Math.max(...flows.map((f) => f.bytes), 1);
  const edges: Edge[] = flows.map((f) => {
    const selected = f.id === selectedFlowID;
    const baseWidth = 1 + Math.log10(1 + (f.bytes / maxBytes) * 100) * 0.7;
    const width = Math.max(1, Math.min(3, baseWidth));
    const lastSeenAt = f.last_seen_at ? Date.parse(f.last_seen_at) : 0;
    const fromDP = f.source === "dp";
    const stale = !fromDP && (!lastSeenAt || now - lastSeenAt > FRESH_MS);
    const hasThreat = (f.threat_id ?? 0) > 0;
    const threatColor = "var(--color-status-error)";
    const stroke = hasThreat ? threatColor : STATE_COLOR[f.state];
    const labelParts: string[] = [formatProtocol(f)];
    if (stale) {
      labelParts.push(`~${formatBytes(f.bytes)}`);
    } else {
      labelParts.push(formatBytes(f.bytes));
    }
    if (hasThreat) {
      labelParts.push("⚠ threat");
    }
    return {
      id: f.id,
      source: f.src,
      target: f.dst,
      label: labelParts.join(" · "),
      animated: hasThreat || (!stale && (f.state === "ok" || f.state === "warn" || selected)),
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke },
      style: {
        stroke,
        strokeWidth: selected ? 3.5 : hasThreat ? Math.max(2.5, width) : width,
        // Threat edges get a constant glow regardless of selection so they
        // stand out at a glance on a busy graph. Selection still adds extra
        // emphasis on top.
        filter: hasThreat
          ? `drop-shadow(0 0 ${selected ? 8 : 5}px ${threatColor})`
          : selected
            ? "drop-shadow(0 0 6px currentColor)"
            : undefined,
        opacity: selected || hasThreat ? 1 : stale ? 0.4 : 0.85,
        strokeDasharray: stale ? "4 4" : undefined,
      },
      labelStyle: {
        fontSize: 10,
        fill: hasThreat ? threatColor : "var(--color-muted-foreground)",
        fontWeight: hasThreat ? 600 : 400,
      },
      labelBgStyle: { fill: "var(--color-card)", fillOpacity: 0.9 },
    };
  });
  return { nodes, edges };
}

function NodeLabel({ workload, kind }: { workload: NetworkWorkload; kind?: NetworkNodeKind }) {
  // L2: drop the verbose workload-id badge; show a tighter `<ns>/<name>` line
  // plus one risk pill (only critical/high) and a counts badge in the corner.
  // Criticality tier now comes from real per-severity counts on the workload
  // object: any critical finding => critical, else any high => high. When both
  // counts are 0 (e.g. synthetic peer/external workloads) we fall back to the
  // risk_score proxy — high ≥ 60, critical ≥ 85.
  const score = workload.risk_score;
  const tier =
    (workload.critical_count ?? 0) > 0
      ? "critical"
      : (workload.high_count ?? 0) > 0
        ? "high"
        : score >= 85
          ? "critical"
          : score >= 60
            ? "high"
            : null;
  const pillColor =
    tier === "critical"
      ? "var(--color-status-error)"
      : tier === "high"
        ? "var(--color-status-warning)"
        : null;
  // Real per-severity counts from the workload row (deployments.critical_count/high_count).
  const criticalCount = workload.critical_count ?? 0;
  const highCount = workload.high_count ?? 0;
  // NV node policy-mode badge: discover = unprotected (learning only), monitor = alerting,
  // protect = blocking. Only badge when a mode is known (workload is in a group).
  const mode = workload.policy_mode || "";
  const modeColor =
    mode === "protect" ? "var(--color-severity-low)"
      : mode === "monitor" ? "var(--color-severity-medium)"
        : mode === "discover" ? "var(--color-severity-high)"
          : null;
  return (
    <div className="relative">
      <div className="flex items-center gap-2">
        {pillColor && <span aria-hidden className="h-2 w-2 shrink-0 rounded-full" style={{ background: pillColor }} />}
        <div className="min-w-0 flex-1 leading-tight">
          <div className="flex items-center gap-1 truncate text-micro text-muted-foreground">
            <span className="truncate">{workload.namespace}</span>
            {/* NET-1: endpoint kind from /network/conversations node_kinds.
                Only badge off-cluster kinds; managed workloads stay clean. */}
            {kind && kind !== "workload" && (
              <span
                className="shrink-0 rounded-sm border border-border bg-muted px-1 text-micro "
                data-testid={`network-node-kind-${kind}`}
              >
                {kind}
              </span>
            )}
            {modeColor && (
              <span
                className="shrink-0 rounded-sm border px-1 text-micro font-medium text-foreground"
                style={{ borderColor: modeColor }}
                title={`Policy mode: ${mode}${mode === "discover" ? " (unprotected — learning only)" : ""}`}
                data-testid={`network-node-mode-${mode}`}
              >
                {mode}
              </span>
            )}
          </div>
          <div className="truncate text-[15px] font-semibold">{workload.name}</div>
        </div>
      </div>
      {workload.finding_count > 0 && (
        <span
          className="absolute -right-2 -top-2 inline-flex items-center gap-0.5 rounded-full border border-border bg-card px-2 py-0.5 text-micro font-mono shadow-[var(--elev-1)]"
          role="img"
          aria-label={`${criticalCount} critical, ${highCount} high findings`}
        >
          {criticalCount > 0 && (
            <span style={{ color: "var(--color-status-error)" }}>{criticalCount}C</span>
          )}
          {criticalCount > 0 && highCount > 0 && <span className="text-muted-foreground">·</span>}
          {highCount > 0 && (
            <span style={{ color: "var(--color-status-warning)" }}>{highCount}H</span>
          )}
        </span>
      )}
    </div>
  );
}

function formatProtocol(flow: Pick<NetworkFlow, "l7_protocol" | "protocol" | "dst_port">) {
  const l7 = flow.l7_protocol || flow.protocol;
  return `${l7}${flow.dst_port ? `/${flow.dst_port}` : ""}`;
}

function formatBytes(bytes: number) {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatDateTime(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatEndpoint(addr?: string, port?: number) {
  if (!addr) return port ? `:${port}` : "n/a";
  return port ? `${addr}:${port}` : addr;
}

function trafficScopeLabel(flow: Pick<NetworkFlow, "src" | "dst">) {
  if (flow.dst.startsWith("external/")) return "egress-external";
  if (flow.src.startsWith("external/")) return "ingress-external";
  const [srcNS] = flow.src.split("/");
  const [dstNS] = flow.dst.split("/");
  return srcNS !== dstNS ? "cross-namespace" : "internal";
}

function shortName(id: string) {
  return id.split("/").pop() ?? id;
}

function downloadCsv(filename: string, headers: string[], rows: string[][]) {
  const csv = [
    headers.map(csvCell).join(","),
    ...rows.map((row) => row.map(csvCell).join(",")),
  ].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function csvCell(value: string) {
  if (/[",\n]/.test(value)) return `"${value.replaceAll("\"", "\"\"")}"`;
  return value;
}

// Compact inline stat pill rendered in the page header instead of the old
// full-width 5-tile row. Roughly NeuVector's "title + inline pills" layout.
function StatPill({
  icon,
  label,
  value,
  tone = "neutral",
  ...rest
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  tone?: "neutral" | "accent" | "critical";
  "data-testid"?: string;
}) {
  const toneClass =
    tone === "critical" ? "text-[color:var(--color-severity-critical)]"
    : tone === "accent" ? "text-[color:var(--color-primary)]"
    : "text-foreground";
  return (
    <span
      className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1"
      title={`${label}: ${value}`}
      {...rest}
    >
      <span className="text-muted-foreground">{icon}</span>
      <span className={cn("text-mono text-meta font-semibold tabular-nums", toneClass)}>{value}</span>
      <span className="text-micro  text-muted-foreground">{label}</span>
    </span>
  );
}

// ThreatsCard — Wave 6 overlay listing recent DPI threats from dp's
// signature engine. Pinned top-right below the legend; auto-hidden when
// there are no threats. Each row shows the threat name + src/dst + time,
// and clicking pivots to the matching flow on the canvas if one exists in
// the current view.
//
// "Matching flow" is best-effort: dp's threat record carries ep_mac and
// 5-tuple, but our flow rows are GROUP'd by (src_workload, dst_workload,
// protocol, l7, dst_port, verdict) — so we map threat→flow by ep_mac +
// dst_port + protocol, taking the most recent match.
// LiveSessionsCard renders the live per-connection table (NV RESTSession) as a bottom-left
// collapsible pill. Starts collapsed so it never obscures the canvas; expands to a table of
// current connections with directional bytes + TCP state.
function LiveSessionsCard({
  sessions,
  total,
  hasMore,
  loading,
  onKill,
  killing,
  lastKill,
}: {
  sessions: import("@/api/client").NetworkSession[];
  total: number;
  hasMore: boolean;
  loading: boolean;
  onKill: (id: number, node: string) => void;
  killing: boolean;
  lastKill: NetworkSessionKillResponse | null;
}) {
  const [collapsed, setCollapsed] = useState(true);
  const count = sessions.length;
  return (
    <div className={cn("rounded-md border border-border bg-card/95 p-2 text-micro shadow-[var(--elev-2)] backdrop-blur", collapsed ? "w-auto" : "w-[440px] max-w-[80vw]")}
      data-testid="network-sessions-card">
      <div className="flex items-center justify-between gap-2 px-1 text-micro  text-muted-foreground">
        <span className="flex items-center gap-1">
          <Activity className="h-3 w-3" aria-hidden />
          Live sessions · {loading ? "…" : hasMore ? `${count}/${total}` : count}
        </span>
        <button type="button" onClick={() => setCollapsed((v) => !v)}
          className="rounded p-0.5 hover:text-foreground" title={collapsed ? "Expand live sessions" : "Collapse live sessions"}
          data-testid="network-sessions-toggle">
          {collapsed ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        </button>
      </div>
      {!collapsed && (
        <div className="mt-1">
          {lastKill && (
            <div className="mb-1 rounded border border-[color:var(--color-status-success)]/40 bg-[color-mix(in_oklab,var(--color-status-success)_10%,transparent)] px-2 py-1 text-micro text-muted-foreground" data-testid="network-session-card-kill-result">
              Queued session {lastKill.session_id}
              {lastKill.expires_at ? ` · Delivery expires ${formatKillRequestedAt(lastKill.expires_at)}` : ""}
              {lastKill.audit_id ? ` - audit #${lastKill.audit_id}` : ""}
            </div>
          )}
          {loading ? (
            <p className="px-1 py-2 text-muted-foreground">Loading…</p>
          ) : count === 0 ? (
            <p className="px-1 py-2 leading-tight text-muted-foreground/80">
              No live sessions reported. The runtime-agent's data-plane uploads its
              ctrl_list_session table every 15s; connections that dp is actively tracking appear here.
            </p>
          ) : (
            <div className="min-w-0">
              {count > 200 && <p className="px-1 py-1 text-micro text-muted-foreground">Showing first 200 of {count} loaded sessions. Open the Sessions tab for the paged list.</p>}
              <DataTable<NetworkSession>
                className="[&_.app-table-scroll]:max-h-[300px]"
                rows={sessions.slice(0, 200)}
                rowKey={(session) => `${session.node}-${session.id}`}
                density="compact"
                pagination={false}
                showDensityToggle={false}
                showColumnChooser={false}
                columns={[
                  { id: "client", header: "Client", kind: "id", size: 160, minSize: 112, cell: (session) => `${session.client_ip}:${session.client_port}` },
                  { id: "server", header: "Server", kind: "id", size: 160, minSize: 112, cell: (session) => `${session.server_ip}:${session.server_port}` },
                  { id: "application", header: "App", kind: "text", size: 120, cell: (session) => session.application },
                  { id: "state", header: "State", kind: "status", cell: (session) => <>{session.client_state || session.ip_proto}{session.threat_id ? <span className="ml-1 text-[color:var(--color-status-error)]" title={`threat ${session.threat_id}`}>⚠</span> : null}</> },
                  { id: "in", header: "In", kind: "bytes", cell: (session) => formatBytes(session.client_bytes) },
                  { id: "out", header: "Out", kind: "bytes", cell: (session) => formatBytes(session.server_bytes) },
                  { id: "age", header: "Age", kind: "age", numeric: true, size: 80, cell: (session) => `${session.age}s` },
                  { id: "actions", header: "", kind: "actions", size: 48, minSize: 48, maxSize: 48, cell: (session) => <button type="button" disabled={killing} onClick={() => { if (window.confirm(`Terminate this ${session.application || session.ip_proto} session (dp ctrl_clear_session)?`)) onKill(session.id, session.node); }} title="Kill session (terminate the live connection)" className="rounded p-1 text-muted-foreground hover:text-[color:var(--color-status-error)] disabled:opacity-40"><X className="h-3 w-3" aria-hidden /></button> },
                ]}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatsCard({
  threats,
  flows,
  weakTLS,
  settingsUnavailable,
  settingsLoading,
  settingsHref,
  onPivot,
}: {
  threats: RuntimeThreat[];
  flows: NetworkFlow[];
  weakTLS: boolean|undefined;
  settingsUnavailable:boolean;
  settingsLoading:boolean;
  settingsHref:string|undefined;
  onPivot: (flowID: string) => void;
}) {
  const [drilldownID, setDrilldownID] = useState<string | null>(null);
  // Start collapsed so the card never auto-opens over the canvas — it's a compact
  // "DPI threats · N" pill the operator expands on demand (keeps the map unobstructed).
  const [collapsed, setCollapsed] = useState(true);
  // Top 5 by reported_at desc. The API already orders by `at DESC`, so we
  // just trim. Higher-severity-first sorting is tempting but the time
  // ordering matches what an operator scanning for "what just happened"
  // expects.
  const recent = threats.slice(0, 5);
  const findFlowForThreat = (t: RuntimeThreat): string | null => {
    if (!t.ep_mac) return null;
    // The flow row doesn't carry ep_mac directly; the threat_id field on
    // network_flows is the joinable bit but only when the flow's bucket
    // tripped a signature in the same window. Match by protocol + dst_port
    // + threat_id as a fall-back; otherwise just pivot by dst_port alone.
    const candidates = flows.filter(
      (f) =>
        f.dst_port === t.dst_port &&
        f.protocol.toLowerCase() === ipProtoName(t.ip_proto).toLowerCase() &&
        (f.threat_id ?? 0) === t.threat_id,
    );
    if (candidates.length > 0) return candidates[0].id;
    const byPort = flows.find((f) => f.dst_port === t.dst_port);
    return byPort?.id ?? null;
  };
  const hot = threats.length > 0;
  return (
    <>
      <div
        className={cn(
          "max-w-[80vw] rounded-md border bg-card/95 p-2 text-micro shadow-[var(--elev-2)] backdrop-blur",
          hot ? "border-[color:var(--color-status-error)]/60" : "border-border",
          collapsed ? "w-auto" : "w-[340px]",
        )}
        data-testid="network-threats-card"
      >
        <div className={cn("mb-1 flex items-center justify-between px-1 text-micro ", hot ? "text-[color:var(--color-status-error)]" : "text-muted-foreground")}>
          <span className="flex items-center gap-1">
            <ShieldAlert className="h-3 w-3" aria-hidden />
            DPI threats · {threats.length}
          </span>
          <button
            type="button"
            onClick={() => setCollapsed((v) => !v)}
            className="rounded p-0.5 text-muted-foreground hover:text-foreground"
            title={collapsed ? "Expand DPI threats" : "Collapse DPI threats"}
            aria-label={collapsed ? "Expand DPI threats" : "Collapse DPI threats"}
            data-testid="network-threats-toggle"
          >
            {collapsed ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />}
          </button>
        </div>
        {!collapsed && (
        <>
        <p className="mb-1 px-1 text-micro leading-tight text-muted-foreground/80">
          Showing latest {recent.length} of {threats.length} loaded DPI threats. Open the Threats tab for the paged list. In monitor mode these are logged, not blocked.
        </p>
        <ul className="space-y-0.5" data-testid="network-threats-list">
          {recent.map((t) => {
            const flowID = findFlowForThreat(t);
            const time = new Date(t.reported_at || t.at).toLocaleTimeString();
            return (
              <li key={t.id}>
                <div
                  className="group flex items-stretch rounded transition-colors hover:bg-accent"
                  data-testid={`network-threat-row-${t.id}`}
                >
                  <button
                    type="button"
                    onClick={() => setDrilldownID(t.id)}
                    className="flex-1 px-1.5 py-1 text-left"
                    title={t.msg || t.threat_name || `threat ${t.threat_id}`}
                    data-testid={`network-threat-drill-${t.id}`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate font-semibold text-foreground">
                        {t.threat_name || `threat_${t.threat_id}`}
                      </span>
                      <span className="shrink-0 text-mono text-muted-foreground">{time}</span>
                    </div>
                    <div className="truncate text-micro text-muted-foreground">
                      {t.src_ip}:{t.src_port} → {t.dst_ip}:{t.dst_port}
                      {t.severity > 0 && (
                        <span className="ml-1 rounded bg-[color:var(--color-status-error)]/15 px-1 text-[color:var(--color-status-error)]">
                          {severityLabel(t.severity)}
                        </span>
                      )}
                      <span className="ml-1 text-muted-foreground/70">· {threatActionLabel(t.action)}</span>
                    </div>
                    {t.msg && (
                      <div className="truncate text-micro text-muted-foreground/80" title={t.msg}>
                        {t.msg}
                      </div>
                    )}
                  </button>
                  {flowID && (
                    <button
                      type="button"
                      onClick={() => onPivot(flowID)}
                      className="border-l border-border/60 px-1.5 text-micro  text-muted-foreground hover:text-foreground"
                      title="Pivot to the matching flow on the canvas"
                      data-testid={`network-threat-pivot-${t.id}`}
                    >
                      flow
                    </button>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
        {threats.length > recent.length && (
          <div className="mt-1 border-t border-border/60 pt-1 px-1 text-micro text-muted-foreground">
            + {threats.length - recent.length} more in the loaded page
          </div>
        )}
        {!hot && (
          <p className="px-1 py-1 text-micro text-muted-foreground">No DPI threats in the loaded page.</p>
        )}
        {/* DPI signature toggle (NV-style): weak-TLS version detection is off by default
            (dp reads the legacy TLS record version in tap mode → false positives on modern HTTPS). */}
        <WeakTLSStatus configured={weakTLS} unavailable={settingsUnavailable} loading={settingsLoading} href={settingsHref} testId="network-weak-tls-toggle"/>
        </>
        )}
      </div>
      {drilldownID && (
        <ThreatDrilldownDialog id={drilldownID} onClose={() => setDrilldownID(null)} />
      )}
    </>
  );
}

// ThreatDrilldownDialog opens when the user clicks the main button of a row
// in the ThreatsCard. Fetches the full row via GET /runtime-threats/{id} —
// which includes the captured packet bytes (base64) and a server-parsed L7
// preview — and renders a tcpdump-style hex+ASCII dump alongside the L7
// summary. The base64→Uint8Array decode is browser-native.
function ThreatDrilldownDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const context = useContext(NetworkViewContext);
  const q = useQuery({
    queryKey: ["runtime-threat", context?.clusterID, id],
    queryFn: () => runtimeThreats.get(id),
    enabled: !!context?.clusterID,
  });
  const mismatch = q.isSuccess && (q.data.id !== id || q.data.cluster_id !== context?.clusterID);
  const detail: RuntimeThreatDetail | undefined = q.isSuccess && !mismatch ? q.data : undefined;
  const bytes = useMemo(() => decodeBase64(detail?.packet ?? ""), [detail?.packet]);
  return (
    <Dialog.Root open onOpenChange={(o) => { if (!o) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-background/30 backdrop-blur-[1px]"
          data-testid="network-threat-dialog-overlay"
        />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 flex h-[min(640px,calc(100dvh-2rem))] w-[min(720px,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col rounded-lg border border-border bg-card shadow-[var(--elev-3)] focus:outline-none"
          data-testid="network-threat-dialog"
          aria-describedby={undefined}
        >
          <div className="h-1 w-full rounded-t-lg bg-[color:var(--color-status-error)]" aria-hidden />
          <header className="flex items-start justify-between gap-2 border-b border-border px-4 py-3">
            <div className="min-w-0 flex-1">
              <Dialog.Title className="flex items-center gap-2 text-display text-sm font-semibold tracking-tight">
                <ShieldAlert className="h-4 w-4 text-[color:var(--color-status-error)]" aria-hidden />
                <span className="text-mono">{detail?.threat_name || `threat_${detail?.threat_id ?? "?"}`}</span>
                {detail?.severity != null && detail.severity > 0 && (
                  <span className="rounded bg-[color:var(--color-status-error)]/15 px-1.5 py-0.5 text-micro text-[color:var(--color-status-error)]">
                    severity {detail.severity}
                  </span>
                )}
              </Dialog.Title>
              {detail?.msg && (
                <div className="mt-0.5 truncate text-micro text-muted-foreground">{detail.msg}</div>
              )}
            </div>
            <Dialog.Close
              aria-label="Close threat inspector"
              className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
              data-testid="network-threat-dialog-close"
            >
              <X className="h-4 w-4" />
            </Dialog.Close>
          </header>
          <div className="flex-1 overflow-auto p-4 text-xs">
            {q.isLoading && <div className="text-muted-foreground">loading…</div>}
            {q.isError && (
              <div className="text-[color:var(--color-status-error)]">
                Failed to load threat: {String((q.error as Error)?.message ?? "")}
              </div>
            )}
            {mismatch && <ErrorState title="Threat evidence does not match the selected cluster and threat." />}
            {detail && (
              <div className="space-y-4">
                <ThreatMetaGrid t={detail} />
                {detail.l7 && <ThreatL7Pane l7={detail.l7} />}
                <ThreatPacketDump bytes={bytes} capLen={detail.cap_len ?? 0} />
                {context && <ThreatPcapCapturePane threat={detail} clusterID={context.clusterID} snapshot={context.snapshot} />}
              </div>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// Threat details share the canonical capture form; no second editor or request path.
export function ThreatPcapCapturePane({ threat, clusterID, snapshot }: { threat: RuntimeThreatDetail; clusterID: string; snapshot: NetworkSavedViewSnapshot }) {
  const location = useLocation();
  if (threat.cluster_id !== clusterID) return <ErrorState title="Threat capture scope does not match the selected cluster." />;
  const captureSnapshot: NetworkSavedViewSnapshot = { ...snapshot, workspace_tab: "pcap", pcap_filters: { ...EMPTY_PCAP_FILTERS, workload: threat.workload_id ?? "", src_ip: threat.src_ip ?? "", dst_ip: threat.dst_ip ?? "", dst_port: threat.dst_port ? String(threat.dst_port) : "", protocol: threat.ip_proto === 6 ? "tcp" : threat.ip_proto === 17 ? "udp" : threat.ip_proto === 1 ? "icmp" : "" } };
  const href = networkViewHref(clusterID, new URLSearchParams(location.searchStr), location.hash, "pcap", captureSnapshot);
  return <div className="space-y-3 rounded border border-border bg-card/50 p-3" data-testid="threat-pcap-pane"><h3 className="text-sm font-semibold">Packet capture</h3><p className="text-xs text-muted-foreground">Review this threat’s workload and traffic filters on the capture request page. The agent must complete the request before a file is available.</p><Button asChild size="sm"><a href={href} data-testid="threat-pcap-new">+ Request capture</a></Button></div>;
}

function ThreatMetaGrid({ t }: { t: RuntimeThreatDetail }) {
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-micro" data-testid="threat-meta">
      <Field label="Source" value={`${t.src_ip ?? ""}${t.src_port ? `:${t.src_port}` : ""}`} />
      <Field label="Destination" value={`${t.dst_ip ?? ""}${t.dst_port ? `:${t.dst_port}` : ""}`} />
      <Field label="Workload" value={t.workload_id || t.ep_mac || "—"} />
      <Field label="Node" value={t.node || "—"} />
      <Field label="Direction" value={t.pkt_ingress ? "ingress" : "egress"} />
      <Field label="dp reported" value={t.reported_at ? new Date(t.reported_at).toLocaleString() : "—"} />
      <Field label="Packet size (wire)" value={String(t.cap_len ?? 0)} />
      <Field label="Captured bytes" value={String(t.pkt_len ?? 0)} />
    </dl>
  );
}

function ThreatL7Pane({ l7 }: { l7: NonNullable<RuntimeThreatDetail["l7"]> }) {
  return (
    <div
      className="rounded border border-border bg-background/40 p-3"
      data-testid={`threat-l7-${l7.kind}`}
    >
      <div className="mb-2 flex items-center gap-2 text-micro  text-muted-foreground">
        <span>L7 preview</span>
        <span className="rounded bg-accent px-1.5 py-0.5 font-mono text-foreground">{l7.kind.toUpperCase()}</span>
      </div>
      {l7.kind === "http" && l7.http && (
        <div className="space-y-1.5 text-mono text-micro">
          <div>
            <span className="text-[color:var(--color-primary)]">{l7.http.method}</span>{" "}
            <span className="break-all">{l7.http.target}</span>{" "}
            {l7.http.version && <span className="text-muted-foreground">{l7.http.version}</span>}
          </div>
          {l7.http.headers && Object.keys(l7.http.headers).length > 0 && (
            <div className="space-y-0.5 text-muted-foreground">
              {Object.entries(l7.http.headers).map(([k, v]) => (
                <div key={k} className="break-all">
                  <span className="text-foreground">{k}:</span> {v}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      {l7.kind === "dns" && l7.dns && (
        <div className="text-mono text-micro">
          <span className="text-[color:var(--color-primary)]">{l7.dns.qtype || "?"}</span>{" "}
          <span className="break-all">{l7.dns.qname || "—"}</span>
        </div>
      )}
      {l7.kind === "tls" && l7.tls && (
        <div className="space-y-1 text-mono text-micro">
          {l7.tls.version && <div><span className="text-muted-foreground">version:</span> {l7.tls.version}</div>}
          {l7.tls.sni && <div><span className="text-muted-foreground">SNI:</span> <span className="break-all">{l7.tls.sni}</span></div>}
        </div>
      )}
    </div>
  );
}

// ThreatPacketDump renders the captured packet bytes in the canonical
// `xxd -C` shape: offset | 16 hex bytes | 16 ASCII chars per row.
// Cap at 256 bytes by default with a "show all" toggle since dp can ship
// up to 2 KB and the dialog is bounded.
function ThreatPacketDump({ bytes, capLen }: { bytes: Uint8Array; capLen: number }) {
  const [showAll, setShowAll] = useState(false);
  if (bytes.length === 0) {
    return (
      <div className="rounded border border-dashed border-border p-3 text-center text-muted-foreground" data-testid="threat-no-packet">
        No packet bytes captured for this threat.
      </div>
    );
  }
  const visible = showAll ? bytes : bytes.subarray(0, 256);
  const lines: { off: number; hex: string; ascii: string }[] = [];
  for (let i = 0; i < visible.length; i += 16) {
    const chunk = visible.subarray(i, Math.min(i + 16, visible.length));
    const hex = Array.from(chunk, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(chunk, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push({ off: i, hex, ascii });
  }
  return (
    <div className="rounded border border-border bg-background/40 p-3" data-testid="threat-packet-dump">
      <div className="mb-2 flex items-center justify-between text-micro  text-muted-foreground">
        <span>Captured packet · {bytes.length} of {capLen || bytes.length} bytes</span>
        {bytes.length > 256 && (
          <button
            type="button"
            onClick={() => setShowAll((v) => !v)}
            className="rounded border border-border bg-card px-1.5 py-0.5 hover:bg-accent"
          >
            {showAll ? "Show first 256" : `Show all (${bytes.length})`}
          </button>
        )}
      </div>
      <pre className="overflow-x-auto whitespace-pre text-mono text-micro leading-snug">
        {lines.map((l) => (
          `${l.off.toString(16).padStart(4, "0")}  ${l.hex.padEnd(16 * 3 - 1, " ")}  ${l.ascii}\n`
        ))}
      </pre>
    </div>
  );
}

// decodeBase64 turns the JSON `packet` field (Go's base64 encoding of bytea)
// into a Uint8Array. atob is browser-native; we tolerate empty / malformed
// input by returning an empty array.
function decodeBase64(s: string): Uint8Array {
  if (!s) return new Uint8Array();
  try {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return new Uint8Array();
  }
}

// ipProtoName maps the IANA IP protocol numbers dp emits onto the lowercase
// strings the read query stores. Mirrors cmd/constellation-runtime-agent's
// dp_flow.go ipProtoToString — keep in sync.
function ipProtoName(p?: number): string {
  switch (p) {
    case 6: return "tcp";
    case 17: return "udp";
    case 1: return "icmp";
    case 58: return "icmpv6";
    default: return "";
  }
}

// Bottom-left floating policy-lifecycle panel: collapses to a single chip
// until clicked, NeuVector-style. Auto-expands when an item is selected.
function CollapsiblePolicyLifecycle(props: React.ComponentProps<typeof PolicyLifecyclePanel>) {
  const [open, setOpen] = useState<boolean>(false);
  useEffect(() => { if (props.item) setOpen(true); }, [props.item]);
  const monitor = (props.items ?? []).filter((it) => it.current_mode === "monitor").length;
  const discover = (props.items ?? []).filter((it) => it.current_mode === "discover").length;
  const protect = (props.items ?? []).filter((it) => it.current_mode === "protect").length;
  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        data-testid="network-lifecycle-chip"
        className="absolute bottom-3 left-3 z-10 inline-flex items-center gap-2 rounded-md border border-border bg-card/95 px-2.5 py-1.5 text-micro shadow-[var(--elev-2)] backdrop-blur hover:bg-accent"
        title="Network policy lifecycle"
      >
        <Eye   className="h-3 w-3 text-muted-foreground" />
        <span className="text-mono tabular-nums">{props.available?discover:"—"}</span>
        <Radio className="h-3 w-3 text-[color:var(--color-status-warning)]" />
        <span className="text-mono tabular-nums">{props.available?monitor:"—"}</span>
        <Lock  className="h-3 w-3 text-[color:var(--color-primary)]" />
        <span className="text-mono tabular-nums">{props.available?protect:"—"}</span>
        <span className="text-muted-foreground">netpol</span>
      </button>
    );
  }
  return (
    <div
      className="absolute bottom-3 left-3 z-10 max-h-[60vh] w-[420px] overflow-auto rounded-md border border-border bg-card/95 p-2 shadow-[var(--elev-2)] backdrop-blur"
      data-testid="network-lifecycle-panel"
    >
      <div className="mb-1 flex items-center justify-between">
        <span className="text-micro  text-muted-foreground">Network Policy Lifecycle</span>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="text-micro text-muted-foreground hover:text-foreground"
        >
          collapse
        </button>
      </div>
      <PolicyLifecyclePanel {...props} />
    </div>
  );
}
