import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
  GitCompareArrows,
  ShieldAlert,
  Waypoints,
  Eye,
  EyeOff,
  Radio,
  Lock,
  X,
  AlertTriangle,
  CheckCircle2,
  Ban,
  ChevronUp,
  ChevronDown,
} from "lucide-react";


import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { StatusPill } from "@/components/ui/status-pill";
import { Sparkline } from "@/components/ui/sparkline";
import { EmptyState } from "@/components/ui/empty-state";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";
import { fmtBytes } from "@/lib/format";
import { toast } from "sonner";

import {
  network,
  quarantine,
  runtimePcap,
  runtimeThreats,
  type NetworkFlow,
  type NetworkFlowState,
  type NetworkNodeKind,
  type NetworkPolicyLifecycle,
  type NetworkPolicyMode,
  type NetworkRecentFlow,
  type NetworkWorkload,
  type PcapCapture,
  type RuntimeThreat,
  type RuntimeThreatDetail,
} from "@/api/client";

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
type VerdictGroup = (typeof VERDICT_GROUPS)[number];

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

const VERDICT_ICON: Record<VerdictGroup, typeof CheckCircle2> = {
  allow: CheckCircle2,
  alert: AlertTriangle,
  block: Ban,
};

const KUBE_SYSTEM_NS = new Set(["kube-system", "kube-public", "kube-node-lease"]);

type ScopeMode = "both" | "internal" | "external";

const EMPTY_WORKLOADS: NetworkWorkload[] = [];
const EMPTY_FLOWS: NetworkFlow[] = [];
const EMPTY_NODE_KINDS: Record<string, NetworkNodeKind> = {};

function lifecycleIdempotencyKey(workload: string, action: string) {
  if (typeof window !== "undefined" && "randomUUID" in window.crypto) {
    return `network-policy:${workload}:${action}:${window.crypto.randomUUID()}`;
  }
  return `network-policy:${workload}:${action}:${Date.now()}`;
}

export function NetworkMapPage() {
  return (
    <ReactFlowProvider>
      <NetworkMapInner />
    </ReactFlowProvider>
  );
}

function NetworkMapInner() {
  const queryClient = useQueryClient();
  const initialParams = useMemo(() => new URLSearchParams(window.location.search), []);
  // B1: cluster scoping. We're mounted under /clusters/:id/network, so the
  // active cluster comes from the route param via useCluster() — NOT from a
  // query string (normal sidebar nav has none, which previously yielded an
  // empty unscoped map). The hooks/useCluster.ts contract requires every
  // fetch on this page to thread this cluster_id.
  const { clusterId } = useCluster();
  const clusterID = clusterId ?? "";
  const [hours, setHours] = useState(() => {
    const value = Number(initialParams.get("hours"));
    return value > 0 ? value : 24;
  });
  // namespace/verdict are real local filters (seeded from the URL on mount)
  // with working setters so the values stay usable by the server-side query.
  const [namespace, setNamespace] = useState(() => initialParams.get("namespace") ?? "");
  const [verdict, setVerdict]     = useState(() => initialParams.get("verdict") ?? "");
  const [selectedFlowID, setSelectedFlowID] = useState<string | null>(() => initialParams.get("flow"));
  const [selectedWorkloadID, setSelectedWorkloadID] = useState<string | null>(() => initialParams.get("workload"));
  const [actionError, setActionError] = useState("");
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
  const [hideKubeSystem, setHideKubeSystem] = useState(true);
  const [hiddenKinds, setHiddenKinds] = useState<Set<NetworkNodeKind>>(() => new Set<NetworkNodeKind>(["unmanaged"]));
  const [scopeMode, setScopeMode] = useState<ScopeMode>("both");
  const [popoverOpen, setPopoverOpen] = useState(false);

  const q = useQuery({
    queryKey: ["network-map", hours, clusterID, namespace, verdict],
    queryFn: () => network.map({ hours, cluster_id: clusterID || undefined, namespace: namespace || undefined, verdict: verdict || undefined }),
    enabled: !!clusterID,
    refetchInterval: live ? 10_000 : false,
  });
  // NET-1: folded service-conversation graph. Distinct from /network/map (raw
  // flow rows) — it carries node_kinds (workload|host|unmanaged|external) so we
  // can badge off-cluster endpoints the raw map can't classify. Cluster-scoped
  // via useCluster() like every other query on this page.
  const conversationsQ = useQuery({
    queryKey: ["network-conversations", hours, clusterID],
    queryFn: () => network.conversations({ hours, cluster_id: clusterID || undefined }),
    enabled: !!clusterID,
    refetchInterval: live ? 10_000 : false,
  });
  const nodeKinds = conversationsQ.data?.node_kinds ?? EMPTY_NODE_KINDS;
  const lifecycleQ = useQuery({
    queryKey: ["network-policy-lifecycle", hours, clusterID, namespace, verdict],
    queryFn: () => network.lifecycle({ hours, cluster_id: clusterID || undefined, namespace: namespace || undefined, verdict: verdict || undefined }),
    enabled: !!clusterID,
    refetchInterval: live ? 10_000 : false,
  });
  // Wave 6: recent DPI threats from the runtime-agent's dp data-plane. Drives
  // the threats card pinned to the bottom-right of the canvas. We pull the
  // same window as the flow query so the two views stay coherent, and use a
  // longer refetch interval (15s) since threats are append-only and don't
  // need the 10s flow cadence.
  const threatsQ = useQuery({
    queryKey: ["runtime-threats", hours, clusterID],
    queryFn: () => runtimeThreats.list({ hours, cluster_id: clusterID || undefined }),
    enabled: !!clusterID,
    refetchInterval: live ? 15_000 : false,
  });
  // NV RESTSession: live per-connection table from the runtime-agent's dp session snapshot.
  const sessionsQ = useQuery({
    queryKey: ["network-sessions", clusterID],
    queryFn: () => network.sessions({ cluster_id: clusterID || undefined }),
    enabled: !!clusterID,
    refetchInterval: live ? 15_000 : false,
  });
  const action = useMutation({
    mutationFn: ({ workload, kind, reason, candidateHash }: { workload: string; kind: "approve" | "apply" | "demote"; reason?: string; candidateHash?: string }) =>
      network.policyAction(workload, kind, { reason, candidate_hash: candidateHash, idempotency_key: lifecycleIdempotencyKey(workload, kind) }, { cluster_id: clusterID || undefined }),
    onSuccess: () => {
      setActionError("");
      void queryClient.invalidateQueries({ queryKey: ["network-policy-lifecycle"] });
      void queryClient.invalidateQueries({ queryKey: ["network-map"] });
    },
    onError: () => {
      setActionError("Policy candidate changed or action failed. Refresh and review the latest candidate.");
      void queryClient.invalidateQueries({ queryKey: ["network-policy-lifecycle"] });
    },
  });
  const rollback = useMutation({
    mutationFn: ({ workload, rollbackRef, reason }: { workload: string; rollbackRef: string; reason?: string }) =>
      network.rollbackPolicy(workload, { rollback_ref: rollbackRef, reason, idempotency_key: lifecycleIdempotencyKey(workload, "rollback") }, { cluster_id: clusterID || undefined }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["network-policy-lifecycle"] });
      void queryClient.invalidateQueries({ queryKey: ["network-map"] });
    },
  });

  // Quarantine the selected workload directly from the graph — NeuVector surfaces
  // quarantine as a per-node incident-response action. Reuses the audited quarantine model.
  const quarantineMut = useMutation({
    mutationFn: ({ workload, reason }: { workload: string; reason: string }) =>
      quarantine.create({ cluster_id: clusterID, scope: "workload", match_key: workload, reason, expires_in_hours: 24 }),
    onSuccess: () => { toast.success("Workload quarantined"); void queryClient.invalidateQueries({ queryKey: ["network-map"] }); },
    onError: () => toast.error("Failed to quarantine workload"),
  });

  const workloads = q.data?.workloads ?? EMPTY_WORKLOADS;
  const flowsRaw = q.data?.flows ?? EMPTY_FLOWS;
  const liveFlows = q.data?.recent_flows ?? [];
  // Cluster list was used by the dropped select; URL-driven now.
  // const clusters = q.data?.summary.clusters ?? [];
  const lifecycleItems = lifecycleQ.data?.items ?? [];

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
  const isKubeSystem = useCallback(
    (f: NetworkFlow) => {
      const srcNS = workloadNS.get(f.src) ?? f.src.split("/")[0];
      const dstNS = workloadNS.get(f.dst) ?? f.dst.split("/")[0];
      return KUBE_SYSTEM_NS.has(srcNS) || KUBE_SYSTEM_NS.has(dstNS);
    },
    [workloadNS],
  );

  // Apply L2 chip filters on top of the server-side filters (which only
  // know about hours / cluster / namespace / verdict). This pass runs against
  // the in-memory flow list so chip toggles feel instant.
  const flows = useMemo(() => {
    return flowsNoSelf.filter((f) => {
      const vg = verdictGroupFromState(f.state, f.verdict);
      if (vg && !verdictsVisible[vg]) return false;
      if (hideKubeSystem && isKubeSystem(f)) return false;
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
  }, [flowsNoSelf, verdictsVisible, hideKubeSystem, scopeMode, protocolFilter, namespaceFilter, workloadNS, isKubeSystem, isExternal, flowProtocols, hiddenKinds, nodeKinds]);

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
    () => workloads.filter((w) => visibleWorkloadIDs.size === 0 || visibleWorkloadIDs.has(w.id)),
    [workloads, visibleWorkloadIDs],
  );

  const selectedFlow = flows.find((f) => f.id === selectedFlowID) ?? null;
  const selectedWorkload = workloads.find((w) => w.id === selectedWorkloadID) ?? null;
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

  const lastUpdated = q.dataUpdatedAt ? new Date(q.dataUpdatedAt).toLocaleTimeString() : "not loaded";

  // Cluster ID is the route param (/clusters/:id/network) and never changes
  // within this page (the cluster switcher is in the sidebar). We sync the
  // remaining filters into the query string while PRESERVING the current
  // pathname so we don't clobber the cluster route — cluster_id is no longer
  // a query param.
  useEffect(() => {
    const params = new URLSearchParams();
    if (hours !== 24) params.set("hours", String(hours));
    if (namespace) params.set("namespace", namespace);
    if (verdict) params.set("verdict", verdict);
    if (selectedFlowID) params.set("flow", selectedFlowID);
    if (selectedWorkloadID) params.set("workload", selectedWorkloadID);
    const next = params.toString()
      ? `${window.location.pathname}?${params.toString()}`
      : window.location.pathname;
    window.history.replaceState(null, "", next);
  }, [hours, namespace, verdict, selectedFlowID, selectedWorkloadID]);

  const selectFlow = useCallback(
    (flowID: string) => {
      setSelectedFlowID(flowID);
      setSelectedWorkloadID(null);
    },
    [],
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
    [flows, selectedFlowID],
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

  // NeuVector-style compact header: full-bleed canvas, inline stat pills
  // (no 5-tile row), no right-rail (the L2 edge-popover replaces it),
  // single-row filter strip. Canvas fills the viewport.
  const workloadCount = q.data?.summary.workloads ?? workloads.length;
  const flowCount = q.data?.summary.flows ?? flowsRaw.length;
  const volume = fmtBytes(q.data?.summary.total_bytes ?? 0);
  const blocked = flowsRaw.filter((f) => f.state === "denied").length;
  const ready = lifecycleQ.data?.summary.ready ?? 0;

  // B2: canvas-level states. A successful fetch with zero workloads AND zero
  // flows means nothing was tapped in the window (no runtime-agent dp data).
  const noData = q.isSuccess && workloads.length === 0 && flowsRaw.length === 0;

  return (
    <div className="flex h-[calc(100vh-72px)] flex-col gap-2">
      <PageHeader
        title="Network · Traffic Map"
        description="Click an edge for details · Convert to NetworkPolicy"
        actions={
          <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-mono">
            <StatPill icon={<Waypoints className="h-3 w-3" />} label="workloads" value={workloadCount} />
            <StatPill icon={<Activity   className="h-3 w-3" />} label="flows"     value={flowCount} />
            <StatPill icon={<Activity   className="h-3 w-3" />} label="vol"       value={volume} />
            <StatPill icon={<ShieldAlert className="h-3 w-3" />} label="blocked"  value={blocked} tone={blocked > 0 ? "critical" : "neutral"} />
            <StatPill
              icon={<AlertTriangle className="h-3 w-3" />}
              label="threats"
              value={threatsQ.data?.length ?? 0}
              tone={(threatsQ.data?.length ?? 0) > 0 ? "critical" : "neutral"}
              data-testid="netstat-threats"
            />
            <StatPill icon={<GitCompareArrows className="h-3 w-3" />} label="ready" value={ready} tone="accent" />
            <StatusPill label={live ? "live · stream" : "paused"} tone={live ? "success" : "neutral"} />
            <Button size="sm" variant="outline" onClick={() => setLive((c) => !c)}>{live ? "Pause" : "Resume"}</Button>
            <Button size="sm" variant="outline" onClick={() => { void q.refetch(); void lifecycleQ.refetch(); }}>Refresh</Button>
          </div>
        }
      />

      {/* L2 filter chip bar — replaces the legacy select bar except the
          server-side (hours/cluster/namespace/verdict) selects which still
          drive the API queries. */}
      {/* Single-row filter strip. Cluster comes from the URL (we're inside
          /clusters/:id/network). Verdict + namespace are chips, not selects.
          Power-user controls collapse into the "More" dropdown. */}
      <div className="flex flex-wrap items-center gap-1.5 rounded-md border border-border bg-card px-2 py-1.5" data-testid="network-filter-bar">
        <Filter className="h-3 w-3 text-muted-foreground" aria-hidden />
        <select
          className="h-6 rounded border border-input bg-card px-1.5 text-[11px] text-mono outline-none focus:border-[color:var(--color-primary)]"
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
          aria-label="Traffic window"
          data-testid="network-window-select"
        >
          <option value={1}>1h</option>
          <option value={24}>24h</option>
          <option value={168}>7d</option>
        </select>
        {/* Server-side verdict / namespace filters — these thread into the
            network.map / lifecycle queries (distinct from the client-side
            verdict + namespace chips that only re-filter the in-memory graph). */}
        <select
          className="h-6 rounded border border-input bg-card px-1.5 text-[11px] text-mono outline-none focus:border-[color:var(--color-primary)]"
          value={verdict}
          onChange={(e) => setVerdict(e.target.value)}
          aria-label="Verdict filter"
          data-testid="network-verdict-select"
        >
          <option value="">All verdicts</option>
          <option value="allow">Allow</option>
          <option value="alert">Alert</option>
          <option value="block">Block</option>
        </select>
        <select
          className="h-6 max-w-[10rem] rounded border border-input bg-card px-1.5 text-[11px] text-mono outline-none focus:border-[color:var(--color-primary)]"
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
        </select>
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
        <span className="mx-1 h-4 w-px bg-border" aria-hidden />
        {observedProtocols.slice(0, 6).map((p) => (
          <Chip key={p} active={protocolFilter.has(p)} onClick={() => toggleProtocol(p)} data-testid={`netchip-proto-${p}`}>
            {p}
          </Chip>
        ))}
        <span className="mx-1 h-4 w-px bg-border" aria-hidden />
        <NamespaceMultiSelect
          namespaces={namespaces}
          selected={namespaceFilter}
          onToggle={toggleNamespace}
          onClear={() => setNamespaceFilter(new Set())}
        />
        <Chip active={hideKubeSystem} onClick={() => setHideKubeSystem((v) => !v)} data-testid="netchip-hide-kubesystem">
          Hide kube-system
        </Chip>
        <div className="inline-flex overflow-hidden rounded-md border border-border" data-testid="netchip-scope">
          {(["both", "internal", "external"] as ScopeMode[]).map((m) => (
            <button
              key={m}
              type="button"
              className={cn(
                "px-2 py-0.5 text-[10px] capitalize transition-colors",
                scopeMode === m
                  ? "bg-[color-mix(in_oklab,var(--color-primary)_22%,transparent)] text-[color:var(--color-primary)]"
                  : "bg-card text-muted-foreground hover:bg-accent",
              )}
              onClick={() => setScopeMode(m)}
              data-testid={`netchip-scope-${m}`}
            >
              {m === "external" ? "Ext" : m === "internal" ? "Int" : "Both"}
            </button>
          ))}
        </div>
        <span className="ml-auto text-[10px] text-mono text-muted-foreground" data-testid="network-last-updated">{lastUpdated}</span>
      </div>

      {/* Full-bleed canvas — fills the remaining vertical space.
          The L2 edge-popover is the single inspector now (no right rail). */}
      <div className="relative flex-1 min-h-[420px] rounded-lg border border-border bg-card" data-testid="network-map">
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
              icon={<AlertTriangle className="h-8 w-8" aria-hidden />}
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
                    className="text-xs font-medium text-[color:var(--color-primary)] hover:underline"
                    data-testid="network-map-empty-health-link"
                  >
                    View cluster health →
                  </a>
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
          className="flex flex-col gap-1 rounded-md border border-border bg-card/95 p-2 text-[11px] shadow-[var(--elev-2)] backdrop-blur"
          data-testid="network-verdict-legend"
        >
          <div className="px-1 text-[9px] uppercase tracking-wider text-muted-foreground">Legend</div>
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
          <div className="mt-1 border-t border-border/60 pt-1 text-[10px] text-muted-foreground">
            <div className="flex items-center gap-1.5"><span aria-hidden className="h-px w-4 bg-muted-foreground" /> <span>fresh ≤ 5 min</span></div>
            <div className="flex items-center gap-1.5"><span aria-hidden className="h-px w-4 bg-muted-foreground/40" style={{ borderTop: "1px dashed currentColor", background: "transparent" }} /> <span>stale (~total)</span></div>
          </div>
          {/* Endpoint-kind visibility toggles. `unmanaged` (unresolved in-cluster
              IPs / infra noise) is hidden by default; click to show. */}
          <div className="mt-1 border-t border-border/60 pt-1">
            <div className="px-1 text-[9px] uppercase tracking-wider text-muted-foreground">Endpoints</div>
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
          threats={threatsQ.data ?? []}
          flows={flows}
          onPivot={(flowID) => {
            selectFlow(flowID);
            setPopoverOpen(true);
          }}
        />
        </div>
        {/* Live sessions (NV RESTSession) — bottom-left collapsible card fed by the
            runtime-agent's dp ctrl_list_session snapshot. Sits above the netpol status bar. */}
        <div className="absolute bottom-14 left-3 z-10">
          <LiveSessionsCard sessions={sessionsQ.data ?? []} loading={sessionsQ.isPending} />
        </div>
        {/* Selected-workload mini panel — bottom-right floating, only when a
            workload (not an edge) is selected. Edge selection opens the
            FlowInspectorPopover overlay instead. */}
        {selectedWorkload && (
          <div className="absolute bottom-3 right-3 z-10 max-w-[300px] rounded-md border border-border bg-card/95 p-3 shadow-[var(--elev-2)] backdrop-blur" data-testid="network-workload-panel">
            <WorkloadDrilldown
              workload={selectedWorkload}
              flows={flows}
              onSelectFlow={(id) => { selectFlow(id); setPopoverOpen(true); }}
            />
            <div className="mt-2 flex items-center justify-between">
              {selectedWorkload.kind !== "External" && clusterID ? (
                <button
                  type="button"
                  disabled={quarantineMut.isPending}
                  onClick={() => {
                    const reason = window.prompt(`Quarantine ${selectedWorkload.id}? Enter a reason:`, "manual isolation from network map");
                    if (reason) quarantineMut.mutate({ workload: selectedWorkload.id, reason });
                  }}
                  className="inline-flex items-center gap-1 rounded border border-[color:var(--color-severity-critical)] px-2 py-0.5 text-[10px] font-medium text-[color:var(--color-severity-critical)] hover:bg-[color:color-mix(in_oklab,var(--color-severity-critical)_12%,transparent)] disabled:opacity-40"
                >
                  <Ban className="h-3 w-3" /> Quarantine
                </button>
              ) : <span />}
              <button
                type="button"
                onClick={() => setSelectedWorkloadID(null)}
                className="text-[10px] text-muted-foreground hover:text-foreground"
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
          pending={action.isPending}
          rollbackPending={rollback.isPending}
          actionError={actionError}
          onSelect={(workload) => {
            setSelectedWorkloadID(workload);
            setSelectedFlowID(null);
          }}
          onAction={(workload, kind, reason, candidateHash) => action.mutate({ workload, kind, reason, candidateHash })}
          onRollback={(workload, rollbackRef, reason) => rollback.mutate({ workload, rollbackRef, reason })}
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
        clusterID={clusterID}
        hours={hours}
        recentFlows={liveFlows}
        threats={threatsQ.data ?? []}
        lifecycle={lifecycleItems}
        onOpenChange={(o) => {
          setPopoverOpen(o);
          if (!o) setSelectedFlowID(null);
        }}
        onStep={stepFlow}
      />
    </div>
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
        "inline-flex h-6 items-center gap-1 rounded border px-2 text-[11px] text-mono whitespace-nowrap transition-colors",
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
          "inline-flex h-6 items-center gap-1 rounded border px-2 text-[11px] text-mono whitespace-nowrap transition-colors",
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
            className="block w-full rounded px-2 py-1 text-left text-[11px] text-muted-foreground hover:bg-accent"
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
                  "block w-full rounded px-2 py-1 text-left text-[11px] transition-colors",
                  on ? "bg-accent text-foreground" : "text-muted-foreground hover:bg-accent/60",
                )}
                aria-pressed={on}
              >
                {on ? "● " : "○ "} {ns}
              </button>
            );
          })}
          {namespaces.length === 0 && <div className="px-2 py-2 text-[11px] text-muted-foreground">No namespaces in window</div>}
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
  recentFlows: NetworkRecentFlow[];
  threats: RuntimeThreat[];
  lifecycle: NetworkPolicyLifecycle[];
  onOpenChange: (open: boolean) => void;
  onStep: (delta: number) => void;
}) {
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
              <div className="mt-0.5 flex items-center gap-2 text-[10px] text-muted-foreground">
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
              <RadixTabs.Content value="streams" className="outline-none">
                <StreamsTab flow={flow} clusterID={clusterID} hours={hours} active={tab === "streams"} />
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
              onClick={() => {
                // POSTs to existing preview endpoint — see PolicyTab for the
                // YAML used; rate-limit is the network policy lifecycle queue.
                // Capture a real approval reason; abort if the user cancels or
                // leaves it blank rather than sending a fabricated one.
                const reason = window.prompt("Reason for converting to NetworkPolicy?")?.trim();
                if (!reason) return;
                void network
                  .policyAction(flow.src, "approve", { reason })
                  .catch(() => {
                    /* surfaced through query invalidation */
                  });
              }}
              data-testid="network-flow-inspector-convert"
            >
              Convert to NetworkPolicy
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

// StreamsTab shows the FULL conversation between the two endpoints (NV's per-conversation
// drill-down): every protocol/port/application stream with directional in/out bytes +
// session counts. One clicked edge is a single proto/port; this consolidates the whole pair.
function StreamsTab({ flow, clusterID, hours, active }: { flow: NetworkFlow; clusterID: string; hours: number; active: boolean }) {
  const q = useQuery({
    queryKey: ["conv-entries", clusterID, flow.src, flow.dst, hours],
    queryFn: () => network.conversationEntries({ from: flow.src, to: flow.dst, cluster_id: clusterID || undefined, hours }),
    enabled: active && !!flow.src && !!flow.dst,
    staleTime: 30_000,
  });
  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading streams…</p>;
  const data = q.data;
  const entries = data?.entries ?? [];
  if (entries.length === 0) return <p className="text-xs text-muted-foreground">No aggregated streams recorded for this pair in the window.</p>;
  const t = data!.totals;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-2">
        <Field label="Streams" value={String(entries.length)} />
        <Field label="In (→)" value={formatBytes(t.client_bytes)} />
        <Field label="Out (←)" value={formatBytes(t.server_bytes)} />
        <Field label="Sessions" value={t.sessions.toLocaleString()} />
        <Field label="Total bytes" value={formatBytes(t.bytes)} />
        <Field label="Packets" value={t.packets.toLocaleString()} />
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-[11px]">
          <thead>
            <tr className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
              <th className="py-1 pr-2 font-medium">Proto / App</th>
              <th className="py-1 pr-2 font-medium">Port</th>
              <th className="py-1 pr-2 text-right font-medium">In →</th>
              <th className="py-1 pr-2 text-right font-medium">Out ←</th>
              <th className="py-1 pr-2 text-right font-medium">Sess</th>
              <th className="py-1 font-medium">Verdict</th>
            </tr>
          </thead>
          <tbody className="text-mono">
            {entries.map((e, i) => (
              <tr key={i} className="border-t border-border/50">
                <td className="py-1 pr-2">{e.protocol}{e.application ? <span className="text-muted-foreground">/{e.application}</span> : ""}</td>
                <td className="py-1 pr-2 text-muted-foreground">{e.port || "—"}</td>
                <td className="py-1 pr-2 text-right">{formatBytes(e.client_bytes)}</td>
                <td className="py-1 pr-2 text-right">{formatBytes(e.server_bytes)}</td>
                <td className="py-1 pr-2 text-right">{e.sessions.toLocaleString()}</td>
                <td className="py-1">
                  <span className={cn("rounded px-1 text-[10px]", e.verdict === "deny" ? "text-[color:var(--color-status-error)]" : "text-muted-foreground")}>{e.verdict}</span>
                  {e.threat_id > 0 && <span className="ml-1 text-[color:var(--color-status-error)]" title={`threat ${e.threat_id}`}>⚠</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[10px] leading-tight text-muted-foreground/80">
        In = {shortName(flow.src)}→{shortName(flow.dst)} payload; Out = responses. Directional bytes are populated on DPI (dp) flows; other sources report totals only.
      </p>
    </div>
  );
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
          className="flex items-center gap-2 rounded border border-border bg-card/60 px-2 py-1.5 text-[11px] text-muted-foreground"
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
        <Field label="Destination" value={formatEndpoint(flow.dst_addr, flow.dst_port)} />
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
      </dl>
      {hasThreat && (
        <div
          className="rounded border border-[color:var(--color-status-error)] bg-card/60 p-2 text-[11px]"
          data-testid="network-flow-tab-threat"
        >
          <div className="mb-1 flex items-center gap-1.5 text-[color:var(--color-status-error)]">
            <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
            <span className="font-semibold">DPI threat detected</span>
          </div>
          <dl className="grid grid-cols-2 gap-1 text-muted-foreground">
            <Field
              label="Threat"
              value={matchedThreat?.threat_name || matchedThreat?.msg || `signature ${flow.threat_id}`}
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
              <span className="text-[10px] text-muted-foreground">
                {severityLabel(t.severity)} · {threatActionLabel(t.action)}
              </span>
            </div>
            {t.msg && (
              <div className="mt-1 text-[11px] text-muted-foreground">{t.msg}</div>
            )}
            <div className="mt-1 text-mono text-[10px] text-muted-foreground">
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
      <div className="flex items-center gap-2 text-[11px]">
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
                "flex items-center justify-between gap-2 rounded border px-2 py-1 text-[11px]",
                t.included
                  ? "border-border bg-card"
                  : "border-[color:var(--color-status-warning)]/40 bg-muted/40 text-muted-foreground",
              )}
            >
              <span className="text-mono">
                {t.direction} · {shortName(t.peer)} · {t.protocol}/{t.port}
              </span>
              <span className="text-[10px]">
                {t.included ? t.verdict : `excluded: ${t.exclude_reason || "n/a"}`}
              </span>
            </li>
          ))}
        </ul>
      )}
      {yaml && (
        <pre className="max-h-64 overflow-auto rounded-md bg-muted p-3 text-[11px] leading-tight">{yaml}</pre>
      )}
    </div>
  );
}

function HistoryTab({ data, samples }: { data: number[]; samples: NetworkRecentFlow[] }) {
  const max = Math.max(...data, 1);
  return (
    <div className="space-y-3" data-testid="network-history-tab">
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Bytes / 24h (binned)</div>
        <div className="mt-2 rounded-md border border-border bg-muted/30 p-3">
          <Sparkline data={data} width={420} height={64} strokeWidth={1.5} />
          <div className="mt-1 flex items-center justify-between text-[10px] text-muted-foreground">
            <span>peak {formatBytes(max)}</span>
            <span>{samples.length} samples</span>
          </div>
        </div>
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Recent samples</div>
        <ul className="mt-2 space-y-1 text-[11px]">
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

function WorkloadDrilldown({ workload, flows, onSelectFlow }: { workload: NetworkWorkload; flows: NetworkFlow[]; onSelectFlow: (flowID: string) => void }) {
  const [tab, setTab] = useState<"ingress" | "egress">("egress");
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
        </div>
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
      </div>
    </div>
  );
}

function PolicyLifecyclePanel({
  item,
  items,
  pending,
  rollbackPending,
  actionError,
  onSelect,
  onAction,
  onRollback,
}: {
  item: NetworkPolicyLifecycle | null;
  items: NetworkPolicyLifecycle[];
  pending: boolean;
  rollbackPending: boolean;
  actionError: string;
  onSelect: (workload: string) => void;
  onAction: (workload: string, kind: "approve" | "apply" | "demote", reason?: string, candidateHash?: string) => void;
  onRollback: (workload: string, rollbackRef: string, reason?: string) => void;
}) {
  const [reason, setReason] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");
  const [rollbackPreviewOpen, setRollbackPreviewOpen] = useState(false);
  const [manifestFlavor, setManifestFlavor] = useState("cilium");

  useEffect(() => {
    setReason("");
    setRollbackReason("");
    setRollbackPreviewOpen(false);
    setManifestFlavor("cilium");
  }, [item?.workload]);

  if (!item) {
    return (
      <section className="mt-4 border-t border-border pt-4" data-testid="network-policy-lifecycle">
        <h2 className="text-sm font-semibold">Network policy lifecycle</h2>
        <p className="mt-1 text-xs text-muted-foreground">No lifecycle data is available for the current traffic window.</p>
      </section>
    );
  }
  const isStale = item.candidate_stale || Boolean(item.approved_candidate_hash && item.candidate_hash && item.approved_candidate_hash !== item.candidate_hash);
  const canApprove = (item.approval_status === "pending" || isStale) && Boolean(item.target_mode);
  const canApply = item.approval_status === "approved" && Boolean(item.target_mode) && !isStale;
  const canDemote = item.current_mode !== "discover";
  const canRollback = item.rollback_available && Boolean(item.rollback_ref);
  const persistedActions = item.audit_trail.filter((event) => ["approve", "apply", "demote", "rollback"].includes(event.action));
  const lastIdempotencyKey = [...item.audit_trail].reverse().find((event) => event.idempotency_key)?.idempotency_key;
  const tuplePreview = item.tuple_preview ?? [];
  const manifests = Object.keys(item.preview.manifests ?? {}).length > 0
    ? item.preview.manifests ?? {}
    : { [item.preview.engine || "cilium"]: item.preview.yaml };
  const manifestFlavors = ["native", "cilium", "calico"].filter((flavor) => Boolean(manifests[flavor]));
  const activeManifestFlavor = manifests[manifestFlavor] ? manifestFlavor : manifestFlavors[0] ?? item.preview.engine ?? "cilium";
  const activeManifest = manifests[activeManifestFlavor] ?? item.preview.yaml;
  const applyStatuses = item.apply_statuses ?? [];
  const latestApplyStatus = [...applyStatuses].sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))[0];
  const actionState = canApprove
    ? `Awaiting approval for ${item.target_mode}`
    : isStale
      ? "Review updated candidate"
      : canApply
      ? `Approved, ready to apply ${item.target_mode}`
      : canRollback
        ? `Rollback available for ${item.current_mode}`
        : item.approval_status;
  return (
    <section className="mt-4 space-y-3 border-t border-border pt-4" data-testid="network-policy-lifecycle">
      <div>
        <h2 className="text-sm font-semibold">Network policy lifecycle</h2>
        <p className="mt-1 text-xs text-muted-foreground">
          Policy for <span className="font-mono">{item.workload}</span>
          {item.cluster_name && <span> on {item.cluster_name}</span>}
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2" data-testid="network-policy-action-bar">
        <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground" data-testid="network-policy-dry-run-badge">
          {persistedActions.length > 0 ? "state persisted" : "preview only"}
        </span>
        <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
          cluster apply gated
        </span>
        {manifestFlavors.length > 1 && (
          <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
            {manifestFlavors.length} manifests
          </span>
        )}
        <ModeBadge mode={item.current_mode} />
        {item.target_mode && (
          <>
            <span className="text-xs text-muted-foreground">to</span>
            <ModeBadge mode={item.target_mode} />
          </>
        )}
        <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">{item.approval_status}</span>
        {item.rollback_available && <span className="rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">rollback ready</span>}
        {isStale && <span className="rounded-md bg-muted px-2 py-1 text-xs text-status-warning" data-testid="network-policy-stale-badge">candidate changed</span>}
      </div>
      {(isStale || actionError) && (
        <div className="rounded-md border border-[color:var(--color-status-warning)]/40 bg-muted p-2 text-xs text-muted-foreground" data-testid="network-policy-stale-warning">
          {actionError || item.stale_reason || "Observed traffic changed since approval. Review the updated candidate before applying."}
        </div>
      )}
      {actionError && (
        <div className="rounded-md border border-border p-2 text-xs text-status-error" data-testid="network-policy-action-error">
          {actionError}
        </div>
      )}
      <div className="rounded-md border border-border p-2 text-xs text-muted-foreground" data-testid="network-policy-action-state">
        <div>{actionState}</div>
        <div className="mt-1 font-mono">{lastIdempotencyKey ? `retry key ${lastIdempotencyKey}` : "retry key pending"}</div>
      </div>
      <div className="rounded-md border border-border p-2 text-xs text-muted-foreground" data-testid="network-policy-apply-status">
        {latestApplyStatus ? (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-medium text-foreground">Live applier</span>
              <span className="rounded bg-muted px-1.5 py-0.5">{latestApplyStatus.flavor}</span>
              <span className={latestApplyStatus.status === "ok" ? "text-[color:var(--color-status-success)]" : "text-[color:var(--color-status-error)]"}>
                {latestApplyStatus.last_action} {latestApplyStatus.status}
              </span>
              <span>{new Date(latestApplyStatus.updated_at).toLocaleTimeString()}</span>
            </div>
            {latestApplyStatus.resource_ref && <div className="mt-1 break-all font-mono">{latestApplyStatus.resource_ref}</div>}
            {latestApplyStatus.error && <div className="mt-1 text-status-error">{latestApplyStatus.error}</div>}
          </>
        ) : (
          <span>Live applier has not reported for this policy.</span>
        )}
      </div>
      <p className="text-xs text-muted-foreground">{item.reason}</p>
      {item.preview.l7_protocols && item.preview.l7_protocols.length > 0 && (
        <div className="rounded-md border border-border p-2 text-xs text-muted-foreground" data-testid="network-policy-l7-intent">
          L7 intent preserved as manifest metadata: {item.preview.l7_protocols.join(", ")}
        </div>
      )}
      <div className="rounded-md border border-border p-3 text-xs" data-testid="network-policy-candidate-card">
        <div className="grid grid-cols-2 gap-2">
          <div data-testid="network-policy-candidate-hash"><Field label="Candidate" value={item.candidate_hash ? item.candidate_hash.slice(0, 12) : "pending"} /></div>
          <div data-testid="network-policy-generated-at"><Field label="Generated" value={item.generated_at ? new Date(item.generated_at).toLocaleTimeString() : "pending"} /></div>
          <div data-testid="network-policy-approved-candidate-hash"><Field label="Approved candidate" value={item.approved_candidate_hash ? item.approved_candidate_hash.slice(0, 12) : "none"} /></div>
          <Field label="Stale" value={isStale ? "yes" : "no"} />
        </div>
      </div>
      {tuplePreview.length > 0 && (
        <div className="rounded-md border border-border p-3" data-testid="network-policy-tuple-preview">
          <div className="text-xs font-medium">Observed tuples</div>
          <ul className="mt-2 max-h-44 space-y-1 overflow-auto text-xs text-muted-foreground">
            {tuplePreview.map((tuple) => (
              <li
                key={`${tuple.direction}-${tuple.peer}-${tuple.protocol}-${tuple.port}-${tuple.verdict}-${tuple.l7_protocol ?? ""}`}
                className="grid grid-cols-[64px_minmax(0,1fr)_86px_58px_90px] gap-2 rounded-sm bg-muted/60 px-2 py-1"
                data-testid={tuple.included ? "network-policy-included-tuple" : "network-policy-held-tuple"}
              >
                <span className="font-mono">{tuple.direction}</span>
                <span className="truncate">{tuple.peer}</span>
                <span>{tuple.l7_protocol ? `${tuple.l7_protocol} ` : ""}{tuple.protocol}/{tuple.port}</span>
                <span>{tuple.samples}x</span>
                <span className={tuple.included ? "text-[color:var(--color-status-success)]" : "text-[color:var(--color-status-warning)]"}>
                  {tuple.included ? "included" : tuple.exclude_reason || tuple.verdict}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <dl className="grid grid-cols-2 gap-2 text-xs">
        <Field label="Flows" value={`${item.summary.total_flows}`} />
        <Field label="Peers" value={`${item.summary.unique_peers}`} />
        <Field label="Alerts" value={`${item.summary.out_of_policy_alerts}`} />
        <Field label="Rollback" value={item.rollback_available ? "available" : "not ready"} />
        <Field label="Cluster" value={item.cluster_name || item.cluster_id || "default"} />
        <Field label="Applied ref" value={item.applied_ref || "pending"} />
        <Field label="Rollback ref" value={item.rollback_ref || "none"} />
      </dl>
      <div className="flex flex-wrap gap-2">
        {canApprove && (
          <button
            type="button"
            data-testid="network-policy-approve"
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent"
            disabled={pending}
            onClick={() => onAction(item.workload, "approve", undefined, item.candidate_hash)}
          >
            Approve {item.target_mode}
          </button>
        )}
        {canApply && (
          <button
            type="button"
            data-testid="network-policy-apply"
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent"
            disabled={pending}
            onClick={() => onAction(item.workload, "apply", undefined, item.candidate_hash)}
          >
            Apply policy
          </button>
        )}
      </div>
      {canDemote && (
      <div className="space-y-2">
        <input
          data-testid="network-policy-demote-reason"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder={item.current_mode === "discover" ? "Already in discover" : "Demotion reason"}
          aria-label="Network policy demotion reason"
          className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
          disabled={item.current_mode === "discover"}
        />
        <button
          type="button"
          data-testid="network-policy-demote"
          className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent disabled:opacity-50"
          disabled={pending || item.current_mode === "discover" || reason.trim() === ""}
          onClick={() => onAction(item.workload, "demote", reason)}
        >
          Demote
        </button>
      </div>
      )}
      {canRollback && item.rollback_ref && (
        <div className="space-y-2 rounded-md border border-border p-3" data-testid="network-policy-rollback-card">
          <div className="text-xs font-medium" data-testid="network-policy-rollback-status">Rollback ready</div>
          <div className="break-all font-mono text-xs text-muted-foreground" data-testid="network-policy-rollback-ref">{item.rollback_ref}</div>
          <button
            type="button"
            data-testid="network-policy-rollback-preview-toggle"
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent"
            onClick={() => setRollbackPreviewOpen((open) => !open)}
          >
            {rollbackPreviewOpen ? "Hide rollback preview" : "Preview rollback"}
          </button>
          {rollbackPreviewOpen && (
            <>
              <pre className="max-h-40 overflow-auto rounded-md bg-muted p-3 text-xs" data-testid="network-policy-rollback-preview">
                {activeManifest}
              </pre>
              <div className="rounded-md border border-border p-3" data-testid="network-policy-rollback-diff">
                <div className="text-xs font-medium">Rollback diff</div>
                <p className="mt-1 text-xs text-muted-foreground">Restores the previous policy bundle and clears the current rollback window.</p>
              </div>
            </>
          )}
          <input
            data-testid="network-policy-rollback-reason"
            value={rollbackReason}
            onChange={(e) => setRollbackReason(e.target.value)}
            placeholder="Rollback reason"
            aria-label="Network policy rollback reason"
            className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
          />
          <button
            type="button"
            data-testid="network-policy-rollback"
            className="rounded-md border border-border px-2.5 py-1 text-xs hover:bg-accent disabled:opacity-50"
            disabled={rollbackPending}
            onClick={() => onRollback(item.workload, item.rollback_ref ?? "", rollbackReason)}
          >
            Roll back
          </button>
        </div>
      )}
      <div>
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-medium">Lifecycle policy preview</h3>
          {manifestFlavors.length > 1 && (
            <div className="flex rounded-md border border-border p-0.5" data-testid="network-policy-manifest-tabs">
              {manifestFlavors.map((flavor) => (
                <button
                  key={flavor}
                  type="button"
                  className={`rounded px-2 py-1 text-xs ${activeManifestFlavor === flavor ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                  onClick={() => setManifestFlavor(flavor)}
                  data-testid={`network-policy-manifest-${flavor}`}
                >
                  {flavor}
                </button>
              ))}
            </div>
          )}
        </div>
        <pre className="max-h-52 overflow-auto rounded-md bg-muted p-3 text-xs" data-testid="network-policy-preview">
          {activeManifest}
        </pre>
      </div>
      <div className="rounded-md border border-border p-3" data-testid="network-policy-diff">
        <div className="text-xs font-medium">Diff</div>
        <p className="mt-1 text-xs text-muted-foreground">{item.diff.summary}</p>
        <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
          {[...item.diff.added, ...item.diff.changed, ...item.diff.removed].map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
      <div className="rounded-md border border-border p-3" data-testid="network-policy-audit-trail">
        <div className="text-xs font-medium">Audit trail</div>
        <ul className="mt-2 max-h-36 space-y-1 overflow-auto text-xs text-muted-foreground">
          {item.audit_trail.slice(-5).map((event) => (
            <li key={`${event.at}-${event.action}-${event.actor}`}>
              <span className="font-mono">{event.action}</span> · {event.message}
            </li>
          ))}
        </ul>
      </div>
      <div className="space-y-1" data-testid="network-policy-lifecycle-rail">
        {items.map((row) => (
          <button
            key={row.workload}
            type="button"
            data-testid="network-policy-lifecycle-row"
            className={`flex w-full items-center justify-between gap-2 rounded-md px-2 py-1.5 text-left text-xs ${
              row.workload === item.workload ? "bg-accent text-foreground" : "bg-muted text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => onSelect(row.workload)}
          >
            <span className="truncate font-mono">{row.workload}</span>
            <ModeBadge mode={row.current_mode} />
          </button>
        ))}
      </div>
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
          <div className="flex items-center gap-1 truncate text-[11px] text-muted-foreground">
            <span className="truncate">{workload.namespace}</span>
            {/* NET-1: endpoint kind from /network/conversations node_kinds.
                Only badge off-cluster kinds; managed workloads stay clean. */}
            {kind && kind !== "workload" && (
              <span
                className="shrink-0 rounded-sm border border-border bg-muted px-1 text-[9px] uppercase tracking-wide"
                data-testid={`network-node-kind-${kind}`}
              >
                {kind}
              </span>
            )}
            {modeColor && (
              <span
                className="shrink-0 rounded-sm px-1 text-[9px] uppercase tracking-wide font-medium"
                style={{ background: `color-mix(in oklab, ${modeColor} 18%, transparent)`, color: modeColor }}
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
          className="absolute -right-2 -top-2 inline-flex items-center gap-0.5 rounded-full border border-border bg-card px-2 py-0.5 text-[10px] font-mono shadow-[var(--elev-1)]"
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
      <span className={cn("text-mono text-[12px] font-semibold tabular-nums", toneClass)}>{value}</span>
      <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</span>
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
function LiveSessionsCard({ sessions, loading }: { sessions: import("@/api/client").NetworkSession[]; loading: boolean }) {
  const [collapsed, setCollapsed] = useState(true);
  const count = sessions.length;
  return (
    <div className={cn("rounded-md border border-border bg-card/95 p-2 text-[11px] shadow-[var(--elev-2)] backdrop-blur", collapsed ? "w-auto" : "w-[440px] max-w-[80vw]")}
      data-testid="network-sessions-card">
      <div className="flex items-center justify-between gap-2 px-1 text-[10px] uppercase tracking-wider text-muted-foreground">
        <span className="flex items-center gap-1"><Activity className="h-3 w-3" aria-hidden />Live sessions · {loading ? "…" : count}</span>
        <button type="button" onClick={() => setCollapsed((v) => !v)}
          className="rounded p-0.5 hover:text-foreground" title={collapsed ? "Expand live sessions" : "Collapse live sessions"}
          data-testid="network-sessions-toggle">
          {collapsed ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
        </button>
      </div>
      {!collapsed && (
        <div className="mt-1">
          {loading ? (
            <p className="px-1 py-2 text-muted-foreground">Loading…</p>
          ) : count === 0 ? (
            <p className="px-1 py-2 leading-tight text-muted-foreground/80">
              No live sessions reported. The runtime-agent's data-plane uploads its
              ctrl_list_session table every 15s; connections that dp is actively tracking appear here.
            </p>
          ) : (
            <div className="max-h-[300px] overflow-auto">
              <table className="w-full text-[10px]">
                <thead className="sticky top-0 bg-card">
                  <tr className="text-left uppercase tracking-wider text-muted-foreground">
                    <th className="py-1 pr-2 font-medium">Client</th>
                    <th className="py-1 pr-2 font-medium">Server</th>
                    <th className="py-1 pr-2 font-medium">App</th>
                    <th className="py-1 pr-2 font-medium">State</th>
                    <th className="py-1 pr-2 text-right font-medium">In</th>
                    <th className="py-1 pr-2 text-right font-medium">Out</th>
                    <th className="py-1 text-right font-medium">Age</th>
                  </tr>
                </thead>
                <tbody className="text-mono">
                  {sessions.slice(0, 200).map((s) => (
                    <tr key={s.node + s.id} className="border-t border-border/40">
                      <td className="py-1 pr-2">{s.client_ip}:{s.client_port}</td>
                      <td className="py-1 pr-2">{s.server_ip}:{s.server_port}</td>
                      <td className="py-1 pr-2 text-muted-foreground">{s.application}</td>
                      <td className="py-1 pr-2 text-muted-foreground">{s.client_state || s.ip_proto}{s.threat_id ? <span className="ml-1 text-[color:var(--color-status-error)]" title={`threat ${s.threat_id}`}>⚠</span> : null}</td>
                      <td className="py-1 pr-2 text-right">{formatBytes(s.client_bytes)}</td>
                      <td className="py-1 pr-2 text-right">{formatBytes(s.server_bytes)}</td>
                      <td className="py-1 text-right text-muted-foreground">{s.age}s</td>
                    </tr>
                  ))}
                </tbody>
              </table>
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
  onPivot,
}: {
  threats: RuntimeThreat[];
  flows: NetworkFlow[];
  onPivot: (flowID: string) => void;
}) {
  const [drilldownID, setDrilldownID] = useState<string | null>(null);
  // Start collapsed so the card never auto-opens over the canvas — it's a compact
  // "DPI threats · N" pill the operator expands on demand (keeps the map unobstructed).
  const [collapsed, setCollapsed] = useState(true);
  if (threats.length === 0) return null;
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
  return (
    <>
      <div
        className={cn(
          "max-w-[80vw] rounded-md border border-[color:var(--color-status-error)]/60 bg-card/95 p-2 text-[11px] shadow-[var(--elev-2)] backdrop-blur",
          collapsed ? "w-auto" : "w-[340px]",
        )}
        data-testid="network-threats-card"
      >
        <div className="mb-1 flex items-center justify-between px-1 text-[10px] uppercase tracking-wider text-[color:var(--color-status-error)]">
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
        <p className="mb-1 px-1 text-[9px] leading-tight text-muted-foreground/80">
          DPI signatures matched on observed traffic. In monitor mode these are logged, not blocked — click a row for the packet &amp; full context.
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
                    <div className="truncate text-[10px] text-muted-foreground">
                      {t.src_ip}:{t.src_port} → {t.dst_ip}:{t.dst_port}
                      {t.severity > 0 && (
                        <span className="ml-1 rounded bg-[color:var(--color-status-error)]/15 px-1 text-[color:var(--color-status-error)]">
                          {severityLabel(t.severity)}
                        </span>
                      )}
                      <span className="ml-1 text-muted-foreground/70">· {threatActionLabel(t.action)}</span>
                    </div>
                    {t.msg && (
                      <div className="truncate text-[10px] text-muted-foreground/80" title={t.msg}>
                        {t.msg}
                      </div>
                    )}
                  </button>
                  {flowID && (
                    <button
                      type="button"
                      onClick={() => onPivot(flowID)}
                      className="border-l border-border/60 px-1.5 text-[9px] uppercase tracking-wider text-muted-foreground hover:text-foreground"
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
          <div className="mt-1 border-t border-border/60 pt-1 px-1 text-[10px] text-muted-foreground">
            + {threats.length - recent.length} more in window
          </div>
        )}
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
  const q = useQuery({
    queryKey: ["runtime-threat", id],
    queryFn: () => runtimeThreats.get(id),
  });
  const detail: RuntimeThreatDetail | undefined = q.data;
  const bytes = useMemo(() => decodeBase64(detail?.packet ?? ""), [detail?.packet]);
  return (
    <Dialog.Root open onOpenChange={(o) => { if (!o) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay
          className="fixed inset-0 z-40 bg-background/30 backdrop-blur-[1px]"
          data-testid="network-threat-dialog-overlay"
        />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 flex h-[640px] w-[720px] -translate-x-1/2 -translate-y-1/2 flex-col rounded-lg border border-border bg-card shadow-[var(--elev-3)] focus:outline-none"
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
                  <span className="rounded bg-[color:var(--color-status-error)]/15 px-1.5 py-0.5 text-[10px] text-[color:var(--color-status-error)]">
                    severity {detail.severity}
                  </span>
                )}
              </Dialog.Title>
              {detail?.msg && (
                <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{detail.msg}</div>
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
            {detail && (
              <div className="space-y-4">
                <ThreatMetaGrid t={detail} />
                {detail.l7 && <ThreatL7Pane l7={detail.l7} />}
                <ThreatPacketDump bytes={bytes} capLen={detail.cap_len ?? 0} />
                <ThreatPcapCapturePane threat={detail} />
              </div>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ThreatPcapCapturePane — Wave C3. Operator can request a 30s pcap on the
// workload that tripped the threat, then download the .pcap when the agent
// finishes. The control plane creates the row immediately; status is
// polled while we're in the dialog so the button transitions inline.
function ThreatPcapCapturePane({ threat }: { threat: RuntimeThreatDetail }) {
  // We deliberately key on `threat.id` so navigating between threats in
  // the dialog resets the local capture state.
  const [activeCapture, setActiveCapture] = useState<PcapCapture | null>(null);
  const [duration, setDuration] = useState(30);
  // Workload is derived from threat.ep_mac → flow workload — but the
  // threat row carries only ep_mac, not workload. We don't have a clean
  // mapping here in the UI today; the operator can edit the workload
  // field before clicking Capture. Default to <ns>/<deploy> if known.
  const [workload, setWorkload] = useState("");

  const start = useMutation({
    mutationFn: async (): Promise<PcapCapture> => {
      if (!workload) throw new Error("workload is required");
      return runtimePcap.start({
        cluster_id: threat.cluster_id,
        workload,
        duration_s: Math.min(60, Math.max(5, duration)),
        // Stamp the 5-tuple from the threat onto the request so the
        // agent's tcpdump filter narrows to this specific conversation.
        src_ip:    threat.src_ip,
        dst_ip:    threat.dst_ip,
        dst_port:  threat.dst_port,
        protocol:  threat.ip_proto === 6 ? "tcp" : threat.ip_proto === 17 ? "udp" : undefined,
      });
    },
    onSuccess: setActiveCapture,
  });

  // Poll the capture row while it's pending/running so the UI updates
  // when the agent picks it up + finishes.
  const refresh = useQuery({
    queryKey: ["pcap-capture", activeCapture?.id],
    queryFn: () => runtimePcap.get(activeCapture!.id),
    enabled: !!activeCapture &&
             (activeCapture.status === "pending" || activeCapture.status === "running"),
    refetchInterval: 2000,
  });
  // Replace the cached row when the refetch comes back with a state change.
  useEffect(() => {
    if (refresh.data && refresh.data.status !== activeCapture?.status) {
      setActiveCapture(refresh.data);
    }
  }, [refresh.data, activeCapture?.status]);

  const cap = activeCapture;
  return (
    <div className="rounded border border-border bg-card/50 p-3" data-testid="threat-pcap-pane">
      <div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
        <span>Live capture</span>
        {cap && (
          <span className="rounded bg-accent px-1.5 py-0.5 font-mono text-foreground">
            {cap.status}
          </span>
        )}
      </div>
      {!cap && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-[11px]">
            <span className="text-muted-foreground">Workload</span>
            <input
              type="text"
              value={workload}
              onChange={(e) => setWorkload(e.target.value)}
              placeholder="namespace/deployment"
              className="flex-1 rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]"
              data-testid="threat-pcap-workload"
            />
            <span className="text-muted-foreground">for</span>
            <input
              type="number"
              min={5}
              max={60}
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              className="w-16 rounded border border-input bg-background px-2 py-1 text-xs outline-none focus:border-[color:var(--color-primary)]"
              data-testid="threat-pcap-duration"
            />
            <span className="text-muted-foreground">seconds</span>
          </div>
          <Button
            size="sm"
            onClick={() => start.mutate()}
            disabled={start.isPending || !workload}
            data-testid="threat-pcap-start"
          >
            {start.isPending ? "Requesting…" : `Capture next ${Math.min(60, Math.max(5, duration))}s`}
          </Button>
          {start.error && (
            <div className="text-[11px] text-[color:var(--color-status-error)]">
              {(start.error as Error).message}
            </div>
          )}
        </div>
      )}
      {cap && cap.status === "pending" && (
        <div className="text-[11px] text-muted-foreground">
          Waiting for a runtime-agent on cluster <span className="text-mono">{cap.cluster_id.slice(0, 8)}</span>{" "}
          to pick this up…
        </div>
      )}
      {cap && cap.status === "running" && (
        <div className="text-[11px] text-muted-foreground">
          Capturing on node <span className="text-mono">{cap.claimed_by_node}</span> for {cap.duration_s}s…
        </div>
      )}
      {cap && cap.status === "completed" && (
        <div className="space-y-1 text-[11px]">
          <div className="text-muted-foreground">
            {((cap.file_size_bytes ?? 0) / 1024).toFixed(1)} KB ·{" "}
            {cap.packet_count ?? 0} packets ·{" "}
            sha256 <span className="text-mono">{(cap.sha256 ?? "").slice(0, 12)}…</span>
          </div>
          <button
            type="button"
            onClick={() => runtimePcap.download(cap.id).catch((e: Error) => toast.error(`PCAP download failed: ${e.message}`))}
            className="inline-block rounded border border-border bg-card px-2 py-1 text-foreground hover:bg-accent"
            data-testid="threat-pcap-download"
          >
            Download .pcap
          </button>
        </div>
      )}
      {cap && cap.status === "failed" && (
        <div className="text-[11px] text-[color:var(--color-status-error)]">
          Capture failed: {cap.error_message || "no detail"}
        </div>
      )}
    </div>
  );
}

function ThreatMetaGrid({ t }: { t: RuntimeThreatDetail }) {
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px]" data-testid="threat-meta">
      <Field label="Source" value={`${t.src_ip ?? ""}${t.src_port ? `:${t.src_port}` : ""}`} />
      <Field label="Destination" value={`${t.dst_ip ?? ""}${t.dst_port ? `:${t.dst_port}` : ""}`} />
      <Field label="Workload (EP MAC)" value={t.ep_mac || "—"} />
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
      <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-wider text-muted-foreground">
        <span>L7 preview</span>
        <span className="rounded bg-accent px-1.5 py-0.5 font-mono text-foreground">{l7.kind.toUpperCase()}</span>
      </div>
      {l7.kind === "http" && l7.http && (
        <div className="space-y-1.5 text-mono text-[11px]">
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
        <div className="text-mono text-[11px]">
          <span className="text-[color:var(--color-primary)]">{l7.dns.qtype || "?"}</span>{" "}
          <span className="break-all">{l7.dns.qname || "—"}</span>
        </div>
      )}
      {l7.kind === "tls" && l7.tls && (
        <div className="space-y-1 text-mono text-[11px]">
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
      <div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-wider text-muted-foreground">
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
      <pre className="overflow-x-auto whitespace-pre text-mono text-[10px] leading-snug">
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
        className="absolute bottom-3 left-3 z-10 inline-flex items-center gap-2 rounded-md border border-border bg-card/95 px-2.5 py-1.5 text-[11px] shadow-[var(--elev-2)] backdrop-blur hover:bg-accent"
        title="Network policy lifecycle"
      >
        <Eye   className="h-3 w-3 text-muted-foreground" />
        <span className="text-mono tabular-nums">{discover}</span>
        <Radio className="h-3 w-3 text-[color:var(--color-status-warning)]" />
        <span className="text-mono tabular-nums">{monitor}</span>
        <Lock  className="h-3 w-3 text-[color:var(--color-primary)]" />
        <span className="text-mono tabular-nums">{protect}</span>
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
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Network Policy Lifecycle</span>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="text-[10px] text-muted-foreground hover:text-foreground"
        >
          collapse
        </button>
      </div>
      <PolicyLifecyclePanel {...props} />
    </div>
  );
}
