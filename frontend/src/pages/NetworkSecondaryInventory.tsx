import { useRef } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "@tanstack/react-router";
import { Download, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { network, runtimePcap, type ConversationStreamInventoryParams, type ConversationStreamInventoryRow, type NetworkConversationFilters, type NetworkFlow, type PcapInventoryParams, type PcapInventoryRow } from "@/api/client";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Collapse } from "@/components/ui/collapse";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useDebounced } from "@/hooks/useDebounced";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { fmtBytes } from "@/lib/format";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { pcapInventoryMatches, pcapInventorySorts, pcapInventoryStatuses, streamInventoryMatches, streamInventorySorts } from "@/lib/network-secondary-inventory";
import { networkViewHref } from "@/lib/network-saved-view-route";
import type { NetworkPcapSavedFilters, NetworkSavedViewSnapshot } from "@/lib/network-saved-views";
import { useRouteSearchParams } from "@/lib/route-search";
import { InventoryScopeState, ScanInventoryContinuation, ScanInventoryExport, useInventoryScope } from "./inventory-workspace";

// A known observed ID is still evidence even when an old signed MAX lost a
// higher identifier. Missing legacy metadata must not imply a healthy maximum.
export function ThreatMaximum({ id, complete }: { id?: number; complete?: boolean }) {
  const qualifier = complete === false ? "Historical maximum unavailable" : complete === undefined ? "Maximum unverified" : "";
  return <span className="inline-flex flex-wrap items-center gap-x-1">{id || "Not reported"}{qualifier && <span className="text-xs text-muted-foreground" title="Retained aggregate history cannot prove the largest unsigned signature identifier.">· {qualifier}</span>}</span>;
}
const PAGE_SIZE = 100;
const bytes = (value: number) => value === 0 ? "0 B" : fmtBytes(value);
const EMPTY_PCAP: NetworkPcapSavedFilters = { status: "", workload: "", duration_s: 30, protocol: "", src_ip: "", dst_ip: "", dst_port: "", bpf_filter: "", interface: "", file_count: "", file_size_mb: "" };
function useSecondaryRoute(prefix: string, sorts: string[], defaultSort: string) {
  const [params, setParams] = useRouteSearchParams();
  const query = params.get(`${prefix}_q`) ?? "", debounced = useDebounced(query, 250);
  const rawPage = Number(params.get(`${prefix}_page`));
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 && rawPage <= INVENTORY_MAX_PAGE ? rawPage - 1 : 0;
  const sort = sorts.includes(params.get(`${prefix}_sort`) ?? "") ? params.get(`${prefix}_sort`)! : defaultSort;
  const valid = ["page", "sort", "order", "q", ...(prefix === "stream" ? ["protocol"] : ["namespace", "node"])].every(key => params.getAll(`${prefix}_${key}`).length <= 1) && (!params.has(`${prefix}_page`) || /^\d+$/.test(params.get(`${prefix}_page`)!) && rawPage >= 1 && rawPage <= INVENTORY_MAX_PAGE) && (!params.has(`${prefix}_sort`) || sorts.includes(params.get(`${prefix}_sort`)!)) && (!params.has(`${prefix}_order`) || ["asc", "desc"].includes(params.get(`${prefix}_order`)!));
  const order = params.get(`${prefix}_order`) === "asc" ? "asc" as const : "desc" as const;
  const update = (changes: Record<string, string | null>, reset = true, replace = false) => setParams(current => {
    const next = new URLSearchParams(current);
    for (const [key, value] of Object.entries(changes)) { if (value === null || value === "") next.delete(key); else next.set(key, value); }
    if (reset) next.delete(`${prefix}_page`);
    return next;
  }, { replace });
  return { params, valid, page, sort, order, query, debounced, debouncing: query !== debounced, update,
    setPage: (value: number) => update({ [`${prefix}_page`]: value === 0 ? null : String(value + 1) }, false),
    setQuery: (value: string) => update({ [`${prefix}_q`]: value }, true, true),
    setSort: (value: { id: string; dir: "asc" | "desc" } | null) => update({ [`${prefix}_sort`]: value?.id ?? defaultSort, [`${prefix}_order`]: value?.dir ?? "desc" }) };
}
export function StreamsTab({ flow, from: explicitFrom, to: explicitTo, clusterID, hours, active, sourceFilters }: { flow?: NetworkFlow; from?: string; to?: string; clusterID: string; hours: number; active: boolean; sourceFilters?: NetworkConversationFilters }) {
  const from = explicitFrom ?? flow?.src ?? "", to = explicitTo ?? flow?.dst ?? "";
  const scope = useInventoryScope(), identity = useTablePreferencesIdentity(), client = useQueryClient();
  const route = useSecondaryRoute("stream", streamInventorySorts, "bytes"), protocol = route.params.get("stream_protocol") ?? "";
  const request: ConversationStreamInventoryParams = { ...sourceFilters, cluster_id: clusterID, from, to, hours, q: route.debounced || undefined, protocol: protocol || undefined, limit: PAGE_SIZE, offset: route.page * PAGE_SIZE, sort: route.sort, order: route.order };
  const key = ["conv-stream-inventory", scope.owner, request];
  const resolved = scope.ready && scope.clusterId === clusterID && !!identity?.org_id && !!identity?.user_id;
  const q = useQuery({ queryKey: key, queryFn: () => network.conversationEntriesInventory(request), enabled: resolved && route.valid && active && !!from && !!to, staleTime: 30_000 });
  const valid = streamInventoryMatches(q.data, request), available = resolved && route.valid && active && !!from && !!to && valid && q.isSuccess && !q.isFetching && !route.debouncing;
  const context = JSON.stringify([scope.owner, request]), current = useRef({ available, context, canRead: false }); current.current = { available, context, canRead: resolved && route.valid };
  const confirmed = useRef<{ context: string; data: unknown } | null>(null);
  if (available) confirmed.current = { context, data: q.data };
  const readable = resolved && route.valid && active && valid && q.isSuccess && !route.debouncing && (!q.isFetching || confirmed.current?.context === context && confirmed.current?.data === q.data);
  const refresh = () => { if (current.current.canRead && current.current.context === context && clusterCacheReady(client, clusterID)) void q.refetch(); };
  const fresh = () => current.current.available && current.current.context === context && clusterCacheReady(client, clusterID) && exportQueryReady(client, key, q.data);
  const columns: Column<ConversationStreamInventoryRow>[] = [
    { id: "from", header: "From", kind: "name", code: true, cell: () => from, exportValue: () => from },
    { id: "from_platform_role", header: "From role", kind: "text", exportHeader: "from_platform_role", cell: row => row.from_platform_role || "Not classified", exportValue: row => row.from_platform_role },
    { id: "to", header: "To", kind: "name", code: true, cell: () => to, exportValue: () => to },
    { id: "to_platform_role", header: "To role", kind: "text", exportHeader: "to_platform_role", cell: row => row.to_platform_role || "Not classified", exportValue: row => row.to_platform_role },
    { id: "protocol", header: "Protocol", kind: "text", cell: row => row.protocol, sort: (a, b) => a.protocol.localeCompare(b.protocol) },
    { id: "application", header: "Application", kind: "name", cell: row => row.application || "Not reported", exportValue: row => row.application, sort: (a, b) => a.application.localeCompare(b.application) },
    { id: "port", header: "Port", kind: "count", cell: row => row.port || "Not reported", exportValue: row => row.port, sort: (a, b) => a.port - b.port },
    ...(["bytes", "client_bytes", "server_bytes", "packets", "sessions", "severity"] as const).map(id => ({ id, header: ({ bytes: "Bytes", client_bytes: "Client bytes", server_bytes: "Server bytes", packets: "Packets", sessions: "Sessions", severity: "Severity" })[id], kind: id.includes("bytes") ? "bytes" as const : "count" as const, cell: (row: ConversationStreamInventoryRow) => id.includes("bytes") ? bytes(row[id]) : row[id].toLocaleString(), exportValue: (row: ConversationStreamInventoryRow) => row[id], sort: (a: ConversationStreamInventoryRow, b: ConversationStreamInventoryRow) => a[id] - b[id] })),
    { id: "verdict", header: "Verdict", kind: "status", cell: row => <span>{row.verdict}{row.threat_id_complete === false && <span aria-label="Historical signature maximum unavailable" title="Historical signature maximum unavailable; inspect Threat ID or Details"> *</span>}</span>, sort: (a, b) => a.verdict.localeCompare(b.verdict) },
    { id: "threat", header: "Threat ID", kind: "count", cell: row => <ThreatMaximum id={row.threat_id} complete={row.threat_id_complete} />, exportValue: row => row.threat_id, sort: (a, b) => a.threat_id - b.threat_id },
    { id: "threat_id_complete", header: "Threat maximum complete", kind: "status", cell: row => row.threat_id_complete === undefined ? "Unverified" : String(row.threat_id_complete), exportValue: row => row.threat_id_complete === undefined ? "unknown" : row.threat_id_complete },
    { id: "last_seen", header: "Last seen", kind: "date", cell: row => new Date(row.last_seen_at).toLocaleString(), exportValue: row => row.last_seen_at, sort: (a, b) => Date.parse(a.last_seen_at) - Date.parse(b.last_seen_at) },
    { id: "row_id", header: "Aggregate tuple ID", kind: "id", cell: row => row.row_id },
  ];
  if (!identity?.org_id || !identity?.user_id) return <ErrorState title="Organization and user context are unavailable." />;
  if (!resolved) return <InventoryScopeState scope={scope} />;
  if (!active) return null;
  if (!from || !to) return <ErrorState title="Select both conversation endpoints." />;
  return <section className="space-y-3" data-testid="network-streams-inventory">
    <div className="flex flex-wrap items-end gap-3"><label className="text-xs">Search streams<input aria-label="Search streams" className="block h-8 rounded border border-input bg-background px-2" value={route.query} onChange={e => route.setQuery(e.target.value)} /></label><label className="text-xs">Protocol<input aria-label="Stream protocol filter" className="block h-8 rounded border border-input bg-background px-2" value={protocol} onChange={e => route.update({ stream_protocol: e.target.value })} /></label><Button variant="outline" disabled={!route.valid} onClick={refresh}><RefreshCw className="h-3.5 w-3.5" />Refresh streams</Button><ScanInventoryExport context={context} disabled={!available} isCurrent={fresh} download={guard => network.conversationEntriesCSV(request, guard)} /></div>
    {!route.valid ? <ErrorState title="Choose supported stream sorting and page values." action={<Button onClick={() => route.update({ stream_sort: null, stream_order: null, stream_page: null, stream_q: route.query, stream_protocol: protocol })}>Reset sorting and page</Button>} /> : q.isError ? <ErrorState title="Conversation streams could not be loaded or refreshed." error={q.error} action={<Button onClick={refresh}>Retry streams</Button>} /> : q.isPending || !readable && q.isFetching || route.debouncing ? <LoadingState label="Loading streams…" /> : !valid ? <ErrorState title="Conversation streams do not match the selected scope, pair or page." action={<Button onClick={refresh}>Retry streams</Button>} /> : <>
      {q.isFetching && <p role="status" className="text-xs text-muted-foreground">Refreshing…</p>}
      <p className="text-xs text-muted-foreground">{q.data.total.toLocaleString()} matching aggregate streams · {bytes(q.data.summary.bytes)} · {q.data.summary.sessions.toLocaleString()} sessions</p>
      <Collapse label="Details"><p className="text-xs text-muted-foreground">{q.data.summary.threat_id_incomplete !== undefined && <span>{q.data.summary.threat_id_incomplete.toLocaleString()} aggregate streams have an unavailable historical signature maximum. Known observed IDs remain evidence; zero does not prove absence of threats. </span>}Totals cover every matching retained rollup for this directed pair and time window. A row aggregates one protocol, application, port and verdict tuple; it is not an individual connection or packet. Matching CSV exports up to 100,000 aggregate tuples. Table CSV covers this server page and selected columns.</p></Collapse>
      <DataTable rows={q.data.entries} columns={columns} rowKey={row => row.row_id} defaultDensity="compact" preferencesKey="network-conversation-streams" defaultHiddenColumnIds={["from", "to", "client_bytes", "server_bytes", "packets", "severity", "threat", "threat_id_complete", "row_id"]} sort={{ id: route.sort, dir: route.order }} manualSorting pagination={false} onSortChange={route.setSort} exportFileName={available ? "network-conversation-streams-page" : undefined} canExport={fresh} exportLabel="Export page CSV" />
      <ScanInventoryContinuation page={route.page} rows={q.data.entries.length} total={q.data.total} matching={q.data.total} hasMore={q.data.has_more} onPage={route.setPage} />
    </>}
  </section>;
}
export function PcapWorkspaceTab({ clusterID, groupFilter, filters, snapshot, onFiltersChange, autoRefresh = true }: { autoRefresh?: boolean; clusterID: string; groupFilter: string; filters: NetworkPcapSavedFilters; snapshot: NetworkSavedViewSnapshot; onFiltersChange: (filters: NetworkPcapSavedFilters) => void }) {
  const client = useQueryClient(), scope = useInventoryScope(), identity = useTablePreferencesIdentity(), location = useLocation();
  const route = useSecondaryRoute("pcap", pcapInventorySorts, "requested");
  const portInvalid = !!filters.dst_port && (!/^\d+$/.test(filters.dst_port) || Number(filters.dst_port) < 1 || Number(filters.dst_port) > 65535);
  const request: PcapInventoryParams = { cluster_id: clusterID, workload: filters.workload.trim() || undefined, namespace: route.params.get("pcap_namespace") || undefined, node: route.params.get("pcap_node") || undefined, group: groupFilter || undefined, status: filters.status as PcapInventoryParams["status"] || undefined, protocol: filters.protocol || undefined, src_ip: filters.src_ip.trim() || undefined, dst_ip: filters.dst_ip.trim() || undefined, dst_port: filters.dst_port && !portInvalid ? Number(filters.dst_port) : undefined, q: route.debounced || undefined, hide_platform: snapshot.hide_platform_components, limit: PAGE_SIZE, offset: route.page * PAGE_SIZE, sort: route.sort, order: route.order };
  const key = ["pcap-captures", clusterID, scope.owner, request], resolved = scope.ready && scope.clusterId === clusterID && !!identity?.org_id && !!identity?.user_id;
  const q = useQuery({ queryKey: key, queryFn: () => runtimePcap.inventory(request), enabled: resolved && route.valid && !portInvalid, refetchInterval: autoRefresh ? 5_000 : false });
  const valid = pcapInventoryMatches(q.data, request, identity?.org_id ?? ""), available = resolved && route.valid && !portInvalid && !route.debouncing && q.isSuccess && !q.isFetching && valid;
  const context = JSON.stringify([scope.owner, request]), current = useRef({ available, context, canRead: false }); current.current = { available, context, canRead: resolved && route.valid };
  const confirmed = useRef<{ context: string; data: unknown } | null>(null);
  if (available) confirmed.current = { context, data: q.data };
  const readable = resolved && route.valid && valid && q.isSuccess && !route.debouncing && (!q.isFetching || confirmed.current?.context === context && confirmed.current?.data === q.data);
  const refresh = () => { if (current.current.canRead && current.current.context === context && clusterCacheReady(client, clusterID)) void q.refetch(); };
  const fresh = () => current.current.available && current.current.context === context && clusterCacheReady(client, clusterID) && exportQueryReady(client, key, q.data);
  const captureExport = useExportGuard(context, !available, fresh);
  const remove = useMutation({ mutationFn: async ({ id, guard }: { id: string; guard: () => boolean; owner: string }) => {
    if (!guard() || !q.data?.captures.some(row => row.id === id && row.cluster_id === clusterID)) throw new Error("Capture scope changed. Refresh and review before removing it.");
    return runtimePcap.remove(id);
  }, onSuccess: (_data, submitted) => { if (submitted.guard()) toast.success("PCAP capture removed"); void client.invalidateQueries({ queryKey: ["pcap-captures", clusterID, submitted.owner] }); }, onError: (err, submitted) => { if (submitted.guard()) toast.error((err as Error).message || "Failed to remove PCAP capture"); } });
  const updateFilter = <K extends keyof NetworkPcapSavedFilters>(field: K, value: NetworkPcapSavedFilters[K]) => { route.update({}); onFiltersChange({ ...filters, [field]: value }); };
  const createHref = networkViewHref(clusterID, new URLSearchParams(location.searchStr), location.hash, "pcap", { ...snapshot, pcap_filters: { ...snapshot.pcap_filters, q: route.query || undefined, namespace: request.namespace, node: request.node } });
  const columns: Column<PcapInventoryRow>[] = [
    { id: "workload", header: "Workload", kind: "name", code: true, cell: row => row.workload, sort: (a, b) => a.workload.localeCompare(b.workload) },
    { id: "platform_role", header: "Platform role", kind: "text", exportHeader: "platform_role", cell: row => row.platform_role || "Not classified", exportValue: row => row.platform_role },
    { id: "namespace", header: "Namespace", kind: "name", cell: row => row.namespace, sort: (a, b) => a.namespace.localeCompare(b.namespace) },
    { id: "filter", header: "Filter", kind: "text", wrap: true, size: 220, cell: row => captureFilter(row) },
    { id: "status", header: "Status", kind: "status", cell: row => row.status, sort: (a, b) => a.status.localeCompare(b.status) },
    { id: "node", header: "Node", kind: "name", cell: row => row.claimed_by_node || "Not reported", exportValue: row => row.claimed_by_node ?? "", sort: (a, b) => (a.claimed_by_node ?? "").localeCompare(b.claimed_by_node ?? "") },
    { id: "packets", header: "Packets", kind: "count", cell: row => row.packet_count === null ? "Not reported" : row.packet_count.toLocaleString(), exportValue: row => row.packet_count, sort: (a, b) => (a.packet_count ?? -1) - (b.packet_count ?? -1) },
    { id: "bytes", header: "Size", kind: "bytes", cell: row => row.file_size_bytes === null ? "Not reported" : bytes(row.file_size_bytes), exportValue: row => row.file_size_bytes, sort: (a, b) => (a.file_size_bytes ?? -1) - (b.file_size_bytes ?? -1) },
    { id: "requested", header: "Requested", kind: "date", cell: row => new Date(row.requested_at).toLocaleString(), exportValue: row => row.requested_at, sort: (a, b) => Date.parse(a.requested_at) - Date.parse(b.requested_at) },
    { id: "expires", header: "Expires", kind: "date", cell: row => new Date(row.expires_at).toLocaleString(), exportValue: row => row.expires_at, sort: (a, b) => Date.parse(a.expires_at) - Date.parse(b.expires_at) },
    { id: "completed", header: "Completed", kind: "date", cell: row => row.completed_at ? new Date(row.completed_at).toLocaleString() : "Not reported", exportValue: row => row.completed_at ?? "", sort: (a, b) => Date.parse(a.completed_at ?? "1970-01-01") - Date.parse(b.completed_at ?? "1970-01-01") },
    { id: "duration", header: "Duration (s)", kind: "count", cell: row => row.duration_s, sort: (a, b) => a.duration_s - b.duration_s },
    { id: "protocol", header: "Protocol", kind: "text", cell: row => row.protocol || "Any", exportValue: row => row.protocol ?? "", sort: (a, b) => (a.protocol ?? "").localeCompare(b.protocol ?? "") },
    { id: "port", header: "Port", kind: "count", cell: row => row.dst_port ?? "Any", exportValue: row => row.dst_port ?? "", sort: (a, b) => (a.dst_port ?? 0) - (b.dst_port ?? 0) },
    { id: "row_id", header: "Capture ID", kind: "id", cell: row => row.row_id },
    { id: "actions", header: "", kind: "actions", exportable: false, size: 160, minSize: 160, wrap: true, cell: row => <div className="flex flex-wrap items-center justify-end gap-1">
      {row.status === "completed" && <Button size="sm" variant="outline" disabled={!available} onClick={() => { const guard = captureExport(); if (guard()) void runtimePcap.download(row.id, guard).catch((err: Error) => { if (guard()) toast.error(`PCAP download failed: ${err.message}`); }); }} data-testid="network-pcap-download"><Download className="h-3.5 w-3.5" />Download</Button>}
      {row.error_message && <span className="break-words text-destructive">{row.error_message}</span>}
      <Button size="icon" variant="ghost" disabled={!available || remove.isPending} title={row.status === "pending" || row.status === "running" ? "Cancel capture" : "Remove capture"} data-testid="network-pcap-delete" onClick={() => { const guard = captureExport(); if (guard() && window.confirm(`Remove PCAP capture ${row.id.slice(0, 8)}?`)) remove.mutate({ id: row.id, guard, owner: scope.owner }); }}><Trash2 className="h-3.5 w-3.5" /></Button>
    </div> },
  ];
  if (!clusterID) return <p>Select a cluster before requesting packet captures.</p>;
  if (!identity?.org_id || !identity?.user_id) return <ErrorState title="Organization and user context are unavailable." />;
  if (!resolved) return <InventoryScopeState scope={scope} />;
  return <section className="space-y-3" data-testid="network-pcap-tab">
    <div className="flex flex-wrap items-center justify-between gap-3"><Button asChild variant="primary"><a href={createHref} data-testid="network-pcap-new">+ Request capture</a></Button><ScanInventoryExport context={context} disabled={!available} isCurrent={fresh} download={guard => runtimePcap.inventoryCSV(request, guard)} /></div>
    <div className="flex flex-wrap items-end gap-3"><label className="text-xs">Search captures<input aria-label="Search captures" className="block h-8 rounded border border-input bg-background px-2" value={route.query} onChange={e => route.setQuery(e.target.value)} /></label>
      {([['workload', 'Workload'], ['src_ip', 'Source IP'], ['dst_ip', 'Destination IP'], ['dst_port', 'Destination port']] as const).map(([field, label]) => <label key={field} className="min-w-0 text-xs">{label}<input aria-label={`Capture ${label.toLowerCase()} filter`} className="block h-8 max-w-full rounded border border-input bg-background px-2" value={filters[field]} onChange={e => updateFilter(field, e.target.value)} /></label>)}
      <label className="text-xs">Protocol<select aria-label="Capture protocol filter" className="block h-8 rounded border border-input bg-background px-2" value={filters.protocol} onChange={e => updateFilter("protocol", e.target.value)}><option value="">Any</option>{["tcp", "udp", "icmp"].map(value => <option key={value} value={value}>{value.toUpperCase()}</option>)}</select></label>
      <label className="text-xs">Status<select aria-label="Capture status filter" data-testid="network-pcap-status" className="block h-8 rounded border border-input bg-background px-2" value={filters.status} onChange={e => updateFilter("status", e.target.value)}><option value="">All captures</option>{pcapInventoryStatuses.map(value => <option key={value} value={value}>{value}</option>)}</select></label>
      {([['namespace', 'Namespace'], ['node', 'Node']] as const).map(([field, label]) => <label key={field} className="text-xs">{label}<input aria-label={`Capture ${field} filter`} className="block h-8 rounded border border-input bg-background px-2" value={route.params.get(`pcap_${field}`) ?? ""} onChange={e => route.update({ [`pcap_${field}`]: e.target.value })} /></label>)}
      <Button variant="outline" onClick={() => { route.update({ pcap_q: null, pcap_namespace: null, pcap_node: null }); onFiltersChange({ ...EMPTY_PCAP }); }}>Clear filters</Button><Button variant="outline" disabled={portInvalid || !route.valid} data-testid="network-pcap-refresh" onClick={refresh}><RefreshCw className="h-3.5 w-3.5" />Refresh</Button>
    </div>
    {!route.valid ? <ErrorState title="Choose supported capture sorting and page values." action={<Button onClick={() => route.update({ pcap_sort: null, pcap_order: null, pcap_page: null, pcap_q: route.query, pcap_namespace: request.namespace ?? null, pcap_node: request.node ?? null })}>Reset sorting and page</Button>} /> : portInvalid ? <ErrorState title="Destination port must be a whole number from 1 to 65535." /> : q.isError ? <ErrorState title="Packet captures could not be loaded or refreshed." error={q.error} action={<Button onClick={refresh}>Retry captures</Button>} /> : q.isPending || !readable && q.isFetching || route.debouncing ? <LoadingState label="Loading captures…" /> : !valid ? <ErrorState title="Capture evidence does not match the selected scope, filters or page." action={<Button onClick={refresh}>Retry captures</Button>} /> : <>
      {q.isFetching && <p role="status" className="text-xs text-muted-foreground">Refreshing…</p>}
      <p className="text-xs text-muted-foreground">{q.data.total.toLocaleString()} matching capture requests · {q.data.summary.running.toLocaleString()} running · {q.data.summary.completed.toLocaleString()} completed</p>
      <Collapse label="Details"><p className="text-xs text-muted-foreground">Counts cover every matching retained capture request. A request does not establish a completed capture. Packet and file totals use {q.data.summary.packet_reports.toLocaleString()} packet reports and {q.data.summary.file_reports.toLocaleString()} file reports; missing measurements remain unavailable. Matching CSV exports up to 100,000 request metadata records across pages; table CSV covers this page. Capture files download separately.</p></Collapse>
      <DataTable rows={q.data.captures} columns={columns} rowKey={row => row.row_id} preferencesKey="network-pcap-captures" defaultHiddenColumnIds={["namespace", "expires", "completed", "duration", "protocol", "port", "row_id"]} sort={{ id: route.sort, dir: route.order }} manualSorting pagination={false} onSortChange={route.setSort} exportFileName={available ? "capture-requests-page" : undefined} canExport={fresh} exportLabel="Export page CSV" testId="network-pcap-table" />
      <ScanInventoryContinuation page={route.page} rows={q.data.captures.length} total={q.data.total} matching={q.data.total} hasMore={q.data.has_more} onPage={route.setPage} />
    </>}
  </section>;
}
function captureFilter(row: PcapInventoryRow) {
  return [row.protocol, row.src_ip, row.dst_ip, row.dst_port ? `:${row.dst_port}` : "", row.bpf_filter ? `bpf ${row.bpf_filter}` : "", row.interface ? `iface ${row.interface}` : "", (row.file_count ?? 0) > 1 ? `${row.file_count}x${row.file_size_mb || "auto"}MB` : ""].filter(Boolean).join(" ") || "any";
}
