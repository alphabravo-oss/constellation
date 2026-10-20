import { expect, type Page, type Route } from "@playwright/test";
import type { ConversationStreamInventoryResponse, ConversationStreamInventoryRow, PcapInventoryResponse, PcapInventoryRow } from "../../src/api/client";
import { conversation, conversationInventory, networkFixtureAt, networkFixtureCluster, notificationThreats, sessionInventory, threatInventory } from "./network-inventory";

export const secondaryCluster = networkFixtureCluster;
export const streamFrom = "operations/agent", streamTo = "prod/api";
export type StreamEvidence = ConversationStreamInventoryRow & { from: string; to: string; peer: string };
const text = (url: URL, key: string) => (url.searchParams.get(key) || "").trim();
const lower = (url: URL, key: string) => text(url, key).toLowerCase();
const integer = (url: URL, key: string, fallback = 0) => Number(url.searchParams.get(key) ?? fallback);
const hidden = (url: URL) => url.searchParams.get("hide_platform") === "true";
const csv = (headers: string[], rows: unknown[][]) => [headers, ...rows].map(row => row.map(value => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\n");
function options(url: URL, defaultSort: string, exporting: boolean) {
  expect(url.searchParams.get("cluster_id")).toBe(secondaryCluster);
  expect(text(url, "group"), "This fixture has no group memberships").toBe("");
  const limit = exporting ? 100000 : integer(url, "limit", 100), offset = exporting ? 0 : integer(url, "offset");
  if (exporting) { expect(url.searchParams.has("limit")).toBe(false); expect(url.searchParams.has("offset")).toBe(false); }
  return { limit, offset, sort: text(url, "sort") || defaultSort, order: (text(url, "order") || "desc") as "asc" | "desc" };
}
function orderRows<T>(rows: T[], sort: string, order: string, value: (row: T, sort: string) => unknown, id: (row: T) => string) {
  expect(["asc", "desc"]).toContain(order);
  return [...rows].sort((a, b) => {
    const left = value(a, sort), right = value(b, sort);
    const compared = typeof left === "number" && typeof right === "number" ? left - right : String(left ?? "").localeCompare(String(right ?? ""));
    return (order === "asc" ? compared : -compared) || id(a).localeCompare(id(b));
  });
}
export function streamEvidence(index: number, values: Partial<StreamEvidence> = {}): StreamEvidence {
  const protocol = index % 2 ? "TCP" : "UDP", application = `APP-${String(index).padStart(4, "0")}`, port = 40000 + index;
  return { from: streamFrom, to: streamTo, peer: "10.0.0.2", row_id: JSON.stringify([protocol.toLowerCase(), application.toLowerCase(), port, "allow"]), protocol, application, port, verdict: "allow", bytes: index * 10, client_bytes: index * 6, server_bytes: index * 4, packets: index, sessions: 1, severity: 0, threat_id: 0, last_seen_at: networkFixtureAt, from_platform_role: "core", to_platform_role: "", ...values };
}
export function streamInventory(url: URL, source: StreamEvidence[], exporting = false): ConversationStreamInventoryResponse {
  const opts = options(url, "bytes", exporting);
  const filters = { from: text(url, "from"), to: text(url, "to"), hours: integer(url, "hours", 24), namespace: text(url, "namespace"), group: "", verdict: lower(url, "verdict"), verdict_group: text(url, "verdict_group"), port: integer(url, "port"), peer: lower(url, "peer"), application: lower(url, "application"), hide_platform: hidden(url), q: lower(url, "q"), protocol: lower(url, "protocol") };
  const matching = source.filter(row => row.from === filters.from && row.to === filters.to && (!filters.hide_platform || row.from_platform_role !== "core" && row.to_platform_role !== "core") && (!filters.namespace || row.from.startsWith(`${filters.namespace}/`) || row.to.startsWith(`${filters.namespace}/`)) && (!filters.verdict || row.verdict === filters.verdict) && (!filters.verdict_group || ["deny", "denied", "block", "blocked"].includes(row.verdict)) && (!filters.port || row.port === filters.port) && (!filters.peer || row.peer.toLowerCase().includes(filters.peer)) && (!filters.application || row.application.toLowerCase().includes(filters.application)) && (!filters.protocol || row.protocol.toLowerCase() === filters.protocol) && (!filters.q || [row.protocol, row.application, row.port, row.verdict].join(" ").toLowerCase().includes(filters.q)));
  const sorted = orderRows(matching, opts.sort, opts.order, (row, key) => key === "threat" ? row.threat_id : key === "last_seen" ? row.last_seen_at : row[key as keyof StreamEvidence], row => row.row_id);
  const summary = { total: matching.length, bytes: matching.reduce((n, row) => n + row.bytes, 0), client_bytes: matching.reduce((n, row) => n + row.client_bytes, 0), server_bytes: matching.reduce((n, row) => n + row.server_bytes, 0), packets: matching.reduce((n, row) => n + row.packets, 0), sessions: matching.reduce((n, row) => n + row.sessions, 0), blocked: matching.filter(row => ["deny", "denied", "block", "blocked"].includes(row.verdict)).length, violating: matching.filter(row => ["alert", "violate"].includes(row.verdict)).length };
  const entries = sorted.slice(opts.offset, opts.offset + opts.limit).map(({ from: _from, to: _to, peer: _peer, ...row }) => row);
  return { cluster_id: secondaryCluster, from: filters.from, to: filters.to, window_hours: filters.hours, entries, total: matching.length, summary, totals: summary, ...opts, has_more: opts.offset + opts.limit < matching.length, filters, source: "rollups", source_complete: true, summary_scope: "matching_retained_rollup_streams" };
}
export function captureEvidence(index: number, values: Partial<PcapInventoryRow> = {}): PcapInventoryRow {
  const id = `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
  return { id, row_id: id, org_id: "org", cluster_id: secondaryCluster, workload: `prod/app-${String(index).padStart(4, "0")}`, namespace: "prod", requested_by: "admin", requested_at: new Date(Date.parse(networkFixtureAt) + index * 1000).toISOString(), duration_s: 30, protocol: index % 2 ? "tcp" : "udp", src_ip: "10.0.0.1", dst_ip: "10.0.0.2", dst_port: 443, status: "completed", claimed_by_node: "node-a", packet_count: index === 1 ? null : index, file_size_bytes: index === 1 ? null : index * 1024, expires_at: new Date(Date.parse(networkFixtureAt) + 86400000).toISOString(), platform_role: "", ...values };
}
export function pcapInventory(url: URL, source: PcapInventoryRow[], exporting = false): PcapInventoryResponse {
  const opts = options(url, "requested", exporting);
  const filters = { q: lower(url, "q"), workload: text(url, "workload"), namespace: text(url, "namespace"), node: text(url, "node"), group: "", status: lower(url, "status"), protocol: lower(url, "protocol"), src_ip: text(url, "src_ip"), dst_ip: text(url, "dst_ip"), dst_port: integer(url, "dst_port"), hide_platform: hidden(url) };
  const matching = source.filter(row => row.org_id === "org" && row.cluster_id === secondaryCluster && (!filters.hide_platform || row.platform_role !== "core") && (!filters.workload || row.workload === filters.workload) && (!filters.namespace || row.namespace === filters.namespace) && (!filters.node || row.claimed_by_node === filters.node) && (!filters.status || row.status === filters.status) && (!filters.protocol || row.protocol === filters.protocol) && (!filters.src_ip || row.src_ip === filters.src_ip) && (!filters.dst_ip || row.dst_ip === filters.dst_ip) && (!filters.dst_port || row.dst_port === filters.dst_port) && (!filters.q || [row.id, row.workload, row.namespace, row.claimed_by_node, row.bpf_filter, row.interface, row.src_ip, row.dst_ip, row.status, row.protocol].join(" ").toLowerCase().includes(filters.q)));
  const sorted = orderRows(matching, opts.sort, opts.order, (row, key) => ({ requested: row.requested_at, expires: row.expires_at, completed: row.completed_at, packets: row.packet_count, bytes: row.file_size_bytes, node: row.claimed_by_node, duration: row.duration_s, port: row.dst_port })[key] ?? row[key as keyof PcapInventoryRow], row => row.id);
  const summary = { total: matching.length, pending: matching.filter(row => row.status === "pending").length, running: matching.filter(row => row.status === "running").length, completed: matching.filter(row => row.status === "completed").length, failed: matching.filter(row => row.status === "failed").length, expired: matching.filter(row => row.status === "expired").length, packets: matching.reduce((n, row) => n + (row.packet_count ?? 0), 0), bytes: matching.reduce((n, row) => n + (row.file_size_bytes ?? 0), 0), packet_reports: matching.filter(row => row.packet_count !== null).length, file_reports: matching.filter(row => row.file_size_bytes !== null).length, platform: matching.filter(row => row.platform_role === "core").length };
  return { cluster_id: secondaryCluster, captures: sorted.slice(opts.offset, opts.offset + opts.limit), total: matching.length, summary, ...opts, has_more: opts.offset + opts.limit < matching.length, filters, source_complete: true, summary_scope: "matching_retained_capture_requests" };
}
export async function streamCSV(route: Route, url: URL, rows: StreamEvidence[]) {
  const page = streamInventory(url, rows, true);
  const headers = ["Aggregate tuple ID", "Cluster ID", "From", "To", "Protocol", "Application", "Port", "Verdict", "Bytes", "Client bytes", "Server bytes", "Packets", "Sessions", "Severity", "Threat ID", "Last observed", "from_platform_role", "to_platform_role"];
  const body = csv(headers, page.entries.map(row => [row.row_id, secondaryCluster, page.from, page.to, row.protocol, row.application, row.port, row.verdict, row.bytes, row.client_bytes, row.server_bytes, row.packets, row.sessions, row.severity, row.threat_id, row.last_seen_at, row.from_platform_role, row.to_platform_role]));
  await route.fulfill({ contentType: "text/csv", headers: { "x-export-total": String(page.total), "x-export-limit": "100000", "x-export-truncated": String(page.total > 100000) }, body });
}
export async function pcapCSV(route: Route, url: URL, rows: PcapInventoryRow[]) {
  const page = pcapInventory(url, rows, true);
  const headers = ["Capture ID", "Cluster ID", "Workload", "Namespace", "platform_role", "Status", "Requested by", "Requested", "Duration seconds", "Source IP", "Destination IP", "Destination port", "Protocol", "BPF filter", "Interface", "Rolling files", "Rolling file MB", "Node", "Claimed", "Completed", "Packets", "File bytes", "SHA256", "Expires", "Error"];
  const body = csv(headers, page.captures.map(row => [row.id, row.cluster_id, row.workload, row.namespace, row.platform_role, row.status, row.requested_by, row.requested_at, row.duration_s, row.src_ip, row.dst_ip, row.dst_port, row.protocol, row.bpf_filter, row.interface, row.file_count, row.file_size_mb, row.claimed_by_node, row.claimed_at, row.completed_at, row.packet_count, row.file_size_bytes, row.sha256, row.expires_at, row.error_message]));
  await route.fulfill({ contentType: "text/csv", headers: { "x-export-total": String(page.total), "x-export-limit": "100000", "x-export-truncated": String(page.total > 100000) }, body });
}
export async function installSecondaryInventory(page: Page, streams: StreamEvidence[], captures: PcapInventoryRow[]) {
  const requests: URL[] = [];
  const pairStreams = streams.filter(row => row.from === streamFrom && row.to === streamTo);
  const pairs = pairStreams.length ? [conversation(streamFrom, streamTo, { from_platform_role: "core", to_platform_role: "", edges: pairStreams.length, bytes: pairStreams.reduce((total, row) => total + row.bytes, 0), packets: pairStreams.reduce((total, row) => total + row.packets, 0) })] : [];
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url()), path = url.pathname.replace(/^\/api\/v1/, "");
    expect(route.request().method(), "Secondary inventory coverage is read-only").toBe("GET");
    if (path === "/auth/me") return route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    if (path === "/clusters") return route.fulfill({ json: { clusters: [{ id: secondaryCluster, name: "Test cluster", state: "connected" }] } });
    if (path === "/groups") return route.fulfill({ json: { groups: [] } });
    if (path === "/runtime-threats" && !url.searchParams.has("cluster_id")) return route.fulfill({ json: notificationThreats(url) });
    requests.push(url);
    if (path === "/network/map") return route.fulfill({ json: { summary: { selected_cluster_id: secondaryCluster, window_hours: integer(url, "hours", 24), workloads: 0, flows: 0 }, workloads: [], flows: [], recent_flows: [] } });
    if (path === "/network/conversations") return route.fulfill({ json: conversationInventory(url, pairs) });
    if (path === "/network/sessions") return route.fulfill({ json: sessionInventory(url, []) });
    if (path === "/runtime-threats") return route.fulfill({ json: threatInventory(url, []) });
    if (path === "/network/policies/lifecycle") return route.fulfill({ json: { summary: { selected_cluster_id: secondaryCluster, total: 0, ready: 0, discover: 0, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 0 }, items: [] } });
    if (path === "/policies/dpi-threats") return route.fulfill({ json: { cluster_id: secondaryCluster, weak_tls_enabled: false } });
    if (path === "/network/conversations/streams") return route.fulfill({ json: streamInventory(url, streams) });
    if (path === "/network/conversations/streams.csv") return streamCSV(route, url, streams);
    if (path === "/runtime-pcap/inventory") return route.fulfill({ json: pcapInventory(url, captures) });
    if (path === "/runtime-pcap/inventory.csv") return pcapCSV(route, url, captures);
    return route.fulfill({ status: 404, json: { error: `Unexpected secondary inventory request: ${path}` } });
  });
  return requests;
}
