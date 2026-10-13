import { expect, type Route } from "@playwright/test";
import type { NetworkConversation, NetworkConversations, NetworkSession, NetworkSessionsResponse, RuntimeThreat, RuntimeThreatPage } from "../../src/api/client";

export const networkFixtureCluster = "11111111-1111-4111-8111-111111111111";
export const networkFixtureAt = new Date().toISOString();
export type ConversationEvidence = NetworkConversation & { port?: number; peers?: string[] };
// AppShell's organization notification preview is a different consumer from
// the scoped primary inventory. Do not accept an unscoped paged request here.
export function notificationThreats(url: URL) {
  expect([...url.searchParams.keys()].sort()).toEqual(["hours", "severity_min"]);
  expect(url.searchParams.get("hours")).toBe("24");
  expect(url.searchParams.get("severity_min")).toBe("4");
  return { threats: [] };
}
const text = (url: URL, key: string) => (url.searchParams.get(key) ?? "").trim();
const lower = (url: URL, key: string) => text(url, key).toLowerCase();
const hidden = (url: URL) => text(url, "hide_platform") === "true";
const number = (url: URL, key: string, fallback = 0) => Number(url.searchParams.get(key) ?? fallback);
function pageOptions(url: URL, sort: string, maxLimit = 500) {
  const limit = number(url, "limit", 100), offset = number(url, "offset");
  expect(limit, `${url.pathname} limit`).toBeGreaterThan(0);
  expect(limit).toBeLessThanOrEqual(maxLimit);
  expect(Number.isSafeInteger(offset)).toBe(true);
  expect(offset).toBeGreaterThanOrEqual(0);
  return { limit, offset, sort: text(url, "sort") || sort, order: (lower(url, "order") || "desc") as "asc" | "desc" };
}
function sorted<T>(rows: T[], sort: string, order: string, value: (row: T, key: string) => string | number, identity: (row: T) => string) {
  expect(["asc", "desc"]).toContain(order);
  return [...rows].sort((a, b) => { const av = value(a, sort), bv = value(b, sort); const cmp = typeof av === "number" && typeof bv === "number" ? av - bv : String(av).localeCompare(String(bv)); return (order === "asc" ? cmp : -cmp) || identity(a).localeCompare(identity(b)); });
}
function assertScope(url: URL) {
  expect(url.searchParams.get("cluster_id"), `${url.pathname} exact cluster`).toBe(networkFixtureCluster);
  expect(text(url, "group"), "These fixtures have no group membership").toBe("");
}
export function conversation(from: string, to: string, values: Partial<ConversationEvidence> = {}): ConversationEvidence {
  return { row_id: JSON.stringify([from, to]), from, to, bytes: 10, packets: 1, edges: 1, last_seen: networkFixtureAt, verdict: "allow", apps: [], ...values };
}
export function session(id: number, workload: string, values: Partial<NetworkSession> = {}): NetworkSession {
  const node = values.node ?? "node-a";
  return { id, row_id: JSON.stringify([networkFixtureCluster, node, id]), cluster_id: networkFixtureCluster, node, workload_id: workload, platform_role: "", application: "7", ip_proto: "TCP", client_ip: "10.0.0.1", client_port: 40000, server_ip: "10.0.0.2", server_port: 443, client_state: "established", server_state: "established", client_bytes: 1, server_bytes: 1, client_pkts: 1, server_pkts: 1, age: 1, idle: 0, ingress: false, severity: 0, updated_at: networkFixtureAt, ...values };
}
export function threat(index: number, values: Partial<RuntimeThreat> = {}): RuntimeThreat {
  return { id: `threat-${index}`, org_id: "org", cluster_id: networkFixtureCluster, workload_id: "default/server", namespace: "default", platform_role: "", node: "node-a", threat_id: 1001, threat_name: `Threat ${index}`, severity: 8, action: 0, application: 7, src_ip: "10.0.0.1", src_port: 40000, dst_ip: "10.0.0.2", dst_port: 443, pkt_ingress: false, sess_ingress: false, reported_at: networkFixtureAt, at: networkFixtureAt, ...values };
}
export function conversationInventory(url: URL, source: ConversationEvidence[]): NetworkConversations {
  assertScope(url);
  const filters = { hours: number(url, "hours", 24), namespace: text(url, "namespace"), group: "", verdict: lower(url, "verdict"), from: text(url, "from"), to: text(url, "to"), verdict_group: text(url, "verdict_group"), port: number(url, "port"), peer: lower(url, "peer"), application: lower(url, "application"), hide_platform: hidden(url) };
  expect(["", "blocked"]).toContain(filters.verdict_group);
  const matching = source.filter(row => (!filters.hide_platform || row.from_platform_role !== "core" && row.to_platform_role !== "core") && (!filters.namespace || row.from.startsWith(`${filters.namespace}/`) || row.to.startsWith(`${filters.namespace}/`)) && (!filters.from || row.from === filters.from) && (!filters.to || row.to === filters.to) && (!filters.verdict || row.verdict === filters.verdict) && (!filters.verdict_group || ["deny", "denied", "block", "blocked"].includes(row.verdict ?? "")) && (!filters.application || row.apps?.some(app => app.toLowerCase() === filters.application)) && (!filters.port || row.port === filters.port) && (!filters.peer || row.peers?.some(peer => peer.toLowerCase().includes(filters.peer))));
  const options = pageOptions(url, "bytes", 5000);
  expect(["from", "to", "bytes", "packets", "edges", "severity", "verdict", "last_seen", "apps"]).toContain(options.sort);
  const ordered = sorted(matching, options.sort, options.order, (row, key) => key === "apps" ? (row.apps ?? []).join(",") : (row[key as keyof NetworkConversation] as string | number) ?? "", row => row.row_id!);
  const nodes = [...new Set(matching.flatMap(row => [row.from, row.to]))];
  return { conversations: ordered.slice(options.offset, options.offset + options.limit), nodes, node_kinds: Object.fromEntries(nodes.map(node => [node, "workload" as const])), edges: [], ...options, total: matching.length, has_more: matching.length > options.offset + options.limit, cluster_id: networkFixtureCluster, window_hours: filters.hours, filters, source: "rollups", source_complete: true, summary_scope: "matching_rollups", summary: { total: matching.length, bytes: matching.reduce((n, row) => n + row.bytes, 0), packets: matching.reduce((n, row) => n + row.packets, 0), edges: matching.reduce((n, row) => n + row.edges, 0), blocked: matching.filter(row => ["deny", "denied", "block", "blocked"].includes(row.verdict ?? "")).length, violating: matching.filter(row => ["alert", "violate"].includes(row.verdict ?? "")).length, nodes: nodes.length } };
}
export function sessionInventory(url: URL, source: NetworkSession[]): NetworkSessionsResponse {
  assertScope(url);
  const protocolNames: Record<string, number> = { tcp: 6, udp: 17, icmp: 1, icmpv6: 58 };
  const proto = lower(url, "protocol");
  const filters = { cluster_id: networkFixtureCluster, group: "", protocol: proto ? protocolNames[proto] ?? Number(proto) : null, port: text(url, "port") ? number(url, "port") : null, application: lower(url, "application"), peer: lower(url, "peer"), workload: lower(url, "workload"), node: lower(url, "node"), hours: number(url, "hours"), q: lower(url, "q"), hide_platform: hidden(url) };
  const matching = source.filter(row => row.cluster_id === networkFixtureCluster && (!filters.hide_platform || row.platform_role !== "core") && (!filters.protocol || protocolNames[row.ip_proto.toLowerCase()] === filters.protocol) && (!filters.port || row.client_port === filters.port || row.server_port === filters.port) && (!filters.application || row.application.toLowerCase().includes(filters.application)) && (!filters.peer || [row.client_ip, row.server_ip].some(ip => ip.toLowerCase().includes(filters.peer))) && (!filters.workload || row.workload_id?.toLowerCase().includes(filters.workload)) && (!filters.node || row.node.toLowerCase().includes(filters.node)) && (!filters.q || [row.node, row.workload_id ?? "", row.application, row.client_ip, row.server_ip].join(" ").toLowerCase().includes(filters.q)));
  const options = pageOptions(url, "bytes");
  expect(["workload", "node", "application", "protocol", "client", "server", "bytes", "client_bytes", "server_bytes", "packets", "age", "idle", "severity", "observed", "state"]).toContain(options.sort);
  const value = (row: NetworkSession, key: string) => ({ workload: row.workload_id ?? "", protocol: row.ip_proto, client: row.client_ip, server: row.server_ip, bytes: row.client_bytes + row.server_bytes, packets: row.client_pkts + row.server_pkts, observed: row.updated_at ?? "", state: row.client_state }[key] ?? row[key as keyof NetworkSession]) as string | number;
  const ordered = sorted(matching, options.sort, options.order, value, row => row.row_id!);
  const client = matching.reduce((n, row) => n + row.client_bytes, 0), server = matching.reduce((n, row) => n + row.server_bytes, 0);
  return { sessions: ordered.slice(options.offset, options.offset + options.limit), ...options, cluster_id: networkFixtureCluster, selected_group_members: 0, filters, total: matching.length, has_more: matching.length > options.offset + options.limit, summary: { total: matching.length, client_bytes: client, server_bytes: server, bytes: client + server, packets: matching.reduce((n, row) => n + row.client_pkts + row.server_pkts, 0), threats: matching.filter(row => row.threat_id).length } };
}
export function threatInventory(url: URL, source: RuntimeThreat[]): RuntimeThreatPage {
  assertScope(url);
  const filters = { group: "", hide_platform: hidden(url), namespace: text(url, "namespace"), port: number(url, "port"), peer: lower(url, "peer"), application: lower(url, "application"), severity_min: number(url, "severity_min"), workload_id: text(url, "workload_id"), category: text(url, "category") === "all" ? "" : text(url, "category"), node: text(url, "node"), q: lower(url, "q") };
  expect(source.every(row => row.threat_id < 20000), "This fixture models IPS threat signatures only").toBe(true);
  const matching = source.filter(row => row.cluster_id === networkFixtureCluster && row.org_id === "org" && (!filters.hide_platform || row.platform_role !== "core") && (!filters.namespace || row.namespace === filters.namespace) && (!filters.port || row.src_port === filters.port || row.dst_port === filters.port) && (!filters.peer || [row.src_ip ?? "", row.dst_ip ?? ""].some(ip => ip.toLowerCase().includes(filters.peer))) && (!filters.application || String(row.application) === filters.application) && row.severity >= filters.severity_min && (!filters.workload_id || row.workload_id === filters.workload_id) && (!filters.node || row.node === filters.node) && (!filters.q || [row.threat_name, row.msg, row.workload_id, row.src_ip, row.dst_ip].join(" ").toLowerCase().includes(filters.q)));
  expect(filters.category, "Category-specific evidence must be provided by its own fixture").toBe("");
  const options = pageOptions(url, "at");
  expect(["at", "reported", "severity", "action", "workload", "category", "node", "signature"]).toContain(options.sort);
  const value = (row: RuntimeThreat, key: string) => ({ reported: row.reported_at, workload: row.workload_id ?? "", signature: row.threat_id, category: "ips" }[key] ?? row[key as keyof RuntimeThreat]) as string | number;
  const ordered = sorted(matching, options.sort, options.order, value, row => row.id);
  return { threats: ordered.slice(options.offset, options.offset + options.limit), ...options, cluster_id: networkFixtureCluster, window_hours: number(url, "hours", 24), filters, total: matching.length, has_more: matching.length > options.offset + options.limit, summary: { total: matching.length, critical: matching.filter(row => row.severity >= 8).length, blocked: matching.filter(row => [2, 3, 4].includes(row.action)).length, ips: matching.length, dlp: 0, waf: 0, workloads: new Set(matching.map(row => row.workload_id).filter(Boolean)).size } };
}
const csv = (headers: string[], rows: Array<Array<string | number>>) => [headers, ...rows].map(row => row.map(cell => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n");
export async function networkCSV(route: Route, url: URL, kind: "conversations" | "sessions", source: ConversationEvidence[] | NetworkSession[]) {
  const all = new URL(url); all.searchParams.set("limit", "500"); all.searchParams.set("offset", "0");
  const page = kind === "conversations" ? conversationInventory(all, source as ConversationEvidence[]) : sessionInventory(all, source as NetworkSession[]);
  expect(page.total!, "Fixture CSV must include every match").toBeLessThanOrEqual(500);
  const body = "conversations" in page ? csv(["from", "to", "from_platform_role", "to_platform_role"], page.conversations.map(row => [row.from, row.to, row.from_platform_role ?? "", row.to_platform_role ?? ""])) : csv(["row_id", "workload_id", "platform_role"], page.sessions.map(row => [row.row_id!, row.workload_id ?? "", row.platform_role!]));
  await route.fulfill({ contentType: "text/csv; charset=utf-8", headers: { "X-Export-Total": String(page.total), "X-Export-Limit": "100000", "X-Export-Truncated": "false" }, body });
}
