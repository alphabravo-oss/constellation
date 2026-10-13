import type { ConversationStreamInventoryParams, ConversationStreamInventoryResponse, PcapInventoryParams, PcapInventoryResponse } from "@/api/client";
import { scanInventoryResponseValid } from "@/pages/inventory-workspace";

export const streamInventorySorts = ["protocol", "application", "port", "verdict", "bytes", "client_bytes", "server_bytes", "packets", "sessions", "severity", "threat", "last_seen"];
export const pcapInventorySorts = ["workload", "namespace", "status", "node", "packets", "bytes", "requested", "expires", "completed", "duration", "protocol", "port"];
export const pcapInventoryStatuses = ["pending", "running", "completed", "failed", "expired"];
const count = (value: unknown): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const text = (value: unknown): value is string => typeof value === "string";
const date = (value: unknown) => text(value) && Number.isFinite(Date.parse(value));
const optionalText = (value: unknown) => value === undefined || text(value);
const normalized = (value?: string) => value?.trim() ?? "";
const lower = (value?: string) => normalized(value).toLowerCase();
function echoes(value: unknown, expected: Record<string, unknown>) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const fields = value as Record<string, unknown>;
  return Object.entries(expected).every(([key, val]) => fields[key] === val) && Object.keys(fields).every(key => key in expected);
}
export function streamInventoryMatches(data: ConversationStreamInventoryResponse | undefined, request: ConversationStreamInventoryParams): data is ConversationStreamInventoryResponse {
  if (!data || data.cluster_id !== request.cluster_id || data.from !== request.from || data.to !== request.to || data.window_hours !== (request.hours ?? 24) || data.source !== "rollups" || data.source_complete !== true || data.summary_scope !== "matching_retained_rollup_streams" || !Array.isArray(data.entries) || !scanInventoryResponseValid(data, data.entries.length, request.offset ?? 0, request.sort ?? "bytes", request.order ?? "desc", ["bytes", "client_bytes", "server_bytes", "packets", "sessions", "blocked", "violating"]) || !echoes(data.filters, { from: normalized(request.from), to: normalized(request.to), hours: request.hours ?? 24, namespace: normalized(request.namespace), group: normalized(request.group), verdict: lower(request.verdict), verdict_group: normalized(request.verdict_group), port: request.port ?? 0, peer: lower(request.peer), application: lower(request.application), hide_platform: request.hide_platform ?? false, q: lower(request.q), protocol: lower(request.protocol) }) || !data.totals || Object.entries(data.summary).some(([key, value]) => data.totals[key] !== value)) return false;
  const ids = new Set<string>();
  return data.entries.every(row => {
    if (!row || typeof row !== "object" || !text(row.row_id) || ids.has(row.row_id) || ![row.protocol, row.application, row.verdict, row.from_platform_role, row.to_platform_role].every(text) || ![row.bytes, row.client_bytes, row.server_bytes, row.packets, row.sessions, row.severity, row.threat_id, row.port].every(count) || row.port > 65535 || !date(row.last_seen_at) || !["", "core"].includes(row.from_platform_role) || !["", "core"].includes(row.to_platform_role) || request.hide_platform && (row.from_platform_role === "core" || row.to_platform_role === "core")) return false;
    let tuple: unknown; try { tuple = JSON.parse(row.row_id); } catch { return false; }
    if (!Array.isArray(tuple) || tuple.length !== 4 || !text(tuple[0]) || tuple[0].toUpperCase() !== row.protocol || tuple[1] !== null && !text(tuple[1]) || String(tuple[1] ?? "").toUpperCase() !== row.application || tuple[2] !== null && !count(tuple[2]) || (tuple[2] ?? 0) !== row.port || !text(tuple[3]) || tuple[3].toLowerCase() !== row.verdict || request.protocol && row.protocol.toLowerCase() !== lower(request.protocol)) return false;
    ids.add(row.row_id); return true;
  });
}
// Match the API's net.ParseIP normalization, including IPv4-mapped IPv6.
export function normalizedCaptureIP(raw?: string) {
  const value = normalized(raw);
  if (!value || !value.includes(":")) return value;
  try {
    const canonical = new URL(`http://[${value}]/`).hostname.slice(1, -1);
    const mapped = canonical.match(/^::ffff:([0-9a-f]+):([0-9a-f]+)$/);
    if (mapped) { const a = parseInt(mapped[1], 16), b = parseInt(mapped[2], 16); return `${a >> 8}.${a & 255}.${b >> 8}.${b & 255}`; }
    return canonical;
  } catch { return value; }
}
export function pcapInventoryMatches(data: PcapInventoryResponse | undefined, request: PcapInventoryParams, orgID: string): data is PcapInventoryResponse {
  if (!data || data.cluster_id !== request.cluster_id || data.source_complete !== true || data.summary_scope !== "matching_retained_capture_requests" || !Array.isArray(data.captures) || !scanInventoryResponseValid(data, data.captures.length, request.offset ?? 0, request.sort ?? "requested", request.order ?? "desc", [...pcapInventoryStatuses, "packets", "bytes", "packet_reports", "file_reports", "platform"]) || pcapInventoryStatuses.reduce((n, key) => n + data.summary[key], 0) !== data.total || !echoes(data.filters, { q: lower(request.q), workload: normalized(request.workload), namespace: normalized(request.namespace), node: normalized(request.node), group: normalized(request.group), status: lower(request.status), protocol: lower(request.protocol), src_ip: normalizedCaptureIP(request.src_ip), dst_ip: normalizedCaptureIP(request.dst_ip), dst_port: request.dst_port ?? 0, hide_platform: request.hide_platform ?? false }) || data.summary.packet_reports > data.total || data.summary.file_reports > data.total || data.summary.platform > data.total) return false;
  const ids = new Set<string>();
  return data.captures.every(row => {
    if (!row || typeof row !== "object" || !text(row.id) || !row.id || row.row_id !== row.id || ids.has(row.row_id) || row.org_id !== orgID || row.cluster_id !== request.cluster_id || ![row.workload, row.namespace, row.requested_by, row.platform_role].every(text) || !row.workload || !pcapInventoryStatuses.includes(row.status) || !date(row.requested_at) || !date(row.expires_at) || !count(row.duration_s) || [row.file_count, row.file_size_mb].some(value => value !== undefined && !count(value)) || row.packet_count !== null && !count(row.packet_count) || row.file_size_bytes !== null && !count(row.file_size_bytes) || ![row.src_ip, row.dst_ip, row.protocol, row.bpf_filter, row.interface, row.claimed_by_node, row.error_message, row.sha256].every(optionalText) || row.claimed_at !== undefined && !date(row.claimed_at) || row.completed_at !== undefined && !date(row.completed_at) || row.dst_port !== undefined && (!count(row.dst_port) || row.dst_port > 65535) || !["", "core"].includes(row.platform_role) || request.hide_platform && row.platform_role === "core" || request.workload && row.workload !== normalized(request.workload) || request.namespace && row.namespace !== normalized(request.namespace) || request.node && row.claimed_by_node !== normalized(request.node) || request.status && row.status !== request.status || request.protocol && row.protocol !== lower(request.protocol) || request.src_ip && row.src_ip !== normalizedCaptureIP(request.src_ip) || request.dst_ip && row.dst_ip !== normalizedCaptureIP(request.dst_ip) || request.dst_port && row.dst_port !== request.dst_port) return false;
    ids.add(row.row_id); return true;
  });
}
