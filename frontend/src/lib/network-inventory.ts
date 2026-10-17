import type {
  NetworkConversations,
  NetworkSessionsResponse,
  RuntimeThreatPage,
} from "@/api/client";
import { scanInventoryResponseValid } from "@/pages/inventory-workspace";

export const conversationSorts = [
  "from",
  "to",
  "bytes",
  "packets",
  "edges",
  "severity",
  "verdict",
  "last_seen",
  "apps",
];
export const sessionSorts = [
  "workload",
  "node",
  "application",
  "protocol",
  "client",
  "server",
  "bytes",
  "client_bytes",
  "server_bytes",
  "packets",
  "age",
  "idle",
  "severity",
  "observed",
  "state",
];
export const threatSorts = [
  "at",
  "reported",
  "severity",
  "action",
  "workload",
  "category",
  "node",
  "signature",
];
export type NetworkInventoryRequest = {
  cluster_id?: string;
  sort?: string;
  order?: "asc" | "desc";
  offset?: number;
  limit?: number;
  hide_platform?: boolean;
  [key: string]: unknown;
};
type InventoryKind = "conversations" | "sessions" | "threats";
const record = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const count = (value: unknown) =>
  typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
const text = (value: unknown) => typeof value === "string";
const optionalText = (value: unknown) => value === undefined || text(value);
const date = (value: unknown) =>
  text(value) && !Number.isNaN(Date.parse(value as string));
const inactive = (value: unknown) =>
  value === undefined ||
  value === null ||
  value === "" ||
  value === 0 ||
  value === false;
const trim = (value: unknown) =>
  typeof value === "string" ? value.trim() : "";
const lower = (value: unknown) => trim(value).toLowerCase();
const tupleMatches = (value: unknown, tuple: unknown[]) => {
  if (!text(value)) return false;
  try {
    return (
      JSON.stringify(JSON.parse(value as string)) === JSON.stringify(tuple)
    );
  } catch {
    return false;
  }
};
function protocol(value: unknown) {
  const key = lower(value);
  if (!key) return null;
  const known: Record<string, number> = {
    tcp: 6,
    "6": 6,
    udp: 17,
    "17": 17,
    icmp: 1,
    "1": 1,
    icmpv6: 58,
    "58": 58,
  };
  if (known[key] !== undefined) return known[key];
  if (
    /^proto-\d+$/.test(key) &&
    Number(key.slice(6)) > 0 &&
    Number(key.slice(6)) <= 255
  )
    return Number(key.slice(6));
  return NaN;
}
// Compare the entire normalized filter cohort, including defaults. Exact
// endpoint identities remain case-sensitive; each source has its own rules.
function filtersMatch(
  data: Record<string, unknown>,
  request: NetworkInventoryRequest,
  kind: InventoryKind,
) {
  if (!record(data.filters)) return false;
  const expected: Record<string, unknown> = {
    group: trim(request.group),
    hide_platform: request.hide_platform ?? false,
  };
  if (kind === "sessions")
    Object.assign(expected, {
      cluster_id: request.cluster_id ?? null,
      protocol: protocol(request.protocol),
      port: request.port ?? null,
      application: lower(
        typeof request.application === "number"
          ? String(request.application)
          : request.application,
      ),
      peer: lower(request.peer),
      workload: lower(request.workload),
      node: lower(request.node),
      hours: request.hours ?? 0,
      q: lower(request.q),
    });
  else {
    if (data.window_hours !== (request.hours ?? 24)) return false;
    Object.assign(expected, {
      namespace: trim(request.namespace),
      port: request.port ?? 0,
      peer: lower(request.peer),
      application: lower(
        typeof request.application === "number"
          ? String(request.application)
          : request.application,
      ),
    });
    if (kind === "conversations")
      Object.assign(expected, {
        hours: request.hours ?? 24,
        verdict: lower(request.verdict),
        from: trim(request.from),
        to: trim(request.to),
        verdict_group: trim(request.verdict_group),
      });
    else
      Object.assign(expected, {
        severity_min: request.severity_min ?? 0,
        workload_id: trim(request.workload_id),
        category: request.category === "all" ? "" : trim(request.category),
        node: trim(request.node),
        q: lower(request.q),
      });
  }
  for (const [key, value] of Object.entries(expected))
    if (data.filters[key] !== value) return false;
  for (const [key, value] of Object.entries(data.filters))
    if (!(key in expected) && !inactive(value)) return false;
  const metadata = new Set([
    "cluster_id",
    "sort",
    "order",
    "offset",
    "limit",
    "hours",
  ]);
  for (const [key, value] of Object.entries(request))
    if (!metadata.has(key) && !(key in expected) && !inactive(value))
      return false;
  return true;
}
function valid(
  data: unknown,
  rows: unknown,
  request: NetworkInventoryRequest,
  fields: string[],
  kind: InventoryKind,
) {
  if (
    !record(data) ||
    !Array.isArray(rows) ||
    !rows.every(record) ||
    !record(data.summary) ||
    (data.cluster_id ?? null) !== (request.cluster_id ?? null) ||
    data.limit !== request.limit ||
    !filtersMatch(data, request, kind)
  )
    return false;
  return scanInventoryResponseValid(
    data as unknown as Parameters<typeof scanInventoryResponseValid>[0],
    rows.length,
    request.offset ?? 0,
    request.sort ?? "",
    request.order ?? "desc",
    fields,
  );
}
export function conversationsValid(
  data: NetworkConversations | undefined,
  request: NetworkInventoryRequest,
) {
  return (
    valid(
      data,
      data?.conversations,
      request,
      ["bytes", "packets", "edges", "blocked", "violating", "nodes"],
      "conversations",
    ) &&
    data!.source === "rollups" &&
    data!.source_complete === true &&
    data!.summary_scope === "matching_rollups" &&
    data!.conversations.every(
      (row) =>
        text(row.from) &&
        text(row.to) &&
        tupleMatches(row.row_id, [row.from, row.to]) &&
        optionalText(row.from_platform_role) &&
        optionalText(row.to_platform_role) &&
        [row.bytes, row.packets, row.edges].every(count) &&
        date(row.last_seen) &&
        (row.severity === undefined || count(row.severity)) &&
        optionalText(row.verdict) &&
        (row.apps === undefined ||
          (Array.isArray(row.apps) && row.apps.every(text))) &&
        (!request.hide_platform ||
          (row.from_platform_role !== "core" &&
            row.to_platform_role !== "core")),
    ) &&
    new Set(data!.conversations.map((row) => row.row_id)).size ===
      data!.conversations.length
  );
}
export function sessionsValid(
  data: NetworkSessionsResponse | undefined,
  request: NetworkInventoryRequest,
) {
  return (
    valid(
      data,
      data?.sessions,
      request,
      ["client_bytes", "server_bytes", "bytes", "packets", "threats"],
      "sessions",
    ) &&
    data!.sessions.every(
      (row) =>
        row.cluster_id === request.cluster_id &&
        text(row.node) &&
        count(row.id) &&
        tupleMatches(row.row_id, [row.cluster_id, row.node, row.id]) &&
        text(row.platform_role) &&
        [
          row.application,
          row.ip_proto,
          row.client_ip,
          row.server_ip,
          row.client_state,
          row.server_state,
        ].every(text) &&
        optionalText(row.workload_id) &&
        [
          row.client_bytes,
          row.server_bytes,
          row.client_pkts,
          row.server_pkts,
          row.age,
          row.idle,
          row.severity,
          row.client_port,
          row.server_port,
        ].every(count) &&
        row.client_port <= 65535 &&
        row.server_port <= 65535 &&
        count(row.client_bytes + row.server_bytes) &&
        count(row.client_pkts + row.server_pkts) &&
        (row.threat_id === undefined || count(row.threat_id)) &&
        typeof row.ingress === "boolean" &&
        date(row.updated_at) &&
        (!request.hide_platform || row.platform_role !== "core"),
    ) &&
    new Set(data!.sessions.map((row) => row.row_id)).size ===
      data!.sessions.length
  );
}
export function threatsValid(
  data: RuntimeThreatPage | undefined,
  request: NetworkInventoryRequest,
) {
  return (
    valid(
      data,
      data?.threats,
      request,
      ["critical", "blocked", "ips", "dlp", "waf", "workloads"],
      "threats",
    ) &&
    data!.threats.every(
      (row) =>
        text(row.id) &&
        !!row.id &&
        text(row.org_id) &&
        row.cluster_id === request.cluster_id &&
        text(row.platform_role) &&
        [row.severity, row.action, row.threat_id].every(count) &&
        [
          row.node,
          row.ep_mac,
          row.workload_id,
          row.namespace,
          row.pod_name,
          row.threat_name,
          row.msg,
          row.src_ip,
          row.dst_ip,
        ].every(optionalText) &&
        [
          row.application,
          row.ip_proto,
          row.src_port,
          row.dst_port,
          row.pkt_len,
          row.cap_len,
        ].every((value) => value === undefined || count(value)) &&
        (row.src_port === undefined || row.src_port <= 65535) &&
        (row.dst_port === undefined || row.dst_port <= 65535) &&
        typeof row.pkt_ingress === "boolean" &&
        typeof row.sess_ingress === "boolean" &&
        date(row.reported_at) &&
        date(row.at) &&
        (!request.hide_platform || row.platform_role !== "core"),
    ) &&
    new Set(data!.threats.map((row) => row.id)).size === data!.threats.length
  );
}
