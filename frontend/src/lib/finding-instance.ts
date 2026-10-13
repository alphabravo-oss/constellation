export interface FindingIdentity {
  id: string;
  first_seen_at: string;
  row_id?: string;
  revision?: string;
  cluster_id?: string | null;
  source_cluster_id?: string | null;
  target_cluster_id?: string | null;
}
// Identity timestamps retain PostgreSQL microseconds. Date is used only for the
// whole-second part; converting the complete timestamp to Date loses identity.
export function findingEpochNanos(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const parts = value.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/);
  if (!parts) return null;
  const [, year, month, day, hour, minute, second, fraction = "", zone] = parts;
  const y = Number(year), m = Number(month), d = Number(day);
  const days = [31, y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (m < 1 || m > 12 || d < 1 || d > days[m - 1] || Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59 || zone !== "Z" && (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59)) return null;
  const whole = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${zone}`);
  if (!Number.isSafeInteger(whole)) return null;
  const nanos = BigInt(whole) * 1_000_000n + BigInt(fraction.padEnd(9, "0"));
  return nanos % 1000n === 0n ? nanos : null;
}
export function sameFindingTimestamp(left: unknown, right: unknown) {
  const value = findingEpochNanos(left);
  return value !== null && value === findingEpochNanos(right);
}
export function findingRowKey(row: Pick<FindingIdentity, "id" | "first_seen_at">): string {
  return JSON.stringify([row.id, findingEpochNanos(row.first_seen_at)?.toString() ?? row.first_seen_at]);
}
export function findingRowIDMatches(row: FindingIdentity) {
  if (typeof row.id !== "string" || !row.id || typeof row.row_id !== "string" || !row.row_id.startsWith(`${row.id}:`)) return false;
  const parts = row.row_id.slice(row.id.length + 1).match(/^(-?)(\d+)(?:\.(\d{1,9}))?$/);
  if (!parts) return false;
  const epoch = BigInt(parts[2]) * 1_000_000_000n + BigInt((parts[3] || "").padEnd(9, "0"));
  return (parts[1] ? -epoch : epoch) === findingEpochNanos(row.first_seen_at);
}
export function findingRevisionValid(value: unknown): value is string {
  return typeof value === "string" && value.length <= 19 && /^[1-9]\d*$/.test(value) && BigInt(value) <= 9223372036854775807n;
}
export function findingInstanceReady(row: FindingIdentity | null | undefined): row is FindingIdentity & { row_id: string; revision: string } {
  return !!row && findingRowIDMatches(row) && findingRevisionValid(row.revision);
}
export function findingBelongsToCluster(row: FindingIdentity, cluster: string) {
  const source = row.source_cluster_id === undefined ? row.cluster_id : row.source_cluster_id;
  return source === cluster || (row.target_cluster_id ?? source) === cluster;
}
export function findingHref(row: Pick<FindingIdentity, "id" | "first_seen_at" | "cluster_id" | "source_cluster_id" | "target_cluster_id">, cluster?: string, action = "") {
  const routeCluster = cluster || row.source_cluster_id || row.cluster_id || row.target_cluster_id;
  const base = routeCluster ? `/clusters/${encodeURIComponent(routeCluster)}/findings` : "/findings";
  const params = new URLSearchParams();
  if (findingEpochNanos(row.first_seen_at) !== null) params.set("first_seen_at", row.first_seen_at);
  return `${base}/${encodeURIComponent(row.id)}${action ? `/${action}` : ""}${params.size ? `?${params}` : ""}`;
}
export function findingChooserHref(cluster: string, id: string) {
  return `/clusters/${encodeURIComponent(cluster)}/findings?${new URLSearchParams({ view: "instances", lifecycle: "all", q: `id:${id}` })}`;
}
export function ambiguousFinding(error: unknown) {
  const response = (error as { response?: { status?: number; data?: { code?: string } } } | undefined)?.response;
  return response?.status === 409 && response.data?.code === "ambiguous_finding_id";
}
export function findingReceiptMatches(receipt: unknown, reviewed: FindingIdentity, cluster: string, comment = false) {
  if (!receipt || typeof receipt !== "object" || !comment && (receipt as { status?: string }).status !== "ok") return false;
  const row = receipt as FindingIdentity;
  return findingInstanceReady(row) && row.id === reviewed.id && sameFindingTimestamp(row.first_seen_at, reviewed.first_seen_at) && findingBelongsToCluster(row, cluster) && (row.source_cluster_id ?? row.cluster_id ?? null) === (reviewed.source_cluster_id ?? reviewed.cluster_id ?? null) && (row.target_cluster_id ?? null) === (reviewed.target_cluster_id ?? null) && findingRevisionValid(reviewed.revision) && (comment ? row.revision === reviewed.revision : BigInt(row.revision) > BigInt(reviewed.revision));
}
export function findingDTOReady(row: FindingIdentity | undefined, id: string, cluster: string, firstSeen?: string) {
  return !!row && findingInstanceReady(row) && row.id === id && findingBelongsToCluster(row, cluster) && (!firstSeen || sameFindingTimestamp(row.first_seen_at, firstSeen));
}
