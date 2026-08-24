import type { AdmissionAssessResult, AdmissionDryRunHistoryRow, ComponentInstance } from "@/api/client";

export interface AdmissionDryRunHistoryEntry {
  id: string;
  assessed_at: string;
  cluster_id?: string;
  image: string;
  namespace: string;
  decision: string;
  enforcement_mode: string;
  current_outcome: string;
  protect_outcome: string;
  matches: number;
}

export interface AdmissionWebhookHealth {
  label: string;
  tone: "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent";
  statTone: "neutral" | "critical" | "high" | "medium" | "low" | "accent";
  detail: string;
  instances: number;
  healthy: number;
  latestSeenAt?: string;
  appliedRevision?: string;
  lastError?: string;
}

export function admissionDryRunHistoryKey(clusterId?: string) {
  return `constellation.admission.dryRunHistory.${clusterId || "global"}.v1`;
}

export function readAdmissionDryRunHistory(storageKey: string): AdmissionDryRunHistoryEntry[] {
  if (typeof localStorage === "undefined") return [];
  try {
    const parsed = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isAdmissionDryRunHistoryEntry);
  } catch {
    return [];
  }
}

export function writeAdmissionDryRunHistory(storageKey: string, entries: AdmissionDryRunHistoryEntry[]) {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(storageKey, JSON.stringify(entries));
  } catch {
    // Keep assessment usable when browser storage is unavailable.
  }
}

export function appendAdmissionDryRunHistory(
  entries: AdmissionDryRunHistoryEntry[],
  entry: AdmissionDryRunHistoryEntry,
  limit = 10,
) {
  return [entry, ...entries.filter((item) => item.id !== entry.id)].slice(0, Math.max(1, limit));
}

export function admissionDryRunHistoryEntryFromRow(row: AdmissionDryRunHistoryRow): AdmissionDryRunHistoryEntry {
  return {
    id: row.id,
    assessed_at: row.assessed_at,
    cluster_id: row.cluster_id || undefined,
    image: row.image,
    namespace: row.namespace || "default",
    decision: row.decision,
    enforcement_mode: row.enforcement_mode || "none",
    current_outcome: row.current_outcome || labelCase(row.decision),
    protect_outcome: row.protect_outcome || labelCase(row.decision),
    matches: row.matches,
  };
}

export function mergeAdmissionDryRunHistory(
  serverEntries: AdmissionDryRunHistoryEntry[],
  localEntries: AdmissionDryRunHistoryEntry[],
  limit = 50,
) {
  const byId = new Map<string, AdmissionDryRunHistoryEntry>();
  for (const entry of localEntries) {
    byId.set(entry.id, entry);
  }
  for (const entry of serverEntries) {
    byId.set(entry.id, entry);
  }
  return Array.from(byId.values())
    .sort((a, b) => historyTime(b) - historyTime(a) || b.id.localeCompare(a.id))
    .slice(0, Math.max(1, limit));
}

export function makeAdmissionDryRunHistoryEntry({
  result,
  image,
  namespace,
  clusterId,
  currentOutcome,
  protectOutcome,
  now = new Date(),
  id,
}: {
  result: AdmissionAssessResult;
  image: string;
  namespace?: string;
  clusterId?: string;
  currentOutcome: string;
  protectOutcome: string;
  now?: Date;
  id?: string;
}): AdmissionDryRunHistoryEntry {
  return {
    id: id || result.dry_run_id || defaultHistoryID(now),
    assessed_at: result.assessed_at || now.toISOString(),
    cluster_id: clusterId || undefined,
    image: image.trim() || result.image,
    namespace: (namespace || result.namespace || "default").trim() || "default",
    decision: result.decision,
    enforcement_mode: result.enforcement_mode || "none",
    current_outcome: result.current_outcome || currentOutcome,
    protect_outcome: result.protect_outcome || protectOutcome,
    matches: result.matches.length,
  };
}

export function admissionWebhookHealth(components: ComponentInstance[]): AdmissionWebhookHealth {
  if (components.length === 0) {
    return {
      label: "Not observed",
      tone: "warning",
      statTone: "medium",
      detail: "no admission heartbeat",
      instances: 0,
      healthy: 0,
    };
  }

  const latest = newestComponent(components);
  const healthy = components.filter((component) => component.status === "healthy").length;
  const degraded = components.filter((component) => ["degraded", "stale", "drift", "crashlooping"].includes(component.status)).length;
  const lastError = latest?.last_error || components.find((component) => component.last_error)?.last_error;
  const appliedRevision = admissionAppliedRevision(latest) || firstAppliedRevision(components);

  if (healthy === components.length) {
    return {
      label: "Live",
      tone: "success",
      statTone: "low",
      detail: `${healthy}/${components.length} healthy`,
      instances: components.length,
      healthy,
      latestSeenAt: latest?.last_seen_at,
      appliedRevision,
      lastError,
    };
  }
  if (healthy > 0) {
    return {
      label: "Degraded",
      tone: "warning",
      statTone: "medium",
      detail: `${healthy}/${components.length} healthy, ${degraded} degraded`,
      instances: components.length,
      healthy,
      latestSeenAt: latest?.last_seen_at,
      appliedRevision,
      lastError,
    };
  }
  return {
    label: labelCase(latest?.status || "not-observed"),
    tone: latest?.status === "crashlooping" || latest?.status === "missing" ? "error" : "warning",
    statTone: latest?.status === "crashlooping" || latest?.status === "missing" ? "high" : "medium",
    detail: latest?.status_reason || `${components.length} observed, none healthy`,
    instances: components.length,
    healthy,
    latestSeenAt: latest?.last_seen_at,
    appliedRevision,
    lastError,
  };
}

export function admissionAppliedRevision(component?: ComponentInstance): string {
  if (!component?.metadata) return "";
  for (const key of ["applied_revision", "policy_revision", "rules_revision", "config_revision", "admission_revision"]) {
    const value = component.metadata[key];
    if (isScalar(value)) return String(value);
  }
  const nested = component.metadata.admission;
  if (isRecord(nested)) {
    for (const key of ["applied_revision", "policy_revision", "rules_revision", "config_revision"]) {
      const value = nested[key];
      if (isScalar(value)) return String(value);
    }
  }
  return "";
}

function firstAppliedRevision(components: ComponentInstance[]) {
  for (const component of components) {
    const revision = admissionAppliedRevision(component);
    if (revision) return revision;
  }
  return "";
}

function newestComponent(components: ComponentInstance[]) {
  return [...components].sort((a, b) => Date.parse(b.last_seen_at) - Date.parse(a.last_seen_at))[0];
}

function isAdmissionDryRunHistoryEntry(value: unknown): value is AdmissionDryRunHistoryEntry {
  const item = value as AdmissionDryRunHistoryEntry;
  return Boolean(
    item &&
    typeof item === "object" &&
    typeof item.id === "string" &&
    typeof item.assessed_at === "string" &&
    typeof item.image === "string" &&
    typeof item.namespace === "string" &&
    typeof item.decision === "string" &&
    typeof item.matches === "number",
  );
}

function defaultHistoryID(now: Date) {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `admission-dry-run-${now.getTime()}-${Math.random().toString(36).slice(2)}`;
}

function historyTime(entry: AdmissionDryRunHistoryEntry) {
  const parsed = Date.parse(entry.assessed_at);
  return Number.isFinite(parsed) ? parsed : 0;
}

function isScalar(value: unknown) {
  return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function labelCase(value: string) {
  return value.charAt(0).toUpperCase() + value.slice(1).replace(/-/g, " ");
}
