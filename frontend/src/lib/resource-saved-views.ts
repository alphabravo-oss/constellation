import type { SavedViewBase } from "@/hooks/useSavedViews";
import { runtimeEventFiltersValid } from "@/pages/runtime-event-inventory";

export type ResourceViewKind = "assets" | "deployments" | "runtime" | "scanner";
export interface ResourceSavedView extends SavedViewBase {
  schema: 1;
  inventory: ResourceViewKind;
  filters: Record<string, string>;
}
const defaults: Record<ResourceViewKind, Record<string, string>> = {
  assets: {
    q: "",
    kind: "all",
    criticality: "all",
    ai_workload: "",
    sort: "risk",
    order: "desc",
  },
  deployments: {
    q: "",
    namespace: "",
    group_mode: "",
    risk_fact: "",
    platform_role: "all",
    hide_platform: "true",
  },
  runtime: {
    tab: "live",
    q: "",
    kind: "",
    source: "",
    severity: "",
    verdict: "",
    workload: "",
    namespace: "",
    node: "",
    after: "",
    before: "",
    sort: "at",
    order: "desc",
  },
  scanner: {
    tab: "jobs",
    q: "",
    status: "all",
    target_type: "",
    cluster_id: "",
    registry_id: "",
    sort: "requested",
    order: "desc",
  },
};
export const resourceViewLabel: Record<ResourceViewKind, string> = {
  assets: "asset",
  deployments: "deployment",
  runtime: "runtime event",
  scanner: "scan job",
};
export const resourceViewKey = (kind: ResourceViewKind) =>
  `constellation.${kind}.views.v1`;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const member = (value: string, allowed: string[]) => allowed.includes(value);
const record = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
export function resourceFiltersValid(
  kind: ResourceViewKind,
  filters: Record<string, string>,
) {
  const expected = Object.keys(defaults[kind]);
  if (
    Object.keys(filters).length !== expected.length ||
    !expected.every((key) => typeof filters[key] === "string") ||
    Object.values(filters).some((value) => value.length > 10000)
  )
    return false;
  if (kind === "assets")
    return (
      member(filters.kind, [
        "all",
        "image",
        "workload",
        "iac-resource",
        "ml-model",
        "cloud-resource",
        "host",
        "repository",
        "serverless",
      ]) &&
      member(filters.criticality, [
        "all",
        "critical",
        "high",
        "medium",
        "low",
      ]) &&
      member(filters.ai_workload, ["", "true", "false"]) &&
      member(filters.sort, [
        "risk",
        "asset",
        "kind",
        "criticality",
        "last-seen",
        "supply-chain",
      ]) &&
      member(filters.order, ["asc", "desc"])
    );
  if (kind === "deployments")
    return (
      member(filters.group_mode, ["", "discover", "monitor", "protect"]) &&
      member(filters.risk_fact, [
        "",
        "privileged",
        "run_as_root",
        "net_exposure",
        "host_network",
      ]) &&
      member(filters.platform_role, ["all", "core", "none"]) &&
      member(filters.hide_platform, ["true", "false"])
    );
  if (kind === "runtime")
    return (
      filters.tab === "live" &&
      runtimeEventFiltersValid(new URLSearchParams(filters))
    );
  return (
    filters.tab === "jobs" &&
    member(filters.status, [
      "all",
      "pending",
      "running",
      "paused",
      "failed",
      "completed",
      "canceled",
    ]) &&
    member(filters.target_type, [
      "",
      "image",
      "workload",
      "host",
      "platform",
      "registry",
      "repository",
      "serverless",
    ]) &&
    member(filters.sort, [
      "requested",
      "target",
      "type",
      "status",
      "attempts",
      "findings",
      "finished",
    ]) &&
    member(filters.order, ["asc", "desc"]) &&
    (!filters.cluster_id || uuid.test(filters.cluster_id)) &&
    (!filters.registry_id || uuid.test(filters.registry_id))
  );
}
export function isResourceSavedView(
  value: unknown,
): value is ResourceSavedView {
  if (
    !record(value) ||
    value.schema !== 1 ||
    typeof value.inventory !== "string" ||
    !Object.hasOwn(defaults, value.inventory) ||
    !record(value.filters) ||
    !Object.values(value.filters).every((field) => typeof field === "string")
  )
    return false;
  return resourceFiltersValid(
    value.inventory as ResourceViewKind,
    value.filters as Record<string, string>,
  );
}
export const resourceViewValidator =
  (kind: ResourceViewKind) =>
  (value: unknown): value is ResourceSavedView =>
    isResourceSavedView(value) && value.inventory === kind;
export function captureResourceView(
  kind: ResourceViewKind,
  params: URLSearchParams,
  overrides: Record<string, string> = {},
): Omit<ResourceSavedView, "id" | "name"> | null {
  const filters = { ...defaults[kind] };
  for (const key of Object.keys(filters)) {
    if (params.getAll(key).length > 1) return null;
    filters[key] = overrides[key] ?? params.get(key) ?? filters[key];
  }
  if (kind === "deployments" && !params.has("q") && params.has("name")) {
    if (params.getAll("name").length > 1) return null;
    filters.q = params.get("name")!;
  }
  if (kind === "deployments") {
    const value = filters.hide_platform.toLowerCase();
    if (["true", "false", "1", "0", "t", "f"].includes(value))
      filters.hide_platform = ["true", "1", "t"].includes(value)
        ? "true"
        : "false";
  }
  return resourceFiltersValid(kind, filters)
    ? { schema: 1, inventory: kind, filters }
    : null;
}
export function applyResourceView(
  params: URLSearchParams,
  view: ResourceSavedView,
): URLSearchParams {
  if (!isResourceSavedView(view)) throw new Error("Invalid saved view");
  const next = new URLSearchParams(params);
  for (const [key, value] of Object.entries(view.filters)) {
    if (value) next.set(key, value);
    else next.delete(key);
  }
  next.delete("page");
  next.delete("selected");
  if (view.inventory === "deployments") next.delete("name");
  if (view.inventory === "runtime") {
    next.delete("event");
    next.delete("event_at");
  }
  return next;
}
export function resourceViewHref(
  kind: ResourceViewKind,
  clusterId: string | undefined,
  params: URLSearchParams,
  hash = "",
  form = false,
) {
  const base =
    kind === "scanner"
      ? "/settings/scanner"
      : clusterId
        ? `/clusters/${encodeURIComponent(clusterId)}/${kind}`
        : "/clusters";
  const query = params.toString(),
    fragment = hash.replace(/^#/, "");
  return `${base}${form ? "/views/new" : ""}${query ? `?${query}` : ""}${fragment ? `#${fragment}` : ""}`;
}
const labels: Record<string, string> = {
  q: "Search",
  kind: "Kind",
  criticality: "Criticality",
  ai_workload: "AI workload",
  sort: "Sort",
  order: "Direction",
  namespace: "Namespace",
  group_mode: "Strongest group mode",
  risk_fact: "Recorded workload fact",
  platform_role: "Platform role",
  hide_platform: "Platform components",
  source: "Source",
  severity: "Minimum severity",
  verdict: "Verdict",
  workload: "Workload contains",
  node: "Node",
  after: "At or after",
  before: "Before",
  status: "Status",
  target_type: "Target type",
  cluster_id: "Cluster ID",
  registry_id: "Registry ID",
};
export function resourceFilterEntries(
  view: Pick<ResourceSavedView, "filters">,
) {
  return Object.entries(view.filters)
    .filter(([key, value]) => value && value !== "all" && key !== "tab")
    .map(
      ([key, value]) =>
        [
          labels[key] ?? key,
          key === "hide_platform"
            ? value === "true"
              ? "Hidden"
              : "Shown"
            : value,
        ] as const,
    );
}
export function resourceViewSummary(view: ResourceSavedView) {
  return (
    resourceFilterEntries(view)
      .map(([label, value]) => `${label}: ${value}`)
      .join(" · ") || "All inventory records"
  );
}
