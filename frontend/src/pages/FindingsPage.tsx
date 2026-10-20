import { findingHref, findingBelongsToCluster, findingDTOReady, findingEpochNanos, findingRowIDMatches, findingInstanceReady, findingRowKey, findingReceiptMatches, isFindingChooserQuery } from "@/lib/finding-instance";
import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
// Findings inventory — server filtering, ordered pages, URL state, and page-scoped selection.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import { useMutation, useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { Save, Tag, ChevronDown } from "lucide-react";

import {
  findings,
  type Finding,
  type Lifecycle,
  type Severity,
  type CVERollup,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { RiskScore } from "@/components/ui/risk-score";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { QueryInput } from "@/components/ui/query-input";
import { FilterChip } from "@/components/ui/filter-chip";
import { Button } from "@/components/ui/button";
import { ActionBar } from "@/components/ui/action-bar";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { EmptyState } from "@/components/ui/empty-state";
import { fmtRelative } from "@/lib/format";
import { SEVERITY_RANK } from "@/lib/severity";
import { cn } from "@/lib/cn";
import { Pager } from "@/components/ui/pager";
import { useDebounced } from "@/hooks/useDebounced";
import { useOperatorDensity } from "@/hooks/useOperatorDensity";
import { useSavedViews } from "@/hooks/useSavedViews";

import { FINDING_VIEWS_KEY, isFindingSavedView, inventoryViewHref, type FindingSavedView as SavedView } from "@/lib/inventory-saved-views";
import { Checkbox, Select } from "@/components/ui/form";
import { ExportMenu, MoreFilters, type ExportOption } from "@/ui";
import { sentenceValue } from "@/components/ui/status-pill";
import { useIncludeSystem } from "@/lib/system-scope";
import { apiRequestId } from "@/lib/api-error";

const DENSITY_KEY     = "constellation.findings.density";
const INSTANCE_TABLE_KEY = "findings.instances";
const OBSERVATION_COLUMNS_MIGRATION = { id: "observation-metadata-v1", hideColumnIds: ["instance", "first-seen"] };
const CVE_TABLE_KEY = "findings.cve-rollup";

const STATE_TABS: Array<{ label: string; lifecycle: Lifecycle; description: string }> = [
  { label: "Open", lifecycle: "open", description: "open findings" },
  { label: "Accepted",   lifecycle: "accepted",   description: "risk accepted" },
  { label: "Suppressed", lifecycle: "suppressed", description: "hidden by rule" },
];

const QUERY_HINTS: Array<{ label: string; value: string; example: string }> = [
  { label: "severity", value: "severity:critical", example: "severity:critical" },
  { label: "kev",      value: "kev:true",          example: "kev:true" },
  { label: "kind",     value: "kind:vulnerability", example: "kind:vulnerability" },
  { label: "cve",      value: "cve:CVE-",          example: "cve:CVE-2024-3094" },
  { label: "package",  value: "package:openssl",   example: "package:openssl" },
  { label: "source",   value: "canonical_engine:trivy", example: "canonical_engine:trivy" },
  { label: "diff",     value: "disagreement:true", example: "disagreement:true" },
  { label: "not",      value: "!status:resolved",  example: "!status:resolved" },
];

type GroupBy = "none" | "severity" | "kind" | "asset";

function cvssScore(row: Pick<Finding | CVERollup, "cvss" | "cvss_base">) {
  return row.cvss_base ?? row.cvss;
}

function cvssColor(score = 0) {
  if (score >= 9) return "var(--color-severity-critical)";
  if (score >= 7) return "var(--color-severity-high)";
  return "var(--color-foreground)";
}

export function FindingsPage() {
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const owner = [identity?.org_id, identity?.user_id];
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const scopeReady = !!identity?.org_id && !!identity?.user_id && !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const [searchParams, setSearchParams] = useRouteSearchParams();
  const location = useLocation();
  const locationHash = location?.hash ?? "";
  const severity = (["critical", "high", "medium", "low", "info"] as const).find((value) => value === searchParams.get("severity")) ?? "";
  const kind = (["vulnerability", "iac", "license", "cloud-config", "drift", "signature", "ml-model", "compliance", "runtime"] as const).find((value) => value === searchParams.get("kind")) ?? "";
  const groupMode = searchParams.get("group_mode") ?? "";
  const idScope = searchParams.get("id_scope") ?? "";
  const allIds = idScope === "all";
  const idLabel = allIds ? "vulnerability IDs" : "CVEs";
  const targetType = searchParams.get("target_type") ?? "";
  const lifecycleValue = searchParams.get("lifecycle");
  const lifecycle: Lifecycle | "" = lifecycleValue === "all" ? "" : (["open", "triaged", "in_progress", "accepted", "suppressed", "resolved"] as const).find((value) => value === lifecycleValue) ?? "open";
  const query = searchParams.get("q") ?? "";
  const instanceChooser = isFindingChooserQuery(query);
  const includeSystemScope = useIncludeSystem(searchParams);
  const includeSystem = includeSystemScope || instanceChooser;
  const workloadScope = includeSystem ? "all" as const : "application" as const;
  const debouncedQuery = useDebounced(query.trim(), 300);
  const querySettled = query.trim() === debouncedQuery;
  const serverQuery = [debouncedQuery, severity ? `severity:${severity}` : ""].filter(Boolean).join(" ");
  const groupBy: GroupBy = (["none", "severity", "kind", "asset"] as const).find((value) => value === searchParams.get("group")) ?? "none";
  const requestedView = searchParams.get("view");
  const activeView = kind && kind !== "vulnerability" ? "instances" : requestedView === "instances" || requestedView === "cve" ? requestedView : severity || lifecycle !== "open" ? "instances" : "cve";
  const fixableOnly = searchParams.get("fixable") === "true" || searchParams.get("fixable") === "1";
  const pageValue = Number(searchParams.get("page"));
  const page = Number.isSafeInteger(pageValue) && pageValue >= 1 ? pageValue - 1 : 0;
  const PAGE_SIZE = 100;
  const sort = ["risk", "severity", "cve", "cvss", "cvss_vector", "title", "package", "fixed", "asset", "lifecycle", "kind", "age", "last_seen"].find((value) => value === searchParams.get("sort")) ?? "risk";
  const order = searchParams.get("order") === "asc" ? "asc" : "desc";
  const setFilters = useCallback((changes: Record<string, string>, resetPage = true, replace = false) => {
    setSearchParams((current) => {
      const next = new URLSearchParams(current);
      for (const [name, value] of Object.entries(changes)) {
        if (value) next.set(name, value); else next.delete(name);
      }
      if (resetPage) next.delete("page");
      return next;
    }, { replace });
  }, [setSearchParams]);
  const setUrlFilter = (name: string, value: string) => setFilters({ [name]: name === "lifecycle" && !value ? "all" : value });
  const setQuery = (value: string | ((current: string) => string)) => setFilters({ q: typeof value === "function" ? value(query) : value }, true, true);
  const setPage = (value: number) => setFilters({ page: value ? String(value + 1) : "" }, false);
  const onSortChange = (value: { id: string; dir: "asc" | "desc" } | null) => setFilters({ sort: value?.id ?? "risk", order: value?.dir ?? "desc" });
  const [density, setDensity] = useOperatorDensity(DENSITY_KEY);
  const { views, deleteView, persistenceError } = useSavedViews<SavedView>(FINDING_VIEWS_KEY, { validate: isFindingSavedView });
  const navigate = useNavigate();
  const openFinding = (finding: Finding) => navigate({ href: findingHref(finding, clusterId) });
  const request: NonNullable<Parameters<typeof findings.list>[0]> = { workload_scope: workloadScope, kind: activeView === "cve" ? "vulnerability" as const : kind || undefined, lifecycle: lifecycle || undefined, cluster_id: clusterId, ...(groupMode ? { group_mode: groupMode } : {}), ...(idScope ? { id_scope: idScope as "all" } : {}), ...(targetType ? { target_type: targetType } : {}), q: serverQuery || undefined, fixable: fixableOnly || undefined, sort: activeView === "cve" ? "risk" : sort, order: activeView === "cve" ? "desc" as const : order };
  const instanceKey = ["findings", ...owner, request, activeView, activeView === "instances" ? page : 0];
  // The rollup needs a single instance solely for its lifecycle counts.
  const q = useQuery({ queryKey: instanceKey, queryFn: () => findings.list({ ...request, limit: activeView === "instances" ? PAGE_SIZE : 1, offset: activeView === "instances" ? page * PAGE_SIZE : 0 }), enabled: scopeReady && querySettled, placeholderData: keepPreviousData });
  const cveKey = ["findings-cve", ...owner, request, page];
  const cveQ = useQuery({ queryKey: cveKey, queryFn: () => findings.byCVE({ workload_scope: workloadScope, cluster_id: clusterId, ...(groupMode ? { group_mode: groupMode } : {}), ...(idScope ? { id_scope: idScope as "all" } : {}), ...(targetType ? { target_type: targetType } : {}), lifecycle: lifecycle || undefined, q: serverQuery || undefined, fixable: fixableOnly || undefined, limit: PAGE_SIZE, offset: page * PAGE_SIZE }), enabled: activeView === "cve" && scopeReady && querySettled, placeholderData: keepPreviousData });
  const activeQ = activeView === "cve" ? cveQ : q;
  const validInstances = !q.data || Array.isArray(q.data.findings) && q.data.findings.every(row => !!row && typeof row.id === "string" && !!clusterId && findingBelongsToCluster(row, clusterId) && findingEpochNanos(row.first_seen_at) !== null && (!row.row_id || findingRowIDMatches(row))) && new Set(q.data.findings.map(findingRowKey)).size === q.data.findings.length;
  const ready = (activeView !== "instances" || validInstances) && scopeReady && querySettled && activeQ.isSuccess && !activeQ.isFetching && !activeQ.isPlaceholderData;
  const rows = useMemo(() => validInstances ? q.data?.findings ?? [] : [], [q.data, validInstances]);
  const cveRows = cveQ.data?.cves ?? [];
  const total = ready ? activeQ.data?.total ?? 0 : undefined;
  const outOfRange = ready && page > 0 && page * PAGE_SIZE >= (total ?? 0);
  const grouped = useMemo(() => groupRows(rows, groupBy), [rows, groupBy]);
  const selectionScope = JSON.stringify([owner, clusterId, workloadScope, groupMode, idScope, targetType, kind, lifecycle, severity, query, fixableOnly, activeView, groupBy, page, sort, order]);
  const [selection, setSelection] = useState<{ scope: string; ids: Set<React.Key> }>({ scope: selectionScope, ids: new Set() });
  const selected = ready && activeView === "instances" && selection.scope === selectionScope ? selection.ids : new Set<React.Key>();
  const setSelected = (ids: Set<React.Key>) => setSelection({ scope: selectionScope, ids });
  useEffect(() => { setSelection({ scope: selectionScope, ids: new Set() }); }, [selectionScope, ready]);
  const activeChips: Array<{ label: string; value: string; onRemove: () => void }> = [];
  if (kind) activeChips.push({ label: "kind", value: kind, onRemove: () => setUrlFilter("kind", "") });
  if (groupMode) activeChips.push({ label: "strongest group mode", value: groupMode, onRemove: () => setUrlFilter("group_mode", "") });
  if (allIds) activeChips.push({ label: "ID scope", value: "all non-null vulnerability IDs", onRemove: () => setUrlFilter("id_scope", "") });
  if (targetType) activeChips.push({ label: "target", value: targetType, onRemove: () => setUrlFilter("target_type", "") });
  if (severity) activeChips.push({ label: "severity", value: severity, onRemove: () => setUrlFilter("severity", "") });
  if (lifecycle !== "open") activeChips.push({ label: "lifecycle", value: lifecycle || "all", onRemove: () => setUrlFilter("lifecycle", "open") });
  if (query) activeChips.push({ label: "q", value: query, onRemove: () => setQuery("") });
  if (fixableOnly) activeChips.push({ label: "fixable", value: "true", onRemove: () => setUrlFilter("fixable", "") });
  function applyView(value: SavedView) {
    setFilters({ include_system: value.includeSystem ? "true" : "", group_mode: value.groupMode ?? "", id_scope: value.idScope ?? "", target_type: value.targetType ?? "", kind: value.kind, lifecycle: value.lifecycle || "all", q: value.query, severity: value.severity ?? "", fixable: value.fixable ? "true" : "", view: value.view ?? ((value.kind && value.kind !== "vulnerability") || (value.lifecycle && value.lifecycle !== "open") || value.severity ? "instances" : "cve"), group: value.group ?? "none", sort: value.sort ?? "risk", order: value.order ?? "desc" });
  }
  const exportContext = JSON.stringify([owner, request, activeView, page, query]);
  const captureExport = useExportGuard(exportContext, !ready, () => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, activeView === "cve" ? cveKey : instanceKey, activeQ.data));
  const exportCSV = useMutation({ mutationFn: async (captured: { shouldDownload: ReturnType<typeof captureExport>; request: Parameters<typeof findings.exportCSV>[0] }) => {
    if (!captured.shouldDownload()) throw new Error("Current results are unavailable");
    await findings.exportCSV(captured.request, captured.shouldDownload);
    if (!captured.shouldDownload()) throw new Error("Current results are unavailable");
  } });

  const columns: Column<Finding>[] = [
    {
      id: "severity", kind: "badge", size: 120, minSize: 112,
      header: "Severity",
      cell: (f) => <SeverityBadge severity={f.severity} kev={Boolean(f.kev)} />,
      exportValue: (f) => f.severity,
      sort: (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
    },
    {
      id: "cve", kind: "id", size: 176, minSize: 160,
      header: "CVE / ID",
      cell: (f) => (
        <span className="flex items-center gap-1.5">
          {f.external_id
            ? <Link to="." href={clusterId ? `/clusters/${clusterId}/cve/${f.external_id}` : `/cve/${f.external_id}`} className="text-mono text-13">{f.external_id}</Link>
            : <span className="text-mono text-xs text-muted-foreground">{f.id.slice(0, 10)}</span>}
        </span>
      ),
      exportValue: (f) => f.external_id ?? f.id,
      sort: (a, b) => (a.external_id ?? "").localeCompare(b.external_id ?? ""),
    },
    {
      id: "cvss", kind: "count", size: 88, minSize: 80,
      header: "CVSS",
      numeric: true,
      cell: (f) => {
        const score = cvssScore(f);
        return <span className="text-mono text-xs" style={{ color: cvssColor(score) }}>{score ? score.toFixed(1) : "—"}</span>;
      },
      exportValue: (f) => cvssScore(f) ?? "",
      sort: (a, b) => (cvssScore(a) ?? 0) - (cvssScore(b) ?? 0),
    },
    {
      id: "cvss_vector", kind: "id", size: 208, minSize: 176,
      header: "Vector",
      cell: (f) => (
        <span className="block truncate text-mono text-micro text-muted-foreground" title={f.cvss_vector || undefined}>
          {f.cvss_vector || "—"}
        </span>
      ),
      exportValue: (f) => f.cvss_vector ?? "",
      sort: (a, b) => (a.cvss_vector ?? "").localeCompare(b.cvss_vector ?? ""),
    },
    {
      id: "title", kind: "text", grow: true, minSize: 240,
      header: "Title",
      cell: (f) => (
        <button
          type="button"
          onClick={() => openFinding(f)}
          className="block truncate text-left text-sm hover:underline"
          title={f.title}
        >
          {f.title}
        </button>
      ),
      exportValue: (f) => f.title,
      sort: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: "package", kind: "name", size: 152, minSize: 128, grow: false,
      header: "Package",
      cell: (f) => <span className="text-mono text-xs">{f.package_name || "—"}</span>,
      exportValue: (f) => f.package_name ?? "",
      sort: (a, b) => (a.package_name ?? "").localeCompare(b.package_name ?? ""),
    },
    {
      id: "fixed", kind: "text", size: 160, minSize: 112, wrap: true,
      header: "Fixed in",
      cell: (f) => <span className="text-mono text-xs text-muted-foreground">{f.fixed_version || "—"}</span>,
      exportValue: (f) => f.fixed_version ?? "",
      sort: (a, b) => (a.fixed_version ?? "").localeCompare(b.fixed_version ?? ""),
    },
    {
      id: "asset", kind: "id", size: 144, minSize: 128,
      header: "Asset",
      cell: (f) => (
        <Link to="." href={`/clusters/${clusterId}/risk/asset/${encodeURIComponent(f.asset_id)}`} className="text-mono text-micro text-muted-foreground hover:text-foreground" title="Open risk workspace">
          {f.asset_id.slice(0, 14)}
        </Link>
      ),
      exportValue: (f) => f.asset_id,
      sort: (a, b) => a.asset_id.localeCompare(b.asset_id),
    },
    {
      id: "risk", kind: "count", size: 88, minSize: 80,
      header: "Risk",
      numeric: true,
      cell: (f) => <RiskScore score={f.risk_score} />,
      exportValue: (f) => f.risk_score,
      sort: (a, b) => a.risk_score - b.risk_score,
    },
    {
      id: "lifecycle", kind: "status", size: 128, minSize: 112,
      header: "Lifecycle",
      cell: (f) => <LifecycleBadge lifecycle={f.lifecycle} />,
      exportValue: (f) => f.lifecycle,
      sort: (a, b) => a.lifecycle.localeCompare(b.lifecycle),
    },
    {
      id: "kind", kind: "status",
      header: "Kind",
      cell: (f) => <span className="text-micro text-mono text-muted-foreground">{f.kind}</span>,
      exportValue: (f) => f.kind,
      sort: (a, b) => a.kind.localeCompare(b.kind),
    },
    { id: "platform-role", header: "Platform role", kind: "status", exportValue: f => f.platform_role ?? "", cell: f => <span className="text-xs">{f.platform_role === "core" ? "Core" : f.platform_role === "" ? "Unclassified" : "Not reported"}</span> },
    {
      id: "age", kind: "age", size: 144, minSize: 128,
      header: "Age",
      cell: (f) => <span className="text-micro text-muted-foreground">{fmtRelative(f.last_seen_at)}</span>,
      exportValue: (f) => f.last_seen_at,
      sort: (a, b) => +new Date(a.last_seen_at) - +new Date(b.last_seen_at),
    },
  ];

  columns.push({ id: "instance", header: "Observation identity", kind: "id", wrap: true, cell: finding => finding.row_id ?? "Not reported", exportValue: finding => finding.row_id ?? "" }, { id: "first-seen", header: "First observed", kind: "date", hideable: !instanceChooser, cell: finding => finding.first_seen_at, exportValue: finding => finding.first_seen_at });
  const totalSelected = selected.size;

  const captureBulk = useExportGuard(selectionScope, !ready, () => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, instanceKey, q.data));
  const bulkAction = useMutation({
    mutationFn: async ({ action, scope, isCurrent }: { action: "triage" | "suppress" | "accept"; scope: string; isCurrent: () => boolean }) => {
      if (scope !== selectionScope || !isCurrent()) throw new Error("Selection is unavailable");
      const current = qc.getQueryState<Awaited<ReturnType<typeof findings.list>>>(instanceKey);
      const ids = Array.from(selected) as string[];
      const available = new Map(current?.data?.findings.map(finding => [findingRowKey(finding), finding]));
      if (!ready || !clusterId || activeView !== "instances" || !ids.length || !clusterCacheReady(qc, clusterId) || !exportQueryReady(qc, instanceKey, q.data) || ids.some(id => { const row = available.get(id); return !findingInstanceReady(row) || !findingDTOReady(row, row.id, clusterId, row.first_seen_at); })) throw new Error("Selection is unavailable");
      const results = await Promise.allSettled(ids.map(async key => {
        const finding = available.get(key)!;
        const selector = { first_seen_at: finding.first_seen_at, cluster_id: clusterId };
        const reviewed_revision = finding.revision!;
        const receipt = action === "triage" ? await findings.instanceTriage(finding.id, selector, { reviewed_revision, priority: "high" }) : action === "suppress" ? await findings.instanceSuppress(finding.id, selector, { reviewed_revision, reason: "bulk suppress via Findings" }) : await findings.instanceAcceptRisk(finding.id, selector, { reviewed_revision, reason: "bulk accept-risk via Findings", accepted_until: new Date(Date.now() + 30 * 86400_000).toISOString() });
        if (!findingReceiptMatches(receipt, finding, clusterId)) throw new Error("Updated observation could not be confirmed");
      }));
      if (results.some((result) => result.status === "rejected")) throw new Error("Some selected findings could not be updated");
    },
    onSettled: (_data, _error, captured) => { if (captured.scope !== selectionScope || !captured.isCurrent()) return; void qc.invalidateQueries({ queryKey: ["findings"] }); void qc.invalidateQueries({ queryKey: ["findings-cve"] }); setSelected(new Set()); },
  });

  const resetBulk = bulkAction.reset;
  useEffect(() => { resetBulk(); }, [selectionScope, resetBulk]);
  const lifecycleCount = (value: Lifecycle) => scopeReady && querySettled && q.isSuccess && !q.isFetching && !q.isPlaceholderData ? q.data.lifecycle_counts?.[value] : undefined;
  const lifecycleHref = (value: Lifecycle) => {
    const next = new URLSearchParams(searchParams);
    next.set("lifecycle", value);
    next.delete("page");
    return `${location?.pathname ?? ""}?${next}`;
  };
  const systemTotal = q.isSuccess && !q.isFetching && !q.isPlaceholderData && typeof q.data.system_total === "number" ? q.data.system_total : undefined;
  const moreFilterCount = [lifecycleValue && lifecycleValue !== "open" ? "1" : "", kind, groupMode, idScope, targetType, fixableOnly ? "1" : "", groupBy !== "none" ? groupBy : ""].filter(Boolean).length;
  const exportMatching = () => exportCSV.mutate({ shouldDownload: captureExport(), request: { ...request, q: activeView === "cve" && !allIds ? [serverQuery, "cve:CVE-"].filter(Boolean).join(" ") : request.q, limit: 100000, offset: 0 } });
  const exportOptions = [{ label: "Matching instances", description: "Up to 100,000 matching instances, across all pages", onSelect: exportMatching, disabled: !ready || exportCSV.isPending }];
  const toolbar = (
    <>
      <QueryInput
        value={query}
        placeholder="Search findings"
        aria-label="Search findings"
        onChange={(e) => setQuery(e.target.value)}
        onClear={() => setQuery("")}
        className="min-w-60 flex-1"
        suggestions={QUERY_HINTS.map((hint) => ({ label: hint.label, value: hint.example }))}
        onSuggestion={(hint) => setQuery((current) => current ? `${current} ${hint.value}` : hint.value)}
      />
      <FilterSelect label="Severity" value={severity} onChange={(value) => setUrlFilter("severity", value)}
        options={[["", "Any severity"], ["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"], ["info", "Info"]]} />
      <MoreFilters count={moreFilterCount}>
        <FilterField label="Lifecycle"><FilterSelect label="Lifecycle" value={lifecycleValue === "all" ? "all" : lifecycle} onChange={(value) => setFilters({ lifecycle: value || "all" })}
        wide options={[["open", "Open"], ["triaged", "Triaged"], ["in_progress", "In progress"], ["accepted", "Accepted"], ["suppressed", "Suppressed"], ["resolved", "Resolved"], ["all", "Any lifecycle"]]} /></FilterField>
        <FilterField label="Kind"><FilterSelect label="Kind" value={kind} onChange={(v) => setFilters({ kind: v, ...(v && v !== "vulnerability" ? { view: "instances" } : {}) })}
        wide options={[["", "Any kind"], ["vulnerability", "Vulnerability"], ["iac", "IaC"], ["license", "License"], ["cloud-config", "Cloud config"], ["drift", "Drift"], ["signature", "Signature"], ["ml-model", "ML model"], ["compliance", "Compliance"], ["runtime", "Runtime"]]} /></FilterField>
        <FilterField label="Strongest group mode"><FilterSelect label="Strongest group mode" value={groupMode} onChange={(value) => setUrlFilter("group_mode", value)} wide options={[["", "Any group mode"], ["discover", "Discover"], ["monitor", "Monitor"], ["protect", "Protect"], ...(!["", "discover", "monitor", "protect"].includes(groupMode) ? [[groupMode, `Invalid mode: ${groupMode}`] as [string, string]] : [])]} /></FilterField>
        <FilterField label="Vulnerability IDs"><FilterSelect label="Vulnerability IDs" value={idScope} onChange={(value) => setUrlFilter("id_scope", value)} wide options={[["", "CVE-only rollups"], ["all", "All non-null IDs"], ...(!["", "all"].includes(idScope) ? [[idScope, `Invalid scope: ${idScope}`] as [string, string]] : [])]} /></FilterField>
        <FilterField label="Target type"><FilterSelect label="Target type" value={targetType} onChange={(value) => setUrlFilter("target_type", value)} wide options={[["", "Any target"], ["image-workload", "Image workload"], ["host", "Host"], ["platform", "Platform"], ["image", "Image"], ["registry", "Registry"], ["repository", "Repository"], ["serverless", "Serverless"], ["workload", "Workload"], ...(!["", "image-workload", "host", "platform", "image", "registry", "repository", "serverless", "workload"].includes(targetType) ? [[targetType, `Invalid target: ${targetType}`] as [string, string]] : [])]} /></FilterField>
        {activeView === "instances" && <FilterField label="Group rows"><FilterSelect label="Group rows" value={groupBy} onChange={(value) => setUrlFilter("group", value === "none" ? "" : value)} wide options={[["none", "No grouping"], ["severity", "By severity"], ["kind", "By kind"], ["asset", "By asset"]]} /></FilterField>}
        <label className="flex items-center gap-2 text-sm">
          <Checkbox checked={fixableOnly} aria-label="Fixable only" onChange={() => setUrlFilter("fixable", fixableOnly ? "" : "true")} />
          Fixable only
        </label>
      </MoreFilters>
      <div className="inline-flex h-9 items-center rounded-md border border-border p-0.5" role="group" aria-label="Rows">
        {([["instances", "Instances"], ["cve", allIds ? "By vulnerability ID" : "By CVE"]] as Array<["instances" | "cve", string]>).map(([v, l]) => (
          <button
            key={v}
            type="button"
            onClick={() => setUrlFilter("view", v)}
            disabled={v === "cve" && Boolean(kind && kind !== "vulnerability")}
            title={v === "cve" && kind && kind !== "vulnerability" ? "By CVE is available for vulnerabilities" : v === "cve" ? "One row per CVE with its blast radius" : "One row per finding instance"}
            aria-pressed={activeView === v}
            data-testid={`findings-view-${v}`}
            className={cn(
              "inline-flex h-7 items-center rounded-sm px-3 text-sm transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50",
              activeView === v ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground",
            )}
          >{l}</button>
        ))}
      </div>
    </>
  );
  const chips = activeChips.length > 0 ? (
    <div className="flex flex-wrap items-center gap-1.5" data-testid="findings-active-filters">
      {activeChips.map((c, i) => <FilterChip key={i} label={c.label} value={c.value} onRemove={c.onRemove} active />)}
      <button type="button" className="h-7 rounded-md px-2 text-meta text-muted-foreground hover:text-foreground" onClick={() => setFilters({ q: "", kind: "", group_mode: "", id_scope: "", target_type: "", severity: "", lifecycle: "open", fixable: "", group: "" })}>Clear all</button>
    </div>
  ) : null;
  const verdictDetail = (
    <div className="space-y-1.5">
      <p>{activeView === "cve" ? `Rollups are ordered by highest risk across all matching ${idLabel}; the CVE table export contains the rollups on this page.` : "Search and ordering apply to the complete matching inventory; the table export and selections cover this page."}</p>
      <p data-testid="findings-system-scope">{systemTotal !== undefined ? `${systemTotal.toLocaleString()} Constellation findings ${includeSystem ? "included" : "hidden"} by the System workloads switch.` : "Constellation finding count unavailable."}</p>
      {groupMode && <p data-testid="findings-mode-scope">Image-workload vulnerabilities linked by image digest to workloads whose strongest configured group mode is {groupMode}. Unmatched workloads are excluded; an ID may appear in more than one mode through different workloads. This describes cached group membership, not applied protection.</p>}
      {allIds && <p>All non-null vulnerability IDs, including advisories without a CVE prefix.</p>}
      {activeView === "cve" && fixableOnly && <p>Fixable rollups count all matching instances of an ID with an available fix.</p>}
    </div>
  );

  return (
    <div className="space-y-4" data-testid="findings-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Findings"
        actions={
          <>
            <SavedViewsMenu views={views} onApply={applyView} onDelete={deleteView} summary={view => [view.lifecycle, view.kind, view.query].filter(Boolean).join(" · ") || "all"} />
            <Button size="sm" disabled={!scopeReady} onClick={() => { if (clusterId) void navigate({ href: inventoryViewHref(clusterId, "findings", searchParams, locationHash, true) }); }}>
              <Save className="h-3.5 w-3.5" /> Save view
            </Button>
          </>
        }
      />

      {persistenceError && <ErrorState title={persistenceError} />}
      <div data-testid="finding-state-tabs"><VerdictBanner
        status={activeQ.isError || !scopeReady ? "degraded" : "info"}
        title={ready ? `${total?.toLocaleString()} matching ${activeView === "cve" ? idLabel : "finding instances"}` : "Finding results are updating"}
        numbers={STATE_TABS.map((tab) => ({ label: tab.label, value: lifecycleCount(tab.lifecycle)?.toLocaleString() ?? "—", href: lifecycleHref(tab.lifecycle), tone: tab.lifecycle === lifecycle ? "default" as const : "muted" as const, testId: `finding-state-${tab.lifecycle}` }))}
        detail={verdictDetail}
      /></div>
      {chips}
      {exportCSV.isError && exportCSV.variables?.shouldDownload() && <ErrorState title="Could not export matching instances. Try again." />}
      {bulkAction.isError && <ErrorState title="Some selected findings could not be updated. Refresh and review their current states before retrying." />}
      {activeView === "cve" && q.isError && <ErrorState title="Lifecycle counts could not be loaded." action={<Button onClick={() => void q.refetch()}>Retry counts</Button>} />}
      {!scopeReady ? <><ToolbarRow toolbar={toolbar} exportOptions={exportOptions} /><ErrorState title="The active cluster could not be resolved. Findings are unavailable until its scope recovers." /></>
        : activeView === "instances" && !validInstances ? <ErrorState title="Finding observations could not be identified safely." action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : activeQ.isError ? <><ToolbarRow toolbar={toolbar} exportOptions={exportOptions} /><ErrorState title="Could not load findings. Review your query and retry." correlationId={apiRequestId(activeQ.error)} action={<Button onClick={() => void activeQ.refetch()}>Retry</Button>} /></>
        : !ready ? <><ToolbarRow toolbar={toolbar} exportOptions={exportOptions} /><LoadingState label={activeQ.isPending ? "Loading findings" : "Updating findings"} /></>
        : outOfRange ? <EmptyState title="This page is outside the current results" hint="The inventory may have changed." action={<Button onClick={() => setPage(0)}>First page</Button>} />
        : <>
          {activeView === "cve" ? <CVETable rows={cveRows} clusterId={clusterId} allIds={allIds} targetType={targetType} toolbar={toolbar} exportOptions={exportOptions} />
            : groupBy === "none" ? <DataTable
                rows={rows} columns={columns} rowKey={findingRowKey}
                density={density} onDensityChange={setDensity} selectable selected={selected} onSelectedChange={setSelected}
                onRowClick={openFinding} sort={{ id: sort === "last_seen" ? "age" : sort, dir: order }} onSortChange={onSortChange} manualSorting pagination={false}
                preferencesKey={INSTANCE_TABLE_KEY} preferenceMigration={OBSERVATION_COLUMNS_MIGRATION} defaultHiddenColumnIds={["cvss_vector", "package", "fixed", "platform-role", "instance", "first-seen", "kind"]}
                toolbar={toolbar} exportOptions={exportOptions}
                canExport={() => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, instanceKey, q.data)} exportFileName="constellation-findings-page" exportLabel="Export this page CSV" testId="findings-table"
                emptyState={<EmptyState title="No findings match" hint="Adjust your filters or clear the query." icon={<Tag />} action={<Button onClick={() => setFilters({ q: "", kind: "", group_mode: "", id_scope: "", target_type: "", severity: "", lifecycle: "open", fixable: "", page: "" })}>Reset filters</Button>} />}
              />
            : <div className="space-y-3">
                <ToolbarRow toolbar={toolbar} exportOptions={exportOptions} />
                <p className="text-meta text-muted-foreground" data-testid="findings-group-scope">{grouped.length} groups from {rows.length} instances on this server page</p>
                {grouped.map((group) => <details key={group.label} open className="rounded-lg border border-border bg-card">
                  <summary className="flex cursor-pointer list-none items-center justify-between gap-2 border-b border-border px-3 py-2"><span className="flex items-center gap-2"><ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /><span className="text-sm font-semibold">{sentenceValue(group.label)}</span><span className="text-meta text-muted-foreground">{group.items.length} on this page</span></span></summary>
                  <DataTable rows={group.items} columns={columns} rowKey={findingRowKey} density={density} onDensityChange={setDensity}
                    selectable selected={selected} onSelectedChange={(ids) => { const merged = new Set(selected); for (const item of group.items) merged.delete(findingRowKey(item)); for (const id of ids) if (group.items.some((item) => findingRowKey(item) === id)) merged.add(id); setSelected(merged); }} onRowClick={openFinding}
                    sort={{ id: sort === "last_seen" ? "age" : sort, dir: order }} onSortChange={onSortChange} manualSorting pagination={false}
                    showDensityToggle={false} showColumnChooser={false} preferencesKey={INSTANCE_TABLE_KEY} preferenceMigration={OBSERVATION_COLUMNS_MIGRATION} defaultHiddenColumnIds={["cvss_vector", "package", "fixed", "platform-role", "instance", "first-seen", "kind"]}
                    canExport={() => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, instanceKey, q.data)} exportFileName={`constellation-findings-page-${safeFilename(group.label)}`} exportLabel="Export this group on this page CSV" className="rounded-none border-0" />
                </details>)}
                {!rows.length && <EmptyState title="No findings match" hint="Adjust your filters or clear the query." />}
              </div>}
          <Pager page={page} pageSize={PAGE_SIZE} total={total} rowsOnPage={activeView === "cve" ? cveRows.length : rows.length} onPage={setPage} />
        </>}
      <ActionBar count={totalSelected} onClear={() => setSelected(new Set())}>
        <Button size="sm" disabled={!ready || bulkAction.isPending} onClick={() => bulkAction.mutate({ action: "triage", scope: selectionScope, isCurrent: captureBulk() })}>Triage</Button>
        <Button size="sm" disabled={!ready || bulkAction.isPending} onClick={() => bulkAction.mutate({ action: "suppress", scope: selectionScope, isCurrent: captureBulk() })}>Suppress</Button>
        <Button size="sm" disabled={!ready || bulkAction.isPending} onClick={() => bulkAction.mutate({ action: "accept", scope: selectionScope, isCurrent: captureBulk() })}>Accept risk · 30 days</Button>
      </ActionBar>
    </div>
  );
}

// CVETable — the NeuVector-style rollup: one row per CVE with its blast radius
// (how many images / clusters it hits and total instances), sorted by risk.
function CVETable({ rows, clusterId, allIds = false, targetType, toolbar, exportOptions }: { rows: CVERollup[]; clusterId?: string; allIds?: boolean; targetType?: string; toolbar?: React.ReactNode; exportOptions?: ExportOption[] }) {
  const referenceLabel = targetType === "host" ? "host reference" : targetType === "platform" ? "platform reference" : "image";
  const columns: Column<CVERollup>[] = [
    { id: "severity", kind: "badge", size: 120, minSize: 112, header: "Severity",
      cell: (c) => <SeverityBadge severity={c.severity} kev={Boolean(c.kev)} />,
      exportValue: (c) => c.severity },
    { id: "cve", kind: "id", size: 176, minSize: 160, header: allIds ? "Vulnerability ID" : "CVE",
      cell: (c) => (
        <span className="flex items-center gap-1.5">
          <span className="text-mono text-xs">{c.cve.startsWith("CVE-") ? <a href={clusterId ? `/clusters/${clusterId}/cve/${encodeURIComponent(c.cve)}` : `/cve/${encodeURIComponent(c.cve)}`} className="hover:underline">{c.cve}</a> : c.cve || "(empty external ID)"}</span>
        </span>
      ),
      exportValue: (c) => c.kev ? `${c.cve} KEV` : c.cve },
    { id: "cvss", kind: "count", size: 88, minSize: 80, header: "CVSS", numeric: true,
      cell: (c) => {
        const score = cvssScore(c);
        return <span className="text-mono text-xs" style={{ color: cvssColor(score) }}>{score ? score.toFixed(1) : "—"}</span>;
      },
      exportValue: (c) => cvssScore(c) ?? "" },
    { id: "cvss_vector", kind: "id", size: 208, minSize: 176, header: "Vector",
      cell: (c) => (
        <span className="block truncate text-mono text-micro text-muted-foreground" title={c.cvss_vector || undefined}>
          {c.cvss_vector || "—"}
        </span>
      ),
      exportValue: (c) => c.cvss_vector ?? "" },
    { id: "package", kind: "name", size: 152, minSize: 128, grow: false, header: "Package",
      cell: (c) => <span className="text-mono text-xs">{c.package || "—"}</span>,
      exportValue: (c) => c.package ?? "" },
    { id: "fixed", kind: "text", size: 160, minSize: 112, wrap: true, header: "Fixed in",
      cell: (c) => <span className="text-mono text-xs text-muted-foreground">{c.fixed_version || "—"}</span>,
      exportValue: (c) => c.fixed_version ?? "" },
    { id: "affected", kind: "count", size: 176, minSize: 144, maxSize: 200, wrap: true, header: "Affected", numeric: true,
      cell: (c) => (
        <span className="text-xs" title={c.images.join("\n")}>
          {c.affected_images} {referenceLabel}{c.affected_images === 1 ? "" : "s"}
          {c.affected_clusters > 1 ? ` · ${c.affected_clusters} clusters` : ""}
        </span>
      ),
      exportValue: (c) => `${c.affected_images} ${referenceLabel}s; ${c.affected_clusters} clusters` },
    { id: "instances", kind: "count", size: 112, minSize: 96, header: "Instances", numeric: true,
      cell: (c) => <span className="text-mono text-xs">{c.instances}</span>,
      exportValue: (c) => c.instances },
    { id: "risk", kind: "count", size: 88, minSize: 80, header: "Risk", numeric: true,
      cell: (c) => <RiskScore score={c.risk_score} />,
      exportValue: (c) => c.risk_score },
    { id: "age", kind: "age", size: 144, minSize: 128, header: "Age",
      cell: (c) => <span className="text-micro text-muted-foreground">{fmtRelative(c.last_seen_at)}</span>,
      exportValue: (c) => c.last_seen_at },
  ];
  return (
    <DataTable
      rows={rows}
      columns={columns}
      rowKey={(c) => c.cve}
      pagination={false}
      preferencesKey={CVE_TABLE_KEY}
      exportFileName={allIds ? "constellation-vulnerability-ids-page" : "constellation-cves-page"}
      exportLabel={allIds ? "Export this vulnerability ID page CSV" : "Export this CVE page CSV"}
      testId="findings-cve-table"
      toolbar={toolbar}
      exportOptions={exportOptions}
      defaultHiddenColumnIds={["cvss_vector"]}
      emptyState={<EmptyState title={allIds ? "No vulnerability IDs match" : "No CVEs match"} hint="Adjust your filters or clear the query." icon={<Tag className="h-8 w-8" />} />}
    />
  );
}

function FilterSelect({
  label, value, onChange, options, wide = false,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
  wide?: boolean;
}) {
  return (
    <Select aria-label={label} value={value} onChange={(e) => onChange(e.target.value)} className={wide ? "w-full" : "h-9"}>
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </Select>
  );
}

/** The table toolbar outside a table (loading, error and grouped views). */
function ToolbarRow({ toolbar, exportOptions }: { toolbar: React.ReactNode; exportOptions: ExportOption[] }) {
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-3 py-2" data-slot="table-toolbar">
      {toolbar}
      <span className="ml-auto" data-testid="findings-table-export-menu"><ExportMenu options={exportOptions} /></span>
    </div>
  );
}

function FilterField({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="space-y-1.5"><p className="text-meta font-medium text-muted-foreground">{label}</p>{children}</div>;
}

function groupRows(rows: Finding[], by: GroupBy): Array<{ label: string; items: Finding[] }> {
  if (by === "none") return [{ label: "All", items: rows }];
  const map = new Map<string, Finding[]>();
  for (const f of rows) {
    const key = by === "severity" ? f.severity : by === "kind" ? f.kind : f.asset_id;
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(f);
  }
  let entries = Array.from(map.entries());
  if (by === "severity") {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    entries = entries.sort((a, b) => order.indexOf(a[0] as Severity) - order.indexOf(b[0] as Severity));
  } else {
    entries.sort((a, b) => b[1].length - a[1].length);
  }
  return entries.map(([label, items]) => ({ label, items }));
}

function safeFilename(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "group";
}
