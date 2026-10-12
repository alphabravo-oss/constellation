// Findings inventory — server filtering, ordered pages, URL state, and page-scoped selection.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import { useMutation, useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { Save, Tag, Bookmark, ChevronDown, ListFilter } from "lucide-react";

import {
  findings,
  type Finding,
  type FindingKind,
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
import { StatCard } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { fmtRelative } from "@/lib/format";
import { SEVERITY_RANK } from "@/lib/severity";
import { cn } from "@/lib/cn";
import { Pager } from "@/components/ui/pager";
import { useDebounced } from "@/hooks/useDebounced";
import { useOperatorDensity } from "@/hooks/useOperatorDensity";
import { useSavedViews, type SavedViewBase } from "@/hooks/useSavedViews";

interface SavedView extends SavedViewBase {
  kind: FindingKind | "";
  lifecycle: Lifecycle | "";
  query: string;
  severity?: Severity | "";
  fixable?: boolean;
  view?: "instances" | "cve";
  group?: GroupBy;
  sort?: string;
  order?: "asc" | "desc";
}

const SAVED_VIEWS_KEY = "constellation.findings.views.v1";
const DENSITY_KEY     = "constellation.findings.density";
const INSTANCE_TABLE_KEY = "findings.instances";
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
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const [searchParams, setSearchParams] = useRouteSearchParams();
  const severity = (["critical", "high", "medium", "low", "info"] as const).find((value) => value === searchParams.get("severity")) ?? "";
  const kind = (["vulnerability", "iac", "license", "cloud-config", "drift", "signature", "ml-model", "compliance", "runtime"] as const).find((value) => value === searchParams.get("kind")) ?? "";
  const lifecycleValue = searchParams.get("lifecycle");
  const lifecycle: Lifecycle | "" = lifecycleValue === "all" ? "" : (["open", "triaged", "in_progress", "accepted", "suppressed", "resolved"] as const).find((value) => value === lifecycleValue) ?? "open";
  const query = searchParams.get("q") ?? "";
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
  const { views, saveView: saveStoredView, deleteView } = useSavedViews<SavedView>(SAVED_VIEWS_KEY);
  const navigate = useNavigate();
  const openFinding = (finding: Finding) => navigate({ href: clusterId ? `/clusters/${clusterId}/findings/${finding.id}` : `/findings/${finding.id}` });
  const request: NonNullable<Parameters<typeof findings.list>[0]> = { kind: activeView === "cve" ? "vulnerability" as const : kind || undefined, lifecycle: lifecycle || undefined, cluster_id: clusterId, q: serverQuery || undefined, fixable: fixableOnly || undefined, sort: activeView === "cve" ? "risk" : sort, order: activeView === "cve" ? "desc" as const : order };
  const instanceKey = ["findings", request, activeView, activeView === "instances" ? page : 0];
  // The rollup needs a single instance solely for its lifecycle counts.
  const q = useQuery({ queryKey: instanceKey, queryFn: () => findings.list({ ...request, limit: activeView === "instances" ? PAGE_SIZE : 1, offset: activeView === "instances" ? page * PAGE_SIZE : 0 }), enabled: scopeReady && querySettled, placeholderData: keepPreviousData });
  const cveQ = useQuery({ queryKey: ["findings-cve", request, page], queryFn: () => findings.byCVE({ cluster_id: clusterId, lifecycle: lifecycle || undefined, q: serverQuery || undefined, fixable: fixableOnly || undefined, limit: PAGE_SIZE, offset: page * PAGE_SIZE }), enabled: activeView === "cve" && scopeReady && querySettled, placeholderData: keepPreviousData });
  const activeQ = activeView === "cve" ? cveQ : q;
  const ready = scopeReady && querySettled && activeQ.isSuccess && !activeQ.isFetching && !activeQ.isPlaceholderData;
  const rows = useMemo(() => q.data?.findings ?? [], [q.data]);
  const cveRows = cveQ.data?.cves ?? [];
  const total = ready ? activeQ.data?.total ?? 0 : undefined;
  const outOfRange = ready && page > 0 && page * PAGE_SIZE >= (total ?? 0);
  const grouped = useMemo(() => groupRows(rows, groupBy), [rows, groupBy]);
  const selectionScope = JSON.stringify([clusterId, kind, lifecycle, severity, query, fixableOnly, activeView, groupBy, page, sort, order]);
  const [selection, setSelection] = useState<{ scope: string; ids: Set<React.Key> }>({ scope: selectionScope, ids: new Set() });
  const selected = ready && activeView === "instances" && selection.scope === selectionScope ? selection.ids : new Set<React.Key>();
  const setSelected = (ids: Set<React.Key>) => setSelection({ scope: selectionScope, ids });
  useEffect(() => { setSelection({ scope: selectionScope, ids: new Set() }); }, [selectionScope, ready]);
  const activeChips: Array<{ label: string; value: string; onRemove: () => void }> = [];
  if (kind) activeChips.push({ label: "kind", value: kind, onRemove: () => setUrlFilter("kind", "") });
  if (severity) activeChips.push({ label: "severity", value: severity, onRemove: () => setUrlFilter("severity", "") });
  if (lifecycle !== "open") activeChips.push({ label: "lifecycle", value: lifecycle || "all", onRemove: () => setUrlFilter("lifecycle", "open") });
  if (query) activeChips.push({ label: "q", value: query, onRemove: () => setQuery("") });
  if (fixableOnly) activeChips.push({ label: "fixable", value: "true", onRemove: () => setUrlFilter("fixable", "") });
  function saveView() {
    const name = prompt("Name this view");
    if (name) saveStoredView(name, { kind, lifecycle, query, severity, fixable: fixableOnly, view: activeView, group: groupBy, sort, order });
  }
  function applyView(value: SavedView) {
    setFilters({ kind: value.kind, lifecycle: value.lifecycle || "all", q: value.query, severity: value.severity ?? "", fixable: value.fixable ? "true" : "", view: value.view ?? ((value.kind && value.kind !== "vulnerability") || (value.lifecycle && value.lifecycle !== "open") || value.severity ? "instances" : "cve"), group: value.group ?? "none", sort: value.sort ?? "risk", order: value.order ?? "desc" });
  }
  const exportCSV = useMutation({ mutationFn: () => {
    if (!ready) throw new Error("Current results are unavailable");
    return findings.exportCSV({ ...request, q: activeView === "cve" ? [serverQuery, "cve:CVE-"].filter(Boolean).join(" ") : request.q, limit: 100000, offset: 0 });
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
            ? <Link to="." href={clusterId ? `/clusters/${clusterId}/cve/${f.external_id}` : `/cve/${f.external_id}`} className="text-mono text-xs hover:text-[color:var(--color-primary)]">{f.external_id}</Link>
            : <span className="text-mono text-xs text-muted-foreground">{f.id.slice(0, 10)}</span>}
          {f.kev && <span className="rounded px-1 py-px text-[9px] font-semibold text-white" style={{ background: "var(--color-severity-critical)" }} title="CISA Known-Exploited">KEV</span>}
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
        <span className="block truncate text-mono text-[10px] text-muted-foreground" title={f.cvss_vector || undefined}>
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
          className="text-left text-sm hover:text-[color:var(--color-primary)] truncate block"
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
        <Link to="." href={`/clusters/${clusterId}/risk/asset/${encodeURIComponent(f.asset_id)}`} className="text-mono text-[10px] text-muted-foreground hover:text-foreground" title="Open risk workspace">
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
      cell: (f) => <span className="text-[10px] text-mono text-muted-foreground">{f.kind}</span>,
      exportValue: (f) => f.kind,
      sort: (a, b) => a.kind.localeCompare(b.kind),
    },
    {
      id: "age", kind: "age", size: 144, minSize: 128,
      header: "Age",
      cell: (f) => <span className="text-[10px] text-muted-foreground">{fmtRelative(f.last_seen_at)}</span>,
      exportValue: (f) => f.last_seen_at,
      sort: (a, b) => +new Date(a.last_seen_at) - +new Date(b.last_seen_at),
    },
  ];

  const totalSelected = selected.size;

  const bulkAction = useMutation({
    mutationFn: async (action: "triage" | "suppress" | "accept") => {
      const current = qc.getQueryState<Awaited<ReturnType<typeof findings.list>>>(instanceKey);
      const ids = Array.from(selected) as string[];
      const available = new Set(current?.data?.findings.map((finding) => finding.id));
      if (!ready || activeView !== "instances" || !ids.length || current?.status !== "success" || current.fetchStatus !== "idle" || ids.some((id) => !available.has(id))) throw new Error("Selection is unavailable");
      const results = await Promise.allSettled(ids.map((id) => action === "triage" ? findings.triage(id, { priority: "high" }) : action === "suppress" ? findings.suppress(id, { reason: "bulk suppress via Findings" }) : findings.acceptRisk(id, { reason: "bulk accept-risk via Findings", accepted_until: new Date(Date.now() + 30 * 86400_000).toISOString() })));
      if (results.some((result) => result.status === "rejected")) throw new Error("Some selected findings could not be updated");
    },
    onSettled: () => { void qc.invalidateQueries({ queryKey: ["findings"] }); void qc.invalidateQueries({ queryKey: ["findings-cve"] }); setSelected(new Set()); },
  });

  return (
    <div className="space-y-4" data-testid="findings-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Findings"
        description="Search matching security findings across the active scope, then review or update individual instances."
        actions={
          <>
            {views.length > 0 && (
              <SavedViewsMenu views={views} onApply={applyView} onDelete={deleteView} />
            )}
            <Button size="sm" variant="outline" onClick={saveView}>
              <Save className="h-3.5 w-3.5" /> Save view
            </Button>
          </>
        }
      />

      <VerdictBanner status={activeQ.isError || !scopeReady ? "degraded" : "info"} title={ready ? `${total?.toLocaleString()} matching ${activeView === "cve" ? "CVEs" : "finding instances"}` : "Finding results are unavailable or updating"} detail={activeView === "cve" ? "Rollups are ordered by highest risk across all matching CVEs." : "Search and ordering apply to the complete matching inventory."} />
      <div className="grid gap-3 sm:grid-cols-3">
        <StatCard label={activeView === "cve" ? "Matching CVEs" : "Matching instances"} value={total?.toLocaleString() ?? "—"} />
        <StatCard label="Rows on this page" value={ready ? activeView === "cve" ? cveRows.length : rows.length : "—"} />
        <StatCard label="Selected on this page" value={totalSelected} />
      </div>
      {/* Query input + hints */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <QueryInput
            value={query}
            placeholder="severity:critical kev:true cve:CVE-2024- !status:resolved"
            aria-label="Search findings"
            onChange={(e) => setQuery(e.target.value)}
            onClear={() => setQuery("")}
          />
          <Select label="Kind" value={kind} onChange={(v) => setFilters({ kind: v, ...(v && v !== "vulnerability" ? { view: "instances" } : {}) })}
            options={[["", "any kind"], ["vulnerability","vulnerability"], ["iac","iac"], ["license","license"],
                      ["cloud-config","cloud-config"], ["drift","drift"], ["signature","signature"],
                      ["ml-model","ml-model"], ["compliance","compliance"], ["runtime","runtime"]]} />
          <Select label="Severity" value={severity} onChange={(value) => setUrlFilter("severity", value)}
            options={[["", "any severity"], ["critical", "critical"], ["high", "high"], ["medium", "medium"], ["low", "low"], ["info", "info"]]} />
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Try</span>
          {QUERY_HINTS.map((h) => (
            <FilterChip
              key={h.value}
              label={h.label}
              value={h.example.split(":")[1]}
              onClick={() => setQuery((cur) => cur ? `${cur} ${h.example}` : h.example)}
            />
          ))}
          {activeChips.length > 0 && (
            <>
              <span className="mx-1 h-3 w-px bg-border" aria-hidden />
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Active</span>
              {activeChips.map((c, i) => (
                <FilterChip key={i} label={c.label} value={c.value} onRemove={c.onRemove} active />
              ))}
            </>
          )}
        </div>
      </div>

      {/* State tabs */}
      <section className="grid grid-cols-1 gap-2 md:grid-cols-3" data-testid="finding-state-tabs">
        {STATE_TABS.map((tab) => {
          const count = scopeReady && querySettled && q.isSuccess && !q.isFetching && !q.isPlaceholderData ? q.data.lifecycle_counts?.[tab.lifecycle] ?? "—" : "—";
          const active = lifecycle === tab.lifecycle;
          return (
            <button
              key={tab.lifecycle}
              type="button"
              onClick={() => setUrlFilter("lifecycle", tab.lifecycle)}
              className={cn(
                "rounded-md border bg-card px-3 py-2.5 text-left transition-all duration-100",
                active
                  ? "border-[color:var(--color-primary)] ring-1 ring-[color:var(--color-primary)]"
                  : "border-border hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]",
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-display text-sm font-semibold">{tab.label}</span>
                <span className={cn(
                  "rounded h-5 px-1.5 text-[11px] text-mono",
                  active ? "bg-[color:var(--color-primary)] text-[color:var(--color-primary-foreground)]" : "bg-muted text-muted-foreground",
                )}>{count}</span>
              </div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">{tab.description}</div>
            </button>
          );
        })}
      </section>

      {/* View: per-instance rows vs NeuVector-style CVE rollup */}
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">View</span>
        {([["instances", "Instances"], ["cve", "By CVE"]] as Array<["instances" | "cve", string]>).map(([v, l]) => (
          <button
            key={v}
            type="button"
            onClick={() => setUrlFilter("view", v)}
            disabled={v === "cve" && Boolean(kind && kind !== "vulnerability")}
            title={v === "cve" && kind && kind !== "vulnerability" ? "By CVE is available for vulnerabilities" : undefined}
            data-testid={`findings-view-${v}`}
            className={cn(
              "rounded h-6 px-2 text-[11px] border transition-colors",
              activeView === v
                ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] text-[color:var(--color-primary)]"
                : "bg-card border-border hover:bg-accent",
              v === "cve" && kind && kind !== "vulnerability" && "cursor-not-allowed opacity-50",
            )}
          >{l}</button>
        ))}
        <span className="ml-2 text-[10px] text-muted-foreground">
          {activeView === "cve" ? "one row per CVE with its blast radius" : "one row per CVE × workload"}
        </span>
        <button
          type="button"
          onClick={() => setUrlFilter("fixable", fixableOnly ? "" : "true")}
          className={cn(
            "ml-auto rounded h-6 px-2 text-[11px] border transition-colors",
            fixableOnly
              ? "bg-[color-mix(in_oklab,var(--color-severity-low)_18%,transparent)] border-[color-mix(in_oklab,var(--color-severity-low)_36%,transparent)] text-[color:var(--color-severity-low)]"
              : "bg-card border-border hover:bg-accent",
          )}
          title="Hide vulnerabilities with no available fix (won't-fix / not-fixed)"
        >{fixableOnly ? "✓ " : ""}Fixable only</button>
        {activeView === "cve" && (
          <span className="rounded h-6 px-2 text-[11px] border border-border bg-card text-muted-foreground">
            {ready ? cveRows.length : "—"} of {total ?? "—"} CVEs
          </span>
        )}
      </div>

      {/* Group by (instance view only) */}
      {activeView === "instances" && (
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground"><ListFilter className="h-3 w-3 inline" /> Group</span>
        {([
          ["none", "None"], ["severity", "Severity"], ["kind", "Kind"], ["asset", "Asset"],
        ] as Array<[GroupBy, string]>).map(([v, l]) => (
          <button
            key={v}
            type="button"
            onClick={() => setUrlFilter("group", v)}
            className={cn(
              "rounded h-6 px-2 text-[11px] border transition-colors",
              groupBy === v
                ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] text-[color:var(--color-primary)]"
                : "bg-card border-border hover:bg-accent",
            )}
          >{l}</button>
        ))}
        <span className="ml-auto text-[11px] text-muted-foreground text-mono">{ready ? rows.length : "—"} on this page · {total ?? "—"} matching instances</span>
      </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <Button variant="outline" disabled={!ready || exportCSV.isPending} onClick={() => exportCSV.mutate()}>{exportCSV.isPending ? "Exporting…" : "Export filtered instances CSV"}</Button>
        <span className="text-xs text-muted-foreground">Up to 100,000 matching instances, across all pages.{activeView === "cve" ? " CVE table exports contain only the rollups on this page." : " Table exports and selections contain only this page."}</span>
      </div>
      {activeView === "cve" && fixableOnly && <p className="text-xs text-muted-foreground">Fixable CVE rollups count all matching instances of a CVE with an available fix. The filtered instance CSV includes only instances with an available fix.</p>}
      {exportCSV.isError && <ErrorState title="Could not export matching instances. Try again." />}
      {bulkAction.isError && <ErrorState title="Some selected findings could not be updated. Refresh and review their current states before retrying." />}
      {activeView === "cve" && q.isError && <ErrorState title="Lifecycle counts could not be loaded." action={<Button onClick={() => void q.refetch()}>Retry counts</Button>} />}
      {!scopeReady ? <ErrorState title="The active cluster could not be resolved. Findings are unavailable until its scope recovers." />
        : activeQ.isError ? <ErrorState title="Could not load findings. Review your query and retry." action={<Button onClick={() => void activeQ.refetch()}>Retry</Button>} />
        : !ready ? <LoadingState label={activeQ.isPending ? "Loading findings…" : "Updating findings…"} />
        : outOfRange ? <EmptyState title="This page is outside the current results" hint="The inventory may have changed. Return to the first page to review matching results." action={<Button onClick={() => setPage(0)}>First page</Button>} />
        : <>
          {activeView === "cve" ? <CVETable rows={cveRows} clusterId={clusterId} />
            : groupBy === "none" ? <DataTable
                key={`${sort}:${order}`} rows={rows} columns={columns} rowKey={(finding) => finding.id}
                density={density} onDensityChange={setDensity} selectable selected={selected} onSelectedChange={setSelected}
                onRowClick={openFinding} defaultSort={{ id: sort === "last_seen" ? "age" : sort, dir: order }} onSortChange={onSortChange} manualSorting pagination={false}
                preferencesKey={INSTANCE_TABLE_KEY} defaultHiddenColumnIds={["package", "fixed"]}
                exportFileName="constellation-findings-page" exportLabel="Export this page CSV" testId="findings-table"
                emptyState={<EmptyState title="No findings match" hint="Adjust your filters or clear the query." icon={<Tag className="h-8 w-8" />} action={<Button variant="outline" onClick={() => setFilters({ q: "", kind: "", severity: "", lifecycle: "open", fixable: "", page: "" })}>Reset filters</Button>} />}
              />
            : <div className="space-y-3">
                <p className="text-xs text-muted-foreground" data-testid="findings-group-scope">{grouped.length} groups from {rows.length} instances on this server page. Group counts, selection, and table CSV cover this page only.</p>
                {grouped.map((group) => <details key={group.label} open className="rounded-md border border-border bg-card">
                  <summary className="flex cursor-pointer items-center justify-between gap-2 border-b border-border px-3 py-2 list-none"><span className="flex items-center gap-2"><ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /><span className="text-sm font-semibold">{group.label}</span><span className="text-xs text-muted-foreground">{group.items.length} on this page</span></span></summary>
                  <DataTable key={`${sort}:${order}`} rows={group.items} columns={columns} rowKey={(finding) => finding.id} density={density} onDensityChange={setDensity}
                    selectable selected={selected} onSelectedChange={(ids) => { const merged = new Set(selected); for (const item of group.items) merged.delete(item.id); for (const id of ids) if (group.items.some((item) => item.id === id)) merged.add(id); setSelected(merged); }} onRowClick={openFinding}
                    defaultSort={{ id: sort === "last_seen" ? "age" : sort, dir: order }} onSortChange={onSortChange} manualSorting pagination={false}
                    showDensityToggle={false} showColumnChooser={false} preferencesKey={INSTANCE_TABLE_KEY} defaultHiddenColumnIds={["package", "fixed"]}
                    exportFileName={`constellation-findings-page-${safeFilename(group.label)}`} exportLabel="Export this group on this page CSV" className="rounded-none border-0" />
                </details>)}
                {!rows.length && <EmptyState title="No findings match" hint="Adjust your filters or clear the query." />}
              </div>}
          <Pager page={page} pageSize={PAGE_SIZE} total={total} rowsOnPage={activeView === "cve" ? cveRows.length : rows.length} onPage={setPage} />
        </>}
      <ActionBar count={totalSelected} onClear={() => setSelected(new Set())}>
        <Button size="sm" variant="outline" disabled={!ready || bulkAction.isPending} onClick={() => bulkAction.mutate("triage")}>Triage</Button>
        <Button size="sm" variant="outline" disabled={!ready || bulkAction.isPending} onClick={() => bulkAction.mutate("suppress")}>Suppress</Button>
        <Button size="sm" variant="outline" disabled={!ready || bulkAction.isPending} onClick={() => bulkAction.mutate("accept")}>Accept risk · 30d</Button>
      </ActionBar>
    </div>
  );
}

// CVETable — the NeuVector-style rollup: one row per CVE with its blast radius
// (how many images / clusters it hits and total instances), sorted by risk.
function CVETable({ rows, clusterId }: { rows: CVERollup[]; clusterId?: string }) {
  const columns: Column<CVERollup>[] = [
    { id: "severity", kind: "badge", size: 120, minSize: 112, header: "Severity",
      cell: (c) => <SeverityBadge severity={c.severity} />,
      exportValue: (c) => c.severity },
    { id: "cve", kind: "id", size: 176, minSize: 160, header: "CVE",
      cell: (c) => (
        <span className="flex items-center gap-1.5">
          <Link to="." href={clusterId ? `/clusters/${clusterId}/cve/${c.cve}` : `/cve/${c.cve}`} className="text-mono text-xs hover:text-[color:var(--color-primary)]">{c.cve}</Link>
          {c.kev && <span className="rounded px-1 py-px text-[9px] font-semibold text-white" style={{ background: "var(--color-severity-critical)" }} title="CISA Known-Exploited">KEV</span>}
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
        <span className="block truncate text-mono text-[10px] text-muted-foreground" title={c.cvss_vector || undefined}>
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
          {c.affected_images} image{c.affected_images === 1 ? "" : "s"}
          {c.affected_clusters > 1 ? ` · ${c.affected_clusters} clusters` : ""}
        </span>
      ),
      exportValue: (c) => `${c.affected_images} images; ${c.affected_clusters} clusters` },
    { id: "instances", kind: "count", size: 112, minSize: 96, header: "Instances", numeric: true,
      cell: (c) => <span className="text-mono text-xs">{c.instances}</span>,
      exportValue: (c) => c.instances },
    { id: "risk", kind: "count", size: 88, minSize: 80, header: "Risk", numeric: true,
      cell: (c) => <RiskScore score={c.risk_score} />,
      exportValue: (c) => c.risk_score },
    { id: "age", kind: "age", size: 144, minSize: 128, header: "Age",
      cell: (c) => <span className="text-[10px] text-muted-foreground">{fmtRelative(c.last_seen_at)}</span>,
      exportValue: (c) => c.last_seen_at },
  ];
  return (
    <DataTable
      rows={rows}
      columns={columns}
      rowKey={(c) => c.cve}
      pagination={false}
      preferencesKey={CVE_TABLE_KEY}
      exportFileName="constellation-cves-page"
      exportLabel="Export this CVE page CSV"
      testId="findings-cve-table"
      emptyState={<EmptyState title="No CVEs match" hint="Adjust your filters or clear the query." icon={<Tag className="h-8 w-8" />} />}
    />
  );
}

function SavedViewsMenu({ views, onApply, onDelete }: { views: SavedView[]; onApply: (v: SavedView) => void; onDelete: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded border border-border bg-card text-xs hover:bg-accent"
      >
        <Bookmark className="h-3.5 w-3.5" /> Views <span className="text-mono text-muted-foreground">({views.length})</span>
      </button>
      {open && (
        <div
          className="absolute right-0 top-full z-30 mt-1 w-[260px] rounded-md border border-border bg-popover p-2 shadow-[var(--elev-popover)]"
          onMouseLeave={() => setOpen(false)}
        >
          <ul className="space-y-1">
            {views.map((v) => (
              <li key={v.id} className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => { onApply(v); setOpen(false); }}
                  className="flex-1 rounded px-2 py-1 text-left text-xs hover:bg-accent"
                >
                  <div className="font-medium">{v.name}</div>
                  <div className="text-[10px] text-mono text-muted-foreground truncate">
                    {[v.lifecycle, v.kind, v.query].filter(Boolean).join(" · ") || "all"}
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => onDelete(v.id)}
                  aria-label={`delete view ${v.name}`}
                  className="rounded p-1 text-muted-foreground hover:bg-muted"
                >×</button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Select({
  label, value, onChange, options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <select
      aria-label={label}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 rounded-md border border-input bg-card px-2.5 text-xs text-mono outline-none focus:border-[color:var(--color-primary)]"
    >
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
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
