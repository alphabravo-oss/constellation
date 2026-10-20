// Global CVE intelligence catalog: server-filtered lookahead pages and matching CSV.
import { MoreFilters } from "@/ui";
import { Checkbox } from "@/components/ui/form";
import { QueryInput } from "@/components/ui/query-input";
import { useMemo, useState, useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { Search } from "lucide-react";

import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { LookaheadExport } from "@/components/LookaheadExport";
import { useRouteSearchParams } from "@/lib/route-search";
import { Pager } from "@/components/ui/pager";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { cve, type CVEResult, type CVESearchParams, type Severity } from "@/api/client";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { KevBadge } from "@/components/ui/kev-badge";
import { DataTable, type Column } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Select } from "@/components/ui/form";

const SOURCES = ["NVD", "KEV", "EPSS", "OSV", "GHSA"] as const;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

function severityOf(cvss?: number): Severity {
  if (cvss == null) return "info";
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  if (cvss >= 0.1) return "low";
  return "info";
}

function useDebounced<T>(value: T, ms = 200): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

export function CVEPage() {
  const navigate = useNavigate();
  const client = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id ?? ""}:${identity?.user_id ?? ""}`;
  const scopeReady = !!identity?.org_id && !!identity?.user_id;

  const [params, setParams] = useRouteSearchParams();
  const q = params.get("q") ?? "";
  const debouncedQ = useDebounced(q, 200);
  const kevOnly = params.get("kev") === "true";
  const epssHigh = params.get("epss_gt") === "0.5";
  const cvssHigh = params.get("cvss_gt") === "7";
  const severity = SEVERITIES.includes(params.get("severity") as Severity) ? params.get("severity") as Severity : "";
  const source = SOURCES.includes(params.get("source") as typeof SOURCES[number]) ? params.get("source")! : "";
  const sortID = params.get("sort") ?? "cvss";
  const sort = { id: ["cve_id", "cvss", "severity", "epss", "kev", "published"].includes(sortID) ? sortID : "cvss", dir: params.get("dir") === "asc" ? "asc" as const : "desc" as const };
  const requestedPage = Number(params.get("page") ?? "1");
  const page = Number.isSafeInteger(requestedPage) && requestedPage > 0 ? requestedPage - 1 : 0;
  const pageSize = 50;
  const changeFilters = (values: Record<string, string>, replace = false) => setParams((current) => {
    current.delete("page");
    for (const [key, value] of Object.entries(values)) { if (value) current.set(key, value); else current.delete(key); }
    return current;
  }, { replace });
  const setQ = (value: string) => changeFilters({ q: value }, true);
  const setSeverity = (value: string) => changeFilters({ severity: value });
  const setSource = (value: string) => changeFilters({ source: value });
  const setSort = (value: typeof sort) => changeFilters({ sort: value.id, dir: value.dir });
  const clearFilters = () => changeFilters({ q: "", kev: "", epss_gt: "", cvss_gt: "", severity: "", source: "" });

  const stats = useQuery({ queryKey: ["cve", "stats", owner], queryFn: () => cve.stats(), staleTime: 60_000, enabled: scopeReady });
  const bundle = useQuery({ queryKey: ["cve", "bundle", owner], queryFn: () => cve.bundle(), staleTime: 60_000, enabled: scopeReady });
  const filters: CVESearchParams = { q: debouncedQ, kev: kevOnly || undefined, epss_gt: epssHigh ? 0.5 : undefined, cvss_gt: cvssHigh ? 7 : undefined, severity: severity || undefined, source: source || undefined, sort: sort.id, dir: sort.dir };
  const searchKey = ["cve", "search", owner, debouncedQ, kevOnly, epssHigh, cvssHigh, severity, source, sort.id, sort.dir, page];
  const search = useQuery({ queryKey: searchKey, queryFn: () => cve.search({ ...filters, limit: pageSize + 1, offset: page * pageSize }), enabled: scopeReady && q === debouncedQ });
  const responseValid = !!search.data && catalogResponseMatches(search.data, pageSize + 1, page * pageSize);
  const ready = scopeReady && search.isSuccess && !search.isError && q === debouncedQ && responseValid;
  const rows = ready ? search.data!.results.slice(0, pageSize) : [];
  const hasMore = ready && search.data!.results.length > pageSize;
  const context = JSON.stringify(searchKey);
  const isCurrent = () => scopeReady && ready && exportQueryReady(client, searchKey, search.data);
  const captureExport = useExportGuard(context, !ready || search.isFetching, isCurrent);
  const statsValid = !!stats.data && ["total", "kev_listed", "epss_gt_50", "cvss_gt_70"].every(key => Number.isSafeInteger(stats.data[key as keyof typeof stats.data]) && Number(stats.data[key as keyof typeof stats.data]) >= 0);
  const bundleValid = !!bundle.data && typeof bundle.data.available === "boolean" && (!bundle.data.imported_at || Number.isFinite(Date.parse(bundle.data.imported_at)));
  const statsData = scopeReady && stats.isSuccess && !stats.isError && statsValid ? stats.data : undefined;
  const bundleData = scopeReady && bundle.isSuccess && !bundle.isError && bundleValid ? bundle.data : undefined;

  const columns = useMemo<Column<CVEResult>[]>(
    () => [
      {
        id: "cve_id", exportValue: r => r.cve_id, kind: "id", size: 176, minSize: 160,
        header: "CVE-ID",
        cell: (r) => (
          <Link to="/cve/$id" params={{ id: r.cve_id }} className="text-mono text-meta text-[color:var(--color-primary)] hover:underline">
            {r.cve_id}
          </Link>
        ),
        sort: (a, b) => a.cve_id.localeCompare(b.cve_id),
      },
      {
        id: "severity", exportValue: r => severityOf(r.cvss_base), kind: "badge", size: 120, minSize: 112,
        header: "Severity",
        cell: (r) => <SeverityBadge severity={severityOf(r.cvss_base)} kev={r.kev_listed} />,
        sort: (a, b) => (a.cvss_base ?? -1) - (b.cvss_base ?? -1),
      },
      {
        id: "cvss", exportValue: r => r.cvss_base ?? "", kind: "count", size: 88, minSize: 80,
        header: "CVSS",
        numeric: true,
        cell: (r) => (
          <span className="text-mono text-meta tabular-nums">
            {r.cvss_base != null ? r.cvss_base.toFixed(1) : <span className="text-muted-foreground">—</span>}
          </span>
        ),
        sort: (a, b) => (a.cvss_base ?? -1) - (b.cvss_base ?? -1),
      },
      {
        id: "kev", exportValue: r => r.kev_listed, kind: "badge", size: 88, minSize: 80,
        header: "KEV",
        cell: (r) => (r.kev_listed ? <KevBadge /> : <span className="text-muted-foreground text-micro">—</span>),
        sort: (a, b) => Number(a.kev_listed) - Number(b.kev_listed),
      },
      {
        id: "epss", exportValue: r => r.epss_probability ?? "", kind: "percent", size: 144, minSize: 136, maxSize: 160,
        header: "EPSS",
        cell: (r) => <EpssBar value={r.epss_probability} />,
        sort: (a, b) => (a.epss_probability ?? -1) - (b.epss_probability ?? -1),
      },
      {
        id: "title", exportValue: r => r.title ?? "", kind: "text", grow: true, minSize: 240,
        header: "Title",
        cell: (r) => (
          <span className="line-clamp-1 text-meta text-foreground/90" title={r.title ?? r.description}>
            {r.title || <span className="text-muted-foreground">(no title)</span>}
          </span>
        ),
      },
      {
        id: "sources", exportValue: r => JSON.stringify(r.sources), kind: "badge", size: 144, minSize: 128, wrap: true,
        header: "Sources",
        cell: (r) => (
          <div className="flex flex-wrap gap-1">
            {(r.sources ?? []).slice(0, 3).map((s) => (
              <span key={s} className="rounded bg-muted px-1.5 py-0.5 text-micro text-mono text-muted-foreground">
                {s}
              </span>
            ))}
          </div>
        ),
      },
      {
        id: "published", exportValue: r => r.published_at ?? "", kind: "date", size: 136, minSize: 128,
        header: "Published",
        cell: (r) =>
          r.published_at ? (
            <span className="text-mono text-micro text-muted-foreground">
              {new Date(r.published_at).toISOString().slice(0, 10)}
            </span>
          ) : (
            <span className="text-muted-foreground text-micro">—</span>
          ),
        sort: (a, b) => (a.published_at ?? "").localeCompare(b.published_at ?? ""),
      },
    ],
    [],
  );

  const totalLabel = statsData ? statsData.total.toLocaleString() : "—";
  const bundleVersion = bundleData?.available ? bundleData.version : "—";
  const importedAt = bundleData?.available && bundleData.imported_at ? new Date(bundleData.imported_at).toLocaleString() : null;

  const filterCount = [kevOnly, epssHigh, cvssHigh].filter(Boolean).length;
  const toolbar = (
    <>
      <QueryInput
        data-testid="cve-search-input"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onClear={() => setQ("")}
        placeholder="Search CVEs, aliases, keywords"
        aria-label="Search CVEs"
        className="min-w-72 flex-1"
        suggestions={["Log4Shell", "Heartbleed", "EternalBlue", "Spring4Shell", "CVE-2024-3094"].map((value) => ({ label: value, value }))}
        onSuggestion={(suggestion) => setQ(suggestion.value)}
      />
      <Select aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value as Severity | "")} className="h-9 w-auto min-w-36">
        <option value="">Any severity</option>
        {SEVERITIES.map((s) => <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>)}
      </Select>
      <Select aria-label="Source" value={source} onChange={(e) => setSource(e.target.value)} className="h-9 w-auto min-w-32">
        <option value="">Any source</option>
        {SOURCES.map((s) => <option key={s} value={s}>{s.toUpperCase()}</option>)}
      </Select>
      <label className="flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm">
        <Checkbox checked={kevOnly} aria-label="Known exploited only" onChange={() => changeFilters({ kev: kevOnly ? "" : "true" })} />
        Known exploited
      </label>
      <MoreFilters count={filterCount - (kevOnly ? 1 : 0)}>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={epssHigh} aria-label="EPSS above 0.5" onChange={() => changeFilters({ epss_gt: epssHigh ? "" : "0.5" })} />EPSS above 0.5</label>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={cvssHigh} aria-label="CVSS above 7" onChange={() => changeFilters({ cvss_gt: cvssHigh ? "" : "7" })} />CVSS above 7</label>
      </MoreFilters>
      {(kevOnly || epssHigh || cvssHigh || severity || source || q) && (
        <button type="button" onClick={clearFilters} className="h-9 rounded-md px-2 text-meta text-muted-foreground hover:text-foreground">Clear all</button>
      )}
    </>
  );
  return (
    <PageContainer>
      <PageHeader
        title="CVE database"
        actions={<Button disabled={!scopeReady || search.isFetching || q !== debouncedQ} onClick={() => { void search.refetch(); void stats.refetch(); void bundle.refetch(); }}>Refresh</Button>}
      />

      {stats.isError || stats.isSuccess && !statsValid ? <VerdictBanner status="degraded" title="CVE catalog summary unavailable" detail="Retry before relying on the catalog totals." /> : stats.isPending ? <VerdictBanner status="info" title="Loading CVE catalog" /> : statsData && (
        <VerdictBanner
          status={statsData.total > 0 ? "ok" : "info"}
          title={statsData.total > 0 ? `${totalLabel} CVEs in the catalog` : "CVE catalog not yet synced"}
          numbers={statsData.total > 0 ? [
            { label: "known exploited (KEV)", value: statsData.kev_listed.toLocaleString(), tone: "critical" },
            { label: "EPSS above 0.5", value: statsData.epss_gt_50.toLocaleString(), tone: "high" },
            { label: "CVSS 7.0 or higher", value: statsData.cvss_gt_70.toLocaleString(), tone: "high" },
          ] : undefined}
          detail={<span>Aggregated from NVD, CISA KEV, EPSS, OSV, GHSA and distribution feeds.{importedAt ? <> Bundle <span className="font-mono">{bundleVersion}</span> imported {importedAt}.</> : null} Manage sources in <a href="/settings/scanner" className="text-link">Settings › Scanner and CVE sources</a>.{bundleData?.available ? <span className="mt-1 block">Bundle <span className="font-mono" data-testid="bundle-version">{bundleVersion}</span> · <span data-testid="bundle-signed">{bundleData.signed ? `signed${bundleData.signer_identity ? ` by ${bundleData.signer_identity}` : ""}` : "unsigned"}</span></span> : null}</span>}
        />
      )}

      {(bundle.isError || bundle.isSuccess && !bundleValid) && <ErrorState title="CVE bundle metadata unavailable." />}
      {/* Results */}
      <div data-testid="cve-results-table">
        {(!scopeReady || search.isError || (search.isSuccess && !responseValid) || search.isPending || q !== debouncedQ) && <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-3 py-2" data-slot="table-toolbar">{toolbar}</div>}
        {!scopeReady ? <LoadingState label="Resolving operator scope" /> : search.isError || search.isSuccess && !responseValid ? <ErrorState title="Could not load CVE results." action={<Button onClick={() => void search.refetch()}>Retry</Button>} /> : search.isPending || q !== debouncedQ ? <LoadingState label="Loading CVE results" /> : <DataTable<CVEResult>
          rows={rows}
          canExport={() => captureExport()()}
          pagination={false}
          preferencesKey="cve-catalog"
          exportFileName="constellation-cve-page.csv"
          exportLabel="Export this page"
          toolbar={toolbar}
          columns={columns}
          rowKey={(r) => r.cve_id}
          onRowClick={(r) => navigate({ href: `/cve/${encodeURIComponent(r.cve_id)}` })}
          sort={sort}
          manualSorting
          onSortChange={(s) => setSort(s ?? { id: "cvss", dir: "desc" })}
          rowTestId={(r) => `cve-row-${r.cve_id}`}
          emptyState={
            search.isLoading ? (
              <div className="px-6 py-10 text-center text-xs text-muted-foreground">Loading…</div>
            ) : (
              <EmptyState
                title="No CVEs match"
                hint={q ? `Nothing matched "${q}". Try clearing filters or a different keyword.` : "Adjust filters to see more results."}
                icon={<Search className="h-8 w-8" />}
              />
            )
          }
        />}
        {ready && search.isFetching && <p role="status" className="text-xs text-muted-foreground">Refreshing catalog results…</p>}
        {ready && rows.length > 0 && <fieldset disabled={search.isFetching || q !== debouncedQ}><Pager page={page} pageSize={pageSize} hasMore={!search.isError && hasMore} rowsOnPage={rows.length} onPage={(next) => setParams((current) => { if (next) current.set("page", String(next + 1)); else current.delete("page"); return current; })} /></fieldset>}
        {ready && !rows.length && page > 0 && <Button onClick={() => setParams(current => { current.delete("page"); return current; })}>First page</Button>}
        <LookaheadExport context={context} disabled={!ready || search.isFetching} isCurrent={isCurrent} path={cve.catalogCSVPath} params={cve.catalogCSVParams(filters)} filename="constellation-cve-catalog.csv" />
      </div>
      <p className="text-xs text-muted-foreground">Global intelligence catalog. Page CSV contains visible columns on this page; matching CSV preserves filters and sorting across pages. Summary metrics cover the entire catalog.</p>
    </PageContainer>
  );
}

function catalogResponseMatches(data: { results: CVEResult[]; limit: number; offset: number }, limit: number, offset: number) {
  if (!Array.isArray(data.results) || data.limit !== limit || data.offset !== offset || data.results.length > limit) return false;
  const ids = new Set<string>();
  return data.results.every(row => {
    if (!row || typeof row.cve_id !== "string" || !row.cve_id.trim() || ids.has(row.cve_id) || typeof row.kev_listed !== "boolean" || !Array.isArray(row.aliases) || !row.aliases.every(value => typeof value === "string") || !Array.isArray(row.sources) || !row.sources.every(value => typeof value === "string") || [row.title, row.description, row.cvss_vector].some(value => value !== undefined && typeof value !== "string") || [row.published_at, row.modified_at].some(value => value !== undefined && (typeof value !== "string" || !Number.isFinite(Date.parse(value)))) || [row.cvss_base, row.epss_probability].some(value => value !== undefined && (typeof value !== "number" || !Number.isFinite(value)))) return false;
    ids.add(row.cve_id); return true;
  });
}

function EpssBar({ value }: { value?: number }) {
  if (value == null) return <span className="text-muted-foreground text-micro">—</span>;
  const pct = Math.min(100, Math.max(0, value * 100));
  const hot = pct >= 50;
  return (
    <div className="flex items-center justify-end gap-1.5">
      <div className="h-1.5 w-14 overflow-hidden rounded-sm bg-muted">
        <div
          className="h-full rounded-sm"
          style={{
            width: `${pct}%`,
            background: hot ? "var(--color-severity-high)" : "color-mix(in oklab, var(--color-primary) 60%, transparent)",
          }}
        />
      </div>
      <span className="text-mono text-micro tabular-nums text-muted-foreground">{pct.toFixed(pct < 1 ? 2 : 1)}%</span>
    </div>
  );
}
