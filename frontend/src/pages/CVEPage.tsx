// CVEPage — browse the live cve_records table (332k+ rows). Shows aggregate
// stat tiles, filter chip bar, and a default list of recent CVEs that the user
// can search/filter without typing a query first.
import { useMemo, useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { Search, Database, Crown, Activity, AlertTriangle } from "lucide-react";

import { useRouteSearchParams } from "@/lib/route-search";
import { Pager } from "@/components/ui/pager";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { cve, type CVEResult, type Severity } from "@/api/client";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { FilterChip } from "@/components/ui/filter-chip";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { KevBadge } from "@/components/ui/kev-badge";
import { DataTable, type Column } from "@/components/ui/data-table";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";

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

  const stats = useQuery({ queryKey: ["cve", "stats"], queryFn: () => cve.stats(), staleTime: 60_000 });
  const bundle = useQuery({ queryKey: ["cve", "bundle"], queryFn: () => cve.bundle(), staleTime: 60_000 });

  const search = useQuery({
    queryKey: ["cve", "search", debouncedQ, kevOnly, epssHigh, cvssHigh, severity, source, sort.id, sort.dir, page],
    queryFn: () =>
      cve.search({
        q: debouncedQ,
        kev: kevOnly || undefined,
        epss_gt: epssHigh ? 0.5 : undefined,
        cvss_gt: cvssHigh ? 7.0 : undefined,
        severity: severity || undefined,
        source: source || undefined,
        sort: sort.id,
        dir: sort.dir,
        limit: pageSize + 1,
        offset: page * pageSize,
      }),
    enabled: q === debouncedQ,
  });

  const rows = search.data?.results.slice(0, pageSize) ?? [];
  const hasMore = (search.data?.results.length ?? 0) > pageSize;

  const columns = useMemo<Column<CVEResult>[]>(
    () => [
      {
        id: "cve_id", kind: "id", size: 176, minSize: 160,
        header: "CVE-ID",
        cell: (r) => (
          <Link to="." href={`/cve/${r.cve_id}`} className="text-mono text-[12px] text-[color:var(--color-primary)] hover:underline">
            {r.cve_id}
          </Link>
        ),
        sort: (a, b) => a.cve_id.localeCompare(b.cve_id),
      },
      {
        id: "severity", kind: "badge", size: 120, minSize: 112,
        header: "Severity",
        cell: (r) => <SeverityBadge severity={severityOf(r.cvss_base)} kev={r.kev_listed} />,
        sort: (a, b) => (a.cvss_base ?? -1) - (b.cvss_base ?? -1),
      },
      {
        id: "cvss", kind: "count", size: 88, minSize: 80,
        header: "CVSS",
        numeric: true,
        cell: (r) => (
          <span className="text-mono text-[12px] tabular-nums">
            {r.cvss_base != null ? r.cvss_base.toFixed(1) : <span className="text-muted-foreground">—</span>}
          </span>
        ),
        sort: (a, b) => (a.cvss_base ?? -1) - (b.cvss_base ?? -1),
      },
      {
        id: "kev", kind: "badge", size: 88, minSize: 80,
        header: "KEV",
        cell: (r) => (r.kev_listed ? <KevBadge /> : <span className="text-muted-foreground text-[10px]">—</span>),
        sort: (a, b) => Number(a.kev_listed) - Number(b.kev_listed),
      },
      {
        id: "epss", kind: "percent", size: 144, minSize: 136, maxSize: 160,
        header: "EPSS",
        cell: (r) => <EpssBar value={r.epss_probability} />,
        sort: (a, b) => (a.epss_probability ?? -1) - (b.epss_probability ?? -1),
      },
      {
        id: "title", kind: "text", grow: true, minSize: 240,
        header: "Title",
        cell: (r) => (
          <span className="line-clamp-1 text-[12px] text-foreground/90" title={r.title ?? r.description}>
            {r.title || <span className="text-muted-foreground">(no title)</span>}
          </span>
        ),
      },
      {
        id: "sources", kind: "badge", size: 144, minSize: 128, wrap: true,
        header: "Sources",
        cell: (r) => (
          <div className="flex flex-wrap gap-1">
            {(r.sources ?? []).slice(0, 3).map((s) => (
              <span key={s} className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono text-muted-foreground">
                {s}
              </span>
            ))}
          </div>
        ),
      },
      {
        id: "published", kind: "date", size: 136, minSize: 128,
        header: "Published",
        cell: (r) =>
          r.published_at ? (
            <span className="text-mono text-[11px] text-muted-foreground">
              {new Date(r.published_at).toISOString().slice(0, 10)}
            </span>
          ) : (
            <span className="text-muted-foreground text-[10px]">—</span>
          ),
        sort: (a, b) => (a.published_at ?? "").localeCompare(b.published_at ?? ""),
      },
    ],
    [],
  );

  const totalLabel = stats.data ? stats.data.total.toLocaleString() : "—";
  const bundleVersion = bundle.data?.available ? bundle.data.version : "—";
  const importedAt = bundle.data?.available && bundle.data.imported_at ? new Date(bundle.data.imported_at).toLocaleString() : null;

  return (
    <PageContainer>
      <PageHeader
        title="CVE Database"
        actions={<Button disabled={search.isFetching || q !== debouncedQ} onClick={() => { void search.refetch(); void stats.refetch(); void bundle.refetch(); }}>Refresh</Button>}
        description={
          <>
            {stats.data ? (
              <>
                {totalLabel} vulnerabilities aggregated from NVD, KEV, EPSS, OSV, and GHSA.
              </>
            ) : (
              "Aggregated from NVD + OSV + GHSA + distros + KEV + EPSS."
            )}
            {importedAt && (
              <>
                {" "}
                Bundle <span className="text-mono">{bundleVersion}</span> imported {importedAt}.
              </>
            )}
          </>
        }
      />

      {/* Verdict — honest state of the catalog (populated vs not yet synced). */}
      {stats.isError ? <VerdictBanner status="degraded" title="CVE catalog summary unavailable" detail="Retry before relying on the catalog totals." /> : stats.isPending ? <VerdictBanner status="info" title="Loading CVE catalog" detail="Fetching current catalog totals." /> : stats.data && (
        stats.data.total > 0 ? (
          <VerdictBanner
            status="ok"
            title={`${totalLabel} CVEs in the catalog`}
            detail="Intelligence from NVD, CISA KEV, and EPSS. Manage sources under Settings → Scanner & CVE Sources."
          />
        ) : (
          <VerdictBanner
            status="info"
            title="CVE catalog not yet synced"
            detail="No CVE records loaded yet. Configure sources under Settings → Scanner & CVE Sources."
          />
        )
      )}

      {/* Stat tiles */}
      <StatGrid>
        <StatCard
          label="Total CVEs"
          value={stats.data ? stats.data.total.toLocaleString() : "—"}
          tone="accent"
          icon={<Database className="h-3 w-3" />}
          hint="Live row count"
        />
        <StatCard
          label="KEV-listed"
          value={stats.data ? stats.data.kev_listed.toLocaleString() : "—"}
          tone="critical"
          icon={<Crown className="h-3 w-3" />}
          hint="CISA Known-Exploited"
        />
        <StatCard
          label="EPSS > 0.5"
          value={stats.data ? stats.data.epss_gt_50.toLocaleString() : "—"}
          tone="high"
          icon={<Activity className="h-3 w-3" />}
          hint="High exploit probability"
        />
        <StatCard
          label="CVSS ≥ 7.0"
          value={stats.data ? stats.data.cvss_gt_70.toLocaleString() : "—"}
          tone="high"
          icon={<AlertTriangle className="h-3 w-3" />}
          hint="High / critical severity"
        />
      </StatGrid>

      {bundle.data?.available && (
        <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-xs">
          <span className="text-muted-foreground">Bundle</span>
          <span className="font-mono" data-testid="bundle-version">{bundleVersion}</span>
          <span className="text-muted-foreground">·</span>
          <span data-testid="bundle-signed">
            {bundle.data.signed ? `signed${bundle.data.signer_identity ? ` by ${bundle.data.signer_identity}` : ""}` : "unsigned"}
          </span>
        </div>
      )}

      {/* Search input */}
      <div className="space-y-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <input
            data-testid="cve-search-input"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by CVE-ID, alias, or keyword (try: Log4Shell, Heartbleed, CVE-2024)"
            className="w-full rounded-md border border-input bg-background py-2 pl-9 pr-3 text-sm focus:border-[color:var(--color-primary)] focus:outline-none"
          />
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground">
          <span>Try:</span>
          {["Log4Shell", "Heartbleed", "EternalBlue", "Spring4Shell", "CVE-2024-3094"].map((ex) => (
            <button
              key={ex}
              type="button"
              onClick={() => setQ(ex)}
              className="rounded border border-border bg-card px-1.5 py-0.5 text-mono text-foreground hover:bg-accent"
            >
              {ex}
            </button>
          ))}
        </div>
      </div>

      {/* Filter chip bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-card px-3 py-2">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Filters</span>
        <FilterChip label="KEV-only" active={kevOnly} onClick={() => changeFilters({ kev: kevOnly ? "" : "true" })} />
        <FilterChip label="EPSS > 0.5" active={epssHigh} onClick={() => changeFilters({ epss_gt: epssHigh ? "" : "0.5" })} />
        <FilterChip label="CVSS ≥ 7" active={cvssHigh} onClick={() => changeFilters({ cvss_gt: cvssHigh ? "" : "7" })} />
        <div className="ml-1 flex items-center gap-1">
          <label className="text-[10px] uppercase tracking-wider text-muted-foreground">Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as Severity | "")}
            className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px]"
          >
            <option value="">any</option>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-1">
          <label className="text-[10px] uppercase tracking-wider text-muted-foreground">Source</label>
          <select
            value={source}
            onChange={(e) => setSource(e.target.value)}
            className="rounded border border-border bg-background px-1.5 py-0.5 text-[11px]"
          >
            <option value="">any</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        {(kevOnly || epssHigh || cvssHigh || severity || source || q) && (
          <button
            type="button"
            onClick={clearFilters}
            className="ml-auto text-[11px] text-muted-foreground hover:text-foreground"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Results */}
      <div data-testid="cve-results-table">
        {search.isError ? <ErrorState title="Could not load CVE results." action={<Button onClick={() => void search.refetch()}>Retry</Button>} /> : search.isPending || q !== debouncedQ ? <LoadingState label="Loading CVE results…" /> : <DataTable<CVEResult>
          rows={rows}
          preferencesKey="cve-catalog"
          exportFileName="constellation-cve-page.csv"
          exportLabel="Export this page"
          columns={columns}
          rowKey={(r) => r.cve_id}
          onRowClick={(r) => navigate({ href: `/cve/${r.cve_id}` })}
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
        <fieldset disabled={search.isFetching || q !== debouncedQ}><Pager page={page} pageSize={pageSize} hasMore={!search.isError && hasMore} rowsOnPage={rows.length} onPage={(next) => setParams((current) => { if (next) current.set("page", String(next + 1)); else current.delete("page"); return current; })} /></fieldset>
      </div>
      <p className="text-xs text-muted-foreground">Filters and sorting apply across the catalog. CSV includes the current page and visible columns. Catalog summary metrics cover all records.</p>
    </PageContainer>
  );
}

function EpssBar({ value }: { value?: number }) {
  if (value == null) return <span className="text-muted-foreground text-[10px]">—</span>;
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
      <span className="text-mono text-[10px] tabular-nums text-muted-foreground">{pct.toFixed(pct < 1 ? 2 : 1)}%</span>
    </div>
  );
}
