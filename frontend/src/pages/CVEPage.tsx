// CVEPage — browse the live cve_records table (332k+ rows). Shows aggregate
// stat tiles, filter chip bar, and a default list of recent CVEs that the user
// can search/filter without typing a query first.
import { useMemo, useState, useEffect, useDeferredValue } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { Search, Database, Crown, Activity, AlertTriangle } from "lucide-react";

import { cve, type CVEResult, type Severity } from "@/api/client";
import { StatCard } from "@/components/ui/stat-card";
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

  const [q, setQ] = useState("");
  const debouncedQ = useDebounced(q, 200);
  const deferredQ = useDeferredValue(debouncedQ);

  const [kevOnly, setKevOnly] = useState(false);
  const [epssHigh, setEpssHigh] = useState(false);
  const [cvssHigh, setCvssHigh] = useState(false);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [source, setSource] = useState<string>("");
  // Sort is applied SERVER-SIDE — the catalog is far larger than one page, so a
  // client-side sort would only reorder the visible 50 rows. Header clicks update this
  // and refetch in the new global order. Default matches the DataTable's defaultSort.
  const [sort, setSort] = useState<{ id: string; dir: "asc" | "desc" }>({ id: "cvss", dir: "desc" });

  const stats = useQuery({ queryKey: ["cve", "stats"], queryFn: () => cve.stats(), staleTime: 60_000 });
  const bundle = useQuery({ queryKey: ["cve", "bundle"], queryFn: () => cve.bundle(), staleTime: 60_000 });

  const search = useQuery({
    queryKey: ["cve", "search", deferredQ, kevOnly, epssHigh, cvssHigh, severity, source, sort.id, sort.dir],
    queryFn: () =>
      cve.search({
        q: deferredQ,
        kev: kevOnly || undefined,
        epss_gt: epssHigh ? 0.5 : undefined,
        cvss_gt: cvssHigh ? 7.0 : undefined,
        severity: severity || undefined,
        source: source || undefined,
        sort: sort.id,
        dir: sort.dir,
        limit: 50,
      }),
    placeholderData: keepPreviousData,
  });

  const rows = search.data?.results ?? [];

  const columns = useMemo<Column<CVEResult>[]>(
    () => [
      {
        id: "cve_id",
        header: "CVE-ID",
        cell: (r) => (
          <Link to={`/cve/${r.cve_id}`} className="text-mono text-[12px] text-[color:var(--color-primary)] hover:underline">
            {r.cve_id}
          </Link>
        ),
        sort: (a, b) => a.cve_id.localeCompare(b.cve_id),
        width: "160px",
      },
      {
        id: "severity",
        header: "Severity",
        cell: (r) => <SeverityBadge severity={severityOf(r.cvss_base)} kev={r.kev_listed} />,
        sort: (a, b) => (a.cvss_base ?? -1) - (b.cvss_base ?? -1),
        width: "110px",
      },
      {
        id: "cvss",
        header: "CVSS",
        numeric: true,
        cell: (r) => (
          <span className="text-mono text-[12px] tabular-nums">
            {r.cvss_base != null ? r.cvss_base.toFixed(1) : <span className="text-muted-foreground">—</span>}
          </span>
        ),
        sort: (a, b) => (a.cvss_base ?? -1) - (b.cvss_base ?? -1),
        width: "80px",
      },
      {
        id: "kev",
        header: "KEV",
        cell: (r) => (r.kev_listed ? <KevBadge /> : <span className="text-muted-foreground text-[10px]">—</span>),
        sort: (a, b) => Number(a.kev_listed) - Number(b.kev_listed),
        width: "70px",
      },
      {
        id: "epss",
        header: "EPSS",
        cell: (r) => <EpssBar value={r.epss_probability} />,
        sort: (a, b) => (a.epss_probability ?? -1) - (b.epss_probability ?? -1),
        width: "120px",
      },
      {
        id: "title",
        header: "Title",
        cell: (r) => (
          <span className="line-clamp-1 text-[12px] text-foreground/90" title={r.title ?? r.description}>
            {r.title || <span className="text-muted-foreground">(no title)</span>}
          </span>
        ),
      },
      {
        id: "sources",
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
        width: "180px",
      },
      {
        id: "published",
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
        width: "110px",
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
      {stats.data && (
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
      <section className="grid grid-cols-2 gap-3 md:grid-cols-4">
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
      </section>

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
        <FilterChip label="KEV-only" active={kevOnly} onClick={() => setKevOnly((v) => !v)} />
        <FilterChip label="EPSS > 0.5" active={epssHigh} onClick={() => setEpssHigh((v) => !v)} />
        <FilterChip label="CVSS ≥ 7" active={cvssHigh} onClick={() => setCvssHigh((v) => !v)} />
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
            onClick={() => {
              setKevOnly(false);
              setEpssHigh(false);
              setCvssHigh(false);
              setSeverity("");
              setSource("");
              setQ("");
            }}
            className="ml-auto text-[11px] text-muted-foreground hover:text-foreground"
          >
            Clear all
          </button>
        )}
      </div>

      {/* Results */}
      <div data-testid="cve-results-table">
        <DataTable<CVEResult>
          rows={rows}
          columns={columns}
          rowKey={(r) => r.cve_id}
          onRowClick={(r) => navigate(`/cve/${r.cve_id}`)}
          defaultSort={{ id: "cvss", dir: "desc" }}
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
        />
      </div>

      <div className="text-[10px] text-muted-foreground">
        Showing {rows.length} of {stats.data ? stats.data.total.toLocaleString() : "—"} rows · ordered by KEV → EPSS → CVSS → published date.
      </div>
    </PageContainer>
  );
}

function EpssBar({ value }: { value?: number }) {
  if (value == null) return <span className="text-muted-foreground text-[10px]">—</span>;
  const pct = Math.min(100, Math.max(0, value * 100));
  const hot = pct >= 50;
  return (
    <div className="flex items-center gap-1.5">
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
