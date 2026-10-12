// RegistryImagesPage — drill-in from the registry list to its scanned image inventory,
// correlated with vulnerability scan results. Closes the "registries are a dead-end list"
// gap (the /registries/{id}/images endpoint existed but nothing navigated to it).
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, Boxes } from "lucide-react";

import { registries, type RegistryImageRow } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { Pager } from "@/components/ui/pager";
import { fmtRelative } from "@/lib/format";

const PAGE = 100;

export function RegistryImagesPage() {
  const { regId } = useParams({ strict: false });
  const { clusterId } = useCluster();
  const [params, setParams] = useRouteSearchParams();
  const search = params.get("q") ?? "";
  const rawPage = Number(params.get("page"));
  const page = Number.isSafeInteger(rawPage) && rawPage >= 1 && rawPage <= Math.floor(Number.MAX_SAFE_INTEGER / PAGE) ? rawPage - 1 : 0;
  const setPage = (next: number) => setParams(current => { if (next) current.set("page", String(next + 1)); else current.delete("page"); return current; });
  const setSearch = (value: string) => setParams(current => { if (value) current.set("q", value); else current.delete("q"); current.delete("page"); return current; });
  const q = search.trim();
  const reg = useQuery({ queryKey: ["registry", regId], queryFn: () => registries.get(regId!), enabled: !!regId });
  const registryReady = reg.isSuccess && reg.data.id === regId;
  const imgs = useQuery({
    queryKey: ["registry-images", regId, q, page],
    queryFn: async () => { const result = await registries.images(regId!, { q: q || undefined, limit: PAGE, offset: page * PAGE }); if (result.offset !== page * PAGE || result.limit !== PAGE || !Number.isSafeInteger(result.total) || result.total < 0) throw new Error("Registry image pagination does not match this request"); return result; },
    enabled: registryReady,
  });
  const ready = registryReady && imgs.isSuccess;
  const unavailable = reg.isError || (reg.isSuccess && !registryReady) || imgs.isError;
  const rows = ready ? imgs.data.images : [];
  const total = ready ? imgs.data.total : undefined;
  const scanned = rows.filter((r) => r.scanned).length;
  const totalCrit = rows.reduce((s, r) => s + (r.critical ?? 0), 0);
  const totalHigh = rows.reduce((s, r) => s + (r.high ?? 0), 0);

  const columns: Column<RegistryImageRow>[] = [
    { id: "repo", header: "Repository", exportValue: (r) => r.repository, kind: "name", code: true, cell: (r) => <span className="text-xs font-medium">{r.repository}</span>, sort: (a, b) => a.repository.localeCompare(b.repository) },
    { id: "tags", header: "Tags", kind: "id", wrap: true, size: 220, maxSize: 280, cell: (r) => r.tags.join(", ") || "—", exportValue: (r) => r.tags.join("; ") },
    { id: "scanned", header: "Scan", exportValue: (r) => r.scanned ? "scanned" : "not scanned", kind: "status", cell: (r) => (
        r.scanned
          ? <span className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-[color-mix(in_oklab,var(--color-severity-low)_16%,transparent)] text-[color:var(--color-severity-low)]">scanned</span>
          : <span className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-muted text-muted-foreground">not scanned</span>
      ), sort: (a, b) => Number(a.scanned) - Number(b.scanned) },
    { id: "vulns", header: "Vulnerabilities", exportValue: (r) => `critical=${r.critical}; high=${r.high}`, kind: "count", size: 150, minSize: 120, maxSize: 200, numeric: true, cell: (r) => (
        (r.critical ?? 0) + (r.high ?? 0) === 0
          ? <span className="text-[11px] text-muted-foreground">{r.scanned ? "no crit/high" : "—"}</span>
          : <span className="flex items-center justify-end gap-1">
              {r.critical > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-critical)" }}>{r.critical}C</span>}
              {r.high > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-high)" }}>{r.high}H</span>}
            </span>
      ), sort: (a, b) => (a.critical * 1000 + a.high) - (b.critical * 1000 + b.high) },
    { id: "findings", header: "Findings", exportValue: (r) => r.finding_count, kind: "count", numeric: true, cell: (r) => <span className="text-mono text-xs">{r.scanned ? r.finding_count : "—"}</span>, sort: (a, b) => (a.finding_count ?? 0) - (b.finding_count ?? 0) },
    { id: "pushed", header: "Last pushed", exportValue: (r) => r.last_pushed_at ?? "", kind: "age", cell: (r) => <span className="text-[10px] text-muted-foreground">{r.last_pushed_at ? fmtRelative(r.last_pushed_at) : "—"}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        backLink={<a href={clusterId ? `/clusters/${clusterId}/registries` : "/registries"} className="inline-flex items-center gap-1 hover:text-foreground"><ChevronLeft className="h-3.5 w-3.5" />Registries</a>}
        title={registryReady ? reg.data.name : "Registry images"}
        actions={<Button variant="outline" disabled={reg.isFetching || imgs.isFetching} onClick={() => { void reg.refetch(); if (registryReady) void imgs.refetch(); }}>Refresh</Button>}
        description="Organization-wide image inventory discovered in this registry, correlated with vulnerability scan results."
      />
      <VerdictBanner status={unavailable ? "degraded" : !ready || rows.length === 0 ? "info" : totalCrit + totalHigh > 0 || scanned < rows.length ? "degraded" : "ok"}
        title={unavailable ? "Registry inventory could not be loaded" : !ready ? "Loading registry images" : rows.length === 0 ? (q ? "No images match this search" : "No images discovered") : scanned < rows.length ? "Some images on this page need scanning" : totalCrit + totalHigh > 0 ? "Image vulnerabilities need attention" : "No critical or high findings on this page"}
        detail="Scan and vulnerability metrics describe this page. Inspect engine coverage and findings on the Images page." />
      <StatGrid>
        <StatCard label="Images" value={total ?? "—"} icon={<Boxes className="h-3.5 w-3.5" />} />
        <StatCard label="Scanned (page)" value={ready ? scanned : "—"} tone={scanned < rows.length ? "medium" : "low"} hint={ready ? `${rows.length - scanned} unscanned on page` : undefined} />
        <StatCard label="Critical (page)" value={ready ? totalCrit : "—"} tone={totalCrit > 0 ? "critical" : "neutral"} />
        <StatCard label="High (page)" value={ready ? totalHigh : "—"} tone={totalHigh > 0 ? "high" : "neutral"} />
      </StatGrid>
      <input
        value={search}
        onChange={(e) => { setSearch(e.target.value); }}
        placeholder="Search repository…"
        aria-label="Search registry repositories"
        className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
      />
      {unavailable ? (
        <p role="alert" className="text-sm text-muted-foreground">Image inventory is unavailable. Refresh to try again.</p>
      ) : !ready ? (
        <p className="text-sm text-muted-foreground">Loading images…</p>
      ) : rows.length === 0 ? (
        <><EmptyState title={page ? "No images on this page" : q ? "No matching images" : "No images discovered"} hint={q ? "Try a different search." : "Run a registry sync to populate the image inventory."} /><Pager page={page} pageSize={PAGE} total={total} rowsOnPage={0} onPage={setPage} /></>
      ) : (
        <>
          <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} pagination={false} preferencesKey="registry-images" exportFileName={`registry-images-page-${page + 1}`} exportLabel="Export this page CSV" />
          <p className="text-xs text-muted-foreground">Sorting and CSV cover this page only. Search and pagination use the full registry inventory.</p>
          <Pager page={page} pageSize={PAGE} total={total} rowsOnPage={rows.length} onPage={setPage} />
        </>
      )}
    </div>
  );
}
