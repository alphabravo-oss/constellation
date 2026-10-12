import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { BadgeCheck, Boxes, FileJson, Search, ShieldAlert, ShieldCheck } from "lucide-react";

import { assets, type Asset } from "@/api/client";
import { useDebounced } from "@/hooks/useDebounced";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { Pager } from "@/components/ui/pager";
import { LoadingState } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import { useInventoryScope } from "./inventory-workspace";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { useRouteSearchParams } from "@/lib/route-search";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { StatCard, StatGrid } from "@/components/ui/stat-card";

const kinds = ["all", "image", "workload", "iac-resource", "ml-model", "cloud-resource", "host", "repository", "serverless"];
const criticalities = ["all", "critical", "high", "medium", "low"];
const ASSET_PAGE_SIZE = 100;

export function AssetsPage() {
  // Cluster-scoped: only show assets belonging to the active cluster. Assets
  // with NULL cluster_id (org-wide registry pulls, ML models, IaC files) are
  // omitted in cluster mode by design — they live in a future org-level inventory
  // surface, not under a specific cluster's posture pane.
  const inventoryScope = useInventoryScope();
  const { clusterId, isLoading: clusterLoading, error: clusterError } = inventoryScope;
  const scopeReady = inventoryScope.ready;
  const [params, setParams] = useRouteSearchParams();
  const kind = params.get("kind") ?? "all";
  const criticality = params.get("criticality") ?? "all";
  const search = params.get("q") ?? "";
  const selectedID = params.get("selected");
  const identity = useTablePreferencesIdentity();
  const ai = params.get("ai_workload") ?? "";
  const sort = params.get("sort") ?? "risk";
  const order = params.get("order") === "asc" ? "asc" : "desc";
  const rawPage = Number(params.get("page") ?? "1");
  const page = Number.isSafeInteger(rawPage) && rawPage >= 1 && rawPage <= 10000000 ? rawPage - 1 : 0;
  const query = useDebounced(search.trim(), 300);
  const querySettled = query === search.trim();
  const setFilter = (key: string, value: string) => setParams(current => { if (value && (key === "q" || value !== "all")) current.set(key, value); else current.delete(key); current.delete("page"); current.delete("selected"); return current; }, { replace: key === "q" });
  const setSelectedID = (id: string) => setParams(current => { current.set("selected", id); return current; });
  const setPage = (next: number) => setParams(current => { if (next) current.set("page", String(next + 1)); else current.delete("page"); current.delete("selected"); return current; });
  const filters = { cluster_id: clusterId, search: query || undefined, kind: kind === "all" ? undefined : kind, criticality: criticality === "all" ? undefined : criticality, ...(ai ? { ai_workload: ai === "true" } : {}), sort, order: order as "asc" | "desc" };
  const q = useQuery({
    queryKey: ["assets", identity?.org_id, identity?.user_id, filters, page], enabled: scopeReady && querySettled,
    queryFn: async () => {
      if ((ai && !["true", "false"].includes(ai)) || (params.has("order") && !["asc", "desc"].includes(params.get("order")!)) || !Number.isSafeInteger(rawPage) || rawPage < 1 || rawPage > 10000000) throw new Error("Invalid asset filter or page");
      const response = await assets.list({ ...filters, limit: ASSET_PAGE_SIZE, offset: page * ASSET_PAGE_SIZE });
      if (!Array.isArray(response.assets) || !Number.isSafeInteger(response.total) || response.total < 0 || response.limit !== ASSET_PAGE_SIZE || response.offset !== page * ASSET_PAGE_SIZE || typeof response.has_more !== "boolean" || response.has_more !== (response.offset + response.assets.length < response.total) || response.sort !== sort || response.order !== order || !response.summary || response.summary.total !== response.total || ["images", "workloads", "critical_high", "open_findings", "unsigned_images", "signed_images", "signature_unknown", "missing_sbom", "with_sbom", "ai"].some(key => !Number.isSafeInteger(response.summary[key]) || response.summary[key] < 0)) throw new Error("Assets pagination or summary metadata is missing");
      if ((response.has_more && response.assets.length === 0) || response.assets.length > ASSET_PAGE_SIZE || new Set(response.assets.map(asset => asset.id)).size !== response.assets.length || response.assets.some(asset => asset.cluster_id !== clusterId || !asset.id || typeof asset.name !== "string" || !asset.labels || typeof asset.labels !== "object" || Array.isArray(asset.labels) || Object.values(asset.labels).some(value => typeof value !== "string"))) throw new Error("Asset inventory does not match the selected cluster or evidence schema");
      return response;
    },
  });
  const ready = scopeReady && querySettled && q.isSuccess && !q.isFetching;
  const filtered = useMemo(() => ready ? q.data!.assets : [], [ready, q.data]);
  const selected = selectedID ? filtered.find(asset => asset.id === selectedID) ?? null : filtered[0] ?? null;
  const summary = ready ? q.data!.summary : undefined;
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<{ scope: string; error: unknown } | null>(null);
  const [exportResult, setExportResult] = useState<{ scope: string; exported: number; total: number; truncated: boolean } | null>(null);
  const exportScope = JSON.stringify([identity, filters]);
  const exportMatching = async () => {
    if (!ready || exporting) return;
    setExportError(null); setExporting(true);
    try { const result = await assets.exportCsv(filters); setExportResult({ scope: exportScope, ...result }); }
    catch (error) { setExportError({ scope: exportScope, error }); } finally { setExporting(false); }
  };
  const setSort = (value: { id: string; dir: "asc" | "desc" } | null) => setParams(current => { current.set("sort", value?.id ?? "risk"); current.set("order", value?.dir ?? "desc"); current.delete("page"); current.delete("selected"); return current; });

  const columns: Column<Asset>[] = [
    {
      id: "asset",
      header: "Asset", sort: () => 0, exportValue: (asset) => asset.name, kind: "name", wrap: true, size: 360, minSize: 280,
      cell: (asset) => (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <KindBadge kind={asset.kind} />
            {asset.ai_workload ? <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs text-primary">AI</span> : null}
          </div>
          <a href={`/clusters/${clusterId}/assets/${asset.id}`} className="mt-2 block break-all font-mono text-xs font-medium hover:underline">
            {asset.name}
          </a>
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{asset.digest ?? asset.repository ?? "-"}</div>
        </>
      ),
    },
    { id: "risk", header: "Risk", sort: () => 0, exportValue: (asset) => `critical=${asset.critical_findings}; high=${asset.high_findings}; open=${asset.open_findings}`, kind: "text", wrap: true, size: 192, minSize: 176, maxSize: 280, cell: (asset) => <RiskStack asset={asset} /> },
    { id: "supply-chain", header: "Supply Chain", sort: () => 0, exportValue: (asset) => `signed=${asset.image_signed ?? "not reported"}; sboms=${asset.sbom_count}; registry=${asset.registry ?? ""}; digest=${asset.digest ?? ""}`, kind: "text", wrap: true, size: 208, minSize: 192, maxSize: 320, cell: (asset) => <SupplyChainStack asset={asset} /> },
    { id: "criticality", header: "Criticality", sort: () => 0, exportValue: (asset) => asset.criticality, kind: "status", cell: (asset) => <span className="text-xs">{asset.criticality}</span> },
    { id: "last-seen", header: "Last Seen", sort: () => 0, exportValue: (asset) => asset.last_seen_at, kind: "date", size: 208, minSize: 208, maxSize: 240, cell: (asset) => <span className="text-xs text-muted-foreground">{formatDate(asset.last_seen_at)}</span> },
  ];

  if (clusterLoading || inventoryScope.fetching) {
    return <p className="text-sm text-muted-foreground" data-testid="assets-loading">Loading cluster…</p>;
  }

  return (
    <div className="space-y-4" data-testid="assets-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Assets"
        description="Risk-ranked inventory across images, workloads, IaC, ML, and cloud resources."
        actions={
          <div className="flex items-center gap-2">
          <Button variant="outline" disabled={!scopeReady || q.isFetching} onClick={() => void q.refetch()}>Refresh</Button>
          <a
            href={selected ? `/clusters/${clusterId}/assets/${selected.id}` : `/clusters/${clusterId}/assets`}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
              !selected && "pointer-events-none opacity-50",
            )}
          >
            <Boxes className="h-4 w-4" aria-hidden />
            Open Full Asset
          </a>
          </div>
        }
      />

      <VerdictBanner status={!scopeReady || q.isError ? "degraded" : (summary?.critical_high ?? 0) > 0 ? "degraded" : "info"}
        title={!scopeReady ? "Cluster scope unavailable" : q.isError ? "Asset inventory unavailable" : !ready ? "Loading or updating assets" : `${q.data.total.toLocaleString()} matching assets`}
        detail="Search, filters, summary, sorting and server pages cover the complete matching inventory. Table CSV covers this page; full CSV exports up to 100,000 matching assets." />
      {!scopeReady ? <ErrorState title="Resolve the selected cluster before loading assets" error={clusterError} action={<Button onClick={inventoryScope.retry}>Retry cluster</Button>} /> : q.isError ? <ErrorState title="Could not load or refresh assets" error={q.error} action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : !ready ? <LoadingState label="Loading or updating assets…" /> : null}
      <StatGrid data-testid="assets-summary">
        <StatCard label="Matching assets" value={summary?.total.toLocaleString() ?? "—"} icon={<Boxes className="h-3.5 w-3.5" />} hint={summary ? `${summary.images} images · ${summary.workloads} workloads · ${summary.ai} AI` : undefined} />
        <StatCard label="Critical / High" value={summary?.critical_high.toLocaleString() ?? "—"} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={(summary?.critical_high ?? 0) > 0 ? "high" : "neutral"} hint={summary ? `${summary.open_findings} open findings` : undefined} />
        <StatCard label="Unsigned images" value={summary?.unsigned_images.toLocaleString() ?? "—"} icon={<BadgeCheck className="h-3.5 w-3.5" />} hint={summary ? `${summary.signed_images} signed · ${summary.signature_unknown} not reported` : undefined} />
        <StatCard label="Missing SBOM" value={summary?.missing_sbom.toLocaleString() ?? "—"} icon={<FileJson className="h-3.5 w-3.5" />} hint={summary ? `${summary.with_sbom} with SBOM evidence` : undefined} />
      </StatGrid>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={search}
              onChange={(event) => setFilter("q", event.target.value)}
              placeholder="Search asset, registry, digest, label"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="asset-search"
            />
          </label>
          <select
            value={kind}
            onChange={(event) => setFilter("kind", event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="asset-kind-filter"
          >
            {kinds.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All kinds" : item}</option>
            ))}
          </select>
          <select
            value={criticality}
            onChange={(event) => setFilter("criticality", event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="asset-criticality-filter"
          >
            {criticalities.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All criticality" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <div className="flex flex-wrap items-center gap-3">
        <label className="text-xs">AI workload <select aria-label="AI workload" value={ai} onChange={event => setFilter("ai_workload", event.target.value)} className="rounded-md border border-border bg-background p-2"><option value="">Any</option><option value="true">AI</option><option value="false">Not AI</option></select></label>
        <Button variant="outline" disabled={!ready || !q.data?.total || exporting} onClick={() => void exportMatching()}>{exporting ? "Exporting…" : "Export matching assets CSV"}</Button>
        <span className="text-xs text-muted-foreground">Up to 100,000 matching assets, across all pages.</span>
      </div>
      {exportError?.scope === exportScope && <ErrorState title="Asset export failed" error={exportError.error} />}
      {exportResult?.scope === exportScope && <p role="status" className="text-xs text-muted-foreground">Exported {exportResult.exported} of {exportResult.total} matching assets.{exportResult.truncated ? " The 100,000-row limit was reached." : ""}</p>}
      {ready && <section className="flex flex-col gap-4">
        <DataTable rows={filtered} columns={columns} rowKey={asset => asset.id} onRowClick={asset => setSelectedID(asset.id)} selected={new Set(selected ? [selected.id] : [])} preferencesKey="assets" manualSorting sort={{ id: sort, dir: order }} onSortChange={setSort} pagination={false} exportFileName="constellation-assets-page" exportLabel="Export this page CSV" testId="assets-table" rowTestId={() => "asset-row"} emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No assets match the current filters or page.</div>} />
        <p className="text-xs text-muted-foreground" data-testid="assets-page-scope">Showing {filtered.length ? page * ASSET_PAGE_SIZE + 1 : 0}–{filtered.length ? page * ASSET_PAGE_SIZE + filtered.length : 0} of {q.data.total} matching assets. Preview and table CSV cover this page.</p>
        {filtered.length > 0 && <Pager page={page} pageSize={ASSET_PAGE_SIZE} total={q.data.total} hasMore={q.data.has_more} rowsOnPage={filtered.length} onPage={setPage} />}
        {page > 0 && !filtered.length && <Button onClick={() => setPage(0)}>First page</Button>}
        {selectedID && !selected ? <p role="status" className="text-sm text-muted-foreground">The selected asset is not in the loaded matches on this page. Change pages or filters to locate it.</p> : <AssetPreview asset={selected} clusterId={clusterId} />}
      </section>}
    </div>
  );
}

function AssetPreview({ asset, clusterId }: { asset: Asset | null; clusterId?: string }) {
  if (!asset) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="asset-preview">
        <h2 className="text-sm font-semibold">Asset inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select an asset to inspect risk, provenance, and labels.</p>
      </aside>
    );
  }
  const labelEntries = Object.entries(asset.labels ?? {});
  return (
    <aside className="space-y-4" data-testid="asset-preview">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <KindBadge kind={asset.kind} />
            <h2 className="mt-2 break-all font-mono text-sm font-semibold">{asset.name}</h2>
            <p className="mt-1 text-xs text-muted-foreground">{asset.criticality} criticality · first seen {formatDate(asset.first_seen_at)}</p>
          </div>
          <div className="flex items-center gap-2">
            <a href={`/clusters/${clusterId}/risk/asset/${encodeURIComponent(asset.id)}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent" data-testid="asset-risk-workspace-link">
              Risk workspace
            </a>
            <a href={`/clusters/${clusterId}/assets/${asset.id}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
              Full Details
            </a>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2">
          <MiniMetric label="Critical" value={asset.critical_findings} tone={asset.critical_findings > 0 ? "danger" : "normal"} />
          <MiniMetric label="High" value={asset.high_findings} tone={asset.high_findings > 0 ? "warn" : "normal"} />
          <MiniMetric label="Open" value={asset.open_findings} tone={asset.open_findings > 0 ? "warn" : "normal"} />
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Supply chain posture</h3>
        <dl className="mt-3 grid gap-2 text-sm">
          <Field label="Signature" value={asset.kind === "image" ? (asset.image_signed === true ? "signed" : asset.image_signed === false ? "unsigned" : "Not reported") : "not an image"} />
          <Field label="SBOMs" value={`${asset.sbom_count}`} />
          <Field label="Registry" value={asset.registry || "-"} />
          <Field label="Repository" value={asset.repository || "-"} />
          <Field label="Tag" value={asset.tag || "-"} />
          <Field label="Size" value={asset.size_bytes ? formatBytes(asset.size_bytes) : "-"} />
          <Field label="Digest" value={asset.digest ?? "-"} wide />
        </dl>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Labels</h3>
        {labelEntries.length > 0 ? (
          <div className="mt-3 flex flex-wrap gap-2">
            {labelEntries.map(([key, value]) => (
              <span key={key} className="rounded-md border border-border px-2 py-1 font-mono text-xs">
                {key}={value}
              </span>
            ))}
          </div>
        ) : (
          <p className="mt-2 text-xs text-muted-foreground">No labels reported.</p>
        )}
      </div>
    </aside>
  );
}

function MiniMetric({ label, value, tone }: { label: string; value: number; tone: "normal" | "warn" | "danger" }) {
  return (
    <div className={cn(
      "rounded-md border border-border p-2",
      tone === "danger" && "border-status-error/40 bg-status-error/10",
      tone === "warn" && "border-status-warning/40 bg-status-warning/10",
    )}>
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}

function Field({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={cn("rounded-md border border-border p-2", wide && "sm:col-span-2")}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
}

function KindBadge({ kind }: { kind: string }) {
  return <span className="rounded-md border border-border px-2 py-0.5 text-xs">{kind}</span>;
}

function RiskStack({ asset }: { asset: Asset }) {
  const posture = asset.critical_findings > 0 ? "critical" : asset.high_findings > 0 ? "high" : asset.open_findings > 0 ? "open" : "clean";
  return (
    <div className="space-y-1" data-testid="asset-posture-chip">
      <span className={cn(
        "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium",
        posture === "critical" && "bg-status-error/10 text-status-error",
        posture === "high" && "bg-status-warning/10 text-status-warning",
        posture === "open" && "bg-primary/10 text-primary",
        posture === "clean" && "bg-muted text-muted-foreground",
      )}>
        <ShieldAlert className="h-3.5 w-3.5" aria-hidden />
        {posture}
      </span>
      <div className="text-xs text-muted-foreground">
        {asset.finding_count} total · {asset.open_findings} open
      </div>
    </div>
  );
}

function SupplyChainStack({ asset }: { asset: Asset }) {
  const signed = asset.kind === "image" && asset.image_signed;
  const unsigned = asset.kind === "image" && asset.image_signed === false;
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap gap-1">
        <span className={cn(
          "inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs",
          signed && "bg-status-success/10 text-status-success",
          unsigned && "bg-status-warning/10 text-status-warning",
          !signed && !unsigned && "bg-muted text-muted-foreground",
        )}>
          <ShieldCheck className="h-3.5 w-3.5" aria-hidden />
          {asset.kind === "image" ? (signed ? "signed" : unsigned ? "unsigned" : "Not reported") : "n/a"}
        </span>
        <span className="inline-flex items-center gap-1 rounded-md bg-muted px-2 py-1 text-xs text-muted-foreground">
          <FileJson className="h-3.5 w-3.5" aria-hidden />
          {asset.sbom_count} SBOM
        </span>
      </div>
      <div className="break-all text-xs text-muted-foreground">{asset.registry || asset.repository || "-"}</div>
    </div>
  );
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}

function formatBytes(bytes: number) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}
