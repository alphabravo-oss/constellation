import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Boxes, Clock3, Database, PackageSearch, Search, ShieldAlert } from "lucide-react";

import { imageScanResults, type ImageScanResult } from "@/api/client";
import { INVENTORY_PAGE_SIZE, scanInventoryResponseValid, ScanInventoryExport, useInventoryScope, useInventoryRoute, InventoryScopeState, InventoryLoadState, ScanInventoryContinuation } from "./inventory-workspace";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { cn } from "@/lib/cn";
import { imageReferenceName, imageScanDisplayName } from "@/lib/asset-identity";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { scanEngineEvidence } from "@/lib/scan-evidence";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Select } from "@/components/ui/form";

const severities = ["all", "critical", "high", "medium", "low", "info"];

export function ImageScansPage() {
  const scope = useInventoryScope();
  const { clusterId } = scope;
  const route = useInventoryRoute();
  const { query, setQuery, selectedID, setSelectedID } = route;
  const severity = route.params.get("severity") || "all";
  const setSeverity = (value: string) => route.update({ severity: value === "all" ? null : value });
  const sort = route.params.get("sort") || "scan";
  const order = route.params.get("order") || "desc";
  const validFilters = severities.includes(severity) && ['image', 'risk', 'exposure', 'scan'].includes(sort) && ["asc", "desc"].includes(order);
  const request = { cluster_id: clusterId, q: route.debouncedQuery || undefined,  limit: INVENTORY_PAGE_SIZE, offset: route.offset, severity: severity === "all" ? undefined : severity, image_digest: route.params.get("image_digest") || route.params.get("digest") || undefined, sort, order: order as "asc" | "desc" };
  const q = useQuery({
    queryKey: ["image-scan-results", scope.owner, clusterId, request],
    queryFn: () => imageScanResults.list(request),
    enabled: scope.ready && !route.debouncing && validFilters,
  });
  const rawRows = q.data?.image_scan_results ?? [];
  const invalid = Boolean(q.data && (!Array.isArray(q.data.image_scan_results) || !scanInventoryResponseValid(q.data, rawRows.length, route.offset, sort, order, ['total', 'packages', 'findings', 'critical_high', 'exposed', 'local', 'stale', 'incomplete']) || rawRows.some(item => item.impacted_count <= 0)));
  const available = scope.ready && q.isSuccess && !route.debouncing && validFilters && !invalid;
  const filtered = available ? rawRows : [];
  const hasMore = available && q.data?.has_more === true;
  const selected = filtered.find((item) => item.id === selectedID) ?? null;
  const summary = available ? q.data!.summary! : {};
  const results = filtered;

  const columns: Column<ImageScanResult>[] = [
    {
      id: "image", sort: () => 0, exportValue: item => [item.image_ref, item.image_digest].join(" · "), kind: "name", grow: true, minSize: 280, wrap: true,
      header: "Image",
      cell: (item) => (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <ImageKindBadge item={item} />
            {item.impacted_count > 0 ? <Pill tone="accent">running workload</Pill> : null}
            {isStale(item.last_scanned_at) ? <Pill tone="warn">stale scan</Pill> : null}
          </div>
          <a href={`/clusters/${clusterId}/images/${item.id}`} className="mt-2 block break-all font-mono text-xs font-medium hover:underline">
            {imageScanDisplayName(item)}
          </a>
          <DigestDisclosure digest={item.image_digest} />
        </>
      ),
    },
    {
      id: "risk", sort: () => 0, exportValue: item => `${item.max_risk_score} risk; ${item.critical_count} critical; ${item.high_count} high; ${item.medium_count} medium`, kind: "count", size: 152, minSize: 136, maxSize: 176, wrap: true,
      header: "Risk",
      cell: (item) => <RiskStack item={item} />,
    },
    {
      id: "exposure", sort: () => 0, exportValue: item => `${item.impacted_count} workloads; ${item.package_count} packages`, kind: "count", size: 144, minSize: 128, maxSize: 160, wrap: true,
      header: "Exposure",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.impacted_count} workload{item.impacted_count === 1 ? "" : "s"}</div>
          <div className="mt-1 text-muted-foreground">{item.package_count} packages</div>
        </div>
      ),
    },
    {
      id: "scan", sort: () => 0, exportValue: item => [item.scanner_profile, item.last_scanned_at, JSON.stringify(item.engine_status ?? {})].join(" · "), kind: "text", size: 232, minSize: 200, wrap: true,
      header: "Scan",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.scanner_profile}</div>
          <div className="mt-1 text-muted-foreground">{formatDate(item.last_scanned_at)}</div>
          <div className="mt-1 text-micro text-muted-foreground">{scanEngineEvidence(item.engine_status).engines.every((engine) => engine.status === "succeeded") ? "Engines completed" : "Incomplete engine evidence"}</div>
        </div>
      ),
    },
  ];

  if (!scope.ready) return <div className="space-y-4"><PageHeader title="Images" description="Shared image scan evidence for images linked to workloads in this cluster." /><InventoryScopeState scope={scope} /></div>;

  return (
    <div className="space-y-4" data-testid="image-scans-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Images"
        description="Every scanned container image and the running workloads exposed to its vulnerabilities."
        actions={
          <a
            href={selected ? `/clusters/${clusterId}/images/${selected.id}` : `/clusters/${clusterId}/images`}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
              !selected && "pointer-events-none opacity-50",
            )}
          >
            <PackageSearch className="h-4 w-4" aria-hidden />
            Open Image Scan
          </a>
        }
      />

      <VerdictBanner status={q.isError || invalid || !validFilters ? "degraded" : !available ? "info" : summary.incomplete > 0 || summary.critical_high > 0 || summary.stale > 0 ? "degraded" : "info"}
        title={q.isError || invalid || !validFilters ? "Image scans are unavailable" : !available ? "Loading image scans" : summary.total === 0 ? "No matching image scans" : summary.incomplete > 0 ? "Some matching scans have incomplete engine evidence" : "Review matching image scan evidence"}
        detail="Metrics cover all image scans matching the server filters. Image scan results are shared evidence; exposure is scoped to this cluster." />
      {available && <StatGrid data-testid="image-scan-summary">
        <StatCard label="Matching images" value={summary.total.toLocaleString()} icon={<Boxes className="h-3.5 w-3.5" />} hint={`${summary.exposed} running · ${summary.local} local`} />
        <StatCard label="Critical / High" value={summary.critical_high.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.critical_high > 0 ? "high" : "neutral"} hint={`${summary.findings} image findings`} />
        <StatCard label="Packages" value={summary.packages.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} hint="across matching image results" />
        <StatCard label="Stale Scans" value={summary.stale.toLocaleString()} icon={<Clock3 className="h-3.5 w-3.5" />} tone={summary.stale > 0 ? "medium" : "neutral"} hint="older than 7 days" />
      </StatGrid>}

      <div className="flex flex-wrap gap-3"><Button disabled={q.isFetching || route.debouncing || !scope.ready || !validFilters} onClick={() => void q.refetch()}>Refresh</Button><ScanInventoryExport context={JSON.stringify([scope.owner, clusterId, request])} disabled={!available || q.isFetching} download={shouldDownload => imageScanResults.exportCSV(request, shouldDownload)} /></div>
      {q.isFetching && q.isSuccess && <p role="status" className="text-sm text-muted-foreground">Refreshing scan inventory…</p>}
      <p className="text-xs text-muted-foreground">Matching CSV includes fixed inventory columns across all matching pages (up to 100,000 records). The table’s page CSV follows visible columns.</p>
      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search repository, image, digest or source reference"
              aria-label="Search image scans"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="image-scan-search"
            />
          </label>
          <Select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="image-scan-severity-filter"
            aria-label="Filter image scans by severity"
          >
            {severities.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All severities" : item}</option>
            ))}
          </Select>
        </div>
      </section>

      <p className="text-xs text-muted-foreground">Shared image scan evidence for images linked to workloads in this cluster. Search runs on the server. Severity and sorting run on the server before pagination.</p>
      {!validFilters && <ErrorState title="The requested server filter or sort is invalid. Choose a listed value to recover." action={<Button onClick={() => route.update({ sort: null, order: null, severity: null })}>Reset filters and sort</Button>} />}
      {available && <ScanInventoryContinuation total={q.data?.total} page={route.page} rows={results.length} matching={filtered.length} hasMore={hasMore} onPage={route.setPage} />}
      {available && selectedID && !selected && <ErrorState title="The selected record is unavailable on this page or hidden by its filters." action={<Button onClick={() => setSelectedID(null)}>Clear selection</Button>} />}
      <section className="flex flex-col gap-4">
        <div data-testid="image-scans-table">
          {!available ? validFilters ? <InventoryLoadState label="Image scans" query={q} invalid={invalid} debouncing={route.debouncing} /> : null : <DataTable
            rows={filtered}
            pagination={false}
            manualSorting
            sort={{ id: sort, dir: order as "asc" | "desc" }}
            onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })}
            preferencesKey="image-scan-results-inventory"
            exportFileName="constellation-image-scan-results-server-page"
            exportLabel="Export this page CSV"
            columns={columns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={new Set(selected ? [selected.id] : [])}
            emptyState={
              <div className="px-3 py-8 text-center text-xs text-muted-foreground">
                {q.isPending ? "Loading image scans..." : q.isError ? "Image scans are unavailable. Refresh to try again." : "No image scans match the current filters."}
              </div>
            }
          />}
        </div>

        {selected && <Collapse label="Selected image summary"><ImagePreview item={selected} clusterId={clusterId} /></Collapse>}
      </section>
    </div>
  );
}

function ImagePreview({ item, clusterId }: { item: ImageScanResult | null; clusterId?: string }) {
  if (!item) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="image-scan-preview">
        <h2 className="text-sm font-semibold">Image scan inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select an image to inspect scan freshness, exposure, and scan provenance.</p>
      </aside>
    );
  }
  return (
    <aside className="space-y-4" data-testid="image-scan-preview">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <ImageKindBadge item={item} />
            <h2 className="mt-2 break-all font-mono text-sm font-semibold">{imageScanDisplayName(item)}</h2>
            <DigestDisclosure digest={item.image_digest} />
          </div>
          <a href={`/clusters/${clusterId}/images/${item.id}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
            Full Details
          </a>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2">
          <MiniMetric label="Critical" value={item.critical_count} tone={item.critical_count > 0 ? "danger" : "normal"} />
          <MiniMetric label="High" value={item.high_count} tone={item.high_count > 0 ? "warn" : "normal"} />
          <MiniMetric label="Risk" value={item.max_risk_score} tone={item.max_risk_score >= 70 ? "warn" : "normal"} />
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Scan identity</h3>
        <dl className="mt-3 grid gap-2 text-sm">
          <Field label="Repository" value={imageReferenceName(item.image_repository) || "-"} />
          <Field label="Tag" value={item.image_tag || "-"} />
          <Field label="Platform" value={item.platform || "-"} />
          <Field label="Scanner Profile" value={item.scanner_profile} />
          <Field label="Source" value={sourceLabel(item)} />
          <Field label="Source Ref" value={<Collapse label="Source reference"><code className="break-all text-xs">{item.source_ref || "-"}</code></Collapse>} />
          {item.vulndb_bundle_version && <Field label="VulnDB Bundle" value={item.vulndb_bundle_version} />}
          {item.vulndb_bundle_hash && <Field label="Bundle Hash" value={<DigestDisclosure digest={item.vulndb_bundle_hash} />} />}
        </dl>
      </div>
    </aside>
  );
}

function isLocalImage(item: ImageScanResult): boolean {
  return item.image_ref.startsWith("sha256:") || !item.image_repository || item.image_repository === item.image_digest;
}

function isStale(value: string): boolean {
  const t = new Date(value).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t > 7 * 86400 * 1000;
}

function ImageKindBadge({ item }: { item: ImageScanResult }) {
  if (item.source_type === "repository") return <Pill tone="accent">repository scan</Pill>;
  return isLocalImage(item) ? <Pill tone="warn">local image</Pill> : <Pill tone="neutral">registry image</Pill>;
}

function sourceLabel(item: ImageScanResult): string {
  if (item.source_type === "repository") return "Repository / CI";
  if (item.source_type === "runtime-agent") return "Runtime agent";
  if (item.source_type === "registry") return "Registry";
  return item.source_type || "Manual";
}

function RiskStack({ item }: { item: ImageScanResult }) {
  return (
    <div className="space-y-1 text-xs">
      <div className="font-semibold">{item.max_risk_score}</div>
      <div className="flex flex-wrap justify-end gap-1">
        {item.critical_count > 0 ? <Pill tone="danger">C {item.critical_count}</Pill> : null}
        {item.high_count > 0 ? <Pill tone="warn">H {item.high_count}</Pill> : null}
        {item.medium_count > 0 ? <Pill tone="neutral">M {item.medium_count}</Pill> : null}
      </div>
    </div>
  );
}

function MiniMetric({ label, value, tone }: { label: string; value: number; tone: "normal" | "warn" | "danger" }) {
  return (
    <div className={cn("rounded-md border border-border p-2", tone === "danger" && "border-destructive/40 bg-destructive/10", tone === "warn" && "border-status-warning/40 bg-status-warning/10")}>
      <div className="text-micro text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
}

function Pill({ children, tone }: { children: ReactNode; tone: "neutral" | "accent" | "warn" | "danger" }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded px-1.5 text-micro font-medium",
        tone === "neutral" && "bg-muted text-muted-foreground",
        tone === "accent" && "bg-primary/10 text-primary",
        tone === "warn" && "bg-status-warning/10 text-status-warning",
        tone === "danger" && "bg-destructive/10 text-destructive",
      )}
    >
      {children}
    </span>
  );
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
