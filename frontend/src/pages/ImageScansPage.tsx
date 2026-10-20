import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { PackageSearch } from "lucide-react";
import { sentenceValue } from "@/components/ui/status-pill";

import { imageScanResults, type ImageScanResult } from "@/api/client";
import { INVENTORY_PAGE_SIZE, scanInventoryResponseValid, InventorySearch, useScanInventoryExport, useInventoryScope, useInventoryRoute, InventoryScopeState, InventoryLoadState, ScanInventoryContinuation } from "./inventory-workspace";
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
            {item.impacted_count > 0 ? <Pill tone="accent">Running workload</Pill> : null}
            {isStale(item.last_scanned_at) ? <Pill tone="warn">Stale scan</Pill> : null}
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

  const matching = useScanInventoryExport({ context: JSON.stringify([scope.owner, clusterId, request]), disabled: !available || q.isFetching, download: shouldDownload => imageScanResults.exportCSV(request, shouldDownload) });
  if (!scope.ready) return <div className="space-y-4"><PageHeader title="Images" description="Scanned container images and the running workloads exposed to them." /><InventoryScopeState scope={scope} /></div>;

  const toolbar = <>
    <InventorySearch value={query} onChange={setQuery} label="Search image scans" placeholder="Search repository, image, digest or source" testId="image-scan-search" />
    <Select value={severity} onChange={(event) => setSeverity(event.target.value)} className="h-9" data-testid="image-scan-severity-filter" aria-label="Filter image scans by severity">
      {severities.map((item) => <option key={item} value={item}>{item === "all" ? "Any severity" : sentenceValue(item)}</option>)}
    </Select>
  </>;
  return (
    <div className="space-y-4" data-testid="image-scans-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Images"
        description="Scanned container images and the running workloads exposed to them."
        actions={<>
          <Button disabled={q.isFetching || route.debouncing || !scope.ready || !validFilters} onClick={() => void q.refetch()}>Refresh</Button>
          <a
            href={selected ? `/clusters/${clusterId}/images/${selected.id}` : `/clusters/${clusterId}/images`}
            className={cn("inline-flex h-8 items-center gap-2 rounded-md border border-border px-3 text-meta font-medium hover:bg-accent", !selected && "pointer-events-none opacity-50")}
          >
            <PackageSearch className="h-4 w-4" aria-hidden />
            Open image scan
          </a>
        </>}
      />

      <VerdictBanner status={q.isError || invalid || !validFilters ? "degraded" : !available ? "info" : summary.incomplete > 0 || summary.critical_high > 0 || summary.stale > 0 ? "degraded" : "info"}
        title={q.isError || invalid || !validFilters ? "Image scans are unavailable" : !available ? "Loading image scans" : summary.total === 0 ? "No matching image scans" : summary.incomplete > 0 ? "Some scans have incomplete engine evidence" : `${summary.total.toLocaleString()} matching images`}
        numbers={available ? [
          { label: "images", value: summary.total.toLocaleString(), title: `${summary.exposed} running · ${summary.local} local` },
          { label: "critical or high", value: summary.critical_high.toLocaleString(), tone: summary.critical_high > 0 ? "high" : "default" },
          { label: "running", value: summary.exposed.toLocaleString() },
          { label: "stale scans", value: summary.stale.toLocaleString(), tone: summary.stale > 0 ? "warning" : "default", title: "Older than 7 days" },
        ] : undefined}
        detail={<div className="space-y-1">
          {available && <p data-testid="image-scan-summary">Matching images {summary.total.toLocaleString()} ({summary.exposed} running · {summary.local} local) · critical or high {summary.critical_high.toLocaleString()} ({summary.findings} image findings) · packages {summary.packages.toLocaleString()} · stale scans {summary.stale.toLocaleString()} (older than 7 days)</p>}
          <p>Metrics cover all image scans matching the server filters. Image scan results are shared evidence; exposure is scoped to this cluster. Matching CSV includes fixed inventory columns across all pages (up to 100,000 records); the page CSV follows visible columns.</p>
        </div>} />
      {q.isFetching && q.isSuccess && <p role="status" className="text-sm text-muted-foreground">Refreshing scan inventory…</p>}
      {matching.status}
      {!validFilters && <ErrorState title="The requested server filter or sort is invalid. Choose a listed value to recover." action={<Button onClick={() => route.update({ sort: null, order: null, severity: null })}>Reset filters and sort</Button>} />}
      {available && selectedID && !selected && <ErrorState title="The selected record is unavailable on this page or hidden by its filters." action={<Button onClick={() => setSelectedID(null)}>Clear selection</Button>} />}
      <section className="flex flex-col gap-4">
        <div data-testid={available ? "image-scans-table" : "image-scans-table-loading"}>
          {validFilters && (q.isError || invalid) ? <InventoryLoadState label="Image scans" query={q} invalid={invalid} debouncing={route.debouncing} /> : validFilters ? <DataTable
            rows={filtered}
            pagination={false}
            manualSorting
            sort={{ id: sort, dir: order as "asc" | "desc" }}
            onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })}
            preferencesKey="image-scan-results-inventory"
            toolbar={toolbar}
            exportOptions={[matching.option]}
            exportFileName="constellation-image-scan-results-server-page"
            exportLabel="This page"
            columns={columns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={new Set(selected ? [selected.id] : [])}
            emptyState={!available ? <InventoryLoadState label="Image scans" query={q} invalid={invalid} debouncing={route.debouncing} /> :
              <div className="px-3 py-8 text-center text-sm text-muted-foreground">No image scans match the current filters.</div>
            }
          /> : null}
        </div>
        {available && <ScanInventoryContinuation total={q.data?.total} page={route.page} rows={results.length} matching={filtered.length} hasMore={hasMore} onPage={route.setPage} />}
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
            Full details
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
          <Field label="Scanner profile" value={item.scanner_profile} />
          <Field label="Source" value={sourceLabel(item)} />
          <Field label="Source reference" value={<Collapse label="Source reference"><code className="break-all text-xs">{item.source_ref || "-"}</code></Collapse>} />
          {item.vulndb_bundle_version && <Field label="VulnDB bundle" value={item.vulndb_bundle_version} />}
          {item.vulndb_bundle_hash && <Field label="Bundle hash" value={<DigestDisclosure digest={item.vulndb_bundle_hash} />} />}
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
  if (item.source_type === "repository") return <Pill tone="accent">Repository scan</Pill>;
  return isLocalImage(item) ? <Pill tone="warn">Local image</Pill> : <Pill tone="neutral">Registry image</Pill>;
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
    <div className={cn("rounded-md border border-border p-2")}>
      <div className="text-micro text-muted-foreground">{label}</div>
      <div className={cn("mt-1 text-lg font-semibold tabular-nums", tone === "danger" && value > 0 && "text-severity-critical", tone === "warn" && value > 0 && "text-severity-high")}>{value}</div>
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
        "inline-flex h-5 items-center rounded-full border border-border px-2 text-micro font-medium",
        tone === "neutral" && "text-muted-foreground",
        tone === "accent" && "text-foreground",
        tone === "warn" && "text-status-warning",
        tone === "danger" && "text-severity-critical",
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
