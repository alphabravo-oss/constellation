import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Boxes, Clock3, Database, PackageSearch, Search, ShieldAlert } from "lucide-react";

import { imageScanResults, type ImageScanResult } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";

const severities = ["all", "critical", "high", "medium", "low", "info"];

export function ImageScansPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [selectedID, setSelectedID] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["image-scan-results", clusterId],
    queryFn: () => imageScanResults.list({ cluster_id: clusterId, limit: 500 }),
    enabled: !!clusterId,
  });

  const results = useMemo(() => q.data?.image_scan_results ?? [], [q.data?.image_scan_results]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return results.filter((item) => {
      if (severity !== "all" && (item.severity_counts?.[severity] ?? 0) === 0) return false;
      if (!needle) return true;
      return [
        item.image_ref,
        item.image_ref_normalized,
        item.image_repository,
        item.image_tag ?? "",
        item.image_digest,
        item.platform ?? "",
        item.scanner_profile,
        item.source_type ?? "",
        item.source_ref ?? "",
        item.vulndb_bundle_version ?? "",
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [query, results, severity]);
  const selected = filtered.find((item) => item.id === selectedID) ?? filtered[0] ?? null;
  const summary = useMemo(() => summarize(results), [results]);

  const columns: Column<ImageScanResult>[] = [
    {
      id: "image",
      header: "Image",
      cell: (item) => (
        <>
          <div className="flex flex-wrap items-center gap-1.5">
            <ImageKindBadge item={item} />
            {item.impacted_count > 0 ? <Pill tone="accent">running workload</Pill> : null}
            {isStale(item.last_scanned_at) ? <Pill tone="warn">stale scan</Pill> : null}
          </div>
          <Link to={`/clusters/${clusterId}/images/${item.id}`} className="mt-2 block break-all font-mono text-xs font-medium hover:underline">
            {displayImage(item)}
          </Link>
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.image_digest}</div>
        </>
      ),
    },
    {
      id: "risk",
      header: "Risk",
      cell: (item) => <RiskStack item={item} />,
    },
    {
      id: "exposure",
      header: "Exposure",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.impacted_count} workload{item.impacted_count === 1 ? "" : "s"}</div>
          <div className="mt-1 text-muted-foreground">{item.package_count} packages</div>
        </div>
      ),
    },
    {
      id: "scan",
      header: "Scan",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.scanner_profile}</div>
          <div className="mt-1 text-muted-foreground">{formatDate(item.last_scanned_at)}</div>
          <div className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{item.vulndb_bundle_version || "bundle unknown"}</div>
        </div>
      ),
    },
  ];

  if (clusterLoading) return <p className="text-sm text-muted-foreground">Loading cluster...</p>;

  return (
    <div className="space-y-4" data-testid="image-scans-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Images"
        description="Every scanned container image and the running workloads exposed to its vulnerabilities."
        actions={
          <Link
            to={selected ? `/clusters/${clusterId}/images/${selected.id}` : `/clusters/${clusterId}/images`}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
              !selected && "pointer-events-none opacity-50",
            )}
          >
            <PackageSearch className="h-4 w-4" aria-hidden />
            Open Image Scan
          </Link>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4" data-testid="image-scan-summary">
        <StatCard label="Images" value={summary.total.toLocaleString()} icon={<Boxes className="h-3.5 w-3.5" />} hint={`${summary.exposed} running · ${summary.local} local`} />
        <StatCard label="Critical / High" value={summary.criticalHigh.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.criticalHigh > 0 ? "high" : "neutral"} hint={`${summary.findings} image findings`} />
        <StatCard label="Packages" value={summary.packages.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} hint={`${summary.bundles} VulnDB bundles`} />
        <StatCard label="Stale Scans" value={summary.stale.toLocaleString()} icon={<Clock3 className="h-3.5 w-3.5" />} tone={summary.stale > 0 ? "medium" : "neutral"} hint="older than 7 days" />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search repository, digest, platform, bundle"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="image-scan-search"
            />
          </label>
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="image-scan-severity-filter"
          >
            {severities.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All severities" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <div data-testid="image-scans-table">
          <DataTable
            rows={filtered}
            columns={columns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={new Set(selected ? [selected.id] : [])}
            showDensityToggle={false}
            emptyState={
              <div className="px-3 py-8 text-center text-xs text-muted-foreground">
                {q.isPending ? "Loading image scans..." : "No image scans match the current filters."}
              </div>
            }
          />
        </div>

        <ImagePreview item={selected} clusterId={clusterId} />
      </section>
    </div>
  );
}

function ImagePreview({ item, clusterId }: { item: ImageScanResult | null; clusterId?: string }) {
  if (!item) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="image-scan-preview">
        <h2 className="text-sm font-semibold">Image scan inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select an image to inspect scan freshness, exposure, and VulnDB provenance.</p>
      </aside>
    );
  }
  return (
    <aside className="space-y-4" data-testid="image-scan-preview">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <ImageKindBadge item={item} />
            <h2 className="mt-2 break-all font-mono text-sm font-semibold">{displayImage(item)}</h2>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.image_digest}</p>
          </div>
          <Link to={`/clusters/${clusterId}/images/${item.id}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
            Full Details
          </Link>
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
          <Field label="Repository" value={item.image_repository || "-"} />
          <Field label="Tag" value={item.image_tag || "-"} />
          <Field label="Platform" value={item.platform || "-"} />
          <Field label="Scanner Profile" value={item.scanner_profile} />
          <Field label="Source" value={sourceLabel(item)} />
          <Field label="Source Ref" value={item.source_ref || "-"} />
          <Field label="VulnDB Bundle" value={item.vulndb_bundle_version || "-"} />
          <Field label="Bundle Hash" value={item.vulndb_bundle_hash || "-"} />
        </dl>
      </div>
    </aside>
  );
}

function summarize(items: ImageScanResult[]) {
  const bundles = new Set(items.map((item) => item.vulndb_bundle_hash || item.vulndb_bundle_version).filter(Boolean));
  return {
    total: items.length,
    exposed: items.filter((item) => item.impacted_count > 0).length,
    local: items.filter(isLocalImage).length,
    criticalHigh: items.reduce((sum, item) => sum + item.critical_count + item.high_count, 0),
    findings: items.reduce((sum, item) => sum + item.finding_count, 0),
    packages: items.reduce((sum, item) => sum + item.package_count, 0),
    stale: items.filter((item) => isStale(item.last_scanned_at)).length,
    bundles: bundles.size,
  };
}

function displayImage(item: ImageScanResult): string {
  if (item.image_repository && item.image_tag) return `${item.image_repository}:${item.image_tag}`;
  if (item.image_repository && item.image_repository !== item.image_digest) return item.image_repository;
  return item.image_ref || item.image_digest;
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
      <div className="flex flex-wrap gap-1">
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
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
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
        "inline-flex h-5 items-center rounded px-1.5 text-[10px] font-medium",
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
