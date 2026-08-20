import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { BadgeCheck, Boxes, FileJson, Search, ShieldAlert, ShieldCheck } from "lucide-react";

import { assets, type Asset } from "@/api/client";
import { cn } from "@/lib/cn";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { downloadCsv } from "@/lib/csv";
import { StatCard } from "@/components/ui/stat-card";

const kinds = ["all", "image", "workload", "iac-resource", "ml-model", "cloud-resource"];
const criticalities = ["all", "critical", "high", "medium", "low"];

export function AssetsPage() {
  // Cluster-scoped: only show assets belonging to the active cluster. Assets
  // with NULL cluster_id (org-wide registry pulls, ML models, IaC files) are
  // omitted in cluster mode by design — they live in a future org-level inventory
  // surface, not under a specific cluster's posture pane.
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [kind, setKind] = useState("all");
  const [criticality, setCriticality] = useState("all");
  const [search, setSearch] = useState("");
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const q = useQuery({
    queryKey: ["assets", clusterId],
    queryFn: () => assets.list({ limit: 250, cluster_id: clusterId }),
  });

  const inventory = useMemo(() => q.data?.assets ?? [], [q.data?.assets]);
  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return inventory.filter((asset) => {
      if (kind !== "all" && asset.kind !== kind) return false;
      if (criticality !== "all" && asset.criticality !== criticality) return false;
      if (!needle) return true;
      return [
        asset.name,
        asset.kind,
        asset.digest ?? "",
        asset.registry ?? "",
        asset.repository ?? "",
        asset.tag ?? "",
        ...Object.values(asset.labels ?? {}),
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [criticality, inventory, kind, search]);
  const selected = filtered.find((asset) => asset.id === selectedID) ?? filtered[0] ?? null;
  const summary = useMemo(() => summarizeAssets(inventory), [inventory]);

  const columns: Column<Asset>[] = [
    {
      id: "asset",
      header: "Asset",
      cell: (asset) => (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <KindBadge kind={asset.kind} />
            {asset.ai_workload ? <span className="rounded-md bg-primary/10 px-2 py-0.5 text-xs text-primary">AI</span> : null}
          </div>
          <Link to={`/clusters/${clusterId}/assets/${asset.id}`} className="mt-2 block break-all font-mono text-xs font-medium hover:underline">
            {asset.name}
          </Link>
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{asset.digest ?? asset.repository ?? "-"}</div>
        </>
      ),
    },
    { id: "risk", header: "Risk", cell: (asset) => <RiskStack asset={asset} /> },
    { id: "supply-chain", header: "Supply Chain", cell: (asset) => <SupplyChainStack asset={asset} /> },
    { id: "criticality", header: "Criticality", cell: (asset) => <span className="text-xs">{asset.criticality}</span> },
    { id: "last-seen", header: "Last Seen", cell: (asset) => <span className="text-xs text-muted-foreground">{formatDate(asset.last_seen_at)}</span> },
  ];

  if (clusterLoading) {
    return <p className="text-sm text-muted-foreground" data-testid="assets-loading">Loading cluster…</p>;
  }

  return (
    <div className="space-y-4" data-testid="assets-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Assets"
        description="Risk-ranked inventory across images, workloads, IaC, ML, and cloud resources."
        actions={
          <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => downloadCsv("constellation-assets", ["Name", "Kind", "Criticality", "OpenFindings", "Critical", "High", "Signed", "SBOMs", "Registry", "Tag", "LastSeen"],
              filtered.map((a) => [a.name, a.kind, a.criticality, a.open_findings, a.critical_findings, a.high_findings, a.image_signed ? "yes" : "", a.sbom_count, a.registry ?? "", a.tag ?? "", a.last_seen_at]))}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent"
          >Export CSV</button>
          <Link
            to={selected ? `/clusters/${clusterId}/assets/${selected.id}` : `/clusters/${clusterId}/assets`}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
              !selected && "pointer-events-none opacity-50",
            )}
          >
            <Boxes className="h-4 w-4" aria-hidden />
            Open Full Asset
          </Link>
          </div>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4" data-testid="assets-summary">
        <StatCard label="Assets" value={summary.total.toLocaleString()} icon={<Boxes className="h-3.5 w-3.5" />} hint={`${summary.images} images · ${summary.workloads} workloads`} />
        <StatCard label="Critical / High" value={summary.criticalHigh.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.criticalHigh > 0 ? "high" : "neutral"} hint={`${summary.openFindings} open findings`} />
        <StatCard label="Unsigned Images" value={summary.unsignedImages.toLocaleString()} icon={<BadgeCheck className="h-3.5 w-3.5" />} tone={summary.unsignedImages > 0 ? "medium" : "neutral"} hint={`${summary.signedImages} signed`} />
        <StatCard label="Missing SBOM" value={summary.missingSBOM.toLocaleString()} icon={<FileJson className="h-3.5 w-3.5" />} hint={`${summary.withSBOM} with SBOM evidence`} />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search asset, registry, digest, label"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="asset-search"
            />
          </label>
          <select
            value={kind}
            onChange={(event) => setKind(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="asset-kind-filter"
          >
            {kinds.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All kinds" : item}</option>
            ))}
          </select>
          <select
            value={criticality}
            onChange={(event) => setCriticality(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="asset-criticality-filter"
          >
            {criticalities.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All criticality" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <DataTable
          rows={filtered}
          columns={columns}
          rowKey={(asset) => asset.id}
          onRowClick={(asset) => setSelectedID(asset.id)}
          selected={new Set(selected ? [selected.id] : [])}
          showDensityToggle={false}
          testId="assets-table"
          rowTestId={() => "asset-row"}
          emptyState={
            <div className="px-3 py-8 text-center text-xs text-muted-foreground">
              {q.isPending ? "Loading assets..." : "No assets match the current filters."}
            </div>
          }
        />

        <AssetPreview asset={selected} clusterId={clusterId} />
      </section>
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
            <Link to={`/clusters/${clusterId}/risk/asset/${encodeURIComponent(asset.id)}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent" data-testid="asset-risk-workspace-link">
              Risk workspace
            </Link>
            <Link to={`/clusters/${clusterId}/assets/${asset.id}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
              Full Details
            </Link>
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
          <Field label="Signature" value={asset.kind === "image" ? (asset.image_signed ? "signed" : "unsigned") : "not an image"} />
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
          {asset.kind === "image" ? (signed ? "signed" : "unsigned") : "n/a"}
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

function summarizeAssets(items: Asset[]) {
  return items.reduce(
    (acc, asset) => {
      acc.total += 1;
      if (asset.kind === "image") acc.images += 1;
      if (asset.kind === "workload") acc.workloads += 1;
      acc.criticalHigh += asset.critical_findings + asset.high_findings;
      acc.openFindings += asset.open_findings;
      if (asset.kind === "image" && asset.image_signed) acc.signedImages += 1;
      if (asset.kind === "image" && asset.image_signed === false) acc.unsignedImages += 1;
      if (asset.sbom_count > 0) acc.withSBOM += 1;
      if (asset.kind === "image" && asset.sbom_count === 0) acc.missingSBOM += 1;
      return acc;
    },
    { total: 0, images: 0, workloads: 0, criticalHigh: 0, openFindings: 0, signedImages: 0, unsignedImages: 0, withSBOM: 0, missingSBOM: 0 },
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
