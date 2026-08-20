// RegistryImagesPage — drill-in from the registry list to its scanned image inventory,
// correlated with vulnerability scan results. Closes the "registries are a dead-end list"
// gap (the /registries/{id}/images endpoint existed but nothing navigated to it).
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, Boxes } from "lucide-react";

import { registries, type RegistryImageRow } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { fmtRelative } from "@/lib/format";

export function RegistryImagesPage() {
  const { regId } = useParams<{ regId: string }>();
  const { clusterId } = useCluster();
  const reg = useQuery({ queryKey: ["registry", regId], queryFn: () => registries.get(regId!), enabled: !!regId });
  const imgs = useQuery({ queryKey: ["registry-images", regId], queryFn: () => registries.images(regId!), enabled: !!regId });
  const rows = imgs.data ?? [];
  const scanned = rows.filter((r) => r.scanned).length;
  const totalCrit = rows.reduce((s, r) => s + (r.critical ?? 0), 0);
  const totalHigh = rows.reduce((s, r) => s + (r.high ?? 0), 0);

  const columns: Column<RegistryImageRow>[] = [
    { id: "repo", header: "Repository", cell: (r) => <span className="text-xs font-medium">{r.repository}</span>, sort: (a, b) => a.repository.localeCompare(b.repository) },
    { id: "tags", header: "Tags", cell: (r) => <span className="text-mono text-[11px] text-muted-foreground max-w-[220px] truncate block" title={r.tags.join(", ")}>{r.tags.slice(0, 4).join(", ") || "—"}</span> },
    { id: "scanned", header: "Scan", width: "96px", cell: (r) => (
        r.scanned
          ? <span className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-[color-mix(in_oklab,var(--color-severity-low)_16%,transparent)] text-[color:var(--color-severity-low)]">scanned</span>
          : <span className="rounded px-1.5 py-0.5 text-[10px] font-medium bg-muted text-muted-foreground">not scanned</span>
      ), sort: (a, b) => Number(a.scanned) - Number(b.scanned) },
    { id: "vulns", header: "Vulnerabilities", numeric: true, cell: (r) => (
        (r.critical ?? 0) + (r.high ?? 0) === 0
          ? <span className="text-[11px] text-muted-foreground">{r.scanned ? "no crit/high" : "—"}</span>
          : <span className="flex items-center justify-end gap-1">
              {r.critical > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-critical)" }}>{r.critical}C</span>}
              {r.high > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-high)" }}>{r.high}H</span>}
            </span>
      ), sort: (a, b) => (b.critical * 1000 + b.high) - (a.critical * 1000 + a.high) },
    { id: "findings", header: "Findings", numeric: true, width: "90px", cell: (r) => <span className="text-mono text-xs">{r.finding_count || "—"}</span>, sort: (a, b) => (a.finding_count ?? 0) - (b.finding_count ?? 0) },
    { id: "pushed", header: "Last pushed", numeric: true, width: "120px", cell: (r) => <span className="text-[10px] text-muted-foreground">{r.last_pushed_at ? fmtRelative(r.last_pushed_at) : "—"}</span> },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        backLink={<Link to={clusterId ? `/clusters/${clusterId}/registries` : "/registries"} className="inline-flex items-center gap-1 hover:text-foreground"><ChevronLeft className="h-3.5 w-3.5" />Registries</Link>}
        title={reg.data?.name || "Registry images"}
        description="Image inventory discovered in this registry, correlated with vulnerability scan results."
      />
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Images" value={rows.length} icon={<Boxes className="h-3.5 w-3.5" />} />
        <StatCard label="Scanned" value={scanned} tone={scanned < rows.length ? "medium" : "low"} hint={`${rows.length - scanned} unscanned`} />
        <StatCard label="Critical" value={totalCrit} tone={totalCrit > 0 ? "critical" : "neutral"} />
        <StatCard label="High" value={totalHigh} tone={totalHigh > 0 ? "high" : "neutral"} />
      </section>
      {imgs.isPending ? (
        <p className="text-sm text-muted-foreground">Loading images…</p>
      ) : rows.length === 0 ? (
        <EmptyState title="No images discovered" hint="Run a registry sync to populate the image inventory." />
      ) : (
        <DataTable rows={rows} columns={columns} rowKey={(r) => r.id} defaultSort={{ id: "vulns", dir: "desc" }} />
      )}
    </div>
  );
}
