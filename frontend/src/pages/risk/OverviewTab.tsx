import { findingHref, findingRowKey } from "@/lib/finding-instance";
import { useRouteSearchParams } from "@/lib/route-search";
import { Collapse } from "@/components/ui/collapse";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { detailPath, type RiskTabProps, type RiskFinding } from "./workspace";

export default function OverviewTab({ workspace }: RiskTabProps) {
  const { entity, records, query, clusterId } = workspace;
  const [params] = useRouteSearchParams();
  const findingsParams = new URLSearchParams(params); findingsParams.set("tab", "findings");
  if (!entity) return null;
  const factors = entity.type === "finding" ? entity.data.risk?.factors : undefined;
  const top = records.slice().sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);
  const columns: Column<RiskFinding>[] = [
    { id: "finding", header: "Finding", kind: "name", wrap: true, cell: row => entity.type === "deployment" ? row.title : <a href={findingHref({ ...row, first_seen_at: row.first_seen_at ?? "" }, clusterId)} className="hover:underline">{row.title}</a> },
    { id: "severity", header: "Severity", kind: "status", cell: row => <SeverityBadge severity={row.severity} /> },
    { id: "risk", header: "Reported risk", kind: "count", numeric: true, cell: row => row.risk_score },
  ];
  return <div className="space-y-5" data-testid="risk-overview-tab">
    <section className="space-y-3 rounded-md border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Evidence scope</h2>
      {entity.type === "asset" && <p className="text-sm text-muted-foreground">{entity.data.asset.kind} asset · {entity.data.asset.criticality} configured criticality. Generic finding counts use this asset’s exact ID and selected cluster. Canonical image findings are separate scan evidence.</p>}
      {entity.type === "deployment" && <p className="text-sm text-muted-foreground">{entity.data.namespace}/{entity.data.name} · {entity.data.kind}. The deployment API resolves owned workload IDs before returning network, runtime, file and compliance evidence. Inventory risk and counts are reported values, separate from bounded detail samples.</p>}
      {entity.type === "node" && <><p className="text-sm text-muted-foreground">Host inventory and vulnerability evidence belong to the exact cluster and node name. Scan status: {entity.data.node.scan_status || "Not reported"}. Agent status: {entity.data.node.runtime_agent_status || "Not reported"}.</p>{!!entity.data.node.coverage_gaps?.length && <p className="text-sm text-muted-foreground">Reported coverage gaps: {entity.data.node.coverage_gaps.join(", ")}</p>}</>}
      {entity.type === "finding" && <p className="text-sm text-muted-foreground">{entity.data.kind} · {entity.data.lifecycle}. This workspace describes one finding and its server-reported risk decomposition.</p>}
    </section>
    {factors?.length ? <section className="space-y-3 rounded-md border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Reported risk subfactors</h2>
      {factors.map((factor, index) => <div key={`${factor.name}-${index}`} data-testid={`risk-subfactor-${factor.name}`} className="space-y-1">
        <div className="flex flex-wrap justify-between gap-2 text-sm"><span>{factor.name}</span><span>{factor.score} weighted points · {factor.raw}/100 raw · {Math.round(factor.weight * 100)}% weight</span></div>
        <p className="text-xs text-muted-foreground">{factor.description}</p>
      </div>)}
    </section> : entity.type === "deployment" && Object.keys(entity.data.risk_factors ?? {}).length > 0 ? <section className="space-y-3 rounded-md border border-border bg-card p-4"><h2 className="text-sm font-semibold">Reported deployment risk factors</h2><dl className="grid gap-3 sm:grid-cols-2">{Object.entries(entity.data.risk_factors).map(([label, value]) => <div key={label} className="flex justify-between gap-3 text-sm"><dt>{label}</dt><dd>{value}</dd></div>)}</dl></section> : <p className="text-sm text-muted-foreground">No risk subfactor breakdown is reported for this entity.</p>}
    {entity.type !== "node" && <section className="space-y-3">
      <h2 className="text-sm font-semibold">Highest-risk findings in the returned evidence</h2>
      <p className="text-xs text-muted-foreground">{entity.type === "asset" ? "Top five from the current server page of generic findings. Canonical image findings are available in the Findings tab." : entity.type === "deployment" ? "Top five from at most 100 open workload findings returned by deployment detail. This is a bounded source sample." : "The selected finding only."}</p>
      {entity.type === "asset" && workspace.invalidPage ? <ErrorState title="This finding page cannot be queried safely." action={<Button onClick={() => workspace.setPage(0)}>Return to first page</Button>} /> : entity.type === "asset" && workspace.findingScopeMismatch ? <ErrorState title="Finding evidence does not match this asset and cluster." /> : entity.type === "asset" && query.isError ? <ErrorState title="Could not load asset finding evidence." action={<Button onClick={() => void query.refetch()}>Retry</Button>} /> : entity.type === "asset" && query.isPending ? <LoadingState label="Loading asset finding evidence…" /> : <DataTable rows={top} columns={columns} rowKey={row => entity.type === "deployment" ? `${row.id}:${top.indexOf(row)}` : findingRowKey({ ...row, first_seen_at: row.first_seen_at ?? "" })} showDensityToggle={false} pagination={false} testId="risk-top-findings" emptyState={<p className="p-4 text-sm text-muted-foreground">No findings in this returned evidence. This does not establish complete coverage.</p>} />}
    </section>}
    {entity.type === "deployment" && <a href={`?${findingsParams.toString()}`} className="text-sm text-primary hover:underline">Browse workload findings</a>}
    <Collapse label="Advanced: entity identity and source metadata"><dl className="grid gap-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Cluster ID</dt><dd className="break-all font-mono">{clusterId}</dd></div><div><dt className="text-muted-foreground">Entity ID</dt><dd className="break-all font-mono">{workspace.entityId}</dd></div></dl></Collapse>
    <a href={detailPath(workspace)} className="text-sm text-primary hover:underline">Review complete entity detail and its supported actions</a>
  </div>;
}
