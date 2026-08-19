import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { findings, type Finding } from "@/api/client";
import { severityBg, SEVERITY_RANK } from "@/lib/severity";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";

export default function FindingsTab({ entityType, entityId }: { entityType: string; entityId: string }) {
  const { clusterId } = useCluster();
  // For asset entity, server-side filter by asset_id is handled in the asset detail
  // endpoint; here we use a search-q filter that the DSL understands.
  const q = useQuery({
    queryKey: ["risk-findings", entityType, entityId],
    queryFn: () => findings.list({ limit: 200 }),
    enabled: !!entityId,
  });

  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading…</p>;
  const list: Finding[] = (q.data?.findings ?? []).filter((f) =>
    entityType === "asset" ? f.asset_id === entityId : true,
  );

  const columns: Column<Finding>[] = [
    {
      id: "risk",
      header: "Risk",
      cell: (f) => <span className="font-mono text-xs">{f.risk_score}</span>,
      sort: (a, b) => a.risk_score - b.risk_score,
    },
    {
      id: "severity",
      header: "Severity",
      cell: (f) => <span className={`rounded-md px-2 py-0.5 text-xs ${severityBg[f.severity]}`}>{f.severity}</span>,
      sort: (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
    },
    {
      id: "title",
      header: "Title",
      cell: (f) => (
        <Link to={clusterId ? `/clusters/${clusterId}/findings/${f.id}` : `/findings/${f.id}`} className="hover:underline">{f.title}</Link>
      ),
      sort: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: "kind",
      header: "Kind",
      cell: (f) => <span className="text-xs text-muted-foreground">{f.kind}</span>,
      sort: (a, b) => a.kind.localeCompare(b.kind),
    },
  ];

  return (
    <div data-testid="risk-findings-table">
      <DataTable
        rows={list}
        columns={columns}
        rowKey={(f) => f.id}
        showDensityToggle={false}
        emptyState={<div className="px-3 py-6 text-center text-xs text-muted-foreground">No related findings.</div>}
      />
    </div>
  );
}
