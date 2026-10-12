import { type DeploymentNetworkFlow } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorState } from "@/components/ui/states";
import { StatusPill } from "@/components/ui/status-pill";
import { EvidenceUnavailable } from "./EvidenceUnavailable";
import { type RiskTabProps } from "./workspace";

export default function NetworkTab({ workspace }: RiskTabProps) {
  const { entity, clusterId } = workspace;
  const root = `/clusters/${clusterId}/network`;
  if (entity?.type !== "deployment") return <div className="space-y-3" data-testid="risk-network-tab"><EvidenceUnavailable workspace={workspace} evidence="Network" /><a href={`${root}?tab=conversations&hours=24`} className="text-sm text-primary hover:underline">Open cluster network context · last 24 hours</a></div>;
  if (entity.data.network_flows?.some(row => row.cluster_id && row.cluster_id !== clusterId)) return <ErrorState title="Embedded network flows do not match this cluster." />;
  const rows = (entity.data.network_flows ?? []).map((row, index) => ({ ...row, _key: `${row.id}-${index}` }));
  const columns: Column<DeploymentNetworkFlow>[] = [
    { id: "from", header: "From", kind: "name", wrap: true, code: true, cell: row => row.src, exportValue: row => row.src },
    { id: "to", header: "To", kind: "text", wrap: true, code: true, cell: row => `${row.dst}:${row.dst_port ?? "—"}`, exportValue: row => `${row.dst}:${row.dst_port ?? ""}` },
    { id: "src_platform_role", header: "From role", kind: "status", size: 144, minSize: 128, maxSize: 176, exportHeader: "src_platform_role", exportValue: row => row.src_platform_role ?? "", cell: row => <StatusPill label={row.src_platform_role || "Not classified"} tone={row.src_platform_role ? "info" : "neutral"} uppercase={false} /> },
    { id: "dst_platform_role", header: "To role", kind: "status", size: 144, minSize: 128, maxSize: 176, exportHeader: "dst_platform_role", exportValue: row => row.dst_platform_role ?? "", cell: row => <StatusPill label={row.dst_platform_role || "Not classified"} tone={row.dst_platform_role ? "info" : "neutral"} uppercase={false} /> },
    { id: "protocol", header: "Protocol", kind: "status", cell: row => row.protocol, exportValue: row => row.protocol },
    { id: "verdict", header: "Verdict", kind: "status", cell: row => row.verdict, exportValue: row => row.verdict },
    { id: "observed", header: "Last observed", kind: "date", wrap: true, cell: row => row.last_seen_at, exportValue: row => row.last_seen_at },
    { id: "pivot", header: "Conversation context", kind: "actions", size: 160, minSize: 144, maxSize: 176, cell: row => <a href={`${root}?${new URLSearchParams({ tab: "conversations", hours: "24", from: row.src, to: row.dst, hide_platform: "false" })}`} className="text-primary hover:underline">Exact pair · 24h</a>, exportable: false },
  ];
  return <div className="space-y-3" data-testid="risk-network-tab"><p className="text-sm text-muted-foreground">At most 50 network flows returned for this deployment’s resolved owned workloads, ordered by last observation. Pair links open exact directed endpoints in the cluster’s 24-hour conversation view.</p><DataTable rows={rows} columns={columns} rowKey={row => row._key} preferencesKey="risk-deployment-network" exportFileName="risk-returned-deployment-network" sourceLimit={50} sourceCount={rows.length} emptyState={<p className="p-4 text-sm text-muted-foreground">No network flows in returned deployment evidence. This does not establish network coverage.</p>} /></div>;
}
