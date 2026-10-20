import { DataTable, type Column } from "@/components/ui/data-table";
import { StatusPill } from "@/components/ui/status-pill";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState } from "@/components/ui/states";
import { type RuntimeEvent } from "@/api/client";
import { EvidenceUnavailable } from "./EvidenceUnavailable";
import { recordRows, type RiskTabProps } from "./workspace";

export default function ProcessTab({ workspace }: RiskTabProps) {
  const { entity, clusterId } = workspace;
  if (entity?.type === "node") {
    const rows = recordRows(entity.data.processes, "items");
    const columns: Column<Record<string, unknown>>[] = [
      { id: "pid", header: "PID", kind: "count", numeric: true, cell: row => String(row.pid ?? "—"), exportValue: row => String(row.pid ?? "") },
      { id: "name", header: "Process", kind: "name", wrap: true, code: true, cell: row => String(row.comm ?? "Not reported"), exportValue: row => String(row.comm ?? "") },
      { id: "command", header: "Command line", kind: "text", wrap: true, grow: true, code: true, cell: row => String(row.cmdline ?? "Not reported"), exportValue: row => String(row.cmdline ?? "") },
      { id: "user", header: "User ID", kind: "count", numeric: true, cell: row => String(row.uid ?? "—"), exportValue: row => String(row.uid ?? "") },
    ];
    return <div className="space-y-3" data-testid="risk-process-tab"><p className="text-sm text-muted-foreground">Host process inventory reported for this exact node. Observed: {entity.data.node.processes_observed_at || "Not collected"}.</p>{entity.data.processes && rows === undefined ? <ErrorState title="Host process inventory has an unsupported response shape." /> : <DataTable rows={(rows ?? []).map((row, index) => ({ ...row, _key: index }))} columns={columns} rowKey={row => row._key} preferencesKey="risk-node-processes" exportFileName="risk-returned-node-processes" emptyState={<p className="p-4 text-sm text-muted-foreground">No process inventory returned. This is not a clean runtime assessment.</p>} />}</div>;
  }
  if (entity?.type !== "deployment") return <div className="space-y-3" data-testid="risk-process-tab"><EvidenceUnavailable workspace={workspace} evidence="Process" /><a href={`/clusters/${clusterId}/runtime?tab=evidence&hours=24`} className="text-sm text-link">Open cluster runtime evidence · last 24 hours</a></div>;
  const baseline = entity.data.process_baseline;
  const processes = (baseline?.processes ?? []).map((row, index) => ({ ...row, _key: index }));
  type ProcessRow = typeof processes[number];
  const processColumns: Column<ProcessRow>[] = [
    { id: "name", header: "Process", kind: "name", wrap: true, code: true, cell: row => row.name, exportValue: row => row.name },
    { id: "path", header: "Path", kind: "text", wrap: true, code: true, cell: row => row.path, exportValue: row => row.path },
    { id: "args", header: "Arguments", kind: "text", wrap: true, grow: true, code: true, cell: row => row.args?.join(" ") || "Not reported", exportValue: row => row.args?.join(" ") },
    { id: "count", header: "Observed", kind: "count", numeric: true, cell: row => row.observed_count, exportValue: row => row.observed_count },
  ];
  const eventColumns: Column<RuntimeEvent>[] = [
    { id: "kind", header: "Event", kind: "name", wrap: true, cell: row => row.kind, exportValue: row => row.kind },
    { id: "workload", header: "Workload", kind: "text", wrap: true, code: true, cell: row => row.workload_id, exportValue: row => row.workload_id },
    { id: "platform_role", header: "Platform role", kind: "status", size: 144, minSize: 128, maxSize: 176, exportHeader: "platform_role", exportValue: row => row.platform_role ?? "", cell: row => <StatusPill label={row.platform_role || "Not classified"} tone={row.platform_role ? "info" : "neutral"} uppercase={false} /> },
    { id: "cluster_id", header: "Cluster", kind: "id", exportHeader: "cluster_id", cell: row => row.cluster_id || "Not reported", exportValue: row => row.cluster_id ?? "" },
    { id: "severity", header: "Severity", kind: "status", cell: row => row.severity, exportValue: row => row.severity },
    { id: "verdict", header: "Verdict", kind: "status", cell: row => row.verdict, exportValue: row => row.verdict },
    { id: "at", header: "Observed", kind: "date", wrap: true, cell: row => row.at, exportValue: row => row.at },
  ];
  const events = (entity.data.runtime_events ?? []).map((row, index) => ({ ...row, _key: `${row.id}-${index}` }));
  return <div className="space-y-5" data-testid="risk-process-tab"><section className="space-y-3"><h2 className="text-sm font-semibold">Reported process baseline</h2>{baseline?.cluster_id && baseline.cluster_id !== clusterId ? <ErrorState title="Process baseline does not match this cluster." /> : <><p className="text-sm text-muted-foreground">Mode: {baseline?.mode || "Not reported"} · {processes.length} returned process entries. These are observations, not proof of enforcement.</p><DataTable rows={processes} columns={processColumns} rowKey={row => row._key} preferencesKey="risk-deployment-processes" exportFileName="risk-returned-deployment-processes" emptyState={<p className="p-4 text-sm text-muted-foreground">No process baseline evidence returned.</p>} /><Collapse label="Advanced: reported process posture"><dl className="grid gap-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Reported learned processes</dt><dd>{baseline?.learned_processes_count ?? "Not reported"}</dd></div><div><dt className="text-muted-foreground">Reported alerts · 24h</dt><dd>{baseline?.monitored_alerts_24h ?? "Not reported"}</dd></div><div><dt className="text-muted-foreground">Reported blocks · 24h</dt><dd>{baseline?.enforced_blocks_24h ?? "Not reported"}</dd></div><div><dt className="text-muted-foreground">Last new process</dt><dd>{baseline?.last_new_process_at || "Not reported"}</dd></div></dl></Collapse></>}</section><section className="space-y-3"><h2 className="text-sm font-semibold">Recent runtime evidence</h2><p className="text-xs text-muted-foreground">Latest 50 events for this deployment’s owned workloads. No 24-hour time bound is applied by this source.</p>{events.some(event => event.cluster_id && event.cluster_id !== clusterId) ? <ErrorState title="Embedded runtime events do not match this cluster." /> : <DataTable rows={events} columns={eventColumns} rowKey={row => row._key} preferencesKey="risk-deployment-runtime" exportFileName="risk-returned-deployment-runtime" sourceLimit={50} sourceCount={events.length} emptyState={<p className="p-4 text-sm text-muted-foreground">No runtime events in returned evidence. This does not establish complete runtime coverage.</p>} />}</section></div>;
}
