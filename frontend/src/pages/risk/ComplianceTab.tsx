import { type DeploymentComplianceEvidence } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ErrorState } from "@/components/ui/states";
import { EvidenceUnavailable } from "./EvidenceUnavailable";
import { recordRows, type RiskTabProps } from "./workspace";

export default function ComplianceTab({ workspace }: RiskTabProps) {
  const { entity, clusterId } = workspace;
  const link = <a href={`/clusters/${clusterId}/compliance`} className="text-sm text-link">Open cluster compliance context</a>;
  if (entity?.type === "node") {
    const rows = recordRows(entity.data.cis, "checks");
    const columns: Column<Record<string, unknown>>[] = [
      { id: "control", header: "Control", kind: "id", wrap: true, cell: row => String(row.id ?? "Not reported"), exportValue: row => String(row.id ?? "") },
      { id: "title", header: "Check", kind: "name", wrap: true, cell: row => String(row.title ?? "Not reported"), exportValue: row => String(row.title ?? "") },
      { id: "result", header: "Result", kind: "status", cell: row => String(row.result ?? "Not reported"), exportValue: row => String(row.result ?? "") },
      { id: "detail", header: "Evidence / remediation", kind: "text", wrap: true, grow: true, cell: row => String(row.detail ?? "Not reported"), exportValue: row => String(row.detail ?? "") },
    ];
    return <div className="space-y-3" data-testid="risk-compliance-tab"><p className="text-sm text-muted-foreground">CIS benchmark evidence reported for this exact node. Observed: {entity.data.node.cis_observed_at || "Not collected"}.</p>{entity.data.cis && rows === undefined ? <ErrorState title="Node CIS evidence has an unsupported response shape." /> : <DataTable rows={(rows ?? []).map((row, index) => ({ ...row, _key: index }))} columns={columns} rowKey={row => row._key} preferencesKey="risk-node-compliance" exportFileName="risk-returned-node-compliance" emptyState={<p className="p-4 text-sm text-muted-foreground">No node CIS evidence returned. Compliance is not established.</p>} />}{link}</div>;
  }
  if (entity?.type !== "deployment") return <div className="space-y-3" data-testid="risk-compliance-tab"><EvidenceUnavailable workspace={workspace} evidence="Compliance" />{link}</div>;
  const rows = (entity.data.compliance_evidence ?? []).map((row, index) => ({ ...row, _key: `${row.id}-${index}` }));
  const columns: Column<DeploymentComplianceEvidence>[] = [
    { id: "control", header: "Control", kind: "name", wrap: true, cell: row => `${row.framework} · ${row.control_id} · ${row.title}`, exportValue: row => `${row.framework} ${row.control_id} ${row.title}` },
    { id: "result", header: "Effective result", kind: "status", cell: row => row.effective_status, exportValue: row => row.effective_status },
    { id: "target", header: "Target", kind: "text", code: true, wrap: true, cell: row => row.target, exportValue: row => row.target },
    { id: "evidence", header: "Evidence", kind: "text", wrap: true, grow: true, cell: row => row.evidence || "Not reported", exportValue: row => row.evidence },
    { id: "remediation", header: "Remediation", kind: "text", wrap: true, grow: true, cell: row => row.remediation || "Not reported", exportValue: row => row.remediation },
  ];
  return <div className="space-y-3" data-testid="risk-compliance-tab"><p className="text-sm text-muted-foreground">Compliance evidence returned for this deployment’s resolved workload targets. Cluster framework totals are separate context.</p><DataTable rows={rows} columns={columns} rowKey={row => row._key} preferencesKey="risk-deployment-compliance" exportFileName="risk-returned-deployment-compliance" emptyState={<p className="p-4 text-sm text-muted-foreground">No deployment compliance evidence returned. A passing assessment is not established.</p>} />{link}</div>;
}
