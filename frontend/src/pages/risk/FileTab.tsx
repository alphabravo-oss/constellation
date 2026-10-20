import { DataTable, type Column } from "@/components/ui/data-table";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState } from "@/components/ui/states";
import { type FileProfileRule } from "@/api/client";
import { EvidenceUnavailable } from "./EvidenceUnavailable";
import { type RiskTabProps } from "./workspace";

export default function FileTab({ workspace }: RiskTabProps) {
  const { entity, clusterId } = workspace;
  if (entity?.type !== "deployment") return <div data-testid="risk-file-tab"><EvidenceUnavailable workspace={workspace} evidence="File activity" /></div>;
  const profile = entity.data.file_profile;
  if (profile?.cluster_id && profile.cluster_id !== clusterId) return <ErrorState title="File profile does not match this cluster." />;
  const files = (profile?.files ?? []).map((row, index) => ({ ...row, _key: index }));
  type FileRow = typeof files[number];
  const columns: Column<FileRow>[] = [
    { id: "path", header: "Path", kind: "name", code: true, wrap: true, cell: row => row.path, exportValue: row => row.path },
    { id: "operation", header: "Operation", kind: "status", cell: row => row.operation, exportValue: row => row.operation },
    { id: "sensitive", header: "Sensitive", kind: "status", cell: row => row.sensitive ? "Yes" : "No", exportValue: row => row.sensitive ? "Yes" : "No" },
    { id: "observed", header: "Observations", kind: "count", numeric: true, cell: row => row.observed_count, exportValue: row => row.observed_count },
    { id: "last", header: "Last observed", kind: "date", wrap: true, cell: row => row.last_seen, exportValue: row => row.last_seen },
  ];
  const rules = (profile?.rules ?? []).map((row, index) => ({ ...row, _key: `${row.id}-${index}` }));
  const ruleColumns: Column<FileProfileRule>[] = [
    { id: "filter", header: "Filter", kind: "name", wrap: true, code: true, cell: row => row.filter, exportValue: row => row.filter },
    { id: "behavior", header: "Behavior", kind: "status", cell: row => row.behavior, exportValue: row => row.behavior },
    { id: "recursive", header: "Recursive", kind: "status", cell: row => row.recursive ? "Yes" : "No", exportValue: row => row.recursive ? "Yes" : "No" },
    { id: "enabled", header: "Enabled", kind: "status", cell: row => row.enabled ? "Yes" : "No", exportValue: row => row.enabled ? "Yes" : "No" },
  ];
  return <div className="space-y-5" data-testid="risk-file-tab"><p className="text-sm text-muted-foreground">File profile for the deployment’s resolved owned workloads. Configured mode: {profile?.mode || "Not reported"}. Returned paths and rules describe reported evidence; configured rules alone do not prove enforcement.</p><DataTable rows={files} columns={columns} rowKey={row => row._key} preferencesKey="risk-deployment-files" exportFileName="risk-returned-deployment-files" emptyState={<p className="p-4 text-sm text-muted-foreground">No file activity evidence returned. This is not a clean file-monitor assessment.</p>} /><Collapse label="Advanced: reported file posture and configured monitor rules"><dl className="mb-4 grid gap-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Reported learned paths</dt><dd>{profile?.learned_paths_count ?? "Not reported"}</dd></div><div><dt className="text-muted-foreground">Reported sensitive paths</dt><dd>{profile?.sensitive_path_count ?? "Not reported"}</dd></div><div><dt className="text-muted-foreground">Reported alerts · 24h</dt><dd>{profile?.monitored_alerts_24h ?? "Not reported"}</dd></div><div><dt className="text-muted-foreground">Reported blocks · 24h</dt><dd>{profile?.enforced_blocks_24h ?? "Not reported"}</dd></div></dl><DataTable rows={rules} columns={ruleColumns} rowKey={row => row._key} preferencesKey="risk-deployment-file-rules" exportFileName="risk-returned-deployment-file-rules" emptyState={<p className="p-4 text-sm text-muted-foreground">No configured rules returned.</p>} /></Collapse></div>;
}
