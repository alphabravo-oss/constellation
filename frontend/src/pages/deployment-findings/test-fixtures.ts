import type { DeploymentFindingInventoryRow, DeploymentFindingsParams, DeploymentFindingsResponse } from "@/api/client";

export function deploymentFindingFixture(index = 0): DeploymentFindingInventoryRow {
  const id = `11111111-1111-4111-8111-${index.toString().padStart(12, "0")}`;
  return { id, row_id: `${id}:1791842400.000000`, first_seen_at: "2026-10-12T22:00:00Z", last_seen_at: "2026-10-12T23:00:00Z", kind: "vulnerability", external_id: `CVE-2099-${(index + 1000).toString()}`, title: `Workload finding ${index}`, severity: "high", risk_score: 70, lifecycle: "open", target_type: "workload", target_ref: "payments/app", package_name: "openssl", package_version: "1.0", fixed_version: "2.0", fixable: true, source_cluster_id: "cluster", target_cluster_id: null, effective_target_cluster_id: "cluster", platform_role: "", attribution: "canonical", owner_count: 1, owner_ambiguous: false };
}
export function deploymentFindingPage(params: DeploymentFindingsParams, rows: DeploymentFindingInventoryRow[] = [deploymentFindingFixture()], deployment = "deployment", workload = "payments/app"): DeploymentFindingsResponse {
  const q = params.q ?? "", lifecycle = params.lifecycle ?? "open", severity = params.severity ?? "";
  const matched = rows.filter(row => (lifecycle === "all" || row.lifecycle === lifecycle) && (!severity || row.severity === severity) && (params.fixable === undefined || row.fixable === params.fixable) && (!q || `${row.title} ${row.external_id} ${row.package_name} ${row.target_ref}`.toLowerCase().includes(q)));
  const offset = params.offset ?? 0;
  const summary: Record<string, number> = { total: matched.length, critical: 0, high: 0, fixable: 0, open: 0, in_progress: 0, triaged: 0, accepted: 0, suppressed: 0, resolved: 0, canonical: 0, pod: 0, ambiguous_owners: 0, other_lifecycle: 0 };
  for (const row of matched) { if (row.lifecycle in summary) summary[row.lifecycle]++; else summary.other_lifecycle++; if (row.severity === "critical" || row.severity === "high") summary[row.severity]++; if (row.fixable) summary.fixable++; summary[row.attribution]++; if (row.owner_ambiguous) summary.ambiguous_owners++; }
  return { deployment_id: deployment, cluster_id: params.cluster_id, workload_id: workload, owner_count: 1, owner_ambiguous: false, items: matched.slice(offset, offset + 100), total: matched.length, summary, has_more: matched.length > offset + 100, limit: 100, offset, sort: params.sort ?? "risk", order: params.order ?? "desc", filters: { q, lifecycle, severity, fixable: params.fixable === undefined ? "" : String(params.fixable) }, source_complete: true, summary_scope: "matching_direct_workload_findings" };
}
