import { findingHref, findingRowKey } from "@/lib/finding-instance";
import { NodeVulnerabilitiesInventory } from "../NodeVulnerabilitiesInventory";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { DeploymentFindingsInventory } from "../DeploymentFindingsInventory";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { findings, type AssetFinding } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Pager } from "@/components/ui/pager";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { FINDINGS_PAGE_SIZE, type RiskTabProps, type RiskFinding } from "./workspace";

export default function FindingsTab({ workspace }: RiskTabProps) {
  const { entity, records, clusterId, query, generic, page, setPage, assetQuery } = workspace;
  const qc = useQueryClient();
  const exportReady = workspace.scopeReady && workspace.entityQ.isSuccess && !workspace.entityQ.isFetching && query.isSuccess && !query.isFetching && !workspace.invalidPage && !workspace.findingScopeMismatch && !!generic?.total;
  const captureExport = useExportGuard(JSON.stringify([workspace.owner, clusterId, workspace.entityType, workspace.entityId, assetQuery, page]), !exportReady, () => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, workspace.entityQueryKey, workspace.entityQ.data) && exportQueryReady(qc, workspace.findingQueryKey, query.data));
  const exportQuery = useMutation({
    mutationFn: async (captured: { cluster_id: string; q: string; shouldDownload: ReturnType<typeof captureExport> }) => {
      if (!captured.shouldDownload()) throw new Error("Refresh asset findings before exporting.");
      await findings.exportCSV({ cluster_id: captured.cluster_id, q: captured.q, sort: "risk", order: "desc", limit: 10000 }, captured.shouldDownload);
      if (!captured.shouldDownload()) throw new Error("Refresh asset findings before exporting.");
    },
  });
  if (!entity) return null;
  if (entity.type === "deployment") return <DeploymentFindingsInventory deployment={entity.data} sourceQueryKey={workspace.entityQueryKey} sourceKind="risk" sourceReady={workspace.scopeReady && workspace.entityQ.isSuccess && !workspace.entityQ.isFetching} />;
  const columns: Column<RiskFinding>[] = [
    { id: "title", header: "Finding", kind: "name", wrap: true, cell: row => <a href={findingHref({ ...row, first_seen_at: row.first_seen_at ?? "" }, clusterId)} className="hover:underline">{row.title}</a>, exportValue: row => row.title },
    { id: "first-seen", header: "First observed", kind: "date", cell: row => row.first_seen_at ?? "Not reported", exportValue: row => row.first_seen_at ?? "" },
    { id: "risk", header: "Risk", kind: "count", numeric: true, cell: row => row.risk_score, exportValue: row => row.risk_score },
    { id: "severity", header: "Severity", kind: "status", cell: row => <SeverityBadge severity={row.severity} />, exportValue: row => row.severity },
    { id: "lifecycle", header: "Lifecycle", kind: "status", cell: row => <LifecycleBadge lifecycle={row.lifecycle} />, exportValue: row => row.lifecycle },
    { id: "platform-role", header: "Platform role", kind: "status", exportValue: row => row.platform_role ?? "", cell: row => row.platform_role === "core" ? "Core" : row.platform_role === "" ? "Unclassified" : "Not reported" },
    { id: "kind", header: "Kind", kind: "status", cell: row => row.kind, exportValue: row => row.kind },
  ];
  if (entity.type === "node") return <div data-testid="risk-findings-table"><NodeVulnerabilitiesInventory clusterId={clusterId!} nodeName={entity.data.node.node} sourceQueryKey={workspace.entityQueryKey} sourceKind="risk" sourceReady={workspace.scopeReady && workspace.entityQ.isSuccess} nodeRefreshing={workspace.entityQ.isFetching} paramPrefix="findings_" /></div>;
  const canonical = entity.type === "asset" ? (entity.data.findings ?? []).filter(row => !!row.image_scan_result_id) : [];
  const canonicalColumns: Column<AssetFinding>[] = [
    { id: "title", header: "Finding", kind: "name", wrap: true, cell: row => row.title, exportValue: row => row.title },
    { id: "external", header: "CVE", kind: "id", wrap: true, cell: row => <a href={`/cve/${encodeURIComponent(row.external_id)}`} className="hover:underline">{row.external_id}</a>, exportValue: row => row.external_id },
    { id: "severity", header: "Severity", kind: "status", cell: row => <SeverityBadge severity={row.severity} />, exportValue: row => row.severity },
    { id: "risk", header: "Risk", kind: "count", numeric: true, cell: row => row.risk_score, exportValue: row => row.risk_score },
  ];
  canonicalColumns.push({ id: "platform-role", header: "Platform role", kind: "status", exportValue: row => row.platform_role ?? "", cell: row => row.platform_role === "" ? "Unclassified" : "Not reported" });
  const outOfRange = !!generic && page > 0 && page * FINDINGS_PAGE_SIZE >= generic.total;
  return <div className="space-y-5" data-testid="risk-findings-table">
    {entity.type === "asset" && <section className="space-y-3"><h2 className="text-sm font-semibold">Canonical image scan evidence</h2><p className="text-xs text-muted-foreground">{canonical.length.toLocaleString()} returned canonical image findings. {entity.data.image_scan_result ? `Latest image scan reports ${entity.data.image_scan_result.finding_count.toLocaleString()} findings.` : "No latest canonical image scan is reported."} Generic finding records below are a separate source.</p><DataTable rows={canonical} columns={canonicalColumns} rowKey={row => row.id} preferencesKey="risk-canonical-image-findings" defaultHiddenColumnIds={["platform-role"]} exportFileName="risk-returned-canonical-image-findings" emptyState={<p className="p-4 text-sm text-muted-foreground">No canonical image findings returned. Check image scan coverage in asset detail.</p>} /></section>}
    <section className="space-y-3"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-sm font-semibold">{entity.type === "asset" ? "Generic finding records" : "Selected finding"}</h2>{entity.type === "asset" && <Button disabled={!exportReady || exportQuery.isPending} onClick={() => { if (clusterId && assetQuery) exportQuery.mutate({ cluster_id: clusterId, q: assetQuery, shouldDownload: captureExport() }); }}>{exportQuery.isPending ? "Exporting…" : "Export matching records (up to 10,000)"}</Button>}</div>
    {exportQuery.isError && exportQuery.variables?.shouldDownload() && <ErrorState title="Could not export asset finding records. Retry the export when the source is available." />}
    <p className="text-xs text-muted-foreground">{entity.type === "asset" ? `Server filters by this exact asset and cluster before paging. ${generic ? `${generic.total.toLocaleString()} matching generic records across all lifecycles.` : "Matching totals are unavailable until the query succeeds."} Fixed order: highest reported risk first.` : "One exact finding; no organization-wide sample."}</p>
    {entity.type === "asset" && workspace.invalidPage ? <ErrorState title="This finding page cannot be queried safely." action={<Button onClick={() => setPage(0)}>Return to first page</Button>} /> : entity.type === "asset" && workspace.findingScopeMismatch ? <ErrorState title="Finding evidence does not match this asset and cluster." /> : entity.type === "asset" && query.isError ? <ErrorState title="Could not load asset finding records." action={<Button onClick={() => void query.refetch()}>Retry</Button>} /> : entity.type === "asset" && query.isPending ? <LoadingState label="Loading asset findings…" /> : outOfRange ? <ErrorState title="This finding page is outside the current result set." action={<Button onClick={() => setPage(0)}>Return to first page</Button>} /> : <><DataTable rows={records} columns={columns} rowKey={row => findingRowKey({ ...row, first_seen_at: row.first_seen_at ?? "" })} pagination={entity.type !== "asset"} preferencesKey={`risk-${entity.type}-findings`} defaultHiddenColumnIds={["platform-role", "first-seen"]} testId="risk-generic-findings" exportFileName="risk-current-finding-evidence" exportLabel={entity.type === "asset" ? "Export current page" : "Export returned findings"} emptyState={<p className="p-4 text-sm text-muted-foreground">No findings in this source response. Verify source coverage in entity detail.</p>} />{entity.type === "asset" && <Pager page={page} pageSize={FINDINGS_PAGE_SIZE} total={generic?.total} hasMore={generic?.has_more} rowsOnPage={records.length} onPage={setPage} />}</>}
    </section>
  </div>;
}
