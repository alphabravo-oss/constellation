import { DeploymentFindingsInventory } from "../DeploymentFindingsInventory";
import { useMutation } from "@tanstack/react-query";
import { findings, type AssetFinding, type HostVulnerability } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Pager } from "@/components/ui/pager";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { FINDINGS_PAGE_SIZE, type RiskTabProps, type RiskFinding } from "./workspace";

export default function FindingsTab({ workspace }: RiskTabProps) {
  const { entity, records, clusterId, query, generic, page, setPage, assetQuery } = workspace;
  const exportQuery = useMutation({
    mutationFn: (request: { cluster_id: string; q: string }) => findings.exportCSV({ ...request, sort: "risk", order: "desc", limit: 10000 }),
  });
  if (!entity) return null;
  if (entity.type === "deployment") return <DeploymentFindingsInventory deployment={entity.data} sourceQueryKey={workspace.entityQueryKey} sourceKind="risk" sourceReady={workspace.scopeReady && workspace.entityQ.isSuccess && !workspace.entityQ.isFetching} />;
  const columns: Column<RiskFinding>[] = [
    { id: "title", header: "Finding", kind: "name", wrap: true, cell: row => <a href={`/clusters/${clusterId}/findings/${encodeURIComponent(row.id)}`} className="hover:underline">{row.title}</a>, exportValue: row => row.title },
    { id: "risk", header: "Risk", kind: "count", numeric: true, cell: row => row.risk_score, exportValue: row => row.risk_score },
    { id: "severity", header: "Severity", kind: "status", cell: row => <SeverityBadge severity={row.severity} />, exportValue: row => row.severity },
    { id: "lifecycle", header: "Lifecycle", kind: "status", cell: row => <LifecycleBadge lifecycle={row.lifecycle} />, exportValue: row => row.lifecycle },
    { id: "platform-role", header: "Platform role", kind: "status", exportValue: row => row.platform_role ?? "", cell: row => row.platform_role === "core" ? "Core" : row.platform_role === "" ? "Unclassified" : "Not reported" },
    { id: "kind", header: "Kind", kind: "status", cell: row => row.kind, exportValue: row => row.kind },
  ];
  if (entity.type === "node") {
    const rows = (entity.data.vulnerabilities ?? []).map((row, index) => ({ ...row, _key: `${row.vuln_id}-${row.package_name}-${row.package_version}-${index}` }));
    const hostColumns: Column<HostVulnerability>[] = [
      { id: "cve", header: "Vulnerability", kind: "name", wrap: true, cell: row => <a href={`/cve/${encodeURIComponent(row.vuln_id)}`} className="hover:underline">{row.vuln_id || "Not reported"}</a>, exportValue: row => row.vuln_id },
      { id: "package", header: "Package", kind: "text", wrap: true, code: true, cell: row => row.package_name, exportValue: row => row.package_name },
      { id: "version", header: "Version", kind: "version", wrap: true, cell: row => row.package_version, exportValue: row => row.package_version },
      { id: "severity", header: "Severity", kind: "status", cell: row => row.severity || "Not reported", exportValue: row => row.severity },
      { id: "fixed", header: "Fixed version", kind: "version", wrap: true, cell: row => row.fixed_version || "Not reported", exportValue: row => row.fixed_version },
    ];
    return <div className="space-y-3" data-testid="risk-findings-table"><p className="text-sm text-muted-foreground">Reported open host vulnerabilities for this exact node. The node endpoint returns at most 2,000 records; reported inventory counts cover the source aggregate.</p><DataTable rows={rows} columns={hostColumns} rowKey={row => row._key} preferencesKey="risk-node-vulnerabilities" exportFileName="risk-node-returned-vulnerabilities" sourceLimit={2000} sourceCount={rows.length} emptyState={<p className="p-4 text-sm text-muted-foreground">{entity.data.node.last_scanned_at ? "No open vulnerabilities in returned host evidence." : "Host vulnerabilities have not been scanned."}</p>} /></div>;
  }
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
    <section className="space-y-3"><div className="flex flex-wrap items-center justify-between gap-3"><h2 className="text-sm font-semibold">{entity.type === "asset" ? "Generic finding records" : "Selected finding"}</h2>{entity.type === "asset" && <Button disabled={query.isPending || query.isFetching || query.isError || workspace.invalidPage || workspace.findingScopeMismatch || exportQuery.isPending || !generic?.total} onClick={() => { if (clusterId && assetQuery) exportQuery.mutate({ cluster_id: clusterId, q: assetQuery }); }}>{exportQuery.isPending ? "Exporting…" : "Export matching records (up to 10,000)"}</Button>}</div>
    {exportQuery.isError && <ErrorState title="Could not export asset finding records. Retry the export when the source is available." />}
    <p className="text-xs text-muted-foreground">{entity.type === "asset" ? `Server filters by this exact asset and cluster before paging. ${generic ? `${generic.total.toLocaleString()} matching generic records across all lifecycles.` : "Matching totals are unavailable until the query succeeds."} Fixed order: highest reported risk first.` : "One exact finding; no organization-wide sample."}</p>
    {entity.type === "asset" && workspace.invalidPage ? <ErrorState title="This finding page cannot be queried safely." action={<Button onClick={() => setPage(0)}>Return to first page</Button>} /> : entity.type === "asset" && workspace.findingScopeMismatch ? <ErrorState title="Finding evidence does not match this asset and cluster." /> : entity.type === "asset" && query.isError ? <ErrorState title="Could not load asset finding records." action={<Button onClick={() => void query.refetch()}>Retry</Button>} /> : entity.type === "asset" && query.isPending ? <LoadingState label="Loading asset findings…" /> : outOfRange ? <ErrorState title="This finding page is outside the current result set." action={<Button onClick={() => setPage(0)}>Return to first page</Button>} /> : <><DataTable rows={records} columns={columns} rowKey={row => row.id} pagination={entity.type !== "asset"} preferencesKey={`risk-${entity.type}-findings`} defaultHiddenColumnIds={["platform-role"]} testId="risk-generic-findings" exportFileName="risk-current-finding-evidence" exportLabel={entity.type === "asset" ? "Export current page" : "Export returned findings"} emptyState={<p className="p-4 text-sm text-muted-foreground">No findings in this source response. Verify source coverage in entity detail.</p>} />{entity.type === "asset" && <Pager page={page} pageSize={FINDINGS_PAGE_SIZE} total={generic?.total} hasMore={generic?.has_more} rowsOnPage={records.length} onPage={setPage} />}</>}
    </section>
  </div>;
}
