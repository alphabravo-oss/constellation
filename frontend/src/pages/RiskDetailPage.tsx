import { Suspense, lazy } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { fmtRelative } from "@/lib/format";
import { detailPath, entityIdentity, useRiskWorkspace } from "./risk/workspace";

const OverviewTab = lazy(() => import("./risk/OverviewTab"));
const FindingsTab = lazy(() => import("./risk/FindingsTab"));
const NetworkTab = lazy(() => import("./risk/NetworkTab"));
const ProcessTab = lazy(() => import("./risk/ProcessTab"));
const FileTab = lazy(() => import("./risk/FileTab"));
const ComplianceTab = lazy(() => import("./risk/ComplianceTab"));

export function RiskDetailPage() {
  const workspace = useRiskWorkspace();
  const { entity, entityQ, entityId, entityType, scopeReady, clusterError, clusterLoading, supported, stats } = workspace;
  const qc = useQueryClient();
  const [requestedTab, setTab] = useTabParam("tab", "overview");
  const tab = ["overview", "findings", "network", "process", "files", "compliance"].includes(requestedTab) ? requestedTab : "overview";
  const identity = entity ? entityIdentity(entity) : undefined;
  const listSegment = entityType === "asset" ? "assets" : entityType === "node" ? "nodes" : entityType === "deployment" ? "deployments" : "findings";
  const root = `/clusters/${encodeURIComponent(workspace.clusterId ?? "")}`;
  const assetFailures = entity?.type === "asset" && (workspace.query.isError || workspace.criticalQ.isError || workspace.highQ.isError || workspace.findingScopeMismatch || workspace.invalidPage);
  const unavailable = !!clusterError || entityQ.isError || (entityQ.isSuccess && !workspace.matches) || assetFailures;
  const source = entity?.type === "asset" ? "Counts cover server-filtered generic finding records; canonical image scan evidence is shown separately." : entity?.type === "deployment" ? "Risk and severity counts are reported by deployment inventory. Direct workload findings and other evidence have explicit source limits." : entity?.type === "node" ? "Counts cover this node’s reported open host vulnerabilities. A composite risk score is not reported." : "Counts describe this finding only. Risk factors come from its reported decomposition.";
  const refresh = () => {
    void entityQ.refetch();
    if (entity?.type === "asset") { void workspace.query.refetch(); void workspace.criticalQ.refetch(); void workspace.highQ.refetch(); }
  };
  return <div className="space-y-5" data-testid="risk-detail-page" data-cluster-id={workspace.clusterId ?? ""}>
    <PageHeader title={identity?.name ?? "Risk workspace"}
      description={identity ? `Reported risk and evidence for this ${entityType} in ${workspace.cluster?.name ?? "the selected cluster"}.` : "Resolve an exact entity in the selected cluster to review its reported risk and evidence."}
      backLink={scopeReady ? <a href={`${root}/${listSegment}`} className="text-sm hover:underline">Back to {listSegment}</a> : undefined}
      actions={entity ? <><Button variant="outline" disabled={entityQ.isFetching} onClick={refresh}>Refresh</Button><Button asChild><a href={detailPath(workspace)}>Open entity detail <ExternalLink className="h-4 w-4" /></a></Button></> : undefined} />
    <VerdictBanner status={unavailable ? "degraded" : (stats.critical ?? 0) > 0 || (stats.risk ?? 0) >= 70 ? "critical" : (stats.high ?? 0) > 0 || (stats.risk ?? 0) > 20 ? "degraded" : "info"}
      title={clusterError ? "Cluster context unavailable" : !scopeReady ? clusterLoading ? "Resolving cluster" : "Select a resolved cluster" : !supported || !entityId ? "Select a supported entity" : entityQ.isError ? "Entity evidence unavailable" : entityQ.isPending ? "Loading entity evidence" : !workspace.matches ? "Entity does not match this cluster" : assetFailures ? "Some finding evidence is unavailable" : stats.risk !== undefined ? `Reported risk: ${stats.risk}/100` : "Review reported entity evidence"}
      detail={entity ? source : "Cluster and entity identity must match before evidence is displayed."} />
    <StatGrid data-testid="risk-summary">
      <StatCard label="Risk score" value={stats.risk ?? "Not reported"} />
      <StatCard label={entity?.type === "asset" ? "Critical generic" : "Critical"} hint={entity?.type === "asset" ? "All lifecycles in generic finding records" : undefined} value={stats.critical ?? "—"} tone={stats.critical ? "critical" : "neutral"} />
      <StatCard label={entity?.type === "asset" ? "High generic" : "High"} hint={entity?.type === "asset" ? "All lifecycles in generic finding records" : undefined} value={stats.high ?? "—"} tone={stats.high ? "high" : "neutral"} />
      <StatCard label={entity?.type === "asset" ? "Open generic" : "Open"} value={stats.open ?? "—"} hint={entity?.type === "deployment" ? "No aggregate open count is reported" : entity?.type === "asset" ? "Open or in-progress generic records" : undefined} />
      <StatCard label="Last observed" valueKind="text" value={identity?.lastSeen ? fmtRelative(identity.lastSeen) : "—"} />
    </StatGrid>
    {!scopeReady ? clusterError ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={() => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", workspace.clusterId] }); }}>Retry</Button>} /> : clusterLoading ? <LoadingState label="Resolving cluster…" /> : <p className="text-sm text-muted-foreground">Select a resolved cluster.</p> : !supported || !entityId ? <EmptyState title="No supported entity selected" hint="Open a risk workspace for an asset, finding, node or deployment." /> : entityQ.isPending ? <LoadingState label="Loading entity evidence…" /> : entityQ.isError ? <ErrorState title="Could not load entity evidence." action={<Button onClick={() => void entityQ.refetch()}>Retry</Button>} /> : !entity ? <ErrorState title="This entity is not in the selected cluster." /> : <Tabs key={`${workspace.clusterId}/${entityType}/${entityId}`} value={tab} onValueChange={setTab} items={[
      { value: "overview", label: "Overview", content: <Suspense fallback={<LoadingState />}><OverviewTab workspace={workspace} /></Suspense> },
      { value: "findings", label: "Findings", content: <Suspense fallback={<LoadingState />}><FindingsTab workspace={workspace} /></Suspense> },
      { value: "network", label: "Network", content: <Suspense fallback={<LoadingState />}><NetworkTab workspace={workspace} /></Suspense> },
      { value: "process", label: "Process", content: <Suspense fallback={<LoadingState />}><ProcessTab workspace={workspace} /></Suspense> },
      { value: "files", label: "File Activity", content: <Suspense fallback={<LoadingState />}><FileTab workspace={workspace} /></Suspense> },
      { value: "compliance", label: "Compliance", content: <Suspense fallback={<LoadingState />}><ComplianceTab workspace={workspace} /></Suspense> },
    ]} />}
  </div>;
}
