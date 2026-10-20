import { ambiguousFinding, findingChooserHref } from "@/lib/finding-instance";
import { useCrumbLabel } from "@/lib/page-title";
import { Suspense, lazy } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState, EmptyState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
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
  useCrumbLabel(identity?.name ? `${identity.name} · risk` : null);
  const assetFailures = entity?.type === "asset" && (workspace.query.isError || workspace.criticalQ.isError || workspace.highQ.isError || workspace.findingScopeMismatch || workspace.invalidPage);
  const unavailable = !!clusterError || entityQ.isError || (entityQ.isSuccess && !workspace.matches) || assetFailures;
  const source = entity?.type === "asset" ? "Counts cover server-filtered generic finding records; canonical image scan evidence is shown separately." : entity?.type === "deployment" ? "Risk and severity counts are reported by deployment inventory. Direct workload findings use a filtered server inventory; other evidence discloses its source limits." : entity?.type === "node" ? "Counts cover this node’s reported open host vulnerabilities. A composite risk score is not reported." : "Counts describe this finding only. Risk factors come from its reported decomposition.";
  const refresh = () => {
    void entityQ.refetch();
    if (entity?.type === "asset") { void workspace.query.refetch(); void workspace.criticalQ.refetch(); void workspace.highQ.refetch(); }
  };
  return <div className="space-y-5" data-testid="risk-detail-page" data-cluster-id={workspace.clusterId ?? ""}>
    <PageHeader title={identity?.name ?? "Risk workspace"}
      eyebrow={identity ? `Risk workspace · ${entityType}` : undefined}
      actions={entity ? <><Button disabled={entityQ.isFetching} onClick={refresh}>Refresh</Button><Button asChild><a href={detailPath(workspace)}>Open entity detail <ExternalLink className="h-4 w-4" /></a></Button></> : undefined} />
    <div data-testid="risk-summary"><VerdictBanner status={unavailable ? "degraded" : (stats.critical ?? 0) > 0 || (stats.risk ?? 0) >= 70 ? "critical" : (stats.high ?? 0) > 0 || (stats.risk ?? 0) > 20 ? "degraded" : "info"}
      title={clusterError ? "Cluster context unavailable" : !scopeReady ? clusterLoading ? "Resolving cluster" : "Select a resolved cluster" : !supported || !entityId ? "Select a supported entity" : entityQ.isError ? "Entity evidence unavailable" : entityQ.isPending ? "Loading entity evidence" : !workspace.matches ? "Entity does not match this cluster" : assetFailures ? "Some finding evidence is unavailable" : stats.risk !== undefined ? `Reported risk: ${stats.risk}/100` : "Review reported entity evidence"}
      numbers={[
        { label: "risk score", value: stats.risk ?? "Not reported" },
        { label: `critical${entity?.type === "asset" ? " (generic)" : ""}`, value: stats.critical ?? "—", tone: stats.critical ? "critical" : "default" },
        { label: `high${entity?.type === "asset" ? " (generic)" : ""}`, value: stats.high ?? "—", tone: stats.high ? "high" : "default" },
        { label: `open${entity?.type === "asset" ? " (generic)" : ""}`, value: stats.open ?? "—", title: entity?.type === "deployment" ? "No aggregate open count is reported" : undefined },
      ]}
      detail={<div className="space-y-1"><p>{entity ? source : "Cluster and entity identity must match before evidence is displayed."}</p><p>Last observed {identity?.lastSeen ? fmtRelative(identity.lastSeen) : "—"}.{entity?.type === "asset" ? " Generic counts cover all lifecycles in generic finding records." : ""}</p></div>} /></div>
    {!workspace.validSelector ? <ErrorState title="Select one valid observation timestamp." /> : !scopeReady ? clusterError ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={() => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", workspace.clusterId] }); }}>Retry</Button>} /> : clusterLoading ? <LoadingState label="Resolving cluster…" /> : <p className="text-sm text-muted-foreground">Select a resolved cluster.</p> : !supported || !entityId ? <EmptyState title="No supported entity selected" hint="Open a risk workspace for an asset, finding, node or deployment." /> : entityQ.isPending ? <LoadingState label="Loading entity evidence…" /> : entityQ.isError ? <ErrorState title={ambiguousFinding(entityQ.error) ? "This finding has multiple retained observations." : "Could not load entity evidence."} action={ambiguousFinding(entityQ.error) ? <a href={findingChooserHref(workspace.clusterId!, entityId)}>Choose an observation</a> : <Button onClick={() => void entityQ.refetch()}>Retry</Button>} /> : !entity ? <ErrorState title="This entity is not in the selected cluster." /> : <Tabs key={`${workspace.owner}/${workspace.clusterId}/${entityType}/${entityId}/${workspace.firstSeen}`} value={tab} onValueChange={setTab} items={[
      { value: "overview", label: "Overview", content: <Suspense fallback={<LoadingState />}><OverviewTab workspace={workspace} /></Suspense> },
      { value: "findings", label: "Findings", content: <Suspense fallback={<LoadingState />}><FindingsTab workspace={workspace} /></Suspense> },
      { value: "network", label: "Network", content: <Suspense fallback={<LoadingState />}><NetworkTab workspace={workspace} /></Suspense> },
      { value: "process", label: "Process", content: <Suspense fallback={<LoadingState />}><ProcessTab workspace={workspace} /></Suspense> },
      { value: "files", label: "File Activity", content: <Suspense fallback={<LoadingState />}><FileTab workspace={workspace} /></Suspense> },
      { value: "compliance", label: "Compliance", content: <Suspense fallback={<LoadingState />}><ComplianceTab workspace={workspace} /></Suspense> },
    ]} />}
  </div>;
}
