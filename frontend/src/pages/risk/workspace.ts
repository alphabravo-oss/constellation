import { assetDisplayName } from "@/lib/asset-identity";
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useRouteSearchParams } from "@/lib/route-search";
import { assets, deployments, findings, nodes, type AssetDetail, type DeploymentDetail, type Finding, type NodeDetail } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export type RiskEntity =
  | { type: "asset"; data: AssetDetail }
  | { type: "deployment"; data: DeploymentDetail }
  | { type: "finding"; data: Finding }
  | { type: "node"; data: NodeDetail };
export type RiskFinding = Pick<Finding, "id" | "title" | "severity" | "risk_score" | "lifecycle" | "kind" | "last_seen_at">;
export interface ReportedRisk { composite: number; factors: Array<{ name: string; description: string; score: number; raw: number; weight: number }> }
export const FINDINGS_PAGE_SIZE = 100;

export function useRiskWorkspace() {
  const { entityType = "", entityId = "" } = useParams({ strict: false });
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const supported = ["asset", "deployment", "node", "finding"].includes(entityType);
  const [params, setParams] = useRouteSearchParams();
  const rawPage = params.get("findings_page");
  const pageValue = Number(rawPage);
  const validPage = Number.isSafeInteger(pageValue) && pageValue >= 1 && Number.isSafeInteger((pageValue - 1) * FINDINGS_PAGE_SIZE);
  const invalidPage = rawPage !== null && !validPage;
  const page = validPage ? pageValue - 1 : 0;
  const setPage = (value: number) => setParams(current => {
    if (value > 0) current.set("findings_page", String(value + 1)); else current.delete("findings_page");
    return current;
  });
  const entityQ = useQuery({
    queryKey: ["risk-entity", clusterId, entityType, entityId],
    enabled: scopeReady && supported && !!entityId,
    queryFn: async (): Promise<RiskEntity> => {
      if (entityType === "asset") return { type: "asset", data: await assets.get(entityId) };
      if (entityType === "deployment") return { type: "deployment", data: await deployments.get(entityId) };
      if (entityType === "node") return { type: "node", data: await nodes.get(clusterId!, entityId) };
      return { type: "finding", data: await findings.get(entityId) };
    },
  });
  const identity = entityQ.data ? entityIdentity(entityQ.data) : undefined;
  const matches = identity?.id === entityId && identity?.clusterId === clusterId;
  const entity = scopeReady && !entityQ.isError && matches ? entityQ.data : undefined;
  const assetQuery = entity?.type === "asset" ? `asset:${entity.data.asset.id}` : undefined;
  const query = useQuery({
    queryKey: ["risk-related", clusterId, entityId, assetQuery, page],
    enabled: !!entity && !!assetQuery && !invalidPage,
    queryFn: () => findings.list({ cluster_id: clusterId, q: assetQuery, limit: FINDINGS_PAGE_SIZE, offset: page * FINDINGS_PAGE_SIZE, sort: "risk", order: "desc" }),
  });
  const criticalQ = useQuery({
    queryKey: ["risk-related-critical", clusterId, entityId, assetQuery], enabled: !!entity && !!assetQuery && !invalidPage,
    queryFn: () => findings.list({ cluster_id: clusterId, q: `${assetQuery} severity:critical`, limit: 1 }),
  });
  const highQ = useQuery({
    queryKey: ["risk-related-high", clusterId, entityId, assetQuery], enabled: !!entity && !!assetQuery && !invalidPage,
    queryFn: () => findings.list({ cluster_id: clusterId, q: `${assetQuery} severity:high`, limit: 1 }),
  });
  const sameAsset = (rows: Finding[] | undefined) => rows?.every(row => row.asset_id === entityId && row.cluster_id === clusterId) ?? true;
  const findingScopeMismatch = entity?.type === "asset" && ((query.isSuccess && !sameAsset(query.data.findings)) || (criticalQ.isSuccess && !sameAsset(criticalQ.data.findings)) || (highQ.isSuccess && !sameAsset(highQ.data.findings)));
  const generic = entity?.type === "asset" && !query.isError && !findingScopeMismatch && !invalidPage ? query.data : undefined;
  const records: RiskFinding[] = entity?.type === "finding" ? [entity.data] : entity?.type === "deployment" ? entity.data.findings ?? [] : generic?.findings ?? [];
  const stats: ReturnType<typeof entityStats> = entity ? entityStats(entity, generic, !generic || criticalQ.isError ? undefined : criticalQ.data?.total, !generic || highQ.isError ? undefined : highQ.data?.total) : {};
  return { entityType, entityId, clusterId, cluster, clusterLoading, clusterError, scopeReady, supported, entityQ, entity, matches, query, criticalQ, highQ, assetQuery, generic, findingScopeMismatch, records, stats, page, invalidPage, setPage };
}
export type RiskWorkspace = ReturnType<typeof useRiskWorkspace>;
export type RiskTabProps = { workspace: RiskWorkspace };

export function entityIdentity(entity: RiskEntity) {
  if (entity.type === "asset") return { id: entity.data.asset.id, clusterId: entity.data.asset.cluster_id, name: assetDisplayName(entity.data.asset, entity.data.image), lastSeen: entity.data.asset.last_seen_at };
  if (entity.type === "node") return { id: entity.data.node.node, clusterId: entity.data.node.cluster_id, name: entity.data.node.node, lastSeen: entity.data.node.last_seen_at };
  return { id: entity.data.id, clusterId: entity.data.cluster_id, name: entity.type === "deployment" ? `${entity.data.namespace}/${entity.data.name}` : entity.data.title, lastSeen: entity.data.last_seen_at };
}
function entityStats(entity: RiskEntity, generic: Awaited<ReturnType<typeof findings.list>> | undefined, critical?: number, high?: number): { risk?: number; critical?: number; high?: number; open?: number } {
  if (entity.type === "finding") return { risk: finiteScore(entity.data.risk_score), critical: Number(entity.data.severity === "critical"), high: Number(entity.data.severity === "high"), open: Number(["open", "in_progress"].includes(entity.data.lifecycle)) };
  if (entity.type === "deployment") return { risk: finiteScore(entity.data.risk_score), critical: entity.data.critical_count, high: entity.data.high_count };
  if (entity.type === "node") return entity.data.node.last_scanned_at ? { critical: entity.data.node.critical_vulns, high: entity.data.node.high_vulns, open: entity.data.node.open_vulns } : {};
  return { critical, high, open: generic?.lifecycle_counts ? generic.lifecycle_counts.open + generic.lifecycle_counts.in_progress : undefined };
}
export function finiteScore(value: unknown): number | undefined { return typeof value === "number" && Number.isFinite(value) ? value : undefined; }
export function detailPath(workspace: RiskWorkspace) {
  const root = `/clusters/${encodeURIComponent(workspace.clusterId!)}`;
  const segment = workspace.entityType === "asset" ? "assets" : workspace.entityType === "node" ? "nodes" : workspace.entityType === "deployment" ? "deployments" : "findings";
  return `${root}/${segment}/${encodeURIComponent(workspace.entityId)}`;
}
export function recordRows(payload: unknown, key: string): Array<Record<string, unknown>> | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const rows = (payload as Record<string, unknown>)[key];
  return Array.isArray(rows) && rows.every(row => row !== null && typeof row === "object" && !Array.isArray(row)) ? rows as Array<Record<string, unknown>> : undefined;
}
