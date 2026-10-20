import { useParams } from "@tanstack/react-router";
import { useIsFetching, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { deployments, type DeploymentDetail, type BaselineMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { clusterCacheReady } from "@/lib/cluster-evidence";
export const deploymentKey = (clusterId: string | undefined, did: string | undefined) => ["deployment", clusterId, did] as const;
export function currentDeployment(qc: QueryClient, clusterId: string, did: string) {
  const source = qc.getQueryState<DeploymentDetail>(deploymentKey(clusterId, did));
  if (!clusterCacheReady(qc, clusterId) || source?.status !== "success" || source.fetchStatus !== "idle" || source.isInvalidated || source.data?.id !== did || source.data.cluster_id !== clusterId) throw new Error("Refresh and review this exact deployment before submitting. Your draft is preserved.");
  return source.data;
}
export function useDeploymentContext() {
  const { did } = useParams({ strict: false });
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const clusterFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !registryFetching && !clusterFetching && clusterCacheReady(qc, clusterId);
  const q = useQuery({ queryKey: deploymentKey(clusterId, did), queryFn: () => deployments.get(did!), enabled: scopeReady && !!did });
  const matches = !!did && q.data?.id === did && q.data.cluster_id === clusterId;
  const detail = scopeReady && !q.isError && matches ? q.data : undefined;
  return { did, clusterId, cluster, clusterLoading, clusterError, scopeReady, q, matches, detail, ready: !!detail && q.isSuccess && !q.isFetching, qc };
}
export function workloadID(detail: DeploymentDetail) { return `${detail.namespace}/${detail.name}`; }
export function profileIsOwned(detail: DeploymentDetail, profile: { cluster_id?: string; workload_id: string; control_workload_id?: string }) {
  const base = workloadID(detail);
  return profile.cluster_id === detail.cluster_id && (profile.control_workload_id ?? profile.workload_id) === base && [base, ...(detail.workload_ids ?? [])].includes(profile.workload_id);
}
export function policyIsCurrent(detail: DeploymentDetail) { const p = detail.network_policy; return !!p && p.cluster_id === detail.cluster_id && p.workload === workloadID(detail); }
export function nextMode(mode: BaselineMode, forward: boolean): BaselineMode | undefined { return forward ? mode === "learn" ? "monitor" : mode === "monitor" ? "enforce" : undefined : mode === "enforce" ? "monitor" : mode === "monitor" ? "learn" : undefined; }
export function actionURL(clusterId: string, did: string, action: string, fields: Record<string, string> = {}) { return `/clusters/${encodeURIComponent(clusterId)}/deployments/${encodeURIComponent(did)}/actions/${action}${Object.keys(fields).length ? `?${new URLSearchParams(fields)}` : ""}`; }
