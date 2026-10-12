import { useIsFetching, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { assets, type AssetDetail } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export const assetDetailKey = (clusterId: string | undefined, assetId: string | undefined) => ["asset", clusterId, assetId] as const;

export function assertAssetScope(data: AssetDetail, clusterId: string, assetId: string) {
  if (data.asset.id !== assetId || data.asset.cluster_id !== clusterId) {
    throw new Error("This asset does not belong to the requested cluster and asset ID.");
  }
  return data;
}

export function useAssetDetailScope() {
  const { aid } = useParams({ strict: false });
  const { clusterId, cluster, isLoading, error } = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const clusterReady = () => {
    if (!clusterId || cluster?.id !== clusterId || isLoading || error) return false;
    const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const detail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle")) return false;
    // useCluster keeps a disabled detail query when the registry resolves this
    // ID. That pending query has no data and is not an unresolved active read.
    if (detail && (detail.status === "error" || detail.fetchStatus !== "idle")) return false;
    return !registry && !detail || (registry?.data?.clusters.find((item) => item.id === clusterId) ?? detail?.data)?.id === clusterId;
  };
  const resolved = !registryFetching && !detailFetching && clusterReady();
  const key = assetDetailKey(clusterId, aid);
  const q = useQuery({
    queryKey: key,
    queryFn: async () => assertAssetScope(await assets.get(aid!), clusterId!, aid!),
    enabled: resolved && !!aid,
  });
  const recheck = () => {
    const current = qc.getQueryState<AssetDetail>(key);
    return clusterReady() && current?.status === "success" && current.fetchStatus === "idle" &&
      current.data?.asset.id === aid && current.data?.asset.cluster_id === clusterId ? current.data : undefined;
  };
  const retryCluster = () => {
    void qc.invalidateQueries({ queryKey: ["clusters"], exact: true });
    void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true });
  };
  return { clusterId, aid, resolved, clusterLoading: isLoading || !!registryFetching || !!detailFetching, clusterError: error, q, recheck, retryCluster };
}

export function assetErrorMessage(error: unknown) {
  const server = (error as { response?: { data?: { error?: string } } } | undefined)?.response?.data?.error;
  return server || (error instanceof Error ? error.message : "The request failed. Please try again.");
}

export function assetDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Not reported" : date.toLocaleString();
}
