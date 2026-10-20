import { useIsFetching, useQueryClient } from "@tanstack/react-query";
import { useCluster } from "@/hooks/useCluster";
import { apiErrorText } from "@/lib/api-error";

/** Shared only by the entity detail pages: a route ID alone is not scope proof. */
export function useEntityClusterScope(required = true) {
  const { clusterId, cluster, isLoading, error } = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const recheck = () => {
    if (!required) return true;
    if (!clusterId || cluster?.id !== clusterId || isLoading || error) return false;
    const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const detail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle")) return false;
    if (detail && (detail.status === "error" || detail.fetchStatus !== "idle")) return false;
    return !registry && !detail || (registry?.data?.clusters.find((item) => item.id === clusterId) ?? detail?.data)?.id === clusterId;
  };
  return {
    clusterId, cluster, error,
    ready: (!required || !registryFetching && !detailFetching) && recheck(),
    loading: required && (isLoading || !!registryFetching || !!detailFetching),
    recheck,
    retry: () => {
      void qc.invalidateQueries({ queryKey: ["clusters"], exact: true });
      void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true });
    },
  };
}

export function entityDetailError(error: unknown) {
  return apiErrorText(error, "The evidence request failed. Please try again.");
}
