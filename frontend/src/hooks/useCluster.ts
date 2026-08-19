// useCluster — single source of truth for the active cluster in cluster-mode routes.
//
// Reads the :id URL param under /clusters/:id/* and resolves it against the cached
// /api/v1/clusters list (populated by the picker) with a single-cluster fallback
// to /api/v1/clusters/:id so deeplinks work without a warm cache.
//
// Pages under the /clusters/:id/* prefix should call this hook and thread the
// returned `cluster_id` into every data fetch — that is the contract that keeps
// the cluster-first IA honest: never query "all clusters" data while in cluster mode.
import { useMemo } from "react";
import { useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { clusters, type ClusterDetail, type ClusterSummary } from "@/api/client";

export interface ClusterContextValue {
  /** The cluster UUID from the URL. May be undefined briefly during route transitions. */
  clusterId: string | undefined;
  /** The resolved cluster, either from the cached list or the single-fetch fallback. */
  cluster: ClusterSummary | ClusterDetail | undefined;
  isLoading: boolean;
  error: Error | null;
  /** Convenience: full list of clusters the org has registered. */
  allClusters: ClusterSummary[];
}

/**
 * useCluster returns the active cluster context derived from /clusters/:id/* routes.
 *
 * Resolution order:
 *   1. Look in the cached `/api/v1/clusters` response (fast path — single round-trip
 *      already happens for the picker / switcher).
 *   2. Fall back to `/api/v1/clusters/:id` if the list cache is cold (deeplinks).
 *
 * A missing `:id` returns `cluster: undefined` so callers can render a redirect.
 */
export function useCluster(): ClusterContextValue {
  const params = useParams<{ id?: string }>();
  const clusterId = params.id;

  const listQ = useQuery({
    queryKey: ["clusters"],
    queryFn: () => clusters.list(),
    staleTime: 30_000,
  });

  const fromList = useMemo<ClusterSummary | undefined>(() => {
    if (!clusterId) return undefined;
    return listQ.data?.clusters.find((c) => c.id === clusterId);
  }, [clusterId, listQ.data?.clusters]);

  const detailQ = useQuery({
    queryKey: ["cluster", clusterId],
    queryFn: () => clusters.getOne(clusterId!),
    enabled: !!clusterId && !fromList && !listQ.isPending,
    staleTime: 30_000,
  });

  return {
    clusterId,
    cluster: fromList ?? detailQ.data,
    isLoading: listQ.isPending || (!fromList && detailQ.isPending && !!clusterId),
    error: (listQ.error as Error | null) ?? (detailQ.error as Error | null) ?? null,
    allClusters: listQ.data?.clusters ?? [],
  };
}
