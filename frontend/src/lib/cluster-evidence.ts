import { type QueryClient } from "@tanstack/react-query";

export function clusterCacheReady(qc: QueryClient, id: string) {
  const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
  const detail = qc.getQueryState<{ id: string }>(["cluster", id]);
  if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle" || registry.isInvalidated)) return false;
  if (detail && (detail.status === "error" || detail.fetchStatus !== "idle" || detail.isInvalidated)) return false;
  if (!registry && !detail) return true;
  return (registry?.data?.clusters.find(item => item.id === id) ?? detail?.data)?.id === id;
}
