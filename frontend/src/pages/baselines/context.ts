import { useIsFetching, useQuery, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { baselines, type BaselineDetail, type BaselineMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { clusterCacheReady } from "@/lib/cluster-evidence";

export function useBaselineScope() {
  const context = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const clusterFetching = useIsFetching({ queryKey: ["cluster", context.clusterId], exact: true });
  const scopeReady = !!context.clusterId && context.cluster?.id === context.clusterId && !context.isLoading && !context.error && !registryFetching && !clusterFetching && clusterCacheReady(qc, context.clusterId);
  const retryScope = () => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", context.clusterId] }); };
  return { ...context, qc, scopeReady, retryScope };
}
export const baselineKey = (workload: string, clusterId: string | undefined) => ["baseline", workload, clusterId] as const;
export function useBaselineContext() {
  const scope = useBaselineScope();
  const { baselineId } = useParams({ strict: false });
  const workload = baselineId ?? "";
  const q = useQuery({ queryKey: baselineKey(workload, scope.clusterId), enabled: scope.scopeReady && !!workload, queryFn: () => baselines.get(workload, { cluster_id: scope.clusterId }) });
  const matches = q.data?.workload_id === workload && q.data.cluster_id === scope.clusterId;
  const profile = scope.scopeReady && matches && !q.isError ? q.data : undefined;
  const ready = !!profile && q.isSuccess && !q.isFetching && !scope.qc.getQueryState(baselineKey(workload, scope.clusterId))?.isInvalidated;
  const retry = () => scope.scopeReady ? void q.refetch() : scope.retryScope();
  return { ...scope, workload, q, profile, ready, retry };
}
export function currentBaseline(qc: QueryClient, clusterId: string, workload: string) {
  const state = qc.getQueryState<BaselineDetail>(baselineKey(workload, clusterId));
  if (!clusterCacheReady(qc, clusterId) || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || state.data?.cluster_id !== clusterId || state.data.workload_id !== workload) throw new Error("Refresh and review this exact workload before saving. Your draft is preserved.");
  return state.data;
}
export function baselineRevision(p: BaselineDetail) { return JSON.stringify({ cluster: p.cluster_id, workload: p.workload_id, mode: p.mode, rules: [...p.rules].sort((a, b) => a.rule_id.localeCompare(b.rule_id)) }); }
export function baselinePath(clusterId: string, workload: string) { return `/clusters/${encodeURIComponent(clusterId)}/runtime/baselines/${encodeURIComponent(workload)}`; }
export function adjacentModes(mode: BaselineMode): BaselineMode[] { return mode === "learn" ? ["monitor"] : mode === "monitor" ? ["learn", "enforce"] : mode === "enforce" ? ["monitor"] : []; }
export const SOURCE_NOTE = "Process observations and 24-hour alert/block counts derive from the latest 1,000 retained process events for the workload and its owned pods. They are samples, not complete activity totals. Configured mode does not establish agent enforcement.";
