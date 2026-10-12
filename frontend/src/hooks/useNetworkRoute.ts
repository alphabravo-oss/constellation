import { useCallback } from "react";
import { useRouteSearchParams } from "@/lib/route-search";
import { NETWORK_SAVED_WORKSPACE_TABS, type NetworkSavedWorkspaceTab } from "@/lib/network-saved-views";

export function useNetworkRoute() {
  const [params, setParams] = useRouteSearchParams();
  const update = useCallback((changes: Record<string, string | null>, replace = false, resetPage = false) => {
    setParams(current => {
      const next = new URLSearchParams(current);
      for (const [key, value] of Object.entries(changes)) {
        if (value === null || value === "") next.delete(key); else next.set(key, value);
      }
      if (resetPage) { next.delete("conversation_page"); next.delete("inspect_from"); next.delete("inspect_to"); }
      return next;
    }, { replace });
  }, [setParams]);
  const hoursValue = Number(params.get("hours"));
  const hours = Number.isInteger(hoursValue) && hoursValue > 0 && hoursValue <= 720 ? hoursValue : 24;
  const tabValue = params.get("tab");
  const workspaceTab = NETWORK_SAVED_WORKSPACE_TABS.includes(tabValue as NetworkSavedWorkspaceTab) ? tabValue as NetworkSavedWorkspaceTab : "map";
  const pageValue = Number(params.get("conversation_page"));
  const conversationPage = Number.isInteger(pageValue) && pageValue > 0 && pageValue <= 10000 ? pageValue - 1 : 0;
  return {
    params, update, hours, workspaceTab, conversationPage,
    namespace: params.get("namespace") ?? "", groupFilter: params.get("group") ?? "", verdict: params.get("verdict") ?? "",
    selectedFlowID: params.get("flow"), selectedWorkloadID: params.get("workload"),
    setHours: useCallback((value: number) => update({ hours: value === 24 ? null : String(value) }, false, true), [update]),
    setNamespace: useCallback((value: string) => update({ namespace: value }, false, true), [update]),
    setGroupFilter: useCallback((value: string) => update({ group: value }, false, true), [update]),
    setVerdict: useCallback((value: string) => update({ verdict: value }, false, true), [update]),
    setSelectedFlowID: useCallback((value: string | null) => update({ flow: value }), [update]),
    setSelectedWorkloadID: useCallback((value: string | null) => update({ workload: value }), [update]),
    setWorkspaceTab: useCallback((value: NetworkSavedWorkspaceTab) => update({ tab: value === "map" ? null : value }), [update]),
    setConversationPage: useCallback((value: number) => update({ conversation_page: value === 0 ? null : String(value + 1) }), [update]),
  };
}
