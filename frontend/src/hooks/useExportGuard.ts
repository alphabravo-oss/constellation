import { useEffect, useRef } from "react";
import { useQueryClient, type QueryClient, type QueryKey } from "@tanstack/react-query";
import type { ScanInventoryDownloadGuard } from "@/api/client";

/** A response may download only while the operator and reviewed evidence stay current. */
export function useExportGuard(context: string, disabled: boolean, isCurrent?: () => boolean) {
  const client = useQueryClient();
  const current = useRef({ context, disabled, isCurrent, generation: 0 });
  const generation = current.current.generation + (current.current.context !== context || current.current.disabled !== disabled ? 1 : 0);
  current.current = { context, disabled, isCurrent, generation };
  const mounted = useRef(false);
  useEffect(() => {
    mounted.current = true;
    // Invalidation/refetch can complete before React renders. Remember the loss of
    // freshness so a later ready state cannot revive an earlier response.
    const unsubscribe = client.getQueryCache().subscribe(() => {
      if (current.current.isCurrent && !current.current.isCurrent()) current.current.generation += 1;
    });
    return () => { mounted.current = false; unsubscribe(); };
  }, [client]);
  return (): ScanInventoryDownloadGuard => {
    const captured = { context, generation };
    return () => mounted.current && !current.current.disabled && captured.context === current.current.context && captured.generation === current.current.generation && (current.current.isCurrent?.() ?? true);
  };
}

export function exportQueryReady(client: QueryClient, key: QueryKey, reviewed?: unknown) {
  const state = client.getQueryState(key);
  return state?.status === "success" && state.fetchStatus === "idle" && !state.isInvalidated && (reviewed === undefined || state.data === reviewed);
}
