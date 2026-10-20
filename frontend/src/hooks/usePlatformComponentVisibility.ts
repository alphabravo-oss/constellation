import { useCallback } from "react";
import { useIncludeSystemPreference } from "@/lib/system-scope";

/**
 * Platform-component visibility for workload inventories. Backed by the header
 * scope switch ("Include system workloads"): hidden = !includeSystem.
 */
export function usePlatformComponentVisibility() {
  const [includeSystem, setIncludeSystem] = useIncludeSystemPreference();
  const setHidden = useCallback(
    (hidden: boolean | ((current: boolean) => boolean)) => {
      const next = typeof hidden === "function" ? hidden(!includeSystem) : hidden;
      setIncludeSystem(!next);
    },
    [includeSystem, setIncludeSystem],
  );
  return [!includeSystem, setHidden] as const;
}
