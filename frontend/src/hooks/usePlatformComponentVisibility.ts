import { useEffect, useState } from "react";

const STORAGE_KEY = "constellation:hide-platform-components";

function initialPreference(): boolean {
  if (typeof window === "undefined") return true;
  try {
    return window.localStorage.getItem(STORAGE_KEY) !== "false";
  } catch {
    return true;
  }
}

/** A shared, persisted presentation preference used by workload inventories. */
export function usePlatformComponentVisibility() {
  const [hidePlatformComponents, setHidePlatformComponents] = useState(initialPreference);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, String(hidePlatformComponents));
    } catch {
      // Storage can be unavailable in hardened/private browser contexts. The
      // in-memory preference still works for the current page.
    }
  }, [hidePlatformComponents]);

  return [hidePlatformComponents, setHidePlatformComponents] as const;
}
