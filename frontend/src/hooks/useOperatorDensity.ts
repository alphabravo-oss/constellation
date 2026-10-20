import { useEffect, useState } from "react";
import type { Density } from "@/components/ui/data-table";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";

function readDensity(key: string | null): Density {
  try {
    const value = key ? localStorage.getItem(key) : null;
    return value === "compact" || value === "comfy" ? value : "cozy";
  } catch { return "cozy"; }
}

export function useOperatorDensity(key: string) {
  const storageKey = operatorStorageKey(key, useTablePreferencesIdentity());
  const [state, setState] = useState(() => ({ key: storageKey, value: readDensity(storageKey) }));
  const value = state.key === storageKey ? state.value : readDensity(storageKey);
  useEffect(() => {
    if (state.key !== storageKey) setState({ key: storageKey, value: readDensity(storageKey) });
  }, [state.key, storageKey]);
  useEffect(() => {
    if (!storageKey || state.key !== storageKey) return;
    try { localStorage.setItem(storageKey, state.value); } catch { /* Storage is optional. */ }
  }, [state, storageKey]);
  return [value, (next: Density) => setState({ key: storageKey, value: next })] as const;
}
