import { useEffect, useSyncExternalStore } from "react";

/**
 * Breadcrumb labels for entity pages. The header never shows raw ids: a detail
 * page registers the human name of its entity (CVE id, asset name, node name)
 * for the current path, and the header renders it as the last crumb. Until a
 * page registers one, the crumb shows the entity noun ("Finding").
 */
const labels = new Map<string, string>();
const listeners = new Set<() => void>();
let version = 0;

function emit() {
  version += 1;
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Register `label` as the crumb for `path` (defaults to the current path). */
export function useCrumbLabel(label: string | null | undefined, path?: string) {
  useEffect(() => {
    if (!label) return;
    const key = path ?? (typeof window !== "undefined" ? window.location.pathname : "");
    if (!key) return;
    labels.set(key, label);
    emit();
    return () => {
      if (labels.get(key) === label) {
        labels.delete(key);
        emit();
      }
    };
  }, [label, path]);
}

export function useCrumbLabels(): Map<string, string> {
  useSyncExternalStore(subscribe, () => version, () => version);
  return labels;
}
