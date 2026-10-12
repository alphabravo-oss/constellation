import { useCallback, useEffect, useState, type Dispatch, type SetStateAction } from "react";

import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";

export interface SavedViewBase {
  id: string;
  name: string;
}

export function readSavedViews<T extends SavedViewBase>(storageKey: string): T[] {
  if (typeof localStorage === "undefined") return [];
  try {
    const parsed = JSON.parse(localStorage.getItem(storageKey) ?? "[]");
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isSavedViewBase) as T[];
  } catch {
    return [];
  }
}

export function writeSavedViews<T extends SavedViewBase>(storageKey: string, views: T[]) {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(storageKey, JSON.stringify(views));
  } catch {
    // Keep the UI usable in browsers where storage is disabled.
  }
}

export function appendSavedView<T extends SavedViewBase>(
  views: T[],
  name: string,
  payload: Omit<T, "id" | "name">,
  makeID: () => string = defaultSavedViewID,
): T[] {
  const trimmed = name.trim();
  if (!trimmed) return views;
  return [...views, { id: makeID(), name: trimmed, ...payload } as T];
}

// Only opt into migration when the caller can identify the previous owner.
// Generic ownerless storage keys must never be adopted by the next login.
function readOperatorViews<T extends SavedViewBase>(storageKey: string | null, legacyUserScopedKey?: string): T[] {
  if (!storageKey) return [];
  try {
    if (legacyUserScopedKey && localStorage.getItem(storageKey) === null) return readSavedViews<T>(legacyUserScopedKey);
  } catch { /* Storage is optional. */ }
  return readSavedViews<T>(storageKey);
}

interface SavedViewsState<T extends SavedViewBase> {
  storageKey: string | null;
  views: T[];
}

export function useSavedViews<T extends SavedViewBase>(key: string, options: { legacyUserScopedKey?: string } = {}) {
  const legacyKey = options.legacyUserScopedKey;
  const identity = useTablePreferencesIdentity();
  const storageKey = operatorStorageKey(key, identity);
  const [state, setState] = useState<SavedViewsState<T>>(() => ({
    storageKey,
    views: readOperatorViews<T>(storageKey, legacyKey),
  }));

  useEffect(() => {
    setState((current) => {
      if (current.storageKey === storageKey) return current;
      return { storageKey, views: readOperatorViews<T>(storageKey, legacyKey) };
    });
  }, [storageKey, legacyKey]);

  useEffect(() => {
    if (!storageKey || state.storageKey !== storageKey) return;
    writeSavedViews(storageKey, state.views);
  }, [state, storageKey]);

  const setViews = useCallback<Dispatch<SetStateAction<T[]>>>((next) => {
    setState((current) => {
      const currentViews = current.storageKey === storageKey ? current.views : readOperatorViews<T>(storageKey, legacyKey);
      const views = typeof next === "function"
        ? (next as (value: T[]) => T[])(currentViews)
        : next;
      return { storageKey, views };
    });
  }, [storageKey, legacyKey]);

  const saveView = useCallback((name: string, payload: Omit<T, "id" | "name">) => {
    setViews((current) => appendSavedView(current, name, payload));
  }, [setViews]);

  const deleteView = useCallback((id: string) => {
    setViews((current) => current.filter((view) => view.id !== id));
  }, [setViews]);

  const views = state.storageKey === storageKey ? state.views : readOperatorViews<T>(storageKey, legacyKey);
  return { views, setViews, saveView, deleteView };
}

function defaultSavedViewID() {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID();
  }
  return `view-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function isSavedViewBase(value: unknown): value is SavedViewBase {
  return Boolean(
    value &&
    typeof value === "object" &&
    typeof (value as SavedViewBase).id === "string" &&
    typeof (value as SavedViewBase).name === "string",
  );
}
