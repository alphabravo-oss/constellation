import { useCallback, useEffect, useState, type Dispatch, type SetStateAction } from "react";

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

interface SavedViewsState<T extends SavedViewBase> {
  storageKey: string;
  views: T[];
}

export function useSavedViews<T extends SavedViewBase>(storageKey: string) {
  const [state, setState] = useState<SavedViewsState<T>>(() => ({
    storageKey,
    views: readSavedViews<T>(storageKey),
  }));

  useEffect(() => {
    setState((current) => {
      if (current.storageKey === storageKey) return current;
      return { storageKey, views: readSavedViews<T>(storageKey) };
    });
  }, [storageKey]);

  useEffect(() => {
    if (state.storageKey !== storageKey) return;
    writeSavedViews(storageKey, state.views);
  }, [state, storageKey]);

  const setViews = useCallback<Dispatch<SetStateAction<T[]>>>((next) => {
    setState((current) => {
      const currentViews = current.storageKey === storageKey ? current.views : readSavedViews<T>(storageKey);
      const views = typeof next === "function"
        ? (next as (value: T[]) => T[])(currentViews)
        : next;
      return { storageKey, views };
    });
  }, [storageKey]);

  const saveView = useCallback((name: string, payload: Omit<T, "id" | "name">) => {
    setViews((current) => appendSavedView(current, name, payload));
  }, [setViews]);

  const deleteView = useCallback((id: string) => {
    setViews((current) => current.filter((view) => view.id !== id));
  }, [setViews]);

  const views = state.storageKey === storageKey ? state.views : readSavedViews<T>(storageKey);
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
