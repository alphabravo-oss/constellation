import { useCallback, useEffect, useMemo, useRef, useState, type SetStateAction } from "react";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";

export interface SavedViewBase { id: string; name: string }
export type SavedViewValidator<T> = (value: unknown) => value is T;
export type SavedViewWriteResult = { ok: true } | { ok: false; error: string };
const STORAGE_ERROR = "Saved views could not be stored in this browser. Check browser storage and try again.";
const SESSION_ERROR = "Saved views require an available organization and user session.";

function validBase(value: unknown): value is SavedViewBase {
  if (!value || typeof value !== "object") return false;
  const view = value as SavedViewBase;
  return typeof view.id === "string" && Boolean(view.id.trim()) && typeof view.name === "string" && Boolean(view.name.trim()) && view.name.trim().length <= 120;
}
function parseViews<T extends SavedViewBase>(raw: string | null, validate?: SavedViewValidator<T>): { views: T[]; error: string | null } {
  if (raw === null) return { views: [], error: null };
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) throw new Error("invalid saved-view collection");
    const seen = new Set<string>();
    const views = parsed.filter((value): value is T => { if (!validBase(value) || (validate && !validate(value)) || seen.has(value.id)) return false; seen.add(value.id); return true; });
    const rejected = parsed.length - views.length;
    return { views, error: rejected ? `${rejected} saved view ${rejected === 1 ? "record was" : "records were"} rejected because the stored data is invalid. Valid views remain available.` : null };
  } catch { return { views: [], error: "Saved view data was rejected because the stored collection is invalid." }; }
}
export function readSavedViews<T extends SavedViewBase>(key: string, validate?: SavedViewValidator<T>): T[] {
  try { return typeof localStorage === "undefined" ? [] : parseViews<T>(localStorage.getItem(key), validate).views; }
  catch { return []; }
}
export function writeSavedViews<T extends SavedViewBase>(key: string, views: T[]): SavedViewWriteResult {
  try { if (typeof localStorage === "undefined") return { ok: false, error: STORAGE_ERROR }; localStorage.setItem(key, JSON.stringify(views)); return { ok: true }; }
  catch { return { ok: false, error: STORAGE_ERROR }; }
}
export function appendSavedView<T extends SavedViewBase>(views: T[], name: string, payload: Omit<T, "id" | "name">, makeID: () => string = defaultSavedViewID): T[] {
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 120) return views;
  return [...views, { ...payload, id: makeID(), name: trimmed } as T];
}
function loadOperatorViews<T extends SavedViewBase>(key: string | null, legacyKey?: string, validate?: SavedViewValidator<T>): { views: T[]; error: string | null } {
  if (!key || typeof localStorage === "undefined") return { views: [], error: null };
  const current = localStorage.getItem(key);
  return parseViews<T>(current === null && legacyKey ? localStorage.getItem(legacyKey) : current, validate);
}
interface State<T> { key: string | null; views: T[]; error: string | null }
export function useSavedViews<T extends SavedViewBase>(key: string, options: { legacyUserScopedKey?: string; validate?: SavedViewValidator<T> } = {}) {
  const { legacyUserScopedKey: legacyKey, validate } = options;
  const identity = useTablePreferencesIdentity();
  const storageKey = identity?.org_id.trim() && identity.user_id.trim() ? operatorStorageKey(key, identity) : null;
  const validator = useRef(validate);
  validator.current = validate;
  const activeKey = useRef(storageKey);
  activeKey.current = storageKey;
  const readState = useCallback((): State<T> => {
    try { return { key: storageKey, ...loadOperatorViews<T>(storageKey, legacyKey, validator.current) }; }
    catch { return { key: storageKey, views: [], error: "Saved views could not be read from this browser." }; }
  }, [storageKey, legacyKey]);
  const [state, setState] = useState<State<T>>(readState);
  useEffect(() => { setState(readState()); }, [readState]);
  const active = state.key === storageKey ? state : readState();
  const setViews = useCallback((next: SetStateAction<T[]>): SavedViewWriteResult => {
    if (activeKey.current !== storageKey) return { ok: false, error: "The saved-view owner or inventory changed. Retry from the current view." };
    if (!storageKey) {
      // Preserve the generic hook's anonymous memory-only behavior; this result
      // never claims persistence. Dedicated forms require resolved identity.
      setState(current => ({ key: null, views: typeof next === "function" ? next(current.key === null ? current.views : []) : next, error: SESSION_ERROR }));
      return { ok: false, error: SESSION_ERROR };
    }
    let views: T[];
    try {
      // Read and write during the action, before navigation/unmount. Neither
      // persistence nor updater execution runs in a replayable state effect.
      const current = loadOperatorViews<T>(storageKey, legacyKey, validator.current).views;
      views = typeof next === "function" ? next(current) : next;
      if (!views.every(value => validBase(value) && (!validator.current || validator.current(value)))) throw new Error("invalid views");
    } catch { const result = { ok: false as const, error: STORAGE_ERROR }; setState(current => ({ key: storageKey, views: current.key === storageKey ? current.views : [], error: result.error })); return result; }
    const result = writeSavedViews(storageKey, views);
    if (result.ok) setState({ key: storageKey, views, error: null });
    else setState(current => ({ key: storageKey, views: current.key === storageKey ? current.views : [], error: result.error }));
    return result;
  }, [storageKey, legacyKey]);
  const saveView = useCallback((name: string, payload: Omit<T, "id" | "name">): SavedViewWriteResult => {
    if (!name.trim() || name.trim().length > 120) return { ok: false, error: "Provide a view name of 1 to 120 characters." };
    return setViews(current => appendSavedView(current, name, payload));
  }, [setViews]);
  const deleteView = useCallback((id: string) => setViews(current => current.filter(view => view.id !== id)), [setViews]);
  const visibleViews = useMemo(() => validate ? active.views.filter(validate) : active.views, [active.views, validate]);
  return { views: visibleViews, setViews, saveView, deleteView, persistenceError: active.error, canPersist: Boolean(storageKey) };
}
function defaultSavedViewID() { return typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `view-${Date.now()}-${Math.random().toString(36).slice(2)}`; }
