import { useCallback, useSyncExternalStore } from "react";

/**
 * Header scope: "Include system workloads". One persisted switch replaces the
 * page-level "Include Constellation system workloads" checkboxes and the
 * per-inventory "Platform hidden" buttons. Pages read the effective value with
 * `useIncludeSystem()` — an explicit `include_system` URL parameter (saved views,
 * shared links) still wins over the stored preference.
 */
const STORAGE_KEY = "constellation:include-system";
const LEGACY_PLATFORM_KEY = "constellation:hide-platform-components";
const listeners = new Set<() => void>();

function read(): boolean {
  if (typeof window === "undefined") return false;
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    if (stored !== null) return stored === "true";
    // Migrate the old inventory preference (hide = true → include = false).
    return window.localStorage.getItem(LEGACY_PLATFORM_KEY) === "false";
  } catch {
    return memory;
  }
}

let memory = false;

export function setIncludeSystemPreference(value: boolean) {
  memory = value;
  try {
    window.localStorage.setItem(STORAGE_KEY, String(value));
    window.localStorage.setItem(LEGACY_PLATFORM_KEY, String(!value));
  } catch {
    // Storage can be unavailable in hardened/private contexts; memory still applies.
  }
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === STORAGE_KEY) listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

/** The stored preference (no URL override). */
export function useIncludeSystemPreference(): [boolean, (value: boolean) => void] {
  const value = useSyncExternalStore(subscribe, read, () => false);
  const set = useCallback((next: boolean) => setIncludeSystemPreference(next), []);
  return [value, set];
}

/**
 * Effective scope for a page: `include_system=true|false` in the URL wins,
 * otherwise the header preference.
 */
export function useIncludeSystem(searchParams?: URLSearchParams): boolean {
  const [preference] = useIncludeSystemPreference();
  const explicit = searchParams?.get("include_system");
  if (explicit === "true") return true;
  if (explicit === "false") return false;
  return preference;
}
