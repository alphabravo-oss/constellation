import { useCallback, useMemo } from "react";
import { useLocation, useRouter } from "@tanstack/react-router";

// Preserve the public URL contract: strings stay strings (including numeric IDs)
// and repeated filters round-trip without JSON encoding or losing unknown keys.
export function parseURLSearch(raw: string): Record<string, string | string[]> {
  const result: Record<string, string | string[]> = Object.create(null);
  for (const [key, value] of new URLSearchParams(raw)) {
    const previous = result[key];
    result[key] = previous === undefined ? value : Array.isArray(previous) ? [...previous, value] : [previous, value];
  }
  return result;
}

export function stringifyURLSearch(search: Record<string, unknown>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(search)) {
    for (const item of Array.isArray(value) ? value : [value]) {
      if (item !== undefined && item !== null) params.append(key, String(item));
    }
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : "";
}

export type SetRouteSearchParams = (
  next: URLSearchParams | Record<string, string> | ((current: URLSearchParams) => URLSearchParams),
  options?: { replace?: boolean },
) => void;

// Existing list filters use URLSearchParams; the router owns navigation/history.
// Read the latest state inside functional updates so adjacent filter changes
// don't overwrite one another using a stale render's query string.
export function useRouteSearchParams(): [URLSearchParams, SetRouteSearchParams] {
  const router = useRouter();
  const search = useLocation({ select: (location) => location.searchStr });
  const params = useMemo(() => new URLSearchParams(search), [search]);
  const setParams = useCallback<SetRouteSearchParams>((next, options) => {
    const location = router.latestLocation;
    const result = typeof next === "function" ? next(new URLSearchParams(location.searchStr)) : new URLSearchParams(next);
    void router.navigate({ href: `${location.pathname}${result.size ? `?${result}` : ""}${location.hash ? `#${location.hash}` : ""}`, replace: options?.replace, resetScroll: false });
  }, [router]);
  return [params, setParams];
}
