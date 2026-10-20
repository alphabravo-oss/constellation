import { useCallback, useMemo, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  isThemeMode,
  ThemeProvider as KitThemeProvider,
  useTheme as useKitTheme,
  type ThemeMode,
  type ThemeStorage,
} from "@/ui/theme";
import { mePreferences, type UserPreferences } from "@/api/client";
import { useAuth } from "@/contexts/AuthContext";

/**
 * Constellation's adapter over the kit theme provider: three modes
 * (system / light / dark). Signed in, the server preference
 * (`GET/PUT /api/v1/me/preferences`) owns the choice; before sign-in (and if
 * the endpoint is unavailable) it lives in localStorage under a namespaced
 * key that public/theme-bootstrap.js reads before first paint.
 */
export const THEME_STORAGE_KEY = "constellation.theme";

export function ThemeProvider({ children }: { children: ReactNode }) {
  const { me } = useAuth();
  const queryClient = useQueryClient();
  const key = useMemo(() => ["me", "preferences", me?.org_id, me?.user_id] as const, [me?.org_id, me?.user_id]);
  const preferences = useQuery({
    queryKey: key,
    queryFn: () => mePreferences.get(),
    enabled: !!me,
    staleTime: 5 * 60_000,
    retry: false,
  });
  const save = useMutation({
    mutationFn: (theme: ThemeMode) => mePreferences.put({ theme }),
    onSuccess: (data) => queryClient.setQueryData<UserPreferences>(key, data),
  });
  const serverValue = me && preferences.data && isThemeMode(preferences.data.theme) ? preferences.data.theme : undefined;
  const onChange = useCallback(
    (mode: ThemeMode) => {
      if (!me) return;
      queryClient.setQueryData<UserPreferences>(key, (current) => ({ ...(current ?? {}), theme: mode }));
      save.mutate(mode);
    },
    // save.mutate is stable across renders.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [key, me, queryClient],
  );
  const storage = useMemo<ThemeStorage>(
    () => ({ storageKey: THEME_STORAGE_KEY, defaultMode: "system", serverValue, onChange }),
    [onChange, serverValue],
  );
  return <KitThemeProvider storage={storage}>{children}</KitThemeProvider>;
}

/** Back-compat surface: `theme` is the resolved theme; `toggle` cycles modes. */
// eslint-disable-next-line react-refresh/only-export-components
export function useTheme(): {
  theme: "light" | "dark";
  mode: ThemeMode;
  setMode: (mode: ThemeMode) => void;
  toggle: () => void;
} {
  const { mode, resolved, setMode, cycle } = useKitTheme();
  return { theme: resolved, mode, setMode, toggle: cycle };
}
