import { useMemo, type ReactNode } from "react";
import {
  ThemeProvider as KitThemeProvider,
  useTheme as useKitTheme,
  type ThemeMode,
  type ThemeStorage,
} from "@/ui/theme";

/**
 * Constellation's adapter over the kit theme provider: three modes
 * (system / light / dark). The choice lives in localStorage under a
 * namespaced key (public/theme-bootstrap.js reads the same key before first
 * paint). A per-user server preference is a backend ask (see ADR 0009).
 */
export const THEME_STORAGE_KEY = "constellation.theme";

export function ThemeProvider({ children }: { children: ReactNode }) {
  const storage = useMemo<ThemeStorage>(
    () => ({ storageKey: THEME_STORAGE_KEY, defaultMode: "system" }),
    [],
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
