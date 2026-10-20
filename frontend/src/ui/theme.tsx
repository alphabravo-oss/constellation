import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { Monitor, Moon, Sun } from "lucide-react";
import { cn } from "./cn";

export type ThemeMode = "light" | "dark" | "system";
export const THEME_MODES: readonly ThemeMode[] = ["system", "light", "dark"];

/**
 * Where the preference lives. The kit ships a localStorage adapter; a product
 * with a per-user preferences API passes a server-backed one (`serverValue`
 * wins whenever it is defined, and `onChange` is called for every change).
 */
export interface ThemeStorage {
  /** Namespaced key — never a bare "theme" (co-hosted apps share origins). */
  storageKey: string;
  /** Authoritative value from the server, when the user is signed in. */
  serverValue?: ThemeMode;
  /** Persist a change (server and/or local). */
  onChange?: (mode: ThemeMode) => void;
  /** Theme used before any preference is known. */
  defaultMode?: ThemeMode;
}

interface ThemeContextValue {
  mode: ThemeMode;
  resolved: "light" | "dark";
  setMode: (mode: ThemeMode) => void;
  cycle: () => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  mode: "system",
  resolved: "dark",
  setMode: () => {},
  cycle: () => {},
});

export function isThemeMode(value: unknown): value is ThemeMode {
  return value === "light" || value === "dark" || value === "system";
}

function readStored(key: string, fallback: ThemeMode): ThemeMode {
  try {
    const stored = localStorage.getItem(key);
    return isThemeMode(stored) ? stored : fallback;
  } catch {
    return fallback;
  }
}

function systemDark(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  );
}

export function resolveTheme(mode: ThemeMode): "light" | "dark" {
  if (mode === "system") return systemDark() ? "dark" : "light";
  return mode;
}

function applyTheme(mode: ThemeMode) {
  const dark = resolveTheme(mode) === "dark";
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.style.colorScheme = dark ? "dark" : "light";
}

export function ThemeProvider({
  storage,
  children,
}: {
  storage: ThemeStorage;
  children: ReactNode;
}) {
  const defaultMode = storage.defaultMode ?? "system";
  const [local, setLocal] = useState<ThemeMode>(() =>
    readStored(storage.storageKey, defaultMode),
  );
  const mode = storage.serverValue ?? local;

  const setMode = useCallback(
    (next: ThemeMode) => {
      setLocal(next);
      try {
        localStorage.setItem(storage.storageKey, next);
      } catch {
        // Storage unavailable: the in-session value still applies.
      }
      storage.onChange?.(next);
    },
    [storage],
  );

  const cycle = useCallback(() => {
    const index = THEME_MODES.indexOf(mode);
    setMode(THEME_MODES[(index + 1) % THEME_MODES.length]);
  }, [mode, setMode]);

  useEffect(() => {
    applyTheme(mode);
    if (mode !== "system") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = () => applyTheme("system");
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [mode]);

  const value = useMemo(
    () => ({ mode, resolved: resolveTheme(mode), setMode, cycle }),
    [mode, setMode, cycle],
  );
  return (
    <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
  );
}

export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}

const modeLabel: Record<ThemeMode, string> = {
  system: "System",
  light: "Light",
  dark: "Dark",
};

/** Header icon button that cycles system → light → dark. */
export function ThemeToggle({ className }: { className?: string }) {
  const { mode, cycle } = useTheme();
  const Icon = mode === "dark" ? Moon : mode === "light" ? Sun : Monitor;
  return (
    <button
      type="button"
      onClick={cycle}
      aria-label={`Theme: ${modeLabel[mode]}. Switch theme`}
      title={`Theme: ${modeLabel[mode]}`}
      className={cn(
        "inline-flex h-8 w-8 items-center justify-center rounded-md text-muted-foreground transition-colors hover:bg-accent hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
    >
      <Icon className="h-4 w-4" />
    </button>
  );
}
