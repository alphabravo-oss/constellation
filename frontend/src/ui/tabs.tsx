import {
  useCallback,
  useEffect,
  useState,
  type ComponentType,
  type KeyboardEvent,
  type ReactNode,
} from "react";
import type { LucideProps } from "lucide-react";
import { cn } from "./cn";
import { useProduct } from "./product";

export interface TabDefinition<K extends string> {
  key: K;
  label: ReactNode;
  icon?: ComponentType<LucideProps>;
  count?: number;
}

/**
 * Controlled tab strip (WAI-ARIA automatic activation: arrows/Home/End move
 * selection and focus). Pair with `useUrlTab` for `?tab=` deep links.
 */
export function Tabs<K extends string>({
  tabs,
  value,
  onChange,
  label = "Sections",
  className,
}: {
  tabs: TabDefinition<K>[];
  value: K;
  onChange: (key: K) => void;
  label?: string;
  className?: string;
}) {
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    let next: number | undefined;
    if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + tabs.length) % tabs.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = tabs.length - 1;
    if (next === undefined) return;
    event.preventDefault();
    onChange(tabs[next].key);
    const buttons =
      event.currentTarget.parentElement?.querySelectorAll<HTMLElement>(
        '[role="tab"]',
      );
    buttons?.[next]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label={label}
      className={cn(
        "flex gap-6 overflow-x-auto border-b border-border",
        className,
      )}
    >
      {tabs.map((tab, index) => {
        const active = tab.key === value;
        const Icon = tab.icon;
        return (
          <button
            key={tab.key}
            type="button"
            role="tab"
            id={`tab-${tab.key}`}
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(tab.key)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={cn(
              "flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 pb-3 text-sm font-medium transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
              active
                ? "border-foreground text-foreground"
                : "border-transparent text-muted-foreground hover:text-foreground",
            )}
          >
            {Icon ? <Icon className="h-4 w-4 shrink-0" aria-hidden /> : null}
            {tab.label}
            {tab.count !== undefined ? (
              <span className="tabular-nums text-muted-foreground">
                {tab.count}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  value,
  children,
  className,
}: {
  value: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      id={`tabpanel-${value}`}
      role="tabpanel"
      aria-labelledby={`tab-${value}`}
      tabIndex={0}
      className={cn(
        "animate-fade-in focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Route-link tab strip (for layout routes whose tabs are real pages). */
export function LinkTabs({
  tabs,
  label = "Sections",
  className,
}: {
  tabs: Array<{ to: string; label: ReactNode; active: boolean }>;
  label?: string;
  className?: string;
}) {
  const { Link } = useProduct();
  return (
    <nav aria-label={label} className={cn("flex gap-6 overflow-x-auto", className)}>
      {tabs.map((tab) => (
        <Link
          key={tab.to}
          to={tab.to}
          current={tab.active}
          className={cn(
            "flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 pb-3 text-sm font-medium transition-colors",
            tab.active
              ? "border-foreground text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground",
          )}
        >
          {tab.label}
        </Link>
      ))}
    </nav>
  );
}

/**
 * URL-synced tab state without a router dependency: reads `?<param>=` and
 * writes with history.replaceState (no new entry, no scroll jump). Products
 * with a typed router may wrap their own hook instead.
 */
export function useUrlTab<K extends string>(
  keys: readonly K[],
  fallback: K,
  param = "tab",
): [K, (next: K) => void] {
  const read = useCallback((): K => {
    if (typeof window === "undefined") return fallback;
    const raw = new URLSearchParams(window.location.search).get(param);
    return raw && (keys as readonly string[]).includes(raw) ? (raw as K) : fallback;
  }, [fallback, keys, param]);
  const [tab, setTab] = useState<K>(read);
  useEffect(() => {
    const sync = () => setTab(read());
    window.addEventListener("popstate", sync);
    return () => window.removeEventListener("popstate", sync);
  }, [read]);
  const set = useCallback(
    (next: K) => {
      const url = new URL(window.location.href);
      url.searchParams.set(param, next);
      window.history.replaceState(window.history.state, "", url);
      setTab(next);
    },
    [param],
  );
  return [tab, set];
}
