import { type ReactNode } from "react";
import * as RadixTabs from "@radix-ui/react-tabs";

import { useRouteSearchParams } from "@/lib/route-search";
import { cn } from "@/lib/cn";

/**
 * useTabParam — deep-linkable tab state backed by the URL query string (?<key>=).
 * A user can link straight to a tab, and back/forward navigates tabs. Drop-in for
 * useState: `const [tab, setTab] = useTabParam("tab", "overview")`.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useTabParam(key: string, defaultValue: string): [string, (v: string) => void] {
  const [params, setParams] = useRouteSearchParams();
  const value = params.get(key) ?? defaultValue;
  const setValue = (v: string) => {
    setParams(current => {
      if (v === defaultValue) current.delete(key);
      else current.set(key, v);
      return current;
    });
  };
  return [value, setValue];
}

/**
 * Tabs — Radix Tabs wrapped with a consistent underlined-pill style.
 * Tab triggers display an optional badge count.
 */
export function Tabs({
  value,
  onValueChange,
  items,
  rightSlot,
  className,
}: {
  value: string;
  onValueChange: (v: string) => void;
  items: Array<{ value: string; label: string; count?: number; content: ReactNode }>;
  rightSlot?: ReactNode;
  className?: string;
}) {
  return (
    <RadixTabs.Root value={value} onValueChange={onValueChange} className={className}>
      <div className="flex items-center justify-between gap-4 border-b border-border">
        <RadixTabs.List className="flex gap-6 overflow-x-auto">
          {items.map((it) => (
            <RadixTabs.Trigger
              key={it.value}
              value={it.value}
              className={cn(
                "relative -mb-px flex shrink-0 items-center gap-2 whitespace-nowrap border-b-2 border-transparent pb-3 pt-1 text-sm font-medium text-muted-foreground transition-colors",
                "hover:text-foreground focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring",
                "data-[state=active]:border-foreground data-[state=active]:text-foreground",
              )}
            >
              {it.label}
              {it.count != null && (
                <span className="tabular-nums text-muted-foreground">
                  {it.count}
                </span>
              )}
            </RadixTabs.Trigger>
          ))}
        </RadixTabs.List>
        {rightSlot && <div className="pr-1">{rightSlot}</div>}
      </div>
      {items.map((it) => (
        <RadixTabs.Content key={it.value} value={it.value} className="mt-(--gap-section) outline-none focus-visible:outline-none">
          {it.content}
        </RadixTabs.Content>
      ))}
    </RadixTabs.Root>
  );
}
