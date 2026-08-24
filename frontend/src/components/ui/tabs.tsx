import { type ReactNode } from "react";
import * as RadixTabs from "@radix-ui/react-tabs";
import { useSearchParams } from "react-router-dom";
import { cn } from "@/lib/cn";

/**
 * useTabParam — deep-linkable tab state backed by the URL query string (?<key>=).
 * A user can link straight to a tab, and back/forward navigates tabs. Drop-in for
 * useState: `const [tab, setTab] = useTabParam("tab", "overview")`.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useTabParam(key: string, defaultValue: string): [string, (v: string) => void] {
  const [params, setParams] = useSearchParams();
  const value = params.get(key) ?? defaultValue;
  const setValue = (v: string) => {
    const next = new URLSearchParams(params);
    if (v === defaultValue) next.delete(key);
    else next.set(key, v);
    setParams(next, { replace: true });
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
      <div className="flex items-center justify-between border-b border-border">
        <RadixTabs.List className="flex flex-wrap">
          {items.map((it) => (
            <RadixTabs.Trigger
              key={it.value}
              value={it.value}
              className={cn(
                "relative -mb-px flex items-center gap-1.5 px-3 py-2 text-sm text-muted-foreground border-b-2 border-transparent transition-colors",
                "hover:text-foreground",
                "data-[state=active]:text-foreground data-[state=active]:border-[color:var(--color-primary)]",
              )}
            >
              {it.label}
              {it.count != null && (
                <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono text-muted-foreground data-[state=active]:text-foreground">
                  {it.count}
                </span>
              )}
            </RadixTabs.Trigger>
          ))}
        </RadixTabs.List>
        {rightSlot && <div className="pr-1">{rightSlot}</div>}
      </div>
      {items.map((it) => (
        <RadixTabs.Content key={it.value} value={it.value} className="mt-4 outline-none focus-visible:outline-none">
          {it.content}
        </RadixTabs.Content>
      ))}
    </RadixTabs.Root>
  );
}
