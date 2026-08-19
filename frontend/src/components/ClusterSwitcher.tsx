// ClusterSwitcher — sidebar pill + dropdown that swaps the active cluster while
// preserving the current sub-path (e.g. /clusters/A/findings → /clusters/B/findings).
//
// Lives at the top of the sidebar when the user is in cluster mode (/clusters/:id/*).
// Built on Radix DropdownMenu with an embedded search input so it scales past 3
// clusters without re-architecting. Includes a "Back to all clusters" item that
// routes to /clusters (the picker).
import { useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Check, ChevronsUpDown, Search, ServerCog, ArrowLeft } from "lucide-react";

import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";

export function ClusterSwitcher() {
  const { clusterId, cluster, allClusters } = useCluster();
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allClusters;
    return allClusters.filter((c) => c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q));
  }, [allClusters, query]);

  // When the user picks cluster B from cluster A's /findings page, send them to
  // cluster B's /findings (preserve sub-path); fall back to /dashboard if there
  // isn't one.
  function pickCluster(nextID: string) {
    setOpen(false);
    const m = location.pathname.match(/^\/clusters\/[^/]+\/(.+)$/);
    const subPath = m?.[1] ?? "dashboard";
    navigate(`/clusters/${nextID}/${subPath}`);
  }

  const label = cluster?.name ?? clusterId?.slice(0, 8) ?? "Select cluster";

  return (
    <DropdownMenu.Root
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        if (o) setTimeout(() => inputRef.current?.focus(), 0);
      }}
    >
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          data-testid="cluster-switcher"
          className={cn(
            "flex w-full items-center gap-2 rounded-md border border-border bg-card px-2 py-1.5 text-left",
            "hover:bg-accent transition-colors",
          )}
          aria-label="Switch cluster"
        >
          <ServerCog className="h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" aria-hidden />
          <span className="flex min-w-0 flex-col leading-tight">
            <span className="text-[9px] uppercase tracking-wider text-muted-foreground">cluster</span>
            <span className="truncate text-[12px] font-semibold">{label}</span>
          </span>
          <ChevronsUpDown className="ml-auto h-3 w-3 flex-shrink-0 text-muted-foreground" aria-hidden />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          sideOffset={6}
          align="start"
          className="z-50 w-[260px] rounded-md border border-border bg-popover p-1.5 shadow-[var(--elev-popover)]"
        >
          <div className="flex items-center gap-1.5 rounded border border-input bg-card px-2 py-1">
            <Search className="h-3 w-3 text-muted-foreground" aria-hidden />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.stopPropagation()}
              placeholder="Search clusters…"
              className="h-5 w-full bg-transparent text-xs outline-none placeholder:text-muted-foreground"
              data-testid="cluster-switcher-search"
            />
          </div>
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          <ul className="max-h-[280px] overflow-auto" data-testid="cluster-switcher-list">
            {filtered.length === 0 && (
              <li className="px-2 py-2 text-[11px] text-muted-foreground">No matches</li>
            )}
            {filtered.map((c) => {
              const active = c.id === clusterId;
              return (
                <li key={c.id}>
                  <button
                    type="button"
                    onClick={() => pickCluster(c.id)}
                    data-testid={`cluster-switcher-option-${c.id}`}
                    className={cn(
                      "flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs",
                      "hover:bg-accent transition-colors",
                      active && "bg-accent",
                    )}
                  >
                    <ServerCog className="h-3 w-3 flex-shrink-0 text-muted-foreground" aria-hidden />
                    <span className="min-w-0 flex-1 truncate font-medium">{c.name}</span>
                    {active && <Check className="h-3 w-3 text-[color:var(--color-primary)]" aria-hidden />}
                  </button>
                </li>
              );
            })}
          </ul>
          <DropdownMenu.Separator className="my-1 h-px bg-border" />
          <DropdownMenu.Item
            onSelect={() => {
              setOpen(false);
              navigate("/clusters");
            }}
            className="flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-xs outline-none data-[highlighted]:bg-accent"
          >
            <ArrowLeft className="h-3 w-3" aria-hidden />
            <span className="flex-1">Back to all clusters</span>
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
