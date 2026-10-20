// ClusterSwitcher — the header scope chip in cluster context. Swaps the active
// cluster while preserving the current sub-path (/clusters/A/findings →
// /clusters/B/findings), with a search field once the fleet grows and a way
// back to all clusters.
import { useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Check, ChevronsUpDown, Search } from "lucide-react";

import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
  StatusDot,
  Tooltip,
  type StatusTone,
} from "@/ui";

export function clusterStateTone(state?: string): StatusTone {
  if (state === "connected" || state === "healthy" || state === "ready") return "success";
  if (state === "degraded" || state === "warn" || state === "stale") return "warning";
  if (state === "disconnected" || state === "error" || state === "failed") return "error";
  return "neutral";
}

export function ClusterSwitcher() {
  const { clusterId, cluster, allClusters } = useCluster();
  const navigate = useNavigate();
  const location = useLocation();
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return allClusters;
    return allClusters.filter((c) => c.name.toLowerCase().includes(q) || c.id.toLowerCase().includes(q));
  }, [allClusters, query]);

  function pickCluster(nextID: string) {
    const m = location.pathname.match(/^\/clusters\/[^/]+\/(.+)$/);
    const subPath = m?.[1] ?? "dashboard";
    // Entity pages (ids) do not exist in the other cluster: keep the section only.
    const section = subPath.split("/")[0];
    navigate({ href: `/clusters/${nextID}/${section === "runtime" && subPath.startsWith("runtime/baselines") ? "runtime/baselines" : section}` });
  }

  const label = cluster?.name ?? "Cluster";
  const tone = clusterStateTone(cluster?.state);

  return (
    <Menu modal={false} onOpenChange={(open) => { if (open) { setQuery(""); setTimeout(() => inputRef.current?.focus(), 0); } }}>
      <Tooltip content={cluster?.name ? <span className="font-mono text-micro">{cluster.name}</span> : null} side="bottom">
        <MenuTrigger asChild>
          {/* Same chrome as the kit ScopeChip, but the label grows with its
              content up to 280 px before truncating (full name in the tooltip). */}
          <button
            type="button"
            data-testid="cluster-switcher"
            aria-label={`Cluster: ${label}. Switch cluster`}
            className="flex h-8 min-w-0 max-w-[min(20rem,40vw)] shrink-0 items-center gap-1.5 rounded-md border border-border px-2 text-sm text-foreground transition-colors hover:bg-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span aria-hidden className={cn("h-2 w-2 shrink-0 rounded-full", toneDot[tone])} />
            <span className="min-w-0 max-w-[280px] truncate font-medium" data-testid="cluster-switcher-name">{label}</span>
            <ChevronsUpDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden />
          </button>
        </MenuTrigger>
      </Tooltip>
      <MenuContent align="start" className="w-72">
        <MenuLabel>Switch cluster</MenuLabel>
        <div className="px-1 pb-1">
          <div className="flex h-8 items-center gap-2 rounded-md border border-input bg-background px-2">
            <Search className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
            <input
              ref={inputRef}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.stopPropagation()}
              placeholder="Search clusters…"
              aria-label="Search clusters"
              className="h-7 w-full bg-transparent text-sm outline-none placeholder:text-muted-foreground"
              data-testid="cluster-switcher-search"
            />
          </div>
        </div>
        <div className="max-h-72 overflow-auto" data-testid="cluster-switcher-list">
          {filtered.length === 0 && <p className="px-2.5 py-2 text-meta text-muted-foreground">No matching clusters</p>}
          {filtered.map((c) => (
            <MenuItem key={c.id} onSelect={() => pickCluster(c.id)} data-testid={`cluster-switcher-option-${c.id}`}>
              <StatusDot tone={clusterStateTone(c.state)} label="" className="w-2" />
              <span className="min-w-0 flex-1 truncate">{c.name}</span>
              {c.id === clusterId && <Check className="h-3.5 w-3.5" aria-label="Current cluster" />}
            </MenuItem>
          ))}
        </div>
        <MenuSeparator />
        <MenuItem onSelect={() => navigate({ href: "/clusters" })}>
          <ArrowLeft className="h-4 w-4" aria-hidden />
          All clusters
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

const toneDot: Record<StatusTone, string> = {
  success: "bg-status-success",
  warning: "bg-status-warning",
  error: "bg-status-error",
  info: "bg-status-info",
  pending: "bg-status-pending",
  neutral: "bg-status-neutral",
};
