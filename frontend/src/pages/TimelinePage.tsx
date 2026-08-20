// TimelinePage — B1 unified incident timeline.
//
// One chronological investigation view that merges the four NeuVector event
// consoles (DPI threats · runtime events · network violations · audit) into a
// single time-ordered stream with type + severity filters. Backed by
// GET /api/v1/security/timeline.
import { useEffect, useMemo, useState } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";

import { securityTimeline, type TimelineItem, type TimelineSource } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { ScopeBar } from "@/components/ScopeBar";
import { PageHeader } from "@/components/ui/page";
import { Pager } from "@/components/ui/pager";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { StatusPill } from "@/components/ui/status-pill";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { fmtRelative } from "@/lib/format";
import { downloadCsv } from "@/lib/csv";

const SOURCE_META: Record<TimelineSource, { label: string; tone: "error" | "warning" | "accent" | "info" }> = {
  dpi_threat: { label: "DPI Threat", tone: "error" },
  runtime_event: { label: "Runtime", tone: "warning" },
  network_violation: { label: "Violation", tone: "accent" },
  audit: { label: "Audit", tone: "info" },
};

const ALL_SOURCES = Object.keys(SOURCE_META) as TimelineSource[];
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const TIMELINE_PAGE = 100;

export function TimelinePage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [sources, setSources] = useState<Set<TimelineSource>>(new Set(ALL_SOURCES));
  const [severities, setSeverities] = useState<Set<string>>(new Set());
  const [page, setPage] = useState(0);

  const typeParam = sources.size === ALL_SOURCES.length ? undefined : [...sources].join(",");
  const sevParam = severities.size === 0 ? undefined : [...severities].join(",");

  useEffect(() => { setPage(0); }, [typeParam, sevParam, clusterId]);
  const q = useQuery({
    queryKey: ["security-timeline", clusterId, typeParam, sevParam, page],
    queryFn: () =>
      securityTimeline.list({ cluster_id: clusterId, type: typeParam, severity: sevParam, limit: TIMELINE_PAGE, offset: page * TIMELINE_PAGE }),
    // No source selected ⇒ nothing to fetch.
    enabled: sources.size > 0,
    placeholderData: keepPreviousData,
  });

  const items = useMemo<TimelineItem[]>(() => q.data?.items ?? [], [q.data]);

  const toggle = <T,>(set: Set<T>, v: T): Set<T> => {
    const next = new Set(set);
    next.has(v) ? next.delete(v) : next.add(v);
    return next;
  };

  if (clusterLoading) return <LoadingState label="Loading cluster…" />;

  return (
    <div className="space-y-4" data-testid="timeline-page" data-cluster-id={clusterId ?? ""}>
      <ScopeBar />
      <PageHeader
        title="Incident Timeline"
        description="Unified, time-ordered stream across DPI threats, runtime events, network violations, and audit — NeuVector's four event consoles in one investigation view."
        actions={
          <button
            type="button"
            disabled={items.length === 0}
            onClick={() => downloadCsv("constellation-security-events", ["Time", "Source", "Severity", "Title", "Namespace", "Workload", "Reference"],
              items.map((it) => [it.at, it.source, it.severity, it.title, it.namespace ?? "", it.workload_id ?? "", it.ref ?? ""]))}
            className="rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent disabled:opacity-40"
          >Export CSV</button>
        }
      />

      <div className="flex flex-wrap items-center gap-4 rounded-md border border-border bg-card px-3 py-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-medium text-muted-foreground mr-1">Type</span>
          {ALL_SOURCES.map((s) => (
            <FilterChip key={s} active={sources.has(s)} onClick={() => setSources((prev) => toggle(prev, s))}>
              {SOURCE_META[s].label}
            </FilterChip>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-medium text-muted-foreground mr-1">Severity</span>
          {SEVERITIES.map((s) => (
            <FilterChip key={s} active={severities.has(s)} onClick={() => setSeverities((prev) => toggle(prev, s))}>
              {s}
            </FilterChip>
          ))}
        </div>
      </div>

      {q.isPending && sources.size > 0 ? (
        <LoadingState label="Loading timeline…" />
      ) : q.isError ? (
        <ErrorState title="Failed to load the incident timeline." error={q.error} />
      ) : items.length === 0 ? (
        <EmptyState title={page > 0 ? "No more events" : "No events"} hint="No events match the current filters in the selected window." />
      ) : (
        <>
        <ol className="relative space-y-1 border-l border-border pl-4" data-testid="timeline-list">
          {items.map((it) => (
            <li key={`${it.source}:${it.id}`} className="relative">
              <span className="absolute -left-[21px] top-3 h-2 w-2 rounded-full bg-border" aria-hidden />
              <div className="flex items-start gap-2 rounded-md border border-border bg-card px-3 py-2">
                <SeverityBadge severity={it.severity} size="xs" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <StatusPill label={SOURCE_META[it.source].label} tone={SOURCE_META[it.source].tone} />
                    <span className="truncate text-xs font-medium">{it.title}</span>
                  </div>
                  <div className="text-[10px] font-mono text-muted-foreground">
                    {[it.namespace, it.workload_id, it.ref].filter(Boolean).join(" · ")}
                  </div>
                </div>
                <span className="shrink-0 text-[10px] text-muted-foreground" title={it.at}>
                  {fmtRelative(it.at)}
                </span>
              </div>
            </li>
          ))}
        </ol>
        <Pager page={page} pageSize={TIMELINE_PAGE} hasMore={q.data?.has_more} rowsOnPage={items.length} onPage={setPage} />
        </>
      )}
    </div>
  );
}

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded-full border px-2.5 py-0.5 text-[11px] capitalize transition-colors ${
        active
          ? "border-primary bg-primary/10 text-primary"
          : "border-border bg-transparent text-muted-foreground hover:bg-muted/40"
      }`}
      aria-pressed={active}
    >
      {children}
    </button>
  );
}
