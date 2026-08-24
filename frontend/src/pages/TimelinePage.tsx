// TimelinePage — B1 unified incident timeline.
//
// One chronological investigation view that merges the four NeuVector event
// consoles (DPI threats · runtime events · network violations · audit) into a
// single time-ordered stream with type + severity filters. Backed by
// GET /api/v1/security/timeline.
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { Bookmark, Save, SlidersHorizontal } from "lucide-react";

import { securityTimeline, type TimelineItem, type TimelineSource } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useSavedViews, type SavedViewBase } from "@/hooks/useSavedViews";
import { ScopeBar } from "@/components/ScopeBar";
import { PageHeader } from "@/components/ui/page";
import { Pager } from "@/components/ui/pager";
import { useTabParam } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { StatusPill } from "@/components/ui/status-pill";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { QueryInput } from "@/components/ui/query-input";
import { fmtRelative } from "@/lib/format";
import { downloadCsv } from "@/lib/csv";
import {
  compactTimelineFilters,
  timelineDateParam,
  timelineSavedViewSummary,
  timelineSeverityParam,
  timelineSourceParam,
  timelineTextParam,
  type TimelineFilterPayload,
} from "@/lib/timeline-filters";

const SOURCE_META: Record<TimelineSource, { label: string; tone: "error" | "warning" | "accent" | "info" }> = {
  dpi_threat: { label: "DPI Threat", tone: "error" },
  runtime_event: { label: "Runtime", tone: "warning" },
  network_violation: { label: "Violation", tone: "accent" },
  audit: { label: "Audit", tone: "info" },
};

const ALL_SOURCES = Object.keys(SOURCE_META) as TimelineSource[];
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const TIMELINE_PAGE = 100;
const SAVED_VIEWS_KEY = "constellation.timeline.views.v1";
const CATEGORY_TABS: Array<{ id: string; label: string; sources: TimelineSource[] }> = [
  { id: "all", label: "All", sources: ALL_SOURCES },
  { id: "activity", label: "Activity", sources: ["runtime_event", "audit"] },
  { id: "audit", label: "Audit", sources: ["audit"] },
  { id: "event", label: "Event", sources: ["runtime_event"] },
  { id: "incident", label: "Incident", sources: ["dpi_threat", "runtime_event", "network_violation"] },
  { id: "threat", label: "Threat", sources: ["dpi_threat", "runtime_event"] },
  { id: "violation", label: "Violation", sources: ["network_violation"] },
  { id: "security", label: "Security", sources: ["dpi_threat", "runtime_event", "network_violation"] },
];

interface TimelineSavedView extends SavedViewBase, TimelineFilterPayload {}

export function TimelinePage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [category, setCategory] = useTabParam("tab", "all");
  const [sources, setSources] = useState<Set<TimelineSource>>(new Set(ALL_SOURCES));
  const [severities, setSeverities] = useState<Set<string>>(new Set());
  const [query, setQuery] = useState("");
  const [namespace, setNamespace] = useState("");
  const [workload, setWorkload] = useState("");
  const [reference, setReference] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [selected, setSelected] = useState<TimelineItem | null>(null);
  const [page, setPage] = useState(0);
  const { views, saveView: saveStoredView, deleteView } = useSavedViews<TimelineSavedView>(SAVED_VIEWS_KEY);
  const activeCategory = category === "custom" || CATEGORY_TABS.some((tab) => tab.id === category) ? category : "all";

  useEffect(() => {
    if (activeCategory === "custom") return;
    const tab = CATEGORY_TABS.find((item) => item.id === activeCategory) ?? CATEGORY_TABS[0];
    setSources(new Set(tab.sources));
  }, [activeCategory]);

  const filters = useMemo(() => compactTimelineFilters({
    category: activeCategory,
    sources: [...sources],
    severities: [...severities],
    query,
    namespace,
    workload,
    reference,
    from,
    to,
  }), [activeCategory, sources, severities, query, namespace, workload, reference, from, to]);

  const typeParam = timelineSourceParam(filters.sources);
  const sevParam = timelineSeverityParam(filters.severities);
  const fromParam = timelineDateParam(filters.from);
  const toParam = timelineDateParam(filters.to);
  const queryParam = timelineTextParam(filters.query);
  const namespaceParam = timelineTextParam(filters.namespace);
  const workloadParam = timelineTextParam(filters.workload);
  const refParam = timelineTextParam(filters.reference);

  useEffect(() => { setPage(0); }, [typeParam, sevParam, fromParam, toParam, queryParam, namespaceParam, workloadParam, refParam, clusterId]);
  const q = useQuery({
    queryKey: ["security-timeline", clusterId, typeParam, sevParam, fromParam, toParam, queryParam, namespaceParam, workloadParam, refParam, page],
    queryFn: () =>
      securityTimeline.list({
        cluster_id: clusterId,
        type: typeParam,
        severity: sevParam,
        from: fromParam,
        to: toParam,
        q: queryParam,
        namespace: namespaceParam,
        workload: workloadParam,
        ref: refParam,
        limit: TIMELINE_PAGE,
        offset: page * TIMELINE_PAGE,
      }),
    // No source selected ⇒ nothing to fetch.
    enabled: sources.size > 0,
    placeholderData: keepPreviousData,
  });

  const items = useMemo<TimelineItem[]>(() => q.data?.items ?? [], [q.data]);

  const selectCategory = (tabID: string, nextSources: TimelineSource[]) => {
    setCategory(tabID);
    setSources(new Set(nextSources));
  };

  const saveView = () => {
    const name = window.prompt("Name this timeline view", timelineSavedViewSummary(filters));
    if (name) saveStoredView(name, filters);
  };

  const applyView = (view: TimelineSavedView) => {
    setCategory(view.category || "custom");
    setSources(new Set(view.sources.length ? view.sources : ALL_SOURCES));
    setSeverities(new Set(view.severities ?? []));
    setQuery(view.query ?? "");
    setNamespace(view.namespace ?? "");
    setWorkload(view.workload ?? "");
    setReference(view.reference ?? "");
    setFrom(view.from ?? "");
    setTo(view.to ?? "");
    setPage(0);
  };

  const clearAdvancedFilters = () => {
    setSeverities(new Set());
    setQuery("");
    setNamespace("");
    setWorkload("");
    setReference("");
    setFrom("");
    setTo("");
  };

  const toggle = <T,>(set: Set<T>, v: T): Set<T> => {
    const next = new Set(set);
    if (next.has(v)) {
      next.delete(v);
    } else {
      next.add(v);
    }
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
          <>
            {views.length > 0 && <TimelineSavedViewsMenu views={views} onApply={applyView} onDelete={deleteView} />}
            <Button type="button" size="sm" variant="outline" onClick={saveView}>
              <Save className="h-3.5 w-3.5" aria-hidden /> Save view
            </Button>
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={items.length === 0}
              onClick={() => downloadCsv("constellation-security-events", ["Time", "Source", "Severity", "Title", "Namespace", "Workload", "Reference"],
                items.map((it) => [it.at, it.source, it.severity, it.title, it.namespace ?? "", it.workload_id ?? "", it.ref ?? ""]))}
            >
              Export CSV
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap gap-1 rounded-md border border-border bg-card p-1" data-testid="timeline-category-tabs">
        {CATEGORY_TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => selectCategory(tab.id, tab.sources)}
            className={`h-7 rounded px-2.5 text-xs font-medium transition-colors ${
              activeCategory === tab.id
                ? "bg-primary/10 text-primary"
                : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
            }`}
            data-testid={`timeline-category-${tab.id}`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="space-y-3 rounded-md border border-border bg-card px-3 py-3" data-testid="timeline-advanced-filters">
        <div className="flex items-center gap-2 text-xs font-semibold">
          <SlidersHorizontal className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
          Filters
        </div>
        <div className="grid gap-2 lg:grid-cols-[minmax(260px,1.4fr)_repeat(3,minmax(130px,1fr))]">
          <QueryInput
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            onClear={() => setQuery("")}
            placeholder="search title, id, workload, namespace, ref"
            size="sm"
          />
          <FilterTextInput label="Namespace" value={namespace} onChange={setNamespace} placeholder="prod" />
          <FilterTextInput label="Workload" value={workload} onChange={setWorkload} placeholder="api" />
          <FilterTextInput label="Reference" value={reference} onChange={setReference} placeholder="policy or target" />
        </div>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <DateFilterInput label="From" value={from} onChange={setFrom} />
          <DateFilterInput label="To" value={to} onChange={setTo} />
          <div className="lg:col-span-2 flex items-end">
            <Button type="button" size="sm" variant="ghost" onClick={clearAdvancedFilters} data-testid="timeline-clear-filters">
              Clear filters
            </Button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] font-medium text-muted-foreground mr-1">Type</span>
          {ALL_SOURCES.map((s) => (
            <FilterChip key={s} active={sources.has(s)} onClick={() => { setCategory("custom"); setSources((prev) => toggle(prev, s)); }}>
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
        <TimelineActiveFilters filters={filters} onClear={clearAdvancedFilters} />
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
              <button
                type="button"
                onClick={() => setSelected(it)}
                className="flex w-full items-start gap-2 rounded-md border border-border bg-card px-3 py-2 text-left transition-colors hover:border-[color:var(--color-primary)]/40 hover:bg-accent/40"
                data-testid="timeline-event-row"
              >
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
              </button>
            </li>
          ))}
        </ol>
        <Pager page={page} pageSize={TIMELINE_PAGE} hasMore={q.data?.has_more} rowsOnPage={items.length} onPage={setPage} />
        <TimelineDetailDrawer item={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  );
}

function TimelineSavedViewsMenu({ views, onApply, onDelete }: { views: TimelineSavedView[]; onApply: (view: TimelineSavedView) => void; onDelete: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <Button type="button" size="sm" variant="outline" onClick={() => setOpen((current) => !current)}>
        <Bookmark className="h-3.5 w-3.5" aria-hidden /> Views <span className="font-mono text-muted-foreground">({views.length})</span>
      </Button>
      {open ? (
        <div
          className="absolute right-0 top-full z-30 mt-1 w-[300px] rounded-md border border-border bg-popover p-2 shadow-[var(--elev-popover)]"
          onMouseLeave={() => setOpen(false)}
          data-testid="timeline-saved-views-menu"
        >
          <ul className="space-y-1">
            {views.map((view) => (
              <li key={view.id} className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => { onApply(view); setOpen(false); }}
                  className="min-w-0 flex-1 rounded px-2 py-1 text-left text-xs hover:bg-accent"
                >
                  <div className="font-medium">{view.name}</div>
                  <div className="truncate font-mono text-[10px] text-muted-foreground">{timelineSavedViewSummary(view)}</div>
                </button>
                <button
                  type="button"
                  onClick={() => onDelete(view.id)}
                  aria-label={`delete timeline view ${view.name}`}
                  className="rounded p-1 text-muted-foreground hover:bg-muted"
                >
                  x
                </button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}

function FilterTextInput({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) {
  return (
    <label className="block text-xs">
      <span className="mb-1 block font-medium text-muted-foreground">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-8 w-full rounded-md border border-input bg-card px-2 font-mono text-xs outline-none transition-colors placeholder:text-muted-foreground/70 focus:border-[color:var(--color-primary)] focus:ring-1 focus:ring-[color:var(--color-primary)]"
      />
    </label>
  );
}

function DateFilterInput({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return (
    <label className="block text-xs">
      <span className="mb-1 block font-medium text-muted-foreground">{label}</span>
      <input
        type="datetime-local"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-8 w-full rounded-md border border-input bg-card px-2 font-mono text-xs outline-none transition-colors focus:border-[color:var(--color-primary)] focus:ring-1 focus:ring-[color:var(--color-primary)]"
      />
    </label>
  );
}

function TimelineActiveFilters({ filters, onClear }: { filters: TimelineFilterPayload; onClear: () => void }) {
  const chips = [
    filters.query ? `q:${filters.query}` : "",
    filters.namespace ? `ns:${filters.namespace}` : "",
    filters.workload ? `workload:${filters.workload}` : "",
    filters.reference ? `ref:${filters.reference}` : "",
    filters.from ? `from:${filters.from}` : "",
    filters.to ? `to:${filters.to}` : "",
  ].filter(Boolean);
  if (chips.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1.5 border-t border-border pt-2">
      <span className="mr-1 text-[11px] font-medium text-muted-foreground">Active</span>
      {chips.map((chip) => (
        <span key={chip} className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-[11px] text-primary">
          {chip}
        </span>
      ))}
      <button type="button" onClick={onClear} className="rounded px-1.5 py-0.5 text-[11px] text-muted-foreground hover:bg-muted">
        clear
      </button>
    </div>
  );
}

function TimelineDetailDrawer({ item, onClose }: { item: TimelineItem | null; onClose: () => void }) {
  return (
    <Drawer
      open={Boolean(item)}
      onOpenChange={(open) => { if (!open) onClose(); }}
      title={item ? item.title : "Event detail"}
      description={item ? `${SOURCE_META[item.source].label} · ${item.severity}` : undefined}
      width="lg"
    >
      {item ? <TimelineDetail item={item} /> : null}
    </Drawer>
  );
}

function TimelineDetail({ item }: { item: TimelineItem }) {
  return (
    <div className="space-y-4" data-testid="timeline-detail-drawer">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={item.severity} size="xs" />
        <StatusPill label={SOURCE_META[item.source].label} tone={SOURCE_META[item.source].tone} />
        <span className="text-xs text-muted-foreground" title={item.at}>{fmtRelative(item.at)}</span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <DetailField label="Source" value={SOURCE_META[item.source].label} />
        <DetailField label="Event ID" value={item.id} mono />
        <DetailField label="Observed" value={new Date(item.at).toLocaleString()} />
        <DetailField label="Cluster" value={item.cluster_id || "org-level"} mono />
        <DetailField label="Namespace" value={item.namespace || "-"} mono />
        <DetailField label="Workload" value={item.workload_id || "-"} mono />
        <DetailField label={referenceLabel(item.source)} value={item.ref || "-"} mono />
      </div>
      <section className="rounded-md border border-border p-3">
        <h3 className="text-xs font-semibold">Source context</h3>
        <p className="mt-2 text-xs text-muted-foreground">{sourceDetailText(item)}</p>
      </section>
      <section className="rounded-md border border-border p-3">
        <h3 className="text-xs font-semibold">Raw timeline record</h3>
        <pre className="mt-2 max-h-[280px] overflow-auto rounded bg-muted p-2 text-[11px]">
          {JSON.stringify(item, null, 2)}
        </pre>
      </section>
    </div>
  );
}

function DetailField({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-[11px] text-muted-foreground">{label}</dt>
      <dd className={`mt-1 break-all text-xs ${mono ? "font-mono" : "font-medium"}`}>{value}</dd>
    </div>
  );
}

function referenceLabel(source: TimelineSource) {
  switch (source) {
    case "dpi_threat":
      return "Threat ID";
    case "runtime_event":
      return "Runtime verdict";
    case "network_violation":
      return "Policy";
    case "audit":
      return "Target kind";
    default:
      return "Reference";
  }
}

function sourceDetailText(item: TimelineItem) {
  switch (item.source) {
    case "dpi_threat":
      return "DPI threat events come from the runtime data plane and map closest to NeuVector threat logs.";
    case "runtime_event":
      return "Runtime events include process, file, L7, DLP, WAF, and detector telemetry normalized into the incident stream.";
    case "network_violation":
      return "Network violations represent policy, admission, drift, or runtime enforcement findings tied back to the affected workload when available.";
    case "audit":
      return "Audit entries are org-level control-plane activity from the tamper-evident audit chain; cluster-scoped timeline views omit audit rows.";
    default:
      return item.ref ? `Reference: ${item.ref}` : "No additional source context.";
  }
}

function FilterChip({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
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
