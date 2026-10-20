import { SavedViewsMenu } from "@/components/SavedViewsMenu";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
// TimelinePage — B1 unified incident timeline.
//
// One chronological investigation view that merges the four NeuVector event
// consoles (DPI threats · runtime events · network violations · audit) into a
// single time-ordered stream with type + severity filters. Backed by
// GET /api/v1/security/timeline.
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useMemo, useState, useEffect, useRef, type ReactNode } from "react";
import { useQuery, useQueryClient, useIsFetching } from "@tanstack/react-query";
import { Save } from "lucide-react";

import {
  securityTimeline,
  type TimelineItem,
  type TimelineSource,
} from "@/api/client";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { useCluster } from "@/hooks/useCluster";
import { useSavedViews } from "@/hooks/useSavedViews";
import { PageHeader } from "@/components/ui/page";
import { Pager } from "@/components/ui/pager";
import { useRouteSearchParams } from "@/lib/route-search";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ExportMenu } from "@/ui";
import { sentenceValue } from "@/components/ui/status-pill";
import { InventoryMoreFilters } from "./inventory-workspace";
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
  timelineAfterParam,
  sameTimelineBoundary,
  TIMELINE_VERDICTS,
  timelineSavedViewSummary,
  timelineSeverityParam,
  timelineSourceParam,
  timelineTextParam,
  type TimelineFilterPayload,
} from "@/lib/timeline-filters";

const SOURCE_META: Record<
  TimelineSource,
  { label: string; tone: "error" | "warning" | "accent" | "info" }
> = {
  dpi_threat: { label: "DPI Threat", tone: "error" },
  runtime_event: { label: "Runtime", tone: "warning" },
  network_violation: { label: "Violation", tone: "accent" },
  audit: { label: "Audit", tone: "info" },
};

const ALL_SOURCES = Object.keys(SOURCE_META) as TimelineSource[];
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const TIMELINE_PAGE = 100;

const CATEGORY_TABS: Array<{
  id: string;
  label: string;
  sources: TimelineSource[];
}> = [
  { id: "all", label: "All", sources: ALL_SOURCES },
  { id: "activity", label: "Activity", sources: ["runtime_event", "audit"] },
  { id: "audit", label: "Audit", sources: ["audit"] },
  { id: "event", label: "Event", sources: ["runtime_event"] },
  {
    id: "incident",
    label: "Incident",
    sources: ["dpi_threat", "runtime_event", "network_violation"],
  },
  { id: "threat", label: "Threat", sources: ["dpi_threat", "runtime_event"] },
  { id: "violation", label: "Violation", sources: ["network_violation"] },
  {
    id: "security",
    label: "Security",
    sources: ["dpi_threat", "runtime_event", "network_violation"],
  },
];

import {
  TIMELINE_VIEWS_KEY,
  isTimelineSavedView,
  inventoryViewHref,
  type TimelineSavedView,
} from "@/lib/inventory-saved-views";
import { Select } from "@/components/ui/form";

export function TimelinePage() {
  const {
    clusterId,
    cluster,
    isLoading: clusterLoading,
    error: clusterError,
  } = useCluster();
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const registryFetching = useIsFetching({
    queryKey: ["clusters"],
    exact: true,
  });
  const detailFetching = useIsFetching({
    queryKey: ["cluster", clusterId],
    exact: true,
  });
  const scopeReady =
    !!clusterId &&
    cluster?.id === clusterId &&
    !clusterLoading &&
    !clusterError &&
    !registryFetching &&
    !detailFetching &&
    clusterCacheReady(qc, clusterId);
  const [params, setParams] = useRouteSearchParams();
  const navigate = useNavigate();
  const locationHash = useLocation({ select: (location) => location.hash });
  const category = params.get("tab") ?? "all";
  const activeCategory =
    category === "custom" || CATEGORY_TABS.some((tab) => tab.id === category)
      ? category
      : "all";
  const sources = useMemo(
    () =>
      new Set<TimelineSource>(
        activeCategory === "custom"
          ? params.has("type")
            ? ALL_SOURCES.filter((source) =>
                params.get("type")!.split(",").includes(source),
              )
            : ALL_SOURCES
          : (
              CATEGORY_TABS.find((tab) => tab.id === activeCategory) ??
              CATEGORY_TABS[0]
            ).sources,
      ),
    [activeCategory, params],
  );
  const severities = useMemo(
    () =>
      new Set<string>(
        SEVERITIES.filter((value) =>
          params.get("severity")?.split(",").includes(value),
        ),
      ),
    [params],
  );
  const query = params.get("q") ?? "";
  const namespace = params.get("namespace") ?? "";
  const workload = params.get("workload") ?? "";
  const reference = params.get("ref") ?? "";
  const from = params.get("from") ?? "";
  const to = params.get("to") ?? "";
  const after = params.get("after") ?? "";
  const requestedHours = params.has("hours")
    ? Number(params.get("hours"))
    : undefined;
  const afterExclusive = params.has("after_exclusive")
    ? params.get("after_exclusive") === "true"
    : undefined;
  const verdict = params.get("verdict") ?? "";
  const exportPending = useRef(false);
  const [exportState, setExportState] = useState<{
    owner: string;
    pending: boolean;
    error?: string;
    result?: string;
  }>();
  const requestedPage = Number(params.get("page") ?? "1");
  const page =
    Number.isSafeInteger(requestedPage) &&
    requestedPage > 0 &&
    requestedPage <= 1000000 / TIMELINE_PAGE + 1
      ? requestedPage - 1
      : 0;
  const selectedID = params.get("event");
  const updateFilters = (
    changes: Record<string, string | null>,
    replace = false,
    resetPage = true,
  ) =>
    setParams(
      (current) => {
        for (const [key, value] of Object.entries(changes)) {
          if (value === null || value === "") current.delete(key);
          else current.set(key, value);
        }
        if (resetPage) {
          current.delete("page");
          current.delete("event");
        }
        return current;
      },
      { replace },
    );
  const setQuery = (value: string) => updateFilters({ q: value }, true);
  const setNamespace = (value: string) =>
    updateFilters({ namespace: value }, true);
  const setWorkload = (value: string) =>
    updateFilters({ workload: value }, true);
  const setReference = (value: string) => updateFilters({ ref: value }, true);
  const setPage = (value: number) =>
    updateFilters(
      { page: value ? String(value + 1) : null, event: null },
      false,
      false,
    );
  const setSelected = (value: TimelineItem | null) =>
    updateFilters(
      { event: value ? `${value.source}:${value.id}` : null },
      false,
      false,
    );
  const { views, deleteView, persistenceError } =
    useSavedViews<TimelineSavedView>(TIMELINE_VIEWS_KEY, {
      validate: isTimelineSavedView,
    });

  const filters = useMemo(
    () =>
      compactTimelineFilters({
        category: activeCategory,
        sources: [...sources],
        severities: [...severities],
        query,
        namespace,
        workload,
        reference,
        from,
        to,
        ...(after ? { after } : {}),
        ...(requestedHours !== undefined ? { hours: requestedHours } : {}),
        ...(afterExclusive !== undefined ? { afterExclusive } : {}),
        ...(verdict ? { verdicts: verdict.split(",") } : {}),
      }),
    [
      activeCategory,
      sources,
      severities,
      query,
      namespace,
      workload,
      reference,
      from,
      to,
      after,
      requestedHours,
      afterExclusive,
      verdict,
    ],
  );

  const typeParam = timelineSourceParam(filters.sources);
  const sevParam = timelineSeverityParam(filters.severities);
  const fromParam = timelineDateParam(filters.from);
  const toParam = timelineDateParam(filters.to);
  const queryParam = timelineTextParam(filters.query);
  const namespaceParam = timelineTextParam(filters.namespace);
  const workloadParam = timelineTextParam(filters.workload);
  const refParam = timelineTextParam(filters.reference);

  const afterParam = timelineAfterParam(after);
  const invalidCohort = Boolean(
    (after && !afterParam) ||
      (requestedHours !== undefined &&
        (!Number.isInteger(requestedHours) ||
          requestedHours < 1 ||
          requestedHours > 2160)) ||
      (after && requestedHours !== undefined) ||
      ((after || requestedHours !== undefined) && (from || to)) ||
      (params.has("after_exclusive") &&
        (!["true", "false"].includes(params.get("after_exclusive")!) ||
          (!after && requestedHours === undefined))) ||
      (verdict &&
        (verdict
          .split(",")
          .some((value) => !TIMELINE_VERDICTS.includes(value)) ||
          sources.size !== 1 ||
          !sources.has("runtime_event"))) ||
      !Number.isSafeInteger(requestedPage) ||
      requestedPage < 1 ||
      requestedPage > 1000000 / TIMELINE_PAGE + 1,
  );
  const invalidWindow =
    invalidCohort ||
    Boolean(
      (from && !fromParam) ||
        (to && !toParam) ||
        (fromParam && toParam && fromParam > toParam),
    );
  const readParams = {
    cluster_id: clusterId,
    type: typeParam,
    severity: sevParam,
    from: fromParam,
    to: toParam,
    q: queryParam,
    namespace: namespaceParam,
    workload: workloadParam,
    ref: refParam,
    ...(afterParam ? { after: afterParam } : {}),
    ...(requestedHours !== undefined ? { hours: requestedHours } : {}),
    ...(afterExclusive !== undefined
      ? { after_exclusive: afterExclusive }
      : {}),
    ...(verdict ? { verdict } : {}),
    limit: TIMELINE_PAGE,
    offset: page * TIMELINE_PAGE,
  };
  const owner = JSON.stringify([identity?.org_id, identity?.user_id, clusterId, readParams]);
  const timelineKey = [
      "security-timeline",
      identity?.org_id, identity?.user_id,
      clusterId,
      sources.size === 0 ? "none" : typeParam,
      sevParam,
      fromParam,
      toParam,
      queryParam,
      namespaceParam,
      workloadParam,
      refParam,
      page,
      afterParam,
      requestedHours,
      afterExclusive,
      verdict,
    ];
  const q = useQuery({
    queryKey: timelineKey,
    queryFn: () => securityTimeline.list(readParams),
    // No source selected ⇒ nothing to fetch.
    enabled: scopeReady && sources.size > 0 && !invalidWindow,
  });

  const scopeMismatch = Boolean(
    q.data &&
      (q.data.offset !== page * TIMELINE_PAGE ||
        q.data.limit !== TIMELINE_PAGE ||
        q.data.items.some(
          (item) =>
            item.cluster_id !== clusterId ||
            !sources.has(item.source) ||
            (severities.size > 0 && !severities.has(item.severity)) ||
            (verdict && !verdict.split(",").includes(item.verdict ?? "")),
        )),
  );
  const cohortMismatch = Boolean(
    q.data &&
      (after || requestedHours !== undefined) &&
      (!q.data.lower_only ||
        q.data.after_exclusive !== Boolean(afterExclusive) ||
        (afterParam && !sameTimelineBoundary(q.data.from, afterParam))),
  );
  const available =
    scopeReady &&
    q.isSuccess &&
    !q.isError &&
    !invalidWindow &&
    !scopeMismatch &&
    !cohortMismatch;
  const captureExport = useExportGuard(owner, !available || q.isFetching, () => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, timelineKey, q.data));
  // Pin an older Dashboard's rolling-window fallback after its first successful
  // response, so later pages and exports retain the exact lower boundary.
  useEffect(() => {
    if (
      !available ||
      requestedHours === undefined ||
      !q.data ||
      !timelineAfterParam(q.data.from)
    )
      return;
    const boundary = q.data.from;
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        next.delete("hours");
        next.set("after", boundary);
        return next;
      },
      { replace: true },
    );
  }, [available, requestedHours, q.data, setParams]);
  const items = useMemo<TimelineItem[]>(
    () => (available && sources.size > 0 ? (q.data?.items ?? []) : []),
    [q.data, available, sources],
  );
  const selected =
    items.find((item) => `${item.source}:${item.id}` === selectedID) ?? null;

  const selectCategory = (tabID: string, nextSources: TimelineSource[]) => {
    updateFilters({
      tab: tabID === "all" ? null : tabID,
      type:
        nextSources.length === ALL_SOURCES.length
          ? null
          : nextSources.join(","),
      verdict: tabID === "event" ? verdict : null,
    });
  };

  const applyView = (view: TimelineSavedView) =>
    updateFilters({
      tab: view.category || "custom",
      type: view.sources.length ? view.sources.join(",") : "none",
      severity: (view.severities ?? []).join(","),
      q: view.query ?? "",
      namespace: view.namespace ?? "",
      workload: view.workload ?? "",
      ref: view.reference ?? "",
      from: view.from ?? "",
      to: view.to ?? "",
      after: view.after ?? null,
      hours: view.hours !== undefined ? String(view.hours) : null,
      after_exclusive:
        view.afterExclusive !== undefined ? String(view.afterExclusive) : null,
      verdict: view.verdicts?.join(",") ?? null,
    });

  const clearAdvancedFilters = () =>
    updateFilters({
      severity: null,
      q: null,
      namespace: null,
      workload: null,
      ref: null,
      from: null,
      to: null,
      after: null,
      hours: null,
      after_exclusive: null,
      verdict: null,
    });

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
  if (!scopeReady)
    return (
      <ErrorState title="Cluster could not be resolved." error={clusterError} />
    );

  return (
    <div
      className="space-y-4"
      data-testid="timeline-page"
      data-cluster-id={clusterId ?? ""}
    >
      <PageHeader
        title="Incidents"
        description={`DPI threats, runtime events, network violations and audit for ${cluster?.name || "this cluster"}, in time order.`}
        actions={
          <>
            <Button
              disabled={q.isFetching || sources.size === 0 || invalidWindow}
              onClick={() => void q.refetch()}
            >
              Refresh
            </Button>
            <SavedViewsMenu views={views} onApply={applyView} onDelete={deleteView} summary={timelineSavedViewSummary} testId="timeline-saved-views-menu" />
            <Button
              type="button"
              size="sm"
              onClick={() => {
                if (clusterId)
                  void navigate({
                    href: inventoryViewHref(
                      clusterId,
                      "timeline",
                      params,
                      locationHash,
                      true,
                    ),
                  });
              }}
            >
              <Save className="h-3.5 w-3.5" aria-hidden /> Save view
            </Button>
            <ExportMenu options={[
              { label: "This page", description: "Events shown on this page", disabled: items.length === 0 || q.isFetching, onSelect: () =>
                downloadCsv(
                  "constellation-security-events",
                  [
                    "Time",
                    "Source",
                    "Severity",
                    "Verdict",
                    "Title",
                    "Namespace",
                    "Workload",
                    "Reference",
                    "platform_role",
                  ],
                  items.map((it) => [
                    it.at,
                    it.source,
                    it.severity,
                    it.verdict ?? "",
                    it.title,
                    it.namespace ?? "",
                    it.workload_id ?? "",
                    it.ref ?? "",
                    it.platform_role ?? "",
                  ]),
                ) },
              { label: exportState?.pending ? "Exporting matching events…" : "Matching events", description: "Up to 10,000 matching records", disabled: !available || q.isFetching || Boolean(exportState?.pending), onSelect: () => {
                if (
                  exportPending.current ||
                  !available ||
                  !clusterId ||
                  !clusterCacheReady(qc, clusterId)
                )
                  return;
                const shouldDownload = captureExport();
                if (!shouldDownload()) return;
                exportPending.current = true;
                const exportOwner = owner;
                setExportState({ owner: exportOwner, pending: true });
                void securityTimeline
                  .exportCSV(readParams, shouldDownload)
                  .then((result) => {
                    if (!shouldDownload()) return;
                    setExportState({
                      owner: exportOwner,
                      pending: false,
                      result: result.truncated
                        ? `Exported ${result.exported.toLocaleString()} of ${result.total.toLocaleString()} matching records; export cap ${result.limit.toLocaleString()}.`
                        : `Exported all ${result.total.toLocaleString()} matching event records.`,
                    });
                  })
                  .catch((error: Error) => {
                    if (!shouldDownload()) return;
                    setExportState({
                      owner: exportOwner,
                      pending: false,
                      error: error.message || "Event export failed. Retry.",
                    });
                  })
                  .finally(() => {
                    exportPending.current = false;
                    setExportState(current => current?.owner === exportOwner ? { ...current, pending: false } : current);
                  });
              } },
            ]} />
          </>
        }
      />

      {persistenceError && <ErrorState title={persistenceError} />}
      {exportState?.owner === owner && exportState.error && (
        <ErrorState title="Matching event export failed." error={exportState.error} />
      )}
      {exportState?.owner === owner && exportState.result && (
        <p role="status" className="text-sm text-muted-foreground">{exportState.result}</p>
      )}
      <VerdictBanner
        status={q.isError || invalidWindow ? "degraded" : "info"}
        title={
          invalidWindow
            ? "Invalid timeline window"
            : q.isError
              ? "Timeline is unavailable"
              : sources.size === 0
                ? "Choose an event source"
                : q.isPending
                  ? "Loading timeline"
                  : q.data?.total !== undefined
                    ? `${q.data.total.toLocaleString()} matching event records`
                    : `${items.length} events on this page`
        }
        numbers={available ? [
          { label: "critical", value: items.filter((item) => item.severity === "critical").length, tone: items.some((item) => item.severity === "critical") ? "critical" : "default", title: "Critical events on this page" },
          { label: "high", value: items.filter((item) => item.severity === "high").length, tone: items.some((item) => item.severity === "high") ? "high" : "default", title: "High events on this page" },
          { label: "sources", value: new Set(items.map((item) => item.source)).size, title: "Sources on this page" },
        ] : undefined}
        detail={<div className="space-y-1">
          {available && <p data-testid="timeline-summary">{q.data?.total !== undefined ? "Matching event records" : "On this page"} {q.data?.total ?? items.length} · critical on page {items.filter((item) => item.severity === "critical").length} · high on page {items.filter((item) => item.severity === "high").length} · sources on page {new Set(items.map((item) => item.source)).size}</p>}
          {available && q.data && sources.size > 0 && <p>{q.data.lower_only ? `${q.data.after_exclusive ? "Strictly after" : "Since"} ${q.data.from}; no upper time bound.` : `Window: ${new Date(q.data.from).toLocaleString()} – ${new Date(q.data.to).toLocaleString()}`}</p>}
          <p>Event-only totals cover all matches; mixed-source browsing uses has-more paging. Page CSV and matching CSV have separate scopes. Filters and selection are saved in the URL.</p>
        </div>}
      />

      <div className="flex flex-wrap items-center gap-2" data-testid="timeline-advanced-filters">
        <div className="inline-flex h-9 items-center rounded-md border border-border p-0.5" data-testid="timeline-category-tabs" role="group" aria-label="Event category">
          {CATEGORY_TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => selectCategory(tab.id, tab.sources)}
              aria-pressed={activeCategory === tab.id}
              className={`inline-flex h-7 items-center rounded-sm px-3 text-sm transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring ${
                activeCategory === tab.id ? "bg-accent font-medium text-foreground" : "text-muted-foreground hover:text-foreground"
              }`}
              data-testid={`timeline-category-${tab.id}`}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <QueryInput
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          onClear={() => setQuery("")}
          placeholder="Search title, id, workload, namespace or reference"
          aria-label="Search events"
          className="w-full max-w-xs"
        />
        <Select
          aria-label="Timeline rolling window"
          value={requestedHours ?? ""}
          onChange={(event) =>
            updateFilters({
              hours: event.target.value,
              after: null,
              from: null,
              to: null,
              after_exclusive: event.target.value ? String(Boolean(afterExclusive)) : null,
            })
          }
          className="h-9"
        >
          <option value="">Custom or pinned window</option>
          <option value="24">Last 24 hours</option>
          <option value="336">Last 14 days</option>
          <option value="168">Last 7 days</option>
        </Select>
        {sources.size === 1 && sources.has("runtime_event") && (
          <Select aria-label="Runtime event verdicts" value={verdict} onChange={(event) => updateFilters({ verdict: event.target.value })} className="h-9">
            <option value="">Any verdict</option>
            <option value="alert,block,quarantine">Alert, block or quarantine</option>
            {TIMELINE_VERDICTS.map((value) => <option key={value} value={value}>{sentenceValue(value)}</option>)}
          </Select>
        )}
        <InventoryMoreFilters count={[namespace, workload, reference, from, to].filter(Boolean).length + (severities.size ? 1 : 0)}>
          <FilterTextInput label="Namespace" value={namespace} onChange={setNamespace} placeholder="prod" />
          <FilterTextInput label="Workload" value={workload} onChange={setWorkload} placeholder="api" />
          <FilterTextInput label="Reference" value={reference} onChange={setReference} placeholder="Policy or target" />
          <div className="grid grid-cols-2 gap-2">
            <DateFilterInput label="From" value={from} onChange={(value) => updateFilters({ from: value, after: null, hours: null, after_exclusive: null })} />
            <DateFilterInput label="To" value={to} onChange={(value) => updateFilters({ to: value, after: null, hours: null, after_exclusive: null })} />
          </div>
          <div className="space-y-1.5">
            <p className="text-meta font-medium text-muted-foreground">Type</p>
            <div className="flex flex-wrap gap-1.5">
              {ALL_SOURCES.map((s) => (
                <FilterChip key={s} active={sources.has(s)} onClick={() => updateFilters({ tab: "custom", type: [...toggle(sources, s)].join(",") || "none", verdict: null })}>
                  {SOURCE_META[s].label}
                </FilterChip>
              ))}
            </div>
          </div>
          <div className="space-y-1.5">
            <p className="text-meta font-medium text-muted-foreground">Severity</p>
            <div className="flex flex-wrap gap-1.5">
              {SEVERITIES.map((s) => (
                <FilterChip key={s} active={severities.has(s)} onClick={() => updateFilters({ severity: [...toggle(severities, s)].join(",") })}>
                  {sentenceValue(s)}
                </FilterChip>
              ))}
            </div>
          </div>
          <Button type="button" size="sm" variant="ghost" onClick={clearAdvancedFilters} data-testid="timeline-clear-filters">
            Clear filters
          </Button>
        </InventoryMoreFilters>
      </div>
      <TimelineActiveFilters filters={filters} onClear={clearAdvancedFilters} />

      {q.isFetching && !q.isPending && (
        <p role="status" className="text-sm text-muted-foreground">
          Refreshing timeline…
        </p>
      )}
      {invalidWindow ? (
        <ErrorState title="Choose valid dates and event filters. Use either after/rolling hours or From/To, and a supported page." />
      ) : scopeMismatch || cohortMismatch ? (
        <ErrorState
          title="Timeline evidence does not match the selected cluster and event window."
          action={<Button onClick={() => void q.refetch()}>Retry</Button>}
        />
      ) : q.isPending && sources.size > 0 ? (
        <LoadingState label="Loading timeline…" />
      ) : q.isError ? (
        <ErrorState
          title="Failed to load the incident timeline."
          error={q.error}
          action={<Button onClick={() => void q.refetch()}>Retry</Button>}
        />
      ) : items.length === 0 ? (
        <>
          <EmptyState
            title={page > 0 ? "No events on this page" : "No events"}
            hint="No events match the current filters in the selected window."
          />
          {page > 0 && (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setPage(page - 1)}
            >
              Previous page
            </Button>
          )}
        </>
      ) : (
        <>
          <ol
            className="relative space-y-1 border-l border-border pl-4"
            data-testid="timeline-list"
          >
            {items.map((it) => (
              <li key={`${it.source}:${it.id}`} className="relative">
                <span
                  className="absolute -left-[21px] top-3 h-2 w-2 rounded-full bg-border"
                  aria-hidden
                />
                <button
                  type="button"
                  onClick={() => setSelected(it)}
                  className="flex w-full items-start gap-2 rounded-md border border-border bg-card px-3 py-2 text-left transition-colors hover:bg-accent/40 focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
                  data-testid="timeline-event-row"
                >
                  <SeverityBadge severity={it.severity} size="xs" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <StatusPill
                        label={SOURCE_META[it.source].label}
                        tone={SOURCE_META[it.source].tone}
                      />
                      <span className="truncate text-sm font-medium">
                        {it.title}
                      </span>
                    </div>
                    <div className="text-micro font-mono text-muted-foreground">
                      {[it.namespace, it.workload_id, it.ref]
                        .filter(Boolean)
                        .join(" · ")}
                    </div>
                  </div>
                  <span
                    className="shrink-0 text-micro text-muted-foreground"
                    title={it.at}
                  >
                    {fmtRelative(it.at)}
                  </span>
                </button>
              </li>
            ))}
          </ol>
          <p
            className="text-xs text-muted-foreground"
            data-testid="timeline-page-scope"
          >
            Showing timeline events {page * TIMELINE_PAGE + 1}–
            {page * TIMELINE_PAGE + items.length} on page {page + 1}.{" "}
            {q.data?.total !== undefined
              ? `Of ${q.data.total.toLocaleString()} matching records. `
              : ""}
            {q.data?.has_more ? "More pages available." : "No more pages."}
          </p>
          <Pager
            page={page}
            pageSize={TIMELINE_PAGE}
            hasMore={q.data?.has_more}
            total={q.data?.total}
            rowsOnPage={items.length}
            onPage={setPage}
          />
          <TimelineDetailDrawer
            item={selected}
            onClose={() => setSelected(null)}
          />
        </>
      )}
      {selectedID && !q.isPending && !q.isError && !selected && (
        <EmptyState
          title="Selected event is unavailable"
          hint="It is absent from this page or the active filters."
        />
      )}
    </div>
  );
}

function FilterTextInput({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="block text-meta">
      <span className="mb-1.5 block font-medium text-muted-foreground">
        {label}
      </span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm outline-none placeholder:text-muted-foreground focus:ring-2 focus:ring-ring"
      />
    </label>
  );
}

function DateFilterInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="block text-meta">
      <span className="mb-1.5 block font-medium text-muted-foreground">
        {label}
      </span>
      <input
        type="datetime-local"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 w-full rounded-md border border-input bg-background px-2 font-mono text-meta outline-none focus:ring-2 focus:ring-ring"
      />
    </label>
  );
}

function TimelineActiveFilters({
  filters,
  onClear,
}: {
  filters: TimelineFilterPayload;
  onClear: () => void;
}) {
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
      <span className="mr-1 text-micro font-medium text-muted-foreground">
        Active
      </span>
      {chips.map((chip) => (
        <span
          key={chip}
          className="rounded-full border border-primary/30 bg-primary/10 px-2 py-0.5 font-mono text-micro text-primary"
        >
          {chip}
        </span>
      ))}
      <button
        type="button"
        onClick={onClear}
        className="rounded px-1.5 py-0.5 text-micro text-muted-foreground hover:bg-muted"
      >
        clear
      </button>
    </div>
  );
}

function TimelineDetailDrawer({
  item,
  onClose,
}: {
  item: TimelineItem | null;
  onClose: () => void;
}) {
  return (
    <Drawer
      open={Boolean(item)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={item ? item.title : "Event detail"}
      description={
        item
          ? `${SOURCE_META[item.source].label} · ${item.severity}`
          : undefined
      }
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
        <StatusPill
          label={SOURCE_META[item.source].label}
          tone={SOURCE_META[item.source].tone}
        />
        <span className="text-xs text-muted-foreground" title={item.at}>
          {fmtRelative(item.at)}
        </span>
      </div>
      <div className="grid gap-2 sm:grid-cols-2">
        <DetailField label="Source" value={SOURCE_META[item.source].label} />
        <DetailField label="Event ID" value={item.id} mono />
        <DetailField
          label="Observed"
          value={new Date(item.at).toLocaleString()}
        />
        <DetailField
          label="Cluster"
          value={item.cluster_id || "org-level"}
          mono
        />
        <DetailField label="Namespace" value={item.namespace || "-"} mono />
        <DetailField label="Workload" value={item.workload_id || "-"} mono />
        {item.source !== "audit" && (
          <DetailField
            label="Platform role"
            value={item.platform_role || "Not classified"}
          />
        )}
        {item.source === "runtime_event" && (
          <DetailField label="Verdict" value={item.verdict || "Not reported"} />
        )}
        <DetailField
          label={referenceLabel(item.source)}
          value={item.ref || "-"}
          mono
        />
      </div>
      <section className="rounded-md border border-border p-3">
        <h3 className="text-xs font-semibold">Source context</h3>
        <p className="mt-2 text-xs text-muted-foreground">
          {sourceDetailText(item)}
        </p>
      </section>
      <section className="rounded-md border border-border p-3">
        <h3 className="text-xs font-semibold">Raw timeline record</h3>
        <pre className="mt-2 max-h-[280px] overflow-auto rounded bg-muted p-2 text-micro">
          {JSON.stringify(item, null, 2)}
        </pre>
      </section>
    </div>
  );
}

function DetailField({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-micro text-muted-foreground">{label}</dt>
      <dd
        className={`mt-1 break-all text-xs ${mono ? "font-mono" : "font-medium"}`}
      >
        {value}
      </dd>
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
      return item.ref
        ? `Reference: ${item.ref}`
        : "No additional source context.";
  }
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex h-7 items-center rounded-full border px-2.5 text-meta transition-colors focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring ${
        active
          ? "border-foreground/40 bg-accent text-foreground"
          : "border-border text-muted-foreground hover:bg-accent/60 hover:text-foreground"
      }`}
      aria-pressed={active}
    >
      {children}
    </button>
  );
}
