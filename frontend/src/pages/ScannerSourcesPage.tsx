import { ResourceSavedViewsControl } from "@/components/ResourceSavedViewsControl";
import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
  TriangleAlert,
  ArrowLeft,
  Save,
  CircleCheck,
  Circle,
  Clock,
  Database,
  Eye,
  HardDrive,
  CirclePause,
  Pencil,
  CirclePlay,
  RefreshCw,
  RotateCcw,
  CircleX,
} from "lucide-react";
import { toast } from "sonner";

import {
  scanJobs,
  scanJobsAdmin,
  scannerOperations,
  systemHealth,
  systemConfigApi,
  type SystemConfigResponse,
  type ScanJob,
  type ScanJobAttempt,
  type ScanJobInventoryResponse,
  type ScanQueueMetric,
  type ScannerCacheHealthEntry,
  type ScannerCacheStat,
  type ScannerWorker,
} from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { isRevisionConflict } from "@/lib/integration-routing";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Collapse } from "@/components/ui/collapse";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { Pager } from "@/components/ui/pager";
import { useInventoryRoute, ScanInventoryExport } from "./inventory-workspace";
import { Drawer } from "@/components/ui/drawer";
import { Field, TextInput, Select } from "@/components/ui/form";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { StatusPill } from "@/components/ui/status-pill";
import { ScannerDbCapacity } from "@/components/ScannerDbCapacity";
import { cn } from "@/lib/cn";
import { fmtRelative } from "@/lib/format";
import { scanJobInventoryResponseValid } from "@/lib/scan-job-inventory";
import {
  scanJobBundleRows,
  scanJobRetryState,
  scanJobTargetRows,
  scanJobTimingRows,
  type ScanJobDetailRow,
} from "@/lib/scan-job-detail";

/**
 * Scanner & CVE Sources — vulnerability data health. Trivy/Grype DB freshness +
 * the live CVE-intelligence feeds (KEV / EPSS / NVD).
 */
export function ScannerSourcesPage() {
  const qc = useQueryClient();
  const [requestedTab, setTab] = useTabParam("tab", "jobs");
  const tab = ["jobs", "workers", "databases", "sources"].includes(requestedTab) ? requestedTab : "jobs";
  const navigate = useNavigate();
  const route = useInventoryRoute();
  const params = route.params;
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const jobStatusFilter = params.get("status") || "all";
  const targetType = params.get("target_type") || "";
  const jobSort = params.get("sort") || "requested";
  const jobOrder = params.get("order") || "desc";
  const clusterFilter = params.get("cluster_id") || "";
  const registryFilter = params.get("registry_id") || "";
  const rawPage = params.get("page");
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const invalidJobs = !JOB_STATUS_FILTERS.includes(jobStatusFilter) || targetType !== "" && !JOB_TARGET_TYPES.includes(targetType) || !JOB_SORTS.includes(jobSort) || !["asc", "desc"].includes(jobOrder) || !!(clusterFilter && !uuidPattern.test(clusterFilter) || registryFilter && !uuidPattern.test(registryFilter)) || rawPage !== null && (!/^\d+$/.test(rawPage) || !Number.isSafeInteger(Number(rawPage)) || Number(rawPage) < 1 || Number(rawPage) > 10000);
  const jobRequest = { q: route.debouncedQuery.trim() || undefined, status: jobStatusFilter === "all" ? undefined : jobStatusFilter, target_type: targetType || undefined, cluster_id: clusterFilter || undefined, registry_id: registryFilter || undefined, sort: jobSort, order: jobOrder as "asc" | "desc", limit: 100, offset: route.offset };
  const jobListKey = ["scan-jobs", "scanner-sources", owner, jobRequest];
  const jobContext = JSON.stringify(jobListKey);
  const currentJobContext = useRef(jobContext);
  currentJobContext.current = jobContext;
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const selectedJobID = route.selectedID || "";
  const setSelectedJobID = (id: string) => route.setSelectedID(id || null);
  const intervalReturn = `/settings/scanner?${params.size ? params.toString() : "tab=databases"}`;
  const intervalHref = `/settings/scanner/databases/edit?return_to=${encodeURIComponent(intervalReturn)}`;
  const systemConfig = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const scanStatus = useQuery({ queryKey: ["scan-status"], queryFn: scannerOperations.status });
  const scannerWorkers = useQuery({ queryKey: ["scan-scanner-workers"], queryFn: scannerOperations.workers });
  const scannerHealth = useQuery({ queryKey: ["system-health"], queryFn: systemHealth.overview, refetchInterval: 30_000 });
  const scanJobList = useQuery({
    queryKey: jobListKey,
    enabled: Boolean(owner) && !invalidJobs && !route.debouncing,
    queryFn: async () => {
      const data = await scanJobs.list(jobRequest);
      if (!scanJobInventoryResponseValid(data, jobRequest, identity?.org_id)) throw new Error("Scan job response does not match this inventory scope or page.");
      return data;
    },
  });
  const jobsAvailable = Boolean(owner) && !invalidJobs && !route.debouncing && scanJobList.isSuccess && !scanJobList.isFetching;
  const config = systemConfig.isSuccess ? systemConfig.data.config : {};
  const refreshMinutes = typeof config.scanner_db_refresh_minutes === "number" ? config.scanner_db_refresh_minutes : 0;
  const offlineDb = config.scanner_offline_db === true;
  const nvdEnabled = config.nvd_enabled === true;
  const [selectedScannerID, setSelectedScannerID] = useState("");

  const cacheStat = useQuery({
    queryKey: ["scanner-cache-stat", selectedScannerID],
    queryFn: async () => { const result = await scannerOperations.cacheStat(selectedScannerID); if (result.scanner_id !== selectedScannerID) throw new Error("Scanner cache identity does not match the selected worker."); return result; },
    enabled: selectedScannerID !== "" && scannerWorkers.isSuccess && scannerWorkers.data.some(worker => worker.id === selectedScannerID),
  });

  const refreshNow = useMutation({
    mutationFn: () => {
      const state = qc.getQueryState<SystemConfigResponse>(["system-config"]);
      if (state?.status !== "success" || state.fetchStatus !== "idle" || state.data?.config.scanner_offline_db === true) throw new Error("Refresh is unavailable until current connected-scanner configuration is loaded.");
      return systemConfigApi.refreshScanner();
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      void qc.invalidateQueries({ queryKey: ["scan-status"] });
      void qc.invalidateQueries({ queryKey: ["scan-scanner-workers"] });
      toast.success("Refresh requested — connected scanners will pull the latest DBs shortly");
    },
    onError: () => toast.error("Failed to request refresh"),
  });

  const invalidateJobLists = (targetOwner: string) => qc.invalidateQueries({ queryKey: ["scan-jobs"], predicate: query => query.queryKey.includes(targetOwner) });
  const jobAction = useMutation({
    mutationFn: ({ reviewed, action, context }: { reviewed: ScanJob; action: ScanJobAction; context: string; owner: string }) => {
      const state = qc.getQueryState<ScanJobInventoryResponse>(jobListKey);
      const job = state?.data?.jobs.find(item => item.id === reviewed.id);
      if (!mounted.current || !jobsAvailable || !owner || context !== currentJobContext.current || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || !job || jobReview(job) !== jobReview(reviewed) || !eligibleJobAction(job, action)) throw new Error("Job state changed or is unavailable. Refresh before continuing.");
      return scanJobsAdmin[action](job.id);
    },
    onSuccess: (_result, vars) => {
      void invalidateJobLists(vars.owner);
      if (!mounted.current || vars.context !== currentJobContext.current) return;
      void qc.invalidateQueries({ queryKey: ["scan-status"] });
      toast.success(`Scan job ${vars.reviewed.id}: ${vars.action} requested`);
    },
    onError: (error: unknown, vars) => {
      if (!mounted.current || vars.context !== currentJobContext.current) return;
      const status = (error as { response?: { status?: number } })?.response?.status;
      toast.error(status === 409 ? "Scan job is no longer in an eligible state" : "Failed to update scan job");
    },
  });
  const runJobAction = (job: ScanJob, action: ScanJobAction) => jobAction.mutate({ reviewed: job, action, context: jobContext, owner });

  const lifecycle = scanStatus.isSuccess ? scanStatus.data : undefined;
  const workers = scannerWorkers.isSuccess ? scannerWorkers.data : [];
  const allJobs = jobsAvailable ? scanJobList.data!.jobs : [];
  const selectedJob = allJobs.find(job => job.id === selectedJobID) ?? null;
  const selectedJobAttempts = useQuery({
    queryKey: ["scan-job-attempts", owner, selectedJobID],
    queryFn: async () => {
      const attempts = await scanJobs.attempts(selectedJobID);
      if (attempts.some(attempt => attempt.job_id !== selectedJobID)) throw new Error("Attempt ledger does not match the selected job.");
      return attempts;
    },
    enabled: Boolean(selectedJob),
  });
  const queueMetrics = jobsAvailable ? scanJobList.data.queue_metrics ?? [] : [];
  const pendingTotal = sumMetric(queueMetrics, "pending") + sumMetric(queueMetrics, "retry_delayed");
  const runningTotal = sumMetric(queueMetrics, "running");
  const staleTotal = sumMetric(queueMetrics, "stale_running");
  const failedTotal = (lifecycle?.failed ?? 0) + sumMetric(queueMetrics, "exhausted");
  const unavailable = !owner || invalidJobs || scanStatus.isError || scanJobList.isError || scannerWorkers.isError || systemConfig.isError || scannerHealth.isError;
  const loading = scanStatus.isPending || scanJobList.isPending || scannerWorkers.isPending || systemConfig.isPending;
  const latestDb = lifecycle?.cvedb_version || newestWorkerDb(workers);
  const latestDbTime = lifecycle?.cvedb_create_time || newestWorkerDbTime(workers);

  const jobColumns: Column<ScanJob>[] = [
      {
        id: "target",
        exportValue: job => job.target_ref,
        header: "Target", kind: "name", code: true, minSize: 260, wrap: true,
        cell: job => {
          const digest = job.target_type === "image" ? job.target_ref.match(/(?:^|@)(sha256:.+)$/)?.[1] : undefined;
          const name = digest ? job.target_ref.replace(/(?:^|@)sha256:.+$/, "") || "Unnamed image" : job.target_ref;
          return <div className="min-w-0">
            <div className="font-mono text-xs text-foreground" title={name}>{name}</div>
            <DigestDisclosure digest={digest} />
            <div className="mt-0.5 flex items-center gap-1.5 text-micro text-muted-foreground"><span>{job.target_type}</span>{job.source_type ? <span>· {job.source_type}</span> : null}{job.registry_id ? <span>· registry</span> : null}</div>
          </div>;
        },
        sort: () => 0,
      },
      { id: "type", header: "Target type", kind: "status", cell: job => job.target_type, exportValue: job => job.target_type, sort: () => 0 },
      { id: "findings", header: "Findings", kind: "count", cell: job => job.finding_count ?? "—", exportValue: job => job.finding_count, sort: () => 0 },
      { id: "finished", header: "Finished", kind: "date", cell: job => job.finished_at ? <span title={formatDate(job.finished_at)}>{fmtRelative(job.finished_at)}</span> : "—", exportValue: job => job.finished_at, sort: () => 0 },
      {
        id: "status",
        exportValue: job => job.status,
        header: "Status", kind: "status",

        cell: (job) => <StatusPill label={job.status} tone={scanJobStatusTone(job.status)} />,
        sort: () => 0,
      },
      {
        id: "attempts",
        exportValue: job => `${job.attempt_count}/${job.max_attempts}`,
        header: "Attempts", kind: "count",

        numeric: true,
        cell: (job) => `${job.attempt_count}/${job.max_attempts}`,
        sort: () => 0,
      },
      {
        id: "worker",
        exportValue: job => job.worker_id,
        header: "Worker", kind: "id", size: 160,

        cell: (job) => <span className="block font-mono text-xs text-muted-foreground" title={job.worker_id}>{job.worker_id || "-"}</span>,
      },
      {
        id: "error",
        exportValue: job => job.error || job.next_attempt_at,
        header: "Error / next retry", kind: "text", size: 240, minSize: 176, maxSize: 320, wrap: true,

        cell: (job) => (
          <span
            className={cn(
              "block text-xs",
              job.error ? "text-[color:var(--color-status-error)]" : "text-muted-foreground",
            )}
            title={job.error || job.next_attempt_at || ""}
          >
            {job.error || (job.next_attempt_at ? `retry ${formatDate(job.next_attempt_at)}` : "-")}
          </span>
        ),
      },
      {
        id: "requested",
        exportValue: job => job.requested_at,
        header: "Requested", kind: "date",

        cell: (job) => <span className="text-xs text-muted-foreground" title={formatDate(job.requested_at)}>{fmtRelative(job.requested_at)}</span>,
        sort: () => 0,
      },
      {
        id: "actions",
        exportable: false,
        header: "", kind: "actions", size: 224, minSize: 224, maxSize: 240,

        className: "text-right",
        cell: (job) => (
          <div className="flex justify-end gap-1">
            <Button
              type="button"
              size="icon"
              variant="outline"
              title="Inspect scan job"
              aria-label="Inspect scan job"
              onClick={() => setSelectedJobID(job.id)}
            >
              <Eye className="h-3.5 w-3.5" />
            </Button>
            <ScanJobActions job={job} pending={jobAction.isPending || !jobsAvailable} onAction={(action) => runJobAction(job, action)} />
          </div>
        ),
      },
  ];

  const workerColumns = useMemo<Column<ScannerWorker>[]>(
    () => [
      {
        id: "id",
        exportValue: scanner => `${scanner.id} · ${scanner.server || "unknown host"}`,
        header: "Scanner", kind: "name", code: true,
        cell: (scanner) => (
          <div className="min-w-0">
            <div className="font-mono text-xs text-foreground" title={scanner.id}>{scanner.id}</div>
            <div className="mt-0.5 text-micro text-muted-foreground" title={scanner.server}>{scanner.server || "unknown host"}</div>
          </div>
        ),
        sort: (a, b) => a.id.localeCompare(b.id),
      },
      {
        id: "joined",
        exportValue: scanner => scanner.joined_timestamp,
        header: "Joined", kind: "date", size: 224, minSize: 208, maxSize: 240,

        cell: (scanner) => <span className="text-xs text-muted-foreground">{formatUnixDate(scanner.joined_timestamp)}</span>,
        sort: (a, b) => a.joined_timestamp - b.joined_timestamp,
      },
      {
        id: "db",
        exportValue: scanner => `${scanner.cvedb_version || ""} · ${scanner.cvedb_create_time || ""}`,
        header: "CVE DB", kind: "version", size: 224, minSize: 208, maxSize: 280, wrap: true,

        cell: (scanner) => (
          <div className="min-w-0">
            <div className="font-mono text-xs">{scanner.cvedb_version || "-"}</div>
            <div className="mt-0.5 text-micro text-muted-foreground">{formatDate(scanner.cvedb_create_time)}</div>
          </div>
        ),
        sort: (a, b) => (a.cvedb_version ?? "").localeCompare(b.cvedb_version ?? ""),
      },
      {
        id: "scanned",
        exportValue: scanner => `${scanner.scanned_images} images · ${scanner.scanned_hosts} hosts`,
        header: "Scanned", kind: "text", align: "right", size: 184, minSize: 144, maxSize: 240, wrap: true,

        numeric: true,
        cell: (scanner) => (
          <span className="text-xs">
            {scanner.scanned_images.toLocaleString()} images
            <span className="text-muted-foreground"> · {scanner.scanned_hosts.toLocaleString()} hosts</span>
          </span>
        ),
        sort: (a, b) => (a.scanned_images + a.scanned_hosts) - (b.scanned_images + b.scanned_hosts),
      },
      {
        id: "cache",
        exportable: false,
        header: "", kind: "actions", size: 112, minSize: 112, maxSize: 128,

        className: "text-right",
        cell: (scanner) => (
          <Button
            type="button"
            variant={selectedScannerID === scanner.id ? "secondary" : "outline"}
            size="sm"
            onClick={() => setSelectedScannerID(scanner.id)}
          >
            <HardDrive className="h-3.5 w-3.5" />
            Cache
          </Button>
        ),
      },
    ],
    [selectedScannerID],
  );

  function refreshOperatorState() {
    void qc.invalidateQueries({ queryKey: ["system-config"] });
    void qc.invalidateQueries({ queryKey: ["scan-status"] });
    void qc.invalidateQueries({ queryKey: ["scan-scanner-workers"] });
    void qc.invalidateQueries({ queryKey: ["system-health"] });
    void invalidateJobLists(owner);
    if (selectedScannerID) {
      void qc.invalidateQueries({ queryKey: ["scanner-cache-stat", selectedScannerID] });
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Scanner & CVE Sources"
        description="Vulnerability data health — the Trivy/Grype databases and CVE feeds that power image and host scanning."
        actions={
          <Button type="button" variant="outline" size="sm" onClick={refreshOperatorState}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh view
          </Button>
        }
      />

      <VerdictBanner
        status={unavailable ? "degraded" : loading || workers.length === 0 ? "info" : failedTotal > 0 || staleTotal > 0 ? "degraded" : "ok"}
        title={unavailable ? "Some scanner status could not be loaded" : loading ? "Loading scanner status" : failedTotal > 0 || staleTotal > 0 ? "Scan jobs need attention" : workers.length === 0 ? "No scanner workers reported" : "Scanner activity is available"}
        detail={[
          latestDb ? `CVE DB ${latestDb}` : "CVE DB version not reported yet",
          latestDbTime ? `exported ${formatDate(latestDbTime)}` : "",
          !systemConfig.isSuccess ? "auto-refresh configuration unavailable" : refreshMinutes > 0 ? `auto-refresh every ${refreshMinutes} minutes` : "auto-refresh on the deploy default",
        ].filter(Boolean).join(" · ")}
      />

      {unavailable && <ErrorState title="Some scanner evidence is unavailable. Failed sources are hidden." action={<Button onClick={refreshOperatorState}>Retry scanner evidence</Button>} />}
      {[systemConfig, scanStatus, scanJobList, scannerWorkers, scannerHealth].some(query => query.isFetching && query.isSuccess) && <p role="status" className="text-sm text-muted-foreground">Refreshing scanner evidence…</p>}
      {refreshNow.isError && <p role="alert" className="text-sm text-destructive">Could not request a database refresh. Try again after refreshing scanner configuration.</p>}
      {jobAction.isError && jobAction.variables?.context === jobContext && <p role="alert" className="text-sm text-destructive">Could not update scan job {jobAction.variables?.reviewed.id}. Refresh the job and try again.</p>}
      <StatGrid data-testid="scanner-operator-summary">
        <StatCard label="Scanned" value={lifecycle ? lifecycle.scanned.toLocaleString() : "—"} icon={<CircleCheck className="h-3.5 w-3.5" />} tone="accent" />
        <StatCard label="Scheduled" value={lifecycle ? lifecycle.scheduled.toLocaleString() : scanJobList.isSuccess ? pendingTotal.toLocaleString() : "—"} icon={<Clock className="h-3.5 w-3.5" />} tone={pendingTotal > 0 ? "medium" : "neutral"} hint={typeof lifecycle?.paused === "number" ? `${lifecycle.paused} paused` : "Paused count unavailable"} />
        <StatCard label="Running" value={lifecycle ? lifecycle.scanning.toLocaleString() : scanJobList.isSuccess ? runningTotal.toLocaleString() : "—"} icon={<RefreshCw className="h-3.5 w-3.5" />} tone={runningTotal > 0 ? "low" : "neutral"} />
        <StatCard label="Failed" value={lifecycle ? lifecycle.failed.toLocaleString() : "—"} icon={<TriangleAlert className="h-3.5 w-3.5" />} tone={failedTotal > 0 ? "high" : "neutral"} />
        <StatCard label="Scanners" value={scannerWorkers.isSuccess ? workers.length.toLocaleString() : "—"} icon={<Database className="h-3.5 w-3.5" />} hint="last 24h" />
      </StatGrid>

      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "jobs", label: "Scan jobs", content: (
          <Card
            title="Scan lifecycle and queue"
            description="Filter and review scan jobs across server pages. Inspect their attempt history and pause, resume, retry or cancel eligible jobs."
          >
            <div className="space-y-4">
              <Collapse label="Queue depth by target type">
              <p className="mb-3 text-xs text-muted-foreground">Organization-wide current queue state, read separately from the filtered job ledger. These counts do not describe only the matching jobs.</p>
              <DataTable<ScanQueueMetric>
                rows={queueMetrics}
                columns={QUEUE_COLUMNS}
                rowKey={(row) => row.target_type}
                emptyState={<div className="px-6 py-8 text-center text-xs text-muted-foreground">{scanJobList.isError || !owner || invalidJobs ? "Queue status could not be loaded." : !jobsAvailable ? "Loading queue status..." : "No queued scan work."}</div>}
                defaultSort={{ id: "pending", dir: "desc" }}
                showDensityToggle={false}
                preferencesKey="scanner-queue-metrics"
                testId="scanner-queue-metrics"
              />
              </Collapse>

              <div className="flex flex-wrap items-center gap-1.5" data-testid="scan-job-status-filters">
                {JOB_STATUS_FILTERS.map((status) => (
                  <button
                    key={status}
                    type="button"
                    aria-pressed={jobStatusFilter === status}
                    onClick={() => route.update({ status: status === "all" ? null : status })}
                    className={cn(
                      "rounded border px-2 py-1 text-xs transition-colors",
                      jobStatusFilter === status
                        ? "border-[color:var(--color-primary)] bg-accent text-foreground"
                        : "border-border text-muted-foreground hover:bg-accent hover:text-foreground",
                    )}
                  >
                    {status}
                  </button>
                ))}
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <TextInput aria-label="Search scan jobs" placeholder="Search target, source, worker or error" value={route.query} onChange={event => route.setQuery(event.target.value)} />
                <Select aria-label="Scan target type" value={targetType} onChange={event => route.update({ target_type: event.target.value })} className="rounded-md border border-border bg-background p-2 text-sm"><option value="">All target types</option>{JOB_TARGET_TYPES.map(type => <option key={type}>{type}</option>)}</Select>
                <Button variant="outline" onClick={() => route.update({ q: null, status: null, target_type: null, cluster_id: null, registry_id: null, sort: null, order: null })}>Reset job filters</Button>
              </div>
              <ResourceSavedViewsControl inventory="scanner" ready={jobsAvailable}/>
              <Collapse label="Advanced: cluster and registry scope">
                <div className="grid gap-3 sm:grid-cols-2"><Field label="Cluster ID"><TextInput aria-label="Scan job cluster ID" value={clusterFilter} onChange={event => route.update({ cluster_id: event.target.value }, true, true)} placeholder="All clusters" /></Field><Field label="Registry ID"><TextInput aria-label="Scan job registry ID" value={registryFilter} onChange={event => route.update({ registry_id: event.target.value }, true, true)} placeholder="All registries" /></Field></div>
              </Collapse>
              {(clusterFilter || registryFilter) && <p className="text-xs text-muted-foreground">{clusterFilter && `Cluster: ${clusterFilter} `}{registryFilter && `Registry: ${registryFilter}`}</p>}
              {!owner ? <ErrorState title="An available organization and user session are required to load scan jobs." /> : invalidJobs ? <ErrorState title="Choose supported scan job filters, IDs, sorting and page." /> : scanJobList.isError ? <ErrorState title="Scan jobs could not be loaded or refreshed." action={<Button onClick={() => void scanJobList.refetch()}>Retry scan jobs</Button>} /> : !jobsAvailable ? <LoadingState label="Loading scan jobs…" /> : <>
                <div className="flex flex-wrap items-center justify-between gap-2"><p className="text-xs text-muted-foreground">{scanJobList.data!.total!.toLocaleString()} matching jobs · {scanJobList.data!.summary!.running.toLocaleString()} running · {scanJobList.data!.summary!.failed.toLocaleString()} failed. Counts cover all matches; table CSV covers this server page and selected columns.</p><ScanInventoryExport key={jobContext} context={jobContext} disabled={!jobsAvailable} download={shouldDownload => scanJobs.exportCSV(jobRequest, shouldDownload)} /></div>
                <DataTable<ScanJob>
                  rows={allJobs}
                  sourceLimit={100}
                  sourceCount={scanJobList.data!.total}
                  columns={jobColumns}
                  rowKey={job => job.id}
                  onRowClick={job => setSelectedJobID(job.id)}
                  selected={new Set(selectedJob ? [selectedJob.id] : [])}
                  emptyState={<div className="px-6 py-8 text-center text-xs text-muted-foreground">No scan jobs match this view or page.</div>}
                  pagination={false}
                  manualSorting
                  sort={{ id: jobSort, dir: jobOrder as "asc" | "desc" }}
                  onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })}
                  preferencesKey="scanner-recent-jobs"
                  exportFileName="scanner-recent-jobs-page"
                  exportLabel="Export this page CSV"
                  testId="scanner-recent-jobs"
                />
                {route.page > 0 && !allJobs.length && <Button onClick={() => route.setPage(0)}>First page</Button>}
                <Pager page={route.page} pageSize={100} rowsOnPage={allJobs.length} total={scanJobList.data!.total} onPage={route.setPage} />
              </>}

            </div>
          </Card>

        ) },
        { value: "workers", label: "Workers and capacity", content: <div className="space-y-4">
          <Card title="Scanner database and capacity" description="Live heartbeat capacity, host VulnDB bundles, and reported Trivy/Grype download and applied revisions.">
            <ScannerDbCapacity heartbeats={scannerHealth.isSuccess ? scannerHealth.data.heartbeats : undefined} unavailable={scannerHealth.isError} loading={scannerHealth.isPending} />
          </Card>

          <Card
            title="Scanner workers"
            description="Workers reported in the last 24 hours. Inspect their database revisions, capacity and caches."
            action={
              <Button type="button" variant="outline" size="sm" onClick={() => void scannerWorkers.refetch()}>
                <RefreshCw className={`h-3.5 w-3.5 ${scannerWorkers.isFetching ? "animate-spin" : ""}`} />
                Workers
              </Button>
            }
          >
            <div className="space-y-4">
              <DataTable<ScannerWorker>
                rows={workers}
                columns={workerColumns}
                rowKey={(scanner) => scanner.id}
                emptyState={<div className="px-6 py-8 text-center text-xs text-muted-foreground">{scannerWorkers.isError ? "Scanner workers could not be loaded." : scannerWorkers.isPending ? "Loading scanner workers..." : "No scanner workers have reported in the last 24 hours."}</div>}
                defaultSort={{ id: "id", dir: "asc" }}
                preferencesKey="scanner-workers"
                exportFileName="scanner-workers-last-24h"
                testId="scanner-workers"
              />

              {selectedScannerID && (!scannerWorkers.isSuccess || !workers.some(worker => worker.id === selectedScannerID)) && <p role="alert" className="text-sm text-destructive">The selected worker is unavailable. Refresh workers before inspecting its cache.</p>}
              {selectedScannerID && scannerWorkers.isSuccess && workers.some(worker => worker.id === selectedScannerID) && (
                <div className="rounded-md border border-border bg-muted/20 p-4" data-testid="scanner-cache-inspector">
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-sm font-medium text-foreground">Cache inspector</div>
                      <div className="mt-0.5 font-mono text-xs text-muted-foreground">{selectedScannerID}</div>
                    </div>
                    <Button type="button" variant="ghost" size="sm" onClick={() => setSelectedScannerID("")}>
                      <CircleX className="h-3.5 w-3.5" />
                      Close
                    </Button>
                  </div>

                  {cacheStat.isPending ? (
                    <div className="text-xs text-muted-foreground">Loading scanner cache status...</div>
                  ) : cacheStat.isError ? (
                    <ErrorState title="Cache status unavailable for this scanner." action={<Button onClick={() => void cacheStat.refetch()}>Retry cache</Button>} />
                  ) : cacheStat.isSuccess && cacheStat.data ? (
                    <>{cacheStat.isFetching && <p role="status" className="text-xs">Refreshing scanner cache…</p>}<ScannerCacheSummary stat={cacheStat.data} /></>
                  ) : null}
                </div>
              )}
            </div>
          </Card>

        </div> },
        { value: "databases", label: "Database refresh", content: (
          <Card
            title="Database refresh"
            description="How often connected scanners pull the latest Trivy & Grype vulnerability databases."
            action={
              <Button
                variant="primary"
                size="sm"
                onClick={() => refreshNow.mutate()}
                disabled={refreshNow.isPending || offlineDb || !systemConfig.isSuccess || systemConfig.isFetching}
                title={offlineDb ? "Air-gapped — scanners can't pull from upstream" : "Force all scanners to pull the latest DBs now"}
              >
                <RefreshCw className={`h-3.5 w-3.5 ${refreshNow.isPending ? "animate-spin" : ""}`} />
                Refresh now
              </Button>
            }
          >
            <div className="space-y-5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div><div className="text-sm font-medium">Auto-refresh interval</div><p className="mt-1 text-sm text-muted-foreground" data-testid="scanner-db-refresh-value">{!systemConfig.isSuccess ? "Configuration unavailable" : refreshMinutes > 0 ? `${refreshMinutes} minutes` : "Deploy default (6 hours)"}</p></div>
                <a href={intervalHref} className="inline-flex items-center gap-2 text-sm text-primary hover:underline" data-testid="scanner-db-refresh-edit"><Pencil className="h-4 w-4" /> Edit interval</a>
              </div>

              <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/30 px-4 py-3">
                <div>
                  <div className="text-sm font-medium text-foreground">Air-gapped mode</div>
                  <div className="text-xs text-muted-foreground">Databases are pre-loaded; no upstream network pulls. Set at deploy time.</div>
                </div>
                <span
                  className={`shrink-0 rounded-full px-2.5 py-1 text-micro font-medium ${
                    offlineDb ? "bg-[color:var(--color-brand)]/10 text-[color:var(--color-brand)]" : "bg-muted text-muted-foreground"
                  }`}
                  data-testid="scanner-offline-db"
                >
                  {systemConfig.isPending || systemConfig.isError ? "Unknown" : offlineDb ? "On" : "Off"}
                </span>
              </div>
            </div>
          </Card>

        ) },
        { value: "sources", label: "CVE sources", content: (
          <Card
            title="CVE intelligence sources"
            description="Sources used for vulnerability intelligence. Configuration does not establish successful delivery or freshness."
            padded={false}
          >
            <div className="divide-y divide-border">
              <SourceRow name="CISA KEV" desc="Known-exploited vulnerabilities catalog" status="Delivery not verified" />
              <SourceRow name="FIRST EPSS" desc="Exploit-probability scores" status="Delivery not verified" />
              <SourceRow
                name="NVD"
                desc="Full CVE catalog — descriptions + CVSS base scores"
                status={systemConfig.isPending || systemConfig.isError ? "Configuration unavailable" : nvdEnabled ? "Enabled" : "Disabled"}
                action={
                  <Button variant="outline" size="sm" onClick={() => navigate({ href: "/settings/scanner/nvd" })}>
                    <Pencil className="h-3.5 w-3.5" /> Configure
                  </Button>
                }
              />
            </div>
          </Card>

        ) },
      ]} />

      <ScanJobDrawer
        job={selectedJob}
        open={Boolean(selectedJobID) && tab === "jobs"}
        unavailable={scanJobList.isError ? "The selected job could not be refreshed. Retry the job inventory before continuing." : !jobsAvailable ? "The selected job is unavailable while this inventory scope is loading or invalid." : "The selected job is outside this page or filter. No other job has been substituted."}
        onOpenChange={(open) => {
          if (!open) setSelectedJobID("");
        }}
        pending={jobAction.isPending || !jobsAvailable}
        attempts={selectedJobAttempts.isSuccess ? selectedJobAttempts.data : []}
        attemptsLoading={selectedJobAttempts.isPending}
        attemptsRefreshing={selectedJobAttempts.isSuccess && selectedJobAttempts.isFetching}
        attemptsError={selectedJobAttempts.isError}
        retryAttempts={() => void selectedJobAttempts.refetch()}
        onAction={(action) => {
          if (selectedJob) runJobAction(selectedJob, action);
        }}
      />
    </div>
  );
}

function SourceRow({ name, desc, status, action }: { name: string; desc: string; status: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-3.5">
      <div className="flex min-w-0 items-center gap-3">
        <Circle className="h-4 w-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">{name}</div>
          <div className="truncate text-xs text-muted-foreground">{desc}</div>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <span className="text-micro font-medium text-muted-foreground">{status}</span>
        {action}
      </div>
    </div>
  );
}

type ScanJobAction = "pause" | "resume" | "retry" | "cancel";

const JOB_TARGET_TYPES = ["image", "workload", "host", "platform", "registry", "repository", "serverless"];
const JOB_SORTS = ["requested", "target", "type", "status", "attempts", "findings", "finished"];
function jobReview(job: ScanJob) { return JSON.stringify([job.id, job.org_id, job.target_id, job.target_type, job.target_ref, job.target_cluster_id, job.registry_id, job.status, job.attempt_count, job.max_attempts, job.claimed_at, job.next_attempt_at, job.finished_at]); }
const JOB_STATUS_FILTERS = ["all", "pending", "running", "failed", "paused", "canceled", "completed"];

const QUEUE_COLUMNS: Column<ScanQueueMetric>[] = [
  {
    id: "type",
    header: "Target type", kind: "name",
    cell: (row) => <span className="font-mono text-xs">{row.target_type}</span>,
    sort: (a, b) => a.target_type.localeCompare(b.target_type),
  },
  { id: "pending", header: "Pending", kind: "count", numeric: true, cell: (row) => row.pending.toLocaleString(), sort: (a, b) => a.pending - b.pending },
  { id: "retry", header: "Retry delay", kind: "count", numeric: true, cell: (row) => row.retry_delayed.toLocaleString(), sort: (a, b) => a.retry_delayed - b.retry_delayed },
  { id: "running", header: "Running", kind: "count", numeric: true, cell: (row) => row.running.toLocaleString(), sort: (a, b) => a.running - b.running },
  { id: "stale", header: "Stale", kind: "count", numeric: true, cell: (row) => row.stale_running.toLocaleString(), sort: (a, b) => a.stale_running - b.stale_running },
  { id: "failed", header: "Failed", kind: "count", numeric: true, cell: (row) => row.failed.toLocaleString(), sort: (a, b) => a.failed - b.failed },
  { id: "completed", header: "Done 1h", kind: "count", numeric: true, cell: (row) => row.completed_last_hour.toLocaleString(), sort: (a, b) => a.completed_last_hour - b.completed_last_hour },
  { id: "oldest", header: "Oldest", kind: "age", align: "right", size: 104, minSize: 88, maxSize: 128, numeric: true, cell: (row) => formatSeconds(row.oldest_pending_seconds), sort: (a, b) => a.oldest_pending_seconds - b.oldest_pending_seconds },
];

function ScanJobActions({
  job,
  pending,
  onAction,
}: {
  job: ScanJob;
  pending: boolean;
  onAction: (action: ScanJobAction) => void;
}) {
  const canPause = job.status === "pending";
  const canResume = job.status === "paused";
  const canRetry = job.status === "failed" || job.status === "canceled";
  const canCancel = job.status === "pending" || job.status === "paused" || job.status === "running";
  if (!canPause && !canResume && !canRetry && !canCancel) {
    return <span className="text-micro text-muted-foreground">No action</span>;
  }
  return (
    <div className="flex justify-end gap-1">
      {canPause && (
        <JobActionButton label="Pause" pending={pending} onClick={() => onAction("pause")}>
          <CirclePause className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
      {canResume && (
        <JobActionButton label="Resume" pending={pending} onClick={() => onAction("resume")}>
          <CirclePlay className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
      {canRetry && (
        <JobActionButton label="Retry" pending={pending} onClick={() => onAction("retry")}>
          <RotateCcw className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
      {canCancel && (
        <JobActionButton label="Cancel" pending={pending} onClick={() => onAction("cancel")} destructive>
          <CircleX className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
    </div>
  );
}

function ScanJobDrawer({
  job,
  open,
  onOpenChange,
  pending,
  unavailable,
  attempts,
  attemptsLoading,
  attemptsRefreshing,
  attemptsError,
  retryAttempts,
  onAction,
}: {
  job: ScanJob | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pending: boolean;
  unavailable: string;
  attempts: ScanJobAttempt[];
  attemptsLoading: boolean;
  attemptsRefreshing: boolean;
  attemptsError: boolean;
  retryAttempts: () => void;
  onAction: (action: ScanJobAction) => void;
}) {
  const retry = job ? scanJobRetryState(job) : null;
  const timingRows = job ? scanJobTimingRows(job) : [];
  const targetRows = job ? scanJobTargetRows(job) : [];
  const bundleRows = job ? scanJobBundleRows(job) : [];
  return (
    <Drawer
      open={open}
      onOpenChange={onOpenChange}
      title={job ? <span className="font-mono text-sm">{job.target_ref}</span> : "Scan job"}
      description={job ? `${job.target_type}${job.source_type ? ` · ${job.source_type}` : ""}` : undefined}
      width="xl"
      footer={job ? (
        <div className="flex items-center justify-between gap-3">
          <div className="text-xs text-muted-foreground">attempt {job.attempt_count}/{job.max_attempts}</div>
          <ScanJobActions job={job} pending={pending} onAction={onAction} />
        </div>
      ) : undefined}
    >
      {!job || !retry ? <p role="status" className="text-sm text-muted-foreground">{unavailable}</p> : (
        <div className="space-y-5" data-testid="scan-job-detail-drawer">
          <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <DetailMetric label="Status" value={<StatusPill label={job.status} tone={scanJobStatusTone(job.status)} />} />
            <DetailMetric label="Retry state" value={<StatusPill label={retry.label} tone={retry.tone} />} hint={formatRetryDetail(retry.detail)} />
            <DetailMetric label="Packages" value={(job.package_count ?? 0).toLocaleString()} />
            <DetailMetric label="Findings" value={(job.finding_count ?? 0).toLocaleString()} />
          </section>

          <section className="space-y-2">
            <SectionTitle title="Scanner error" />
            {job.error ? (
              <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-md border border-[color:var(--color-status-error)]/30 bg-[color:var(--color-status-error)]/5 p-3 font-mono text-xs text-[color:var(--color-status-error)]">
                {job.error}
              </pre>
            ) : (
              <div className="rounded-md border border-border bg-muted/20 px-3 py-2 text-xs text-muted-foreground">No scanner error recorded.</div>
            )}
          </section>

          <DetailSection title="Attempt timeline" rows={timingRows} dateValues />
          <AttemptHistory jobID={job.id} attempts={attempts} loading={attemptsLoading} refreshing={attemptsRefreshing} error={attemptsError} retry={retryAttempts} />
          <DetailSection title="Target metadata" rows={targetRows} mono />
          {bundleRows.length > 0 ? <DetailSection title="VulnDB provenance" rows={bundleRows} mono /> : null}
        </div>
      )}
    </Drawer>
  );
}

const ATTEMPT_COLUMNS: Column<ScanJobAttempt>[] = [
  { id: "attempt", header: "Try", kind: "count", cell: item => item.attempt_number, exportValue: item => item.attempt_number, sort: (a, b) => a.attempt_number - b.attempt_number },
  { id: "status", header: "Status", kind: "status", cell: item => <StatusPill label={item.status} tone={scanJobStatusTone(item.status)} />, exportValue: item => item.status, sort: (a, b) => a.status.localeCompare(b.status) },
  { id: "worker", header: "Worker", kind: "id", cell: item => item.worker_id || "—", exportValue: item => item.worker_id, sort: (a, b) => (a.worker_id ?? "").localeCompare(b.worker_id ?? "") },
  { id: "started", header: "Started", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: item => formatDate(item.started_at), exportValue: item => item.started_at, sort: (a, b) => a.started_at.localeCompare(b.started_at) },
  { id: "finished", header: "Finished", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: item => item.finished_at ? formatDate(item.finished_at) : "—", exportValue: item => item.finished_at, sort: (a, b) => (a.finished_at ?? "").localeCompare(b.finished_at ?? "") },
  { id: "retry", header: "Next retry", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: item => item.next_attempt_at ? formatDate(item.next_attempt_at) : "—", exportValue: item => item.next_attempt_at },
  { id: "lease", header: "Lease expires", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: item => item.lease_expires_at ? formatDate(item.lease_expires_at) : "—", exportValue: item => item.lease_expires_at },
  { id: "error", header: "Error", kind: "text", wrap: true, grow: true, cell: item => item.error || "—", exportValue: item => item.error },
];

function AttemptHistory({ jobID, attempts, loading, refreshing, error, retry }: { jobID: string; attempts: ScanJobAttempt[]; loading: boolean; refreshing: boolean; error: boolean; retry: () => void }) {
  return <section className="space-y-2">
    <SectionTitle title="Attempt history" />
    <p className="text-xs text-muted-foreground">Persisted attempts for this exact job. CSV exports the returned ledger only; the endpoint supplies no total or truncation indicator.</p>
    {error ? <ErrorState title="Attempt history is unavailable." action={<Button onClick={retry}>Retry attempts</Button>} /> : loading ? <LoadingState label="Loading attempts…" /> : <>
      {refreshing && <p role="status" className="text-xs text-muted-foreground">Refreshing attempts…</p>}
      <DataTable rows={attempts} columns={ATTEMPT_COLUMNS} rowKey={item => item.id} defaultSort={{ id: "attempt", dir: "asc" }} preferencesKey="scanner-job-attempts" exportFileName={`scanner-job-${jobID}-attempts`} testId="scanner-job-attempts" emptyState={<p className="p-6 text-sm text-muted-foreground">No attempt ledger recorded.</p>} />
    </>}
  </section>;
}

function DetailMetric({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2">
      <div className="text-micro  text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-medium text-foreground">{value}</div>
      {hint ? <div className="mt-1 truncate text-micro text-muted-foreground" title={hint}>{hint}</div> : null}
    </div>
  );
}

function DetailSection({ title, rows, mono, dateValues }: { title: string; rows: ScanJobDetailRow[]; mono?: boolean; dateValues?: boolean }) {
  return (
    <section className="space-y-2">
      <SectionTitle title={title} />
      <div className="rounded-md border border-border">
        {rows.length === 0 ? (
          <div className="px-3 py-2 text-xs text-muted-foreground">No data reported.</div>
        ) : (
          rows.map((row) => (
            <div key={`${title}-${row.label}`} className="grid gap-2 border-b border-border px-3 py-2 text-xs last:border-b-0 sm:grid-cols-[150px_minmax(0,1fr)]">
              <div className="text-muted-foreground">{row.label}</div>
              <div
                className={cn("min-w-0 break-words text-foreground", mono && "font-mono text-micro")}
                title={dateValues ? formatDate(row.value) : row.value}
              >
                {dateValues ? formatDate(row.value) : row.value}
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function SectionTitle({ title }: { title: string }) {
  return <h2 className="text-xs font-semibold  text-muted-foreground">{title}</h2>;
}

function formatRetryDetail(value: string) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : formatDate(value);
}

function JobActionButton({
  children,
  label,
  pending,
  destructive,
  onClick,
}: {
  children: React.ReactNode;
  label: string;
  pending: boolean;
  destructive?: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      type="button"
      size="icon"
      variant={destructive ? "ghost" : "outline"}
      title={label}
      aria-label={label}
      disabled={pending}
      onClick={onClick}
      className={destructive ? "text-[color:var(--color-status-error)]" : undefined}
    >
      {children}
    </Button>
  );
}

function ScannerCacheSummary({ stat }: { stat: ScannerCacheStat }) {
  return (
    <div className="space-y-3">
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <CacheInfo label="Status" value={stat.status} />
        <CacheInfo label="Records" value={stat.record_count.toLocaleString()} />
        <CacheInfo label="Size" value={formatBytes(stat.record_size_bytes)} />
        <CacheInfo label="Hit ratio" value={cacheHitRatio(stat.cache_hits, stat.cache_misses)} />
      </div>
      <div className="grid gap-2 lg:grid-cols-2">
        {stat.caches.length === 0 ? (
          <div className="rounded-md border border-border bg-card px-3 py-2 text-xs text-muted-foreground">No cache directories reported.</div>
        ) : (
          stat.caches.map((cache) => <CacheEntry key={cache.name} cache={cache} />)
        )}
      </div>
    </div>
  );
}

function CacheInfo({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2">
      <div className="text-micro  text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-mono text-xs text-foreground" title={value}>{value}</div>
    </div>
  );
}

function CacheEntry({ cache }: { cache: ScannerCacheHealthEntry & { name: string } }) {
  return (
    <div className="rounded-md border border-border bg-card px-3 py-2 text-xs">
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <div className="font-medium text-foreground">{cache.name}</div>
          <div className="mt-0.5 truncate font-mono text-micro text-muted-foreground" title={cache.path}>{cache.path || "-"}</div>
        </div>
        <StatusPill label={cache.status || "unknown"} tone={cacheStatusTone(cache.status)} />
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2 text-micro text-muted-foreground">
        <span>{cache.record_count ?? 0} records</span>
        <span>{formatBytes(cache.record_size_bytes ?? 0)}</span>
        <span>{cache.writable ? "writable" : "read-only"}</span>
      </div>
      {cache.error ? <div className="mt-2 text-micro text-[color:var(--color-status-error)]">{cache.error}</div> : null}
    </div>
  );
}

function sumMetric(metrics: ScanQueueMetric[], key: keyof Pick<ScanQueueMetric, "pending" | "retry_delayed" | "running" | "stale_running" | "exhausted">) {
  return metrics.reduce((acc, item) => acc + (Number(item[key]) || 0), 0);
}

function newestWorkerDb(workers: ScannerWorker[]) {
  return workers.find((worker) => worker.cvedb_version)?.cvedb_version ?? "";
}

function newestWorkerDbTime(workers: ScannerWorker[]) {
  return workers.find((worker) => worker.cvedb_create_time)?.cvedb_create_time ?? "";
}

function scanJobStatusTone(status: string): "neutral" | "success" | "warning" | "error" | "info" | "pending" | "accent" {
  switch (status) {
    case "completed":
      return "success";
    case "running":
      return "info";
    case "pending":
      return "pending";
    case "paused":
      return "warning";
    case "failed":
      return "error";
    case "canceled":
      return "neutral";
    default:
      return "neutral";
  }
}

function cacheStatusTone(status?: string): "neutral" | "success" | "warning" | "error" | "info" {
  switch (status) {
    case "ready":
    case "ok":
    case "healthy":
      return "success";
    case "missing":
    case "degraded":
      return "warning";
    case "error":
    case "failed":
      return "error";
    default:
      return "neutral";
  }
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatUnixDate(value?: number) {
  if (!value) return "-";
  return formatDate(new Date(value * 1000).toISOString());
}

function formatSeconds(seconds: number) {
  if (!seconds || seconds < 1) return "-";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remainder = minutes % 60;
  return remainder > 0 ? `${hours}h ${remainder}m` : `${hours}h`;
}

function formatBytes(bytes: number) {
  if (!bytes || bytes < 1) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 || unit === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function cacheHitRatio(hits: number, misses: number) {
  const total = hits + misses;
  if (total === 0) return "-";
  return `${Math.round((hits / total) * 100)}%`;
}


/** This form updates organization-wide configuration; it never sends a scanner refresh. */
export function ScannerDatabaseSettingsFormPage() {
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id.trim() && identity.user_id.trim() ? `${identity.org_id}:${identity.user_id}` : "";
  return <ScannerDatabaseSettingsScope key={owner} owner={owner} />;
}

function ScannerDatabaseSettingsScope({ owner }: { owner: string }) {
  const q = useQuery({ queryKey: ["system-config"], queryFn: systemConfigApi.get, enabled: !!owner });
  const [params] = useRouteSearchParams();
  const requestedBack = params.get("return_to");
  const backTo = requestedBack && /^\/settings\/scanner(?:\?[^#]*)?$/.test(requestedBack) ? requestedBack : "/settings/scanner?tab=databases";
  const [initial, setInitial] = useState<SystemConfigResponse | null>(null);
  useEffect(() => { if (owner && !initial && q.isSuccess && !q.isError && !q.isFetching && Number.isInteger(q.data.revision) && q.data.revision >= 0) setInitial(q.data); }, [owner, initial, q.isSuccess, q.isError, q.isFetching, q.data]);
  const conflict = !!initial && q.data?.revision !== initial.revision;
  return <div className="space-y-6" data-testid="scanner-db-settings-form">
    <PageHeader title="Edit scanner database refresh" description="Set the organization-wide interval used by connected scanners to refresh vulnerability databases. Saving the interval does not request an immediate refresh."
      backLink={<a href={backTo} className="inline-flex items-center gap-2 hover:text-foreground"><ArrowLeft className="h-4 w-4" /> Scanner database settings</a>} />
    {!owner ? <ErrorState title="An available organization and user session are required to edit scanner settings." /> : !initial ? q.isPending || q.isFetching ? <LoadingState label="Loading scanner database settings…" /> : <ErrorState title="Scanner database settings are unavailable." action={<Button onClick={() => void q.refetch()}>Retry settings</Button>} /> : <>
      {q.isError && <ErrorState title="Could not refresh scanner settings. Your draft is preserved." action={<Button onClick={() => void q.refetch()}>Retry settings</Button>} />}
      {q.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing scanner settings. Your draft is preserved; saving is paused.</p>}
      {conflict && <p role="alert" className="text-sm text-destructive">System configuration changed elsewhere. Your draft is preserved. Cancel and reopen the latest settings before saving.</p>}
      <ScannerIntervalEditor initial={initial} backTo={backTo} canSave={q.isSuccess && !q.isFetching && !conflict} />
    </>}
  </div>;
}

function ScannerIntervalEditor({ initial, backTo, canSave }: { initial: SystemConfigResponse; backTo: string; canSave: boolean }) {
  const qc = useQueryClient(); const navigate = useNavigate();
  const stored = typeof initial.config.scanner_db_refresh_minutes === "number" ? initial.config.scanner_db_refresh_minutes : 0;
  const [minutes, setMinutes] = useState(String(stored));
  const value = Number(minutes);
  const valid = minutes.trim() !== "" && Number.isSafeInteger(value) && value >= 0;
  const pending = useRef(false);
  const active = useRef(true);
  const currentBack = useRef(backTo); currentBack.current = backTo;
  const unknown = useRef(false);
  const [unconfirmed, setUnconfirmed] = useState(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const save = useMutation({ mutationFn: async (input: { minutes: number; backTo: string }) => {
    const state = qc.getQueryState<SystemConfigResponse>(["system-config"]);
    if (!active.current || unknown.current || !canSave || !valid || state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated || state.data?.revision !== initial.revision) throw new Error("Current scanner configuration is unavailable or changed. Your draft is preserved.");
    const result = await systemConfigApi.patch({ scanner_db_refresh_minutes: input.minutes }, initial.revision);
    if (!result || !Number.isInteger(result.revision) || result.revision <= initial.revision || result.config?.scanner_db_refresh_minutes !== input.minutes) {
      unknown.current = true;
      if (active.current) setUnconfirmed(true);
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      throw new Error("The response did not confirm the reviewed interval. Inspect current settings before another save.");
    }
    return result;
  }, onSuccess: (_result, input) => { void qc.invalidateQueries({ queryKey: ["system-config"] }); if (active.current && currentBack.current === input.backTo) void navigate({ href: input.backTo }); }, onError: error => { if (scannerRevisionConflict(error)) void qc.invalidateQueries({ queryKey: ["system-config"] }); }, onSettled: () => { pending.current = false; } });
  return <>
    <VerdictBanner status="info" title="This interval is shared across the organization" detail={`Saving updates system configuration revision ${initial.revision}. Air-gapped deployments use preloaded databases and do not pull upstream.`} />
    <Card title="Automatic database refresh"><form className="space-y-6" onSubmit={event => { event.preventDefault(); if (canSave && valid && !save.isPending && !pending.current && !unknown.current && !scannerRevisionConflict(save.error)) { pending.current = true; save.mutate({ minutes: value, backTo }); } }}>
      <Field label="Auto-refresh interval" htmlFor="scanner-db-refresh-minutes" hint="Whole minutes. 0 uses the deploy default (6 hours).">
        <TextInput id="scanner-db-refresh-minutes" type="number" min={0} step={1} value={minutes} onChange={event => setMinutes(event.target.value)} disabled={save.isPending} data-testid="scanner-db-refresh-minutes" />
      </Field>
      {!valid && <p role="alert" className="text-sm text-destructive">Use a nonnegative whole number of minutes.</p>}
      {unconfirmed && <p role="alert" className="text-sm text-destructive">Save outcome is unconfirmed. Cancel and inspect current settings before saving again.</p>}
      {save.isError && <p role="alert" className="text-sm text-destructive">{scannerRevisionConflict(save.error) ? "System configuration changed elsewhere. Your draft is preserved. Cancel and reopen the latest settings before saving." : "Could not save scanner settings. Your draft is preserved. Try again after refreshing settings."}</p>}
      <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" variant="primary" disabled={!canSave || !valid || unconfirmed || save.isPending || scannerRevisionConflict(save.error)} data-testid="scanner-db-refresh-save"><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save interval"}</Button></div>
    </form></Card>
  </>;
}

function eligibleJobAction(job: ScanJob, action: ScanJobAction) {
  switch (action) {
    case "pause": return job.status === "pending";
    case "resume": return job.status === "paused";
    case "retry": return job.status === "failed" || job.status === "canceled";
    case "cancel": return job.status === "pending" || job.status === "running" || job.status === "paused";
  }
}

function scannerRevisionConflict(error: unknown) { return isRevisionConflict(error) || (error as { response?: { status?: number } } | null)?.response?.status === 409; }
