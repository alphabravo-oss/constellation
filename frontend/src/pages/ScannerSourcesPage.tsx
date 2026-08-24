import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  CheckCircle2,
  Circle,
  Clock,
  Database,
  Eye,
  HardDrive,
  PauseCircle,
  Pencil,
  PlayCircle,
  RefreshCw,
  RotateCcw,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";

import {
  scanJobs,
  scanJobsAdmin,
  scannerOperations,
  systemConfigApi,
  type ScanJob,
  type ScanJobAttempt,
  type ScanQueueMetric,
  type ScannerCacheHealthEntry,
  type ScannerCacheStat,
  type ScannerWorker,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { Field, TextInput } from "@/components/ui/form";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { StatusPill } from "@/components/ui/status-pill";
import { cn } from "@/lib/cn";
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
  const navigate = useNavigate();
  const systemConfig = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const scanStatus = useQuery({ queryKey: ["scan-status"], queryFn: scannerOperations.status });
  const scannerWorkers = useQuery({ queryKey: ["scan-scanner-workers"], queryFn: scannerOperations.workers });
  const scanJobList = useQuery({ queryKey: ["scan-jobs", "scanner-sources"], queryFn: () => scanJobs.list() });
  const config = systemConfig.data?.config ?? {};
  const revision = systemConfig.data?.revision ?? 0;
  const refreshMinutes = typeof config.scanner_db_refresh_minutes === "number" ? config.scanner_db_refresh_minutes : 0;
  const offlineDb = config.scanner_offline_db === true;
  const nvdEnabled = config.nvd_enabled === true;
  const [jobStatusFilter, setJobStatusFilter] = useState("all");
  const [selectedScannerID, setSelectedScannerID] = useState("");
  const [selectedJobID, setSelectedJobID] = useState("");

  const cacheStat = useQuery({
    queryKey: ["scanner-cache-stat", selectedScannerID],
    queryFn: () => scannerOperations.cacheStat(selectedScannerID),
    enabled: selectedScannerID !== "",
  });

  const refreshNow = useMutation({
    mutationFn: () => systemConfigApi.refreshScanner(),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      void qc.invalidateQueries({ queryKey: ["scan-status"] });
      void qc.invalidateQueries({ queryKey: ["scan-scanner-workers"] });
      toast.success("Refresh requested — connected scanners will pull the latest DBs shortly");
    },
    onError: () => toast.error("Failed to request refresh"),
  });
  const updateRefresh = useMutation({
    mutationFn: (minutes: number) => systemConfigApi.patch({ scanner_db_refresh_minutes: minutes }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      toast.success("Scanner DB refresh interval updated");
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status === 409) {
        void qc.invalidateQueries({ queryKey: ["system-config"] });
        toast.error("Config changed elsewhere; reloaded latest — please retry.");
        return;
      }
      toast.error("Failed to update scanner DB refresh interval");
    },
  });

  const jobAction = useMutation({
    mutationFn: ({ id, action }: { id: string; action: ScanJobAction }) => {
      switch (action) {
        case "pause":
          return scanJobsAdmin.pause(id);
        case "resume":
          return scanJobsAdmin.resume(id);
        case "retry":
          return scanJobsAdmin.retry(id);
        case "cancel":
          return scanJobsAdmin.cancel(id);
      }
    },
    onSuccess: (_result, vars) => {
      void qc.invalidateQueries({ queryKey: ["scan-status"] });
      void qc.invalidateQueries({ queryKey: ["scan-jobs", "scanner-sources"] });
      toast.success(`Scan job ${vars.action} requested`);
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      toast.error(status === 409 ? "Scan job is no longer in an eligible state" : "Failed to update scan job");
    },
  });

  const lifecycle = scanStatus.data;
  const workers = scannerWorkers.data ?? [];
  const allJobs = useMemo(() => scanJobList.data?.jobs ?? [], [scanJobList.data?.jobs]);
  const selectedJob = useMemo(() => allJobs.find((job) => job.id === selectedJobID) ?? null, [allJobs, selectedJobID]);
  const selectedJobAttempts = useQuery({
    queryKey: ["scan-job-attempts", selectedJobID],
    queryFn: () => scanJobs.attempts(selectedJobID),
    enabled: Boolean(selectedJobID),
  });
  const filteredJobs = useMemo(
    () => (jobStatusFilter === "all" ? allJobs : allJobs.filter((job) => job.status === jobStatusFilter)),
    [allJobs, jobStatusFilter],
  );
  const queueMetrics = scanJobList.data?.queue_metrics ?? [];
  const pendingTotal = sumMetric(queueMetrics, "pending") + sumMetric(queueMetrics, "retry_delayed");
  const runningTotal = sumMetric(queueMetrics, "running");
  const staleTotal = sumMetric(queueMetrics, "stale_running");
  const failedTotal = (lifecycle?.failed ?? 0) + sumMetric(queueMetrics, "exhausted");
  const latestDb = lifecycle?.cvedb_version || newestWorkerDb(workers);
  const latestDbTime = lifecycle?.cvedb_create_time || newestWorkerDbTime(workers);

  const jobColumns = useMemo<Column<ScanJob>[]>(
    () => [
      {
        id: "target",
        header: "Target",
        cell: (job) => (
          <div className="min-w-0">
            <div className="truncate font-mono text-xs text-foreground" title={job.target_ref}>{job.target_ref}</div>
            <div className="mt-0.5 flex items-center gap-1.5 text-[10px] text-muted-foreground">
              <span>{job.target_type}</span>
              {job.source_type ? <span>· {job.source_type}</span> : null}
              {job.registry_id ? <span>· registry</span> : null}
            </div>
          </div>
        ),
        sort: (a, b) => a.target_ref.localeCompare(b.target_ref),
      },
      {
        id: "status",
        header: "Status",
        width: "112px",
        cell: (job) => <StatusPill label={job.status} tone={scanJobStatusTone(job.status)} />,
        sort: (a, b) => a.status.localeCompare(b.status),
      },
      {
        id: "attempts",
        header: "Attempts",
        width: "86px",
        numeric: true,
        cell: (job) => `${job.attempt_count}/${job.max_attempts}`,
        sort: (a, b) => a.attempt_count - b.attempt_count,
      },
      {
        id: "worker",
        header: "Worker",
        width: "160px",
        cell: (job) => <span className="block truncate font-mono text-xs text-muted-foreground" title={job.worker_id}>{job.worker_id || "-"}</span>,
        sort: (a, b) => (a.worker_id ?? "").localeCompare(b.worker_id ?? ""),
      },
      {
        id: "error",
        header: "Error / next retry",
        width: "220px",
        cell: (job) => (
          <span
            className={cn(
              "block truncate text-xs",
              job.error ? "text-[color:var(--color-status-error)]" : "text-muted-foreground",
            )}
            title={job.error || job.next_attempt_at || ""}
          >
            {job.error || (job.next_attempt_at ? `retry ${formatDate(job.next_attempt_at)}` : "-")}
          </span>
        ),
        sort: (a, b) => (a.error || a.next_attempt_at || "").localeCompare(b.error || b.next_attempt_at || ""),
      },
      {
        id: "requested",
        header: "Requested",
        width: "170px",
        cell: (job) => <span className="text-xs text-muted-foreground">{formatDate(job.requested_at)}</span>,
        sort: (a, b) => a.requested_at.localeCompare(b.requested_at),
      },
      {
        id: "actions",
        header: "",
        width: "210px",
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
            <ScanJobActions job={job} pending={jobAction.isPending} onAction={(action) => jobAction.mutate({ id: job.id, action })} />
          </div>
        ),
      },
    ],
    [jobAction],
  );

  const workerColumns = useMemo<Column<ScannerWorker>[]>(
    () => [
      {
        id: "id",
        header: "Scanner",
        cell: (scanner) => (
          <div className="min-w-0">
            <div className="truncate font-mono text-xs text-foreground" title={scanner.id}>{scanner.id}</div>
            <div className="mt-0.5 truncate text-[10px] text-muted-foreground" title={scanner.server}>{scanner.server || "unknown host"}</div>
          </div>
        ),
        sort: (a, b) => a.id.localeCompare(b.id),
      },
      {
        id: "joined",
        header: "Joined",
        width: "160px",
        cell: (scanner) => <span className="text-xs text-muted-foreground">{formatUnixDate(scanner.joined_timestamp)}</span>,
        sort: (a, b) => a.joined_timestamp - b.joined_timestamp,
      },
      {
        id: "db",
        header: "CVE DB",
        width: "190px",
        cell: (scanner) => (
          <div className="min-w-0">
            <div className="truncate font-mono text-xs">{scanner.cvedb_version || "-"}</div>
            <div className="mt-0.5 truncate text-[10px] text-muted-foreground">{formatDate(scanner.cvedb_create_time)}</div>
          </div>
        ),
        sort: (a, b) => (a.cvedb_version ?? "").localeCompare(b.cvedb_version ?? ""),
      },
      {
        id: "scanned",
        header: "Scanned",
        width: "160px",
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
        header: "",
        width: "120px",
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
    void qc.invalidateQueries({ queryKey: ["scan-status"] });
    void qc.invalidateQueries({ queryKey: ["scan-scanner-workers"] });
    void qc.invalidateQueries({ queryKey: ["scan-jobs", "scanner-sources"] });
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
        status={offlineDb ? "info" : failedTotal > 0 || staleTotal > 0 ? "degraded" : "ok"}
        title={offlineDb ? "Air-gapped — databases loaded from a local mirror" : "Scanners fed by live Trivy + Grype databases"}
        detail={[
          latestDb ? `CVE DB ${latestDb}` : "CVE DB version not reported yet",
          latestDbTime ? `exported ${formatDate(latestDbTime)}` : "",
          refreshMinutes > 0 ? `auto-refresh every ${refreshMinutes} minutes` : "auto-refresh on the deploy default",
        ].filter(Boolean).join(" · ")}
      />

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6" data-testid="scanner-operator-summary">
        <StatCard label="Scanned" value={(lifecycle?.scanned ?? 0).toLocaleString()} icon={<CheckCircle2 className="h-3.5 w-3.5" />} tone="accent" />
        <StatCard label="Scheduled" value={(lifecycle?.scheduled ?? pendingTotal).toLocaleString()} icon={<Clock className="h-3.5 w-3.5" />} tone={pendingTotal > 0 ? "medium" : "neutral"} />
        <StatCard label="Running" value={(lifecycle?.scanning ?? runningTotal).toLocaleString()} icon={<RefreshCw className="h-3.5 w-3.5" />} tone={runningTotal > 0 ? "low" : "neutral"} />
        <StatCard label="Failed" value={(lifecycle?.failed ?? 0).toLocaleString()} icon={<AlertTriangle className="h-3.5 w-3.5" />} tone={failedTotal > 0 ? "high" : "neutral"} />
        <StatCard label="Paused" value={(lifecycle?.paused ?? 0).toLocaleString()} icon={<PauseCircle className="h-3.5 w-3.5" />} tone={(lifecycle?.paused ?? 0) > 0 ? "medium" : "neutral"} />
        <StatCard label="Scanners" value={workers.length.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} hint="last 24h" />
      </section>

      <Card
        title="Database refresh"
        description="How often connected scanners pull the latest Trivy & Grype vulnerability databases."
        action={
          <Button
            variant="primary"
            size="sm"
            onClick={() => refreshNow.mutate()}
            disabled={refreshNow.isPending || offlineDb}
            title={offlineDb ? "Air-gapped — scanners can't pull from upstream" : "Force all scanners to pull the latest DBs now"}
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshNow.isPending ? "animate-spin" : ""}`} />
            Refresh now
          </Button>
        }
      >
        <div className="space-y-5">
          <Field
            label="Auto-refresh interval"
            hint="Minutes between automatic database refreshes. 0 uses the deploy default (6 hours)."
          >
            <div className="flex items-center gap-2">
              <TextInput
                type="number"
                min={0}
                defaultValue={refreshMinutes}
                key={`refresh-${revision}-${refreshMinutes}`}
                disabled={systemConfig.isLoading || updateRefresh.isPending}
                onBlur={(e) => {
                  const n = Number.parseInt(e.target.value, 10);
                  if (!Number.isNaN(n) && n !== refreshMinutes) updateRefresh.mutate(n);
                }}
                className="w-28"
                data-testid="scanner-db-refresh-minutes"
              />
              <span className="text-xs text-muted-foreground">minutes</span>
            </div>
          </Field>

          <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/30 px-4 py-3">
            <div>
              <div className="text-sm font-medium text-foreground">Air-gapped mode</div>
              <div className="text-xs text-muted-foreground">Databases are pre-loaded; no upstream network pulls. Set at deploy time.</div>
            </div>
            <span
              className={`shrink-0 rounded-full px-2.5 py-1 text-[11px] font-medium ${
                offlineDb ? "bg-[color:var(--color-brand)]/10 text-[color:var(--color-brand)]" : "bg-muted text-muted-foreground"
              }`}
              data-testid="scanner-offline-db"
            >
              {offlineDb ? "On" : "Off"}
            </span>
          </div>
        </div>
      </Card>

      <Card
        title="Scan lifecycle and queue"
        description="NeuVector-style scan status plus queue depth by target type. Operators can pause, resume, retry, or cancel jobs without leaving the scanner page."
      >
        <div className="space-y-4">
          <DataTable<ScanQueueMetric>
            rows={queueMetrics}
            columns={QUEUE_COLUMNS}
            rowKey={(row) => row.target_type}
            emptyState={<div className="px-6 py-8 text-center text-xs text-muted-foreground">No queued scan work.</div>}
            defaultSort={{ id: "pending", dir: "desc" }}
            showDensityToggle={false}
            testId="scanner-queue-metrics"
          />

          <div className="flex flex-wrap items-center gap-1.5" data-testid="scan-job-status-filters">
            {JOB_STATUS_FILTERS.map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => setJobStatusFilter(status)}
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

          <DataTable<ScanJob>
            rows={filteredJobs}
            columns={jobColumns}
            rowKey={(job) => job.id}
            onRowClick={(job) => setSelectedJobID(job.id)}
            emptyState={<div className="px-6 py-8 text-center text-xs text-muted-foreground">No scan jobs match this view.</div>}
            defaultSort={{ id: "requested", dir: "desc" }}
            preferencesKey="scanner-recent-jobs"
            exportFileName="scanner-recent-jobs"
            testId="scanner-recent-jobs"
          />
        </div>
      </Card>

      <Card
        title="Scanner workers"
        description="Live scanner workers reported by the NeuVector-compatible /scan/scanner route, with cache health inspection for each worker."
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
            emptyState={<div className="px-6 py-8 text-center text-xs text-muted-foreground">No scanner workers have reported in the last 24 hours.</div>}
            defaultSort={{ id: "id", dir: "asc" }}
            showDensityToggle={false}
            testId="scanner-workers"
          />

          {selectedScannerID && (
            <div className="rounded-md border border-border bg-muted/20 p-4" data-testid="scanner-cache-inspector">
              <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <div className="text-sm font-medium text-foreground">Cache inspector</div>
                  <div className="mt-0.5 font-mono text-xs text-muted-foreground">{selectedScannerID}</div>
                </div>
                <Button type="button" variant="ghost" size="sm" onClick={() => setSelectedScannerID("")}>
                  <XCircle className="h-3.5 w-3.5" />
                  Close
                </Button>
              </div>

              {cacheStat.isPending ? (
                <div className="text-xs text-muted-foreground">Loading scanner cache status...</div>
              ) : cacheStat.isError ? (
                <div className="text-xs text-[color:var(--color-status-error)]">Cache status unavailable for this scanner.</div>
              ) : cacheStat.data ? (
                <ScannerCacheSummary stat={cacheStat.data} />
              ) : null}
            </div>
          )}
        </div>
      </Card>

      <Card
        title="CVE intelligence sources"
        description="Live feeds that populate the CVE Database with descriptions, severity, and exploitation intelligence."
        padded={false}
      >
        <div className="divide-y divide-border">
          <SourceRow name="CISA KEV" desc="Known-exploited vulnerabilities catalog" live />
          <SourceRow name="FIRST EPSS" desc="Exploit-probability scores, refreshed daily" live />
          <SourceRow
            name="NVD"
            desc="Full CVE catalog — descriptions + CVSS base scores"
            live={nvdEnabled}
            action={
              <Button variant="outline" size="sm" onClick={() => navigate("/settings/scanner/nvd")}>
                <Pencil className="h-3.5 w-3.5" /> Configure
              </Button>
            }
          />
        </div>
      </Card>

      <ScanJobDrawer
        job={selectedJob}
        open={Boolean(selectedJob)}
        onOpenChange={(open) => {
          if (!open) setSelectedJobID("");
        }}
        pending={jobAction.isPending}
        attempts={selectedJobAttempts.data ?? []}
        attemptsLoading={selectedJobAttempts.isFetching}
        onAction={(action) => {
          if (selectedJob) jobAction.mutate({ id: selectedJob.id, action });
        }}
      />
    </div>
  );
}

function SourceRow({ name, desc, live, action }: { name: string; desc: string; live: boolean; action?: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 px-5 py-3.5">
      <div className="flex min-w-0 items-center gap-3">
        {live ? (
          <CheckCircle2 className="h-4 w-4 shrink-0 text-[color:var(--color-status-success)]" />
        ) : (
          <Circle className="h-4 w-4 shrink-0 text-muted-foreground/40" />
        )}
        <div className="min-w-0">
          <div className="text-sm font-medium text-foreground">{name}</div>
          <div className="truncate text-xs text-muted-foreground">{desc}</div>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-3">
        <span className={`text-[11px] font-medium ${live ? "text-[color:var(--color-status-success)]" : "text-muted-foreground"}`}>
          {live ? "Live" : "Off"}
        </span>
        {action}
      </div>
    </div>
  );
}

type ScanJobAction = "pause" | "resume" | "retry" | "cancel";

const JOB_STATUS_FILTERS = ["all", "pending", "running", "failed", "paused", "canceled", "completed"];

const QUEUE_COLUMNS: Column<ScanQueueMetric>[] = [
  {
    id: "type",
    header: "Target type",
    cell: (row) => <span className="font-mono text-xs">{row.target_type}</span>,
    sort: (a, b) => a.target_type.localeCompare(b.target_type),
  },
  { id: "pending", header: "Pending", numeric: true, cell: (row) => row.pending.toLocaleString(), sort: (a, b) => a.pending - b.pending },
  { id: "retry", header: "Retry delay", numeric: true, cell: (row) => row.retry_delayed.toLocaleString(), sort: (a, b) => a.retry_delayed - b.retry_delayed },
  { id: "running", header: "Running", numeric: true, cell: (row) => row.running.toLocaleString(), sort: (a, b) => a.running - b.running },
  { id: "stale", header: "Stale", numeric: true, cell: (row) => row.stale_running.toLocaleString(), sort: (a, b) => a.stale_running - b.stale_running },
  { id: "failed", header: "Failed", numeric: true, cell: (row) => row.failed.toLocaleString(), sort: (a, b) => a.failed - b.failed },
  { id: "completed", header: "Done 1h", numeric: true, cell: (row) => row.completed_last_hour.toLocaleString(), sort: (a, b) => a.completed_last_hour - b.completed_last_hour },
  { id: "oldest", header: "Oldest", numeric: true, cell: (row) => formatSeconds(row.oldest_pending_seconds), sort: (a, b) => a.oldest_pending_seconds - b.oldest_pending_seconds },
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
    return <span className="text-[10px] text-muted-foreground">No action</span>;
  }
  return (
    <div className="flex justify-end gap-1">
      {canPause && (
        <JobActionButton label="Pause" pending={pending} onClick={() => onAction("pause")}>
          <PauseCircle className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
      {canResume && (
        <JobActionButton label="Resume" pending={pending} onClick={() => onAction("resume")}>
          <PlayCircle className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
      {canRetry && (
        <JobActionButton label="Retry" pending={pending} onClick={() => onAction("retry")}>
          <RotateCcw className="h-3.5 w-3.5" />
        </JobActionButton>
      )}
      {canCancel && (
        <JobActionButton label="Cancel" pending={pending} onClick={() => onAction("cancel")} destructive>
          <XCircle className="h-3.5 w-3.5" />
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
  attempts,
  attemptsLoading,
  onAction,
}: {
  job: ScanJob | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  pending: boolean;
  attempts: ScanJobAttempt[];
  attemptsLoading: boolean;
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
      {!job || !retry ? null : (
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
          <AttemptHistory attempts={attempts} loading={attemptsLoading} />
          <DetailSection title="Target metadata" rows={targetRows} mono />
          {bundleRows.length > 0 ? <DetailSection title="VulnDB provenance" rows={bundleRows} mono /> : null}
        </div>
      )}
    </Drawer>
  );
}

function AttemptHistory({ attempts, loading }: { attempts: ScanJobAttempt[]; loading: boolean }) {
  return (
    <section className="space-y-2">
      <SectionTitle title="Attempt history" />
      <div className="overflow-x-auto rounded-md border border-border">
        <div className="grid min-w-[620px] grid-cols-[64px_110px_minmax(0,1fr)_150px_150px] border-b border-border bg-muted/30 px-3 py-2 text-[10px] uppercase tracking-wider text-muted-foreground">
          <div>Try</div>
          <div>Status</div>
          <div>Worker</div>
          <div>Started</div>
          <div>Finished</div>
        </div>
        {loading ? (
          <div className="px-3 py-2 text-xs text-muted-foreground">Loading attempts...</div>
        ) : attempts.length === 0 ? (
          <div className="px-3 py-2 text-xs text-muted-foreground">No attempt ledger recorded.</div>
        ) : (
          attempts.map((attempt) => (
            <div
              key={attempt.id}
              className="grid min-w-[620px] grid-cols-[64px_110px_minmax(0,1fr)_150px_150px] gap-2 border-b border-border px-3 py-2 text-xs last:border-b-0"
            >
              <div className="font-mono text-[11px]">{attempt.attempt_number}</div>
              <div><StatusPill label={attempt.status} tone={scanJobStatusTone(attempt.status)} /></div>
              <div className="min-w-0 truncate font-mono text-[11px]" title={attempt.worker_id}>{attempt.worker_id || "-"}</div>
              <div className="text-[11px] text-muted-foreground">{formatDate(attempt.started_at)}</div>
              <div className="text-[11px] text-muted-foreground">{attempt.finished_at ? formatDate(attempt.finished_at) : formatDate(attempt.next_attempt_at)}</div>
              {attempt.error ? (
                <div className="col-span-5 min-w-0 whitespace-pre-wrap break-words rounded bg-[color:var(--color-status-error)]/5 px-2 py-1 font-mono text-[11px] text-[color:var(--color-status-error)]">
                  {attempt.error}
                </div>
              ) : null}
            </div>
          ))
        )}
      </div>
    </section>
  );
}

function DetailMetric({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <div className="rounded-md border border-border bg-muted/20 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-medium text-foreground">{value}</div>
      {hint ? <div className="mt-1 truncate text-[10px] text-muted-foreground" title={hint}>{hint}</div> : null}
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
                className={cn("min-w-0 break-words text-foreground", mono && "font-mono text-[11px]")}
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
  return <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">{title}</h2>;
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
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</div>
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
          <div className="mt-0.5 truncate font-mono text-[10px] text-muted-foreground" title={cache.path}>{cache.path || "-"}</div>
        </div>
        <StatusPill label={cache.status || "unknown"} tone={cacheStatusTone(cache.status)} />
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2 text-[10px] text-muted-foreground">
        <span>{cache.record_count ?? 0} records</span>
        <span>{formatBytes(cache.record_size_bytes ?? 0)}</span>
        <span>{cache.writable ? "writable" : "read-only"}</span>
      </div>
      {cache.error ? <div className="mt-2 text-[10px] text-[color:var(--color-status-error)]">{cache.error}</div> : null}
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
