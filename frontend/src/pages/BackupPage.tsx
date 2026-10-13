import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Save,
  Download,
  UploadCloud,
  Clock,
  RefreshCw,
  Calendar,
  CheckCircle2,
  AlertTriangle,
  PlayCircle,
  Pencil,
  Cloud,
  HardDrive,
} from "lucide-react";

import {
  backupsApi,
  type BackupSummary,
  type BackupSchedule,
  type BackupInventoryParams,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card, DetailRow } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { TextInput, Select } from "@/components/ui/form";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import {
  useInventoryRoute,
  ScanInventoryExport,
  ScanInventoryContinuation,
} from "./inventory-workspace";
import {
  backupFiltersValid,
  backupInventoryValid,
  backupRowValid,
} from "./backup-inventory";

export function BackupPage() {
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const owner =
    identity?.org_id.trim() && identity.user_id.trim()
      ? `${identity.org_id}:${identity.user_id}`
      : "";
  const route = useInventoryRoute(INVENTORY_MAX_PAGE);
  const params = route.params,
    sort = params.get("sort") || "when",
    order = params.get("order") || "desc";
  const filter = (key: string) =>
    params.get(key) && params.get(key) !== "all" ? params.get(key)! : undefined;
  const request: BackupInventoryParams = {
    q: route.debouncedQuery.trim().toLowerCase() || undefined,
    status: filter("status"),
    mode: filter("mode"),
    signed: filter("signed"),
    sort,
    order: order as "asc" | "desc",
    limit: 100,
    offset: route.offset,
  };
  const valid = backupFiltersValid(params),
    key = ["backups", "inventory", owner, request],
    context = JSON.stringify(key);
  const listQ = useQuery({
    queryKey: key,
    queryFn: () => backupsApi.inventory(request),
    enabled: !!owner && valid && !route.debouncing,
    refetchInterval: 5000,
  });
  const schedQ = useQuery({
    queryKey: ["backups-schedule", owner],
    queryFn: async () => {
      const data = await backupsApi.getSchedule();
      if (
        !data ||
        typeof data.enabled !== "boolean" ||
        typeof data.cron_expr !== "string" ||
        !["none", "static-key", "keyless"].includes(data.sign_mode) ||
        [data.s3_bucket, data.s3_prefix, data.s3_endpoint].some(
          (value) => value !== undefined && typeof value !== "string",
        )
      )
        throw new Error("Backup settings could not be confirmed.");
      return data;
    },
    enabled: !!owner,
  });
  const mismatch =
    listQ.data !== undefined &&
    !backupInventoryValid(listQ.data, request, identity?.org_id || "");
  const available =
    !!owner && valid && !route.debouncing && listQ.isSuccess && !mismatch;
  const rows = available ? listQ.data!.backups : [],
    last = available ? listQ.data!.latest_success : null;
  const captureExport = useExportGuard(
    context,
    !available || listQ.isFetching,
    () => exportQueryReady(qc, key, listQ.data),
  );
  const captureOwner = useExportGuard(owner, !owner);
  const scheduleKey = ["backups-schedule", owner];
  const captureCreate = useExportGuard(
    JSON.stringify([owner, schedQ.data]),
    !owner || !schedQ.isSuccess || schedQ.isFetching,
    () => exportQueryReady(qc, scheduleKey, schedQ.data),
  );
  const [pending, setPending] = useState<{
    id: string;
    owner: string;
    ownerCurrent: () => boolean;
  } | null>(null);
  const activePending = pending?.owner === owner ? pending : null;
  const pendingKey = ["backup-detail", owner, activePending?.id];
  const pendingQ = useQuery({
    queryKey: pendingKey,
    queryFn: async () => {
      const data = await backupsApi.get(activePending!.id);
      if (!backupRowValid(data) || data.id !== activePending!.id)
        throw new Error("Backup receipt does not match the requested job.");
      return data;
    },
    enabled: !!owner && !!activePending,
    refetchInterval: (query) =>
      query.state.data?.status === "running" ? 5000 : false,
  });
  const capturePending = useExportGuard(
    JSON.stringify(pendingKey),
    !activePending || !pendingQ.isSuccess || pendingQ.isFetching,
    () => exportQueryReady(qc, pendingKey, pendingQ.data),
  );
  const handledPending = useRef<string | null>(null);
  const createMutation = useMutation({
    mutationFn: async (submitted: {
      owner: string;
      sign_mode: string;
      current: () => boolean;
      ownerCurrent: () => boolean;
    }) => {
      if (!submitted.current())
        throw new Error("Refresh backup settings before starting a backup.");
      const result = await backupsApi.create({
        sign_mode: submitted.sign_mode,
      });
      if (
        !result ||
        typeof result.id !== "string" ||
        !result.id.trim() ||
        result.status !== "running"
      )
        throw new Error("Backup start receipt could not be confirmed.");
      return { submitted, result };
    },
    onSuccess: ({ submitted, result }) => {
      void qc.invalidateQueries({
        queryKey: ["backups"],
        predicate: (query) => query.queryKey.includes(submitted.owner),
      });
      if (!submitted.current() || !submitted.ownerCurrent()) return;
      toast.success("Backup started");
      setPending({
        id: result.id,
        owner: submitted.owner,
        ownerCurrent: submitted.ownerCurrent,
      });
    },
    onError: (e: Error, submitted) => {
      if (submitted.current() && submitted.ownerCurrent())
        toast.error(`Backup failed: ${e.message}`);
    },
  });
  useEffect(() => {
    if (!activePending) return;
    if (!activePending.ownerCurrent()) {
      setPending(null);
      return;
    }
    if (
      !pendingQ.isSuccess ||
      pendingQ.isFetching ||
      pendingQ.data.id !== activePending.id ||
      handledPending.current === activePending.id
    )
      return;
    const row = pendingQ.data,
      current = capturePending();
    if (!current() || (row.status !== "succeeded" && row.status !== "failed"))
      return;
    handledPending.current = activePending.id;
    void qc.invalidateQueries({
      queryKey: ["backups"],
      predicate: (query) => query.queryKey.includes(activePending.owner),
    });
    const clear = () =>
      setPending((saved) => (saved === activePending ? null : saved));
    if (row.status === "failed") {
      toast.error(`Backup failed: ${row.error || "unknown"}`);
      clear();
      return;
    }
    toast.success(
      `Backup ${row.id.slice(0, 8)} complete (${row.size_bytes} bytes)`,
    );
    const fresh = () => activePending.ownerCurrent() && current();
    void backupsApi
      .download(row.id, fresh)
      .catch((e: Error) => {
        if (fresh()) toast.error(`Download failed: ${e.message}`);
      })
      .finally(clear);
  }, [
    activePending,
    pendingQ.isSuccess,
    pendingQ.isFetching,
    pendingQ.data,
    qc,
    capturePending,
  ]);
  const downloadRow = (row: BackupSummary) => {
    const current = captureExport();
    if (
      !current() ||
      !rows.some((item) => item.id === row.id && item.status === "succeeded")
    )
      return;
    void backupsApi.download(row.id, current).catch((e: Error) => {
      if (current()) toast.error(`Download failed: ${e.message}`);
    });
  };

  const historyColumns: Column<BackupSummary>[] = [
    {
      id: "when",
      exportValue: (b) => b.started_at,
      header: "When",
      sort: () => 0,
      kind: "date",
      size: 224,
      minSize: 208,
      maxSize: 240,
      cell: (b) => (
        <span className="font-mono text-xs">
          {new Date(b.started_at).toLocaleString()}
        </span>
      ),
    },
    {
      id: "mode",
      exportValue: (b) => b.mode,
      header: "Mode",
      sort: () => 0,
      kind: "status",
      cell: (b) => b.mode,
    },
    {
      id: "size",
      exportHeader: "Size (bytes)",
      exportValue: (b) => b.size_bytes,
      header: "Size",
      sort: () => 0,
      kind: "bytes",
      size: 128,
      minSize: 104,
      maxSize: 160,
      cell: (b) => (
        <span className="font-mono text-xs">
          {b.size_bytes ? `${(b.size_bytes / 1024).toFixed(1)} KiB` : "—"}
        </span>
      ),
    },
    {
      id: "status",
      exportValue: (b) => b.status,
      header: "Status",
      sort: () => 0,
      kind: "status",
      cell: (b) => (
        <>
          {b.status === "succeeded" && (
            <span className="inline-flex items-center gap-1 text-status-success">
              <CheckCircle2 className="h-3.5 w-3.5" />
              succeeded
            </span>
          )}
          {b.status === "running" && (
            <span className="inline-flex items-center gap-1 text-status-warning">
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              running
            </span>
          )}
          {b.status === "failed" && (
            <span className="inline-flex items-center gap-1 text-destructive">
              <AlertTriangle className="h-3.5 w-3.5" />
              failed
            </span>
          )}
        </>
      ),
    },
    {
      id: "signer",
      exportValue: (b) => b.signer_identity || "Not reported",
      header: "Signer",
      sort: () => 0,
      kind: "name",
      code: true,
      cell: (b) => (
        <span className="inline-block font-mono text-xs align-bottom">
          {b.signer_identity || "—"}
        </span>
      ),
    },
    {
      id: "actions",
      exportable: false,
      header: "Actions",
      kind: "actions",
      size: 144,
      minSize: 136,
      maxSize: 160,
      className: "text-right",
      cell: (b) =>
        b.status === "succeeded" ? (
          <Button
            variant="outline"
            size="sm"
            disabled={!available || listQ.isFetching}
            onClick={() => downloadRow(b)}
          >
            <Download className="h-3 w-3" /> Download
          </Button>
        ) : null,
    },
  ];

  return (
    <div className="space-y-6" data-testid="backup-page">
      <PageHeader
        eyebrow={
          <Link
            to="/settings"
            className="inline-flex items-center gap-1 font-normal normal-case tracking-normal hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to Settings
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <Save className="h-5 w-5" aria-hidden /> Backup &amp; Restore
          </span>
        }
        description="Signed, portable full-org backups. Restore on any Constellation instance."
        actions={
          <Button
            variant="primary"
            size="lg"
            onClick={() => {
              const current = captureCreate();
              if (current() && schedQ.data)
                createMutation.mutate({
                  owner,
                  sign_mode: schedQ.data.sign_mode,
                  current,
                  ownerCurrent: captureOwner(),
                });
            }}
            disabled={
              !owner ||
              !schedQ.isSuccess ||
              schedQ.isFetching ||
              createMutation.isPending ||
              !!activePending
            }
            data-testid="backup-create-button"
          >
            {activePending ? (
              <RefreshCw className="h-4 w-4 animate-spin" />
            ) : (
              <PlayCircle className="h-4 w-4" />
            )}
            {activePending ? "Backing up…" : "Take backup now"}
          </Button>
        }
      />

      {/* Backup destination — where backups are stored. */}
      {!owner ? (
        <ErrorState title="Resolve the current organization and user before loading backups." />
      ) : schedQ.isError ? (
        <ErrorState
          title="Backup settings are unavailable."
          action={
            <Button onClick={() => void schedQ.refetch()}>
              Retry settings
            </Button>
          }
        />
      ) : schedQ.isPending ? (
        <LoadingState label="Loading backup settings…" />
      ) : (
        <DestinationCard schedule={schedQ.data} />
      )}
      {activePending && (
        <p role="status" className="text-xs text-muted-foreground">
          Backup {activePending.id} ·{" "}
          {pendingQ.isError
            ? "Status unavailable"
            : pendingQ.data?.status || "Checking status"}
          {pendingQ.isError && (
            <Button size="sm" onClick={() => void pendingQ.refetch()}>
              Retry backup status
            </Button>
          )}
        </p>
      )}

      {/* Status — latest backup metrics as a full-width stat row. */}
      <section data-testid="backup-status" className="space-y-3">
        <p className="text-xs text-muted-foreground">
          Latest successful backup for this organization · independent of
          history filters.
        </p>
        {available && last ? (
          <StatGrid>
            <StatCard
              label="Created"
              value={
                <span className="text-base font-mono">
                  {new Date(last.started_at).toLocaleString()}
                </span>
              }
            />
            <StatCard
              label="Size"
              value={
                <span className="font-mono">
                  {(last.size_bytes / 1024).toFixed(1)} KiB
                </span>
              }
            />
            <StatCard
              label="Signer"
              value={
                <span className="text-base font-mono">
                  {last.signer_identity ||
                    (last.signed ? "(signed)" : "unsigned")}
                </span>
              }
              tone={last.signed ? "low" : "neutral"}
            />
            <StatCard
              label="Destination"
              value={
                <span className="text-base font-mono">
                  {last.s3_uri || "Local"}
                </span>
              }
              tone={last.s3_uri ? "accent" : "neutral"}
              icon={
                last.s3_uri ? (
                  <Cloud className="h-3 w-3" />
                ) : (
                  <HardDrive className="h-3 w-3" />
                )
              }
            />
          </StatGrid>
        ) : (
          <p className="text-sm text-muted-foreground">
            {available
              ? "No successful backup recorded for this organization."
              : "Latest successful backup is unavailable until history resolves."}
          </p>
        )}
      </section>

      {/* Backup table */}
      <Card
        title={
          <span className="flex items-center gap-2">
            <Clock className="h-4 w-4" aria-hidden /> History
          </span>
        }
        description="Retained backup run metadata for this organization."
      >
        <div className="flex flex-wrap items-end gap-3">
          <label className="min-w-48 flex-1 text-xs">
            Search history
            <TextInput
              aria-label="Search backup history"
              value={route.query}
              onChange={(event) => route.setQuery(event.target.value)}
            />
          </label>
          <label className="text-xs">
            Status
            <Select
              aria-label="Backup status"
              value={params.get("status") || "all"}
              onChange={(event) => route.update({ status: event.target.value })}
            >
              <option value="all">All statuses</option>
              {["running", "succeeded", "failed"].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </Select>
          </label>
          <label className="text-xs">
            Mode
            <Select
              aria-label="Backup mode"
              value={params.get("mode") || "all"}
              onChange={(event) => route.update({ mode: event.target.value })}
            >
              <option value="all">All modes</option>
              <option value="org-backup">Organization backup</option>
              <option value="pg-dump">Database dump</option>
            </Select>
          </label>
          <label className="text-xs">
            Signature
            <Select
              aria-label="Backup signature"
              value={params.get("signed") || "all"}
              onChange={(event) => route.update({ signed: event.target.value })}
            >
              <option value="all">All signatures</option>
              <option value="true">Signed</option>
              <option value="false">Unsigned</option>
            </Select>
          </label>
          <Button
            disabled={!owner || !valid || route.debouncing || listQ.isFetching}
            onClick={() => void listQ.refetch()}
          >
            Refresh history
          </Button>
          <Button
            variant="ghost"
            onClick={() =>
              route.update({
                q: null,
                status: null,
                mode: null,
                signed: null,
                sort: null,
                order: null,
              })
            }
          >
            Reset history filters
          </Button>
        </div>
        {!owner ? null : !valid ? (
          <ErrorState title="Choose supported backup filters, sorting and page." />
        ) : listQ.isError || mismatch ? (
          <ErrorState
            title="Backup history is unavailable or could not be refreshed."
            action={
              <Button onClick={() => void listQ.refetch()}>
                Retry history
              </Button>
            }
          />
        ) : !available ? (
          <LoadingState label="Loading backup history…" />
        ) : (
          <>
            <VerdictBanner
              status="info"
              title={`${listQ.data!.total.toLocaleString()} matching backup runs · ${rows.length} on page ${route.page + 1}${listQ.isFetching ? " · Refreshing" : ""}`}
              detail={
                <>
                  <p>
                    Filters, summaries and matching CSV describe all retained
                    owned metadata. Unowned legacy system backups are excluded.
                    Latest successful backup covers the full organization,
                    independently of filters. These records do not verify
                    current artifact availability or restore readiness.
                  </p>
                  <p>
                    {listQ.data!.summary.running} running ·{" "}
                    {listQ.data!.summary.succeeded} succeeded ·{" "}
                    {listQ.data!.summary.failed} failed ·{" "}
                    {listQ.data!.summary.signed} signed. Matching CSV includes
                    up to 100,000 metadata records; artifact downloads remain
                    separate.
                  </p>
                </>
              }
            />
            <ScanInventoryExport
              context={context}
              disabled={listQ.isFetching}
              isCurrent={() => exportQueryReady(qc, key, listQ.data)}
              download={(current) => backupsApi.inventoryCSV(request, current)}
            />
            <div data-testid="backup-history">
              <DataTable
                rows={rows}
                columns={historyColumns}
                rowKey={(b) => b.id}
                preferencesKey="backup-run-history"
                pagination={false}
                manualSorting
                sort={{ id: sort, dir: order as "asc" | "desc" }}
                onSortChange={(next) =>
                  route.update({
                    sort: next?.id || null,
                    order: next?.dir || null,
                  })
                }
                exportFileName="constellation-backup-metadata-page"
                exportLabel="Export this page metadata CSV"
                canExport={captureExport()}
                emptyState={
                  <p className="p-6 text-sm text-muted-foreground">
                    No backup runs match these filters or page.
                  </p>
                }
              />
            </div>
            <ScanInventoryContinuation
              page={route.page}
              rows={rows.length}
              hasMore={listQ.data!.has_more}
              total={listQ.data!.total}
              matching={rows.length}
              onPage={route.setPage}
            />
          </>
        )}
      </Card>

      {/* Schedule */}
      <Collapse label="Schedule and restore">
        <SchedulePanel schedule={schedQ.isSuccess ? schedQ.data : undefined} />

        {/* Restore */}
        <RestoreCard />
      </Collapse>
    </div>
  );
}

// ------------------------------------------------------------

// DestinationCard — the obvious place to choose WHERE backups are stored:
// local disk (not durable) or an Amazon S3 bucket. The config form lives on its
// own page (/settings/backup/destination); here we only show the current verdict
// and an affordance that navigates to it.
function DestinationCard({
  schedule,
}: {
  schedule: BackupSchedule | undefined;
}) {
  const navigate = useNavigate();
  const hasS3 = !!(schedule?.s3_bucket && schedule.s3_bucket.trim());

  const s3Uri = hasS3
    ? `s3://${schedule!.s3_bucket}/${(schedule!.s3_prefix ?? "").replace(/^\/+/, "")}`
    : "";

  return (
    <section className="space-y-3" data-testid="backup-destination">
      {hasS3 ? (
        <VerdictBanner
          status="ok"
          title={
            <span className="flex items-center gap-2">
              <Cloud className="h-4 w-4" aria-hidden /> Scheduled backup
              destination configured
            </span>
          }
          detail={
            <span>
              Configured destination: <span className="font-mono">{s3Uri}</span>
              . Successful run metadata reports its recorded archive location.
            </span>
          }
          actions={
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate({ href: "/settings/backup/destination" })}
              data-testid="backup-destination-configure"
            >
              <Pencil className="h-3.5 w-3.5" /> Configure destination
            </Button>
          }
        />
      ) : (
        <VerdictBanner
          status="degraded"
          title={
            <span className="flex items-center gap-2">
              <HardDrive className="h-4 w-4" aria-hidden /> Local storage only —
              backups are not durable
            </span>
          }
          detail="Backups are written to the server's local disk and lost if the instance is destroyed. Set an Amazon S3 destination for durable, off-cluster storage."
          actions={
            <Button
              variant="primary"
              size="sm"
              onClick={() => navigate({ href: "/settings/backup/destination" })}
              data-testid="backup-destination-configure"
            >
              <Cloud className="h-3.5 w-3.5" /> Set S3 destination
            </Button>
          }
        />
      )}
    </section>
  );
}

// ------------------------------------------------------------

function SchedulePanel({ schedule }: { schedule: BackupSchedule | undefined }) {
  const navigate = useNavigate();

  if (!schedule) {
    return (
      <Card title="Scheduled backups">
        <p className="text-sm text-muted-foreground">Loading schedule…</p>
      </Card>
    );
  }

  return (
    <div data-testid="backup-schedule">
      <Card
        title={
          <span className="flex items-center gap-2">
            <Calendar className="h-4 w-4" aria-hidden /> Scheduled backups
          </span>
        }
        description="Automatic signed backups on a cron schedule, written to the destination above."
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate({ href: "/settings/backup/schedule" })}
          >
            <Pencil className="h-3.5 w-3.5" /> Configure
          </Button>
        }
      >
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
          <DetailRow label="Status">
            {schedule.enabled ? "Enabled" : "Disabled"}
          </DetailRow>
          <DetailRow label="Schedule" mono>
            {schedule.cron_expr || "—"}
          </DetailRow>
          <DetailRow label="Signing" mono>
            {schedule.sign_mode}
          </DetailRow>
          <DetailRow label="Last run" mono>
            {schedule.last_run_at
              ? new Date(schedule.last_run_at).toLocaleString()
              : "never"}
          </DetailRow>
        </dl>
      </Card>
    </div>
  );
}

// ------------------------------------------------------------

function RestoreCard() {
  const navigate = useNavigate();
  return (
    <div data-testid="backup-restore">
      <Card
        title={
          <span className="flex items-center gap-2">
            <UploadCloud className="h-4 w-4" aria-hidden /> Restore
          </span>
        }
        description={
          <>
            Import a signed <code>constellation-backup-*.tar.gz</code> onto this
            instance. The manifest, signer identity, and per-table counts are
            shown before anything is applied.
          </>
        }
        action={
          <Button
            variant="outline"
            size="sm"
            onClick={() => navigate({ href: "/settings/backup/restore" })}
          >
            <UploadCloud className="h-3.5 w-3.5" /> Restore from backup
          </Button>
        }
      >
        <p className="text-sm text-muted-foreground">
          Uploading a backup never overwrites data until you confirm — verify
          the signature and per-table counts first, then choose how conflicts
          are handled.
        </p>
      </Card>
    </div>
  );
}
