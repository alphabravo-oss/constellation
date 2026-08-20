// BackupPage — Wave N5 full-org backup / restore.
//
// Route: /settings/backup.
//
// Layout (top -> bottom):
//   1. Backup destination card — Local vs Amazon S3 (verdict banner + "Configure
//      destination" navigates to /settings/backup/destination). The obvious place
//      to point backups at a durable S3 bucket.
//   2. Status card. Last backup timestamp, size, signer identity, destination.
//   3. "Take backup now" button — POSTs /backups, polls /backups/{id}, then auto-downloads.
//   4. Backup history table (id, when, size, mode, signed, status, download).
//   5. Schedule panel — cron-expression + sign mode ("Configure" navigates to
//      /settings/backup/schedule).
//   6. Restore card — "Restore from backup" navigates to /settings/backup/restore.
//
// The destination / schedule / restore forms live on their own dedicated route
// pages (the Astronomer add/edit-as-a-page pattern) — see src/pages/backup/.
//
// Server-side endpoints used:
//   GET    /api/v1/backups
//   POST   /api/v1/backups
//   GET    /api/v1/backups/{id}
//   GET    /api/v1/backups/{id}/download
//   GET    /api/v1/backups/schedule
import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
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
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card, DetailRow } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export function BackupPage() {
  const qc = useQueryClient();
  const listQ = useQuery({ queryKey: ["backups"], queryFn: () => backupsApi.list(), refetchInterval: 5000 });
  const schedQ = useQuery({ queryKey: ["backups-schedule"], queryFn: () => backupsApi.getSchedule() });

  const [pendingID, setPendingID] = useState<string | null>(null);
  const createMutation = useMutation({
    mutationFn: () => backupsApi.create({ sign_mode: schedQ.data?.sign_mode || "none" }),
    onSuccess: (resp) => {
      toast.success("Backup started");
      setPendingID(resp.id);
      qc.invalidateQueries({ queryKey: ["backups"] });
    },
    onError: (e: Error) => toast.error(`Backup failed: ${e.message}`),
  });

  // Poll pending backup; once succeeded, optionally auto-download.
  useEffect(() => {
    if (!pendingID || !listQ.data) return;
    const row = listQ.data.find((b) => b.id === pendingID);
    if (!row) return;
    if (row.status === "succeeded") {
      toast.success(`Backup ${pendingID.slice(0, 8)} complete (${row.size_bytes} bytes)`);
      setPendingID(null);
      // Auto-download via the authenticated client. The download route requires a Bearer
      // token (attached by the axios interceptor), which a plain window.open would not send.
      backupsApi.download(row.id).catch((e: Error) => toast.error(`Download failed: ${e.message}`));
    } else if (row.status === "failed") {
      toast.error(`Backup failed: ${row.error || "unknown"}`);
      setPendingID(null);
    }
  }, [pendingID, listQ.data]);

  const last = useMemo<BackupSummary | undefined>(
    () => (listQ.data ?? []).find((b) => b.status === "succeeded"),
    [listQ.data],
  );

  const historyColumns: Column<BackupSummary>[] = [
    { id: "when", header: "When", cell: (b) => <span className="font-mono text-xs">{new Date(b.started_at).toLocaleString()}</span> },
    { id: "mode", header: "Mode", cell: (b) => b.mode },
    { id: "size", header: "Size", cell: (b) => <span className="font-mono text-xs">{b.size_bytes ? `${(b.size_bytes / 1024).toFixed(1)} KiB` : "—"}</span> },
    {
      id: "status",
      header: "Status",
      cell: (b) => (
        <>
          {b.status === "succeeded" && <span className="inline-flex items-center gap-1 text-status-success"><CheckCircle2 className="h-3.5 w-3.5" />succeeded</span>}
          {b.status === "running" && <span className="inline-flex items-center gap-1 text-status-warning"><RefreshCw className="h-3.5 w-3.5 animate-spin" />running</span>}
          {b.status === "failed" && <span className="inline-flex items-center gap-1 text-destructive"><AlertTriangle className="h-3.5 w-3.5" />failed</span>}
        </>
      ),
    },
    { id: "signer", header: "Signer", cell: (b) => <span className="inline-block max-w-[16ch] truncate font-mono text-xs align-bottom">{b.signer_identity || "—"}</span> },
    {
      id: "actions",
      header: "Actions",
      className: "text-right",
      cell: (b) =>
        b.status === "succeeded" ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => backupsApi.download(b.id).catch((e: Error) => toast.error(`Download failed: ${e.message}`))}
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
            onClick={() => createMutation.mutate()}
            disabled={createMutation.isPending || pendingID !== null}
            data-testid="backup-create-button"
          >
            {pendingID ? <RefreshCw className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
            {pendingID ? "Backing up…" : "Take backup now"}
          </Button>
        }
      />

      {/* Backup destination — where backups are stored. */}
      <DestinationCard schedule={schedQ.data} />

      {/* Status — latest backup metrics as a full-width stat row. */}
      <section data-testid="backup-status" className="space-y-3">
        {last ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Created" value={<span className="text-base font-mono">{new Date(last.started_at).toLocaleString()}</span>} />
            <StatCard label="Size" value={<span className="font-mono">{(last.size_bytes / 1024).toFixed(1)} KiB</span>} />
            <StatCard label="Signer" value={<span className="text-base font-mono">{last.signer_identity || (last.signed ? "(signed)" : "unsigned")}</span>} tone={last.signed ? "low" : "neutral"} />
            <StatCard label="Destination" value={<span className="text-base font-mono">{last.s3_uri || "Local"}</span>} tone={last.s3_uri ? "accent" : "neutral"} icon={last.s3_uri ? <Cloud className="h-3 w-3" /> : <HardDrive className="h-3 w-3" />} />
          </div>
        ) : (
          <Card title="Latest backup" description="The most recent successful backup and where it landed.">
            <p className="text-sm text-muted-foreground">No backups yet. Click "Take backup now" to create the first one.</p>
          </Card>
        )}
      </section>

      {/* Backup table */}
      <Card
        title={<span className="flex items-center gap-2"><Clock className="h-4 w-4" aria-hidden /> History</span>}
        description="Every backup run on this instance, newest first."
        padded={false}
      >
        <div data-testid="backup-history">
          <DataTable
            rows={listQ.data ?? []}
            columns={historyColumns}
            rowKey={(b) => b.id}
            emptyState={<div className="p-6 text-sm text-muted-foreground">No backups recorded.</div>}
          />
        </div>
      </Card>

      {/* Schedule */}
      <SchedulePanel schedule={schedQ.data} />

      {/* Restore */}
      <RestoreCard />
    </div>
  );
}

// ------------------------------------------------------------

// DestinationCard — the obvious place to choose WHERE backups are stored:
// local disk (not durable) or an Amazon S3 bucket. The config form lives on its
// own page (/settings/backup/destination); here we only show the current verdict
// and an affordance that navigates to it.
function DestinationCard({ schedule }: { schedule: BackupSchedule | undefined }) {
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
              <Cloud className="h-4 w-4" aria-hidden /> Backups are stored in Amazon S3
            </span>
          }
          detail={
            <span>
              Destination: <span className="font-mono">{s3Uri}</span>. Scheduled backups (and on-demand
              backups where supported) are written here — durable, off-cluster storage.
            </span>
          }
          actions={
            <Button variant="outline" size="sm" onClick={() => navigate("/settings/backup/destination")} data-testid="backup-destination-configure">
              <Pencil className="h-3.5 w-3.5" /> Configure destination
            </Button>
          }
        />
      ) : (
        <VerdictBanner
          status="degraded"
          title={
            <span className="flex items-center gap-2">
              <HardDrive className="h-4 w-4" aria-hidden /> Local storage only — backups are not durable
            </span>
          }
          detail="Backups are written to the server's local disk and lost if the instance is destroyed. Set an Amazon S3 destination for durable, off-cluster storage."
          actions={
            <Button variant="primary" size="sm" onClick={() => navigate("/settings/backup/destination")} data-testid="backup-destination-configure">
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
        title={<span className="flex items-center gap-2"><Calendar className="h-4 w-4" aria-hidden /> Scheduled backups</span>}
        description="Automatic signed backups on a cron schedule, written to the destination above."
        action={
          <Button variant="outline" size="sm" onClick={() => navigate("/settings/backup/schedule")}>
            <Pencil className="h-3.5 w-3.5" /> Configure
          </Button>
        }
      >
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1 md:grid-cols-4">
          <DetailRow label="Status">{schedule.enabled ? "Enabled" : "Disabled"}</DetailRow>
          <DetailRow label="Schedule" mono>{schedule.cron_expr || "—"}</DetailRow>
          <DetailRow label="Signing" mono>{schedule.sign_mode}</DetailRow>
          <DetailRow label="Last run" mono>{schedule.last_run_at ? new Date(schedule.last_run_at).toLocaleString() : "never"}</DetailRow>
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
        title={<span className="flex items-center gap-2"><UploadCloud className="h-4 w-4" aria-hidden /> Restore</span>}
        description={
          <>
            Import a signed <code>constellation-backup-*.tar.gz</code> onto this instance. The manifest,
            signer identity, and per-table counts are shown before anything is applied.
          </>
        }
        action={
          <Button variant="outline" size="sm" onClick={() => navigate("/settings/backup/restore")}>
            <UploadCloud className="h-3.5 w-3.5" /> Restore from backup
          </Button>
        }
      >
        <p className="text-sm text-muted-foreground">
          Uploading a backup never overwrites data until you confirm — verify the signature and per-table
          counts first, then choose how conflicts are handled.
        </p>
      </Card>
    </div>
  );
}
