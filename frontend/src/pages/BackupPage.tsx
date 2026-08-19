// BackupPage — Wave N5 full-org backup / restore.
//
// Route: /settings/backup.
//
// Layout (top -> bottom):
//   1. Backup destination card — Local vs Amazon S3 (verdict banner + "Configure
//      destination" drawer). The obvious place to point backups at a durable S3 bucket.
//   2. Status card. Last backup timestamp, size, signer identity, destination.
//   3. "Take backup now" button — POSTs /backups, polls /backups/{id}, then auto-downloads.
//   4. Backup history table (id, when, size, mode, signed, status, download).
//   5. Schedule panel — cron-expression + sign mode (destination is set in card #1).
//   6. Restore wizard — upload file -> verify -> confirm-then-apply.
//
// Server-side endpoints used:
//   GET    /api/v1/backups
//   POST   /api/v1/backups
//   GET    /api/v1/backups/{id}
//   GET    /api/v1/backups/{id}/download
//   POST   /api/v1/backups/verify
//   POST   /api/v1/backups/restore
//   GET    /api/v1/backups/schedule
//   POST   /api/v1/backups/schedule
import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ArrowLeft,
  Save,
  Download,
  UploadCloud,
  Clock,
  ShieldCheck,
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
  type BackupManifestDTO,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Drawer } from "@/components/ui/drawer";
import { StatCard } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";

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
          <button
            type="button"
            onClick={() => backupsApi.download(b.id).catch((e: Error) => toast.error(`Download failed: ${e.message}`))}
            className="inline-flex items-center gap-1 rounded border border-border bg-background px-2 py-1 text-xs hover:bg-muted"
          >
            <Download className="h-3 w-3" /> Download
          </button>
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
          <button
            type="button"
            onClick={() => createMutation.mutate()}
            disabled={createMutation.isPending || pendingID !== null}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90 disabled:opacity-50"
            data-testid="backup-create-button"
          >
            {pendingID ? <RefreshCw className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />}
            {pendingID ? "Backing up…" : "Take backup now"}
          </button>
        }
      />

      {/* Backup destination — where backups are stored. */}
      <DestinationCard schedule={schedQ.data} />

      {/* Status card */}
      <section className="rounded-lg border border-border bg-card p-4" data-testid="backup-status">
        <h2 className="mb-3 text-sm font-medium uppercase text-muted-foreground">Latest backup</h2>
        {last ? (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <StatCard label="Created" value={<span className="text-base font-mono">{new Date(last.started_at).toLocaleString()}</span>} />
            <StatCard label="Size" value={<span className="font-mono">{(last.size_bytes / 1024).toFixed(1)} KiB</span>} />
            <StatCard label="Signer" value={<span className="text-base font-mono">{last.signer_identity || (last.signed ? "(signed)" : "unsigned")}</span>} tone={last.signed ? "low" : "neutral"} />
            <StatCard label="Destination" value={<span className="text-base font-mono">{last.s3_uri || "Local"}</span>} tone={last.s3_uri ? "accent" : "neutral"} icon={last.s3_uri ? <Cloud className="h-3 w-3" /> : <HardDrive className="h-3 w-3" />} />
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">No backups yet. Click "Take backup now" to create the first one.</p>
        )}
      </section>

      {/* Backup table */}
      <section className="rounded-lg border border-border bg-card" data-testid="backup-history">
        <header className="flex items-center justify-between border-b border-border p-3">
          <h2 className="flex items-center gap-2 text-sm font-medium">
            <Clock className="h-4 w-4" aria-hidden /> History
          </h2>
        </header>
        <DataTable
          rows={listQ.data ?? []}
          columns={historyColumns}
          rowKey={(b) => b.id}
          emptyState={<div className="p-6 text-sm text-muted-foreground">No backups recorded.</div>}
        />
      </section>

      {/* Schedule */}
      <SchedulePanel schedule={schedQ.data} />

      {/* Restore wizard */}
      <RestoreWizard />
    </div>
  );
}

// ------------------------------------------------------------

// DestinationCard — the obvious place to choose WHERE backups are stored:
// local disk (not durable) or an Amazon S3 bucket. The S3 target lives on the
// BackupSchedule (s3_bucket / s3_prefix / s3_endpoint); we merge our edits into
// the current schedule so cron / sign_mode / enabled are never wiped.
function DestinationCard({ schedule }: { schedule: BackupSchedule | undefined }) {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"local" | "s3">("local");
  const [bucket, setBucket] = useState("");
  const [prefix, setPrefix] = useState("");
  const [endpoint, setEndpoint] = useState("");

  const hasS3 = !!(schedule?.s3_bucket && schedule.s3_bucket.trim());

  // Seed the drawer form from the current schedule each time it opens.
  function openDrawer() {
    setMode(hasS3 ? "s3" : "local");
    setBucket(schedule?.s3_bucket ?? "");
    setPrefix(schedule?.s3_prefix ?? "");
    setEndpoint(schedule?.s3_endpoint ?? "");
    setOpen(true);
  }

  const save = useMutation({
    mutationFn: () => {
      if (!schedule) throw new Error("schedule not loaded yet");
      const merged: BackupSchedule = {
        ...schedule,
        s3_bucket: mode === "s3" ? bucket.trim() : "",
        s3_prefix: mode === "s3" ? prefix.trim() : "",
        s3_endpoint: mode === "s3" ? endpoint.trim() : "",
      };
      return backupsApi.putSchedule(merged);
    },
    onSuccess: () => {
      toast.success("Backup destination saved");
      setOpen(false);
      qc.invalidateQueries({ queryKey: ["backups-schedule"] });
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

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
            <button
              type="button"
              onClick={openDrawer}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1.5 text-xs hover:bg-accent"
              data-testid="backup-destination-configure"
            >
              <Pencil className="h-3.5 w-3.5" /> Configure destination
            </button>
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
            <button
              type="button"
              onClick={openDrawer}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-2.5 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
              data-testid="backup-destination-configure"
            >
              <Cloud className="h-3.5 w-3.5" /> Set S3 destination
            </button>
          }
        />
      )}

      <Drawer
        open={open}
        onOpenChange={setOpen}
        title="Backup destination"
        description="Choose where scheduled and on-demand backups are stored."
      >
        <div className="flex flex-col gap-4 text-sm">
          <fieldset className="flex flex-col gap-2">
            <span className="text-xs font-medium text-muted-foreground">Store backups in</span>
            <label className="flex items-start gap-2 rounded border border-border p-2.5 has-[:checked]:border-[color-mix(in_oklab,var(--color-primary)_40%,var(--color-border))]">
              <input
                type="radio"
                name="backup-dest-mode"
                className="mt-0.5"
                checked={mode === "local"}
                onChange={() => setMode("local")}
              />
              <span className="flex flex-col">
                <span className="flex items-center gap-1.5 font-medium"><HardDrive className="h-3.5 w-3.5" /> Local storage</span>
                <span className="text-xs text-muted-foreground">Server disk. Simple, but not durable — lost if the instance is destroyed.</span>
              </span>
            </label>
            <label className="flex items-start gap-2 rounded border border-border p-2.5 has-[:checked]:border-[color-mix(in_oklab,var(--color-primary)_40%,var(--color-border))]">
              <input
                type="radio"
                name="backup-dest-mode"
                className="mt-0.5"
                checked={mode === "s3"}
                onChange={() => setMode("s3")}
              />
              <span className="flex flex-col">
                <span className="flex items-center gap-1.5 font-medium"><Cloud className="h-3.5 w-3.5" /> Amazon S3</span>
                <span className="text-xs text-muted-foreground">Durable, off-cluster object storage. Recommended for production.</span>
              </span>
            </label>
          </fieldset>

          {mode === "s3" && (
            <div className="flex flex-col gap-3">
              <label className="flex flex-col gap-1">
                <span className="text-xs text-muted-foreground">S3 bucket</span>
                <input
                  value={bucket}
                  onChange={(e) => setBucket(e.target.value)}
                  className="rounded border border-border bg-background px-2 py-1 font-mono"
                  placeholder="my-backup-bucket"
                  data-testid="backup-destination-bucket"
                />
              </label>
              <label className="flex flex-col gap-1">
                <span className="text-xs text-muted-foreground">S3 prefix (optional)</span>
                <input
                  value={prefix}
                  onChange={(e) => setPrefix(e.target.value)}
                  className="rounded border border-border bg-background px-2 py-1 font-mono"
                  placeholder="constellation/"
                  data-testid="backup-destination-prefix"
                />
              </label>
              {bucket.trim() && (
                <p className="rounded border border-border bg-muted/30 p-2 text-xs">
                  Backups will be written to{" "}
                  <span className="font-mono">s3://{bucket.trim()}/{prefix.trim().replace(/^\/+/, "")}</span>
                </p>
              )}
              <Collapse label="Advanced">
                <label className="flex flex-col gap-1">
                  <span className="text-xs text-muted-foreground">S3 endpoint (optional — for S3-compatible stores like MinIO)</span>
                  <input
                    value={endpoint}
                    onChange={(e) => setEndpoint(e.target.value)}
                    className="rounded border border-border bg-background px-2 py-1 font-mono"
                    placeholder="https://s3.us-east-1.amazonaws.com"
                    data-testid="backup-destination-endpoint"
                  />
                </label>
              </Collapse>
            </div>
          )}

          <button
            type="button"
            onClick={() => save.mutate()}
            disabled={save.isPending || !schedule || (mode === "s3" && !bucket.trim())}
            className="w-full rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            data-testid="backup-destination-save"
          >
            {save.isPending ? "Saving…" : "Save destination"}
          </button>
        </div>
      </Drawer>
    </section>
  );
}

// ------------------------------------------------------------

function SchedulePanel({ schedule }: { schedule: BackupSchedule | undefined }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState<BackupSchedule | null>(null);
  const [open, setOpen] = useState(false);
  // Initialize draft from schedule when it arrives.
  useEffect(() => {
    if (schedule && !draft) setDraft(schedule);
  }, [schedule, draft]);
  const save = useMutation({
    mutationFn: (s: BackupSchedule) => backupsApi.putSchedule(s),
    onSuccess: () => {
      toast.success("Schedule saved");
      setOpen(false);
      qc.invalidateQueries({ queryKey: ["backups-schedule"] });
    },
    onError: (e: Error) => toast.error(`Save failed: ${e.message}`),
  });

  if (!draft) {
    return (
      <section className="rounded-lg border border-border bg-card p-4">
        <p className="text-sm text-muted-foreground">Loading schedule…</p>
      </section>
    );
  }

  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="backup-schedule">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-medium">
          <Calendar className="h-4 w-4" aria-hidden /> Scheduled backups
        </h2>
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent"
        >
          <Pencil className="h-3.5 w-3.5" /> Configure
        </button>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-3 text-sm md:grid-cols-4">
        <div><dt className="text-xs text-muted-foreground">Status</dt><dd>{draft.enabled ? "Enabled" : "Disabled"}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Schedule</dt><dd className="font-mono">{draft.cron_expr || "—"}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Signing</dt><dd className="font-mono">{draft.sign_mode}</dd></div>
        <div><dt className="text-xs text-muted-foreground">Last run</dt><dd className="font-mono">{schedule?.last_run_at ? new Date(schedule.last_run_at).toLocaleString() : "never"}</dd></div>
      </dl>

      <Drawer open={open} onOpenChange={setOpen} title="Configure backup schedule" description="Automatic signed backups on a cron schedule.">
      <div className="grid grid-cols-1 gap-3 text-sm md:grid-cols-2">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-muted-foreground">Cron expression (UTC)</span>
          <input
            value={draft.cron_expr}
            onChange={(e) => setDraft({ ...draft, cron_expr: e.target.value })}
            className="rounded border border-border bg-background px-2 py-1 font-mono"
            placeholder="0 3 * * *"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-xs text-muted-foreground">Signing mode</span>
          <select
            value={draft.sign_mode}
            onChange={(e) => setDraft({ ...draft, sign_mode: e.target.value as BackupSchedule["sign_mode"] })}
            className="rounded border border-border bg-background px-2 py-1"
          >
            <option value="static-key">static-key (ed25519)</option>
            <option value="keyless">keyless (Sigstore Fulcio)</option>
            <option value="none">none (dev only)</option>
          </select>
        </label>
        <label className="flex items-center gap-2 md:col-span-2">
          <input
            type="checkbox"
            checked={draft.enabled}
            onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
          />
          <span>Enabled</span>
        </label>
        <p className="md:col-span-2 rounded border border-border bg-muted/30 p-2 text-xs text-muted-foreground">
          Scheduled backups are written to the destination configured in the{" "}
          <span className="font-medium text-foreground">Backup destination</span> card above.
        </p>
      </div>
      <button
        type="button"
        onClick={() => save.mutate(draft)}
        disabled={save.isPending}
        className="mt-4 w-full rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
      >
        {save.isPending ? "Saving…" : "Save schedule"}
      </button>
      </Drawer>
    </section>
  );
}

// ------------------------------------------------------------

function RestoreWizard() {
  const [open, setOpen] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [manifest, setManifest] = useState<BackupManifestDTO | null>(null);
  const [policy, setPolicy] = useState<"skip" | "overwrite">("skip");
  const [allowUnverified, setAllowUnverified] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const verifyMutation = useMutation({
    mutationFn: (f: File) => backupsApi.verify(f),
    onSuccess: (m) => {
      setManifest(m);
      toast.success(`Manifest valid: org=${m.org_name}, tables=${m.tables.length}`);
    },
    onError: (e: Error) => toast.error(`Verify failed: ${e.message}`),
  });

  const restoreMutation = useMutation({
    mutationFn: () => {
      if (!file) throw new Error("no file");
      return backupsApi.restore(file, { on_conflict: policy, allow_unverified: allowUnverified });
    },
    onSuccess: () => {
      toast.success("Restore applied. Reload the dashboard to see new rows.");
      setFile(null);
      setManifest(null);
      setOpen(false);
      if (inputRef.current) inputRef.current.value = "";
    },
    onError: (e: Error) => toast.error(`Restore failed: ${e.message}`),
  });

  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="backup-restore">
      <div className="flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-medium">
          <UploadCloud className="h-4 w-4" aria-hidden /> Restore
        </h2>
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent"
        >
          <UploadCloud className="h-3.5 w-3.5" /> Restore from backup
        </button>
      </div>
      <p className="mt-1 text-xs text-muted-foreground">
        Import a signed <code>constellation-backup-*.tar.gz</code> onto this instance. The manifest,
        signer identity, and per-table counts are shown before anything is applied.
      </p>

      <Drawer open={open} onOpenChange={setOpen} title="Restore from a backup tarball" description="Upload a backup; verify its signature and contents before applying.">
      <div className="flex flex-col gap-3">
        <input
          ref={inputRef}
          type="file"
          accept=".tar.gz,.tgz,application/gzip"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) {
              setFile(f);
              setManifest(null);
              verifyMutation.mutate(f);
            }
          }}
          className="text-sm"
        />
        {manifest && (
          <div className="rounded border border-border bg-muted/30 p-3 text-sm">
            <p className="mb-2 flex items-center gap-2 font-medium">
              <ShieldCheck className="h-4 w-4 text-status-success" aria-hidden />
              {manifest.signer_identity
                ? <span>Signed by <code className="font-mono">{manifest.signer_identity}</code></span>
                : <span className="text-status-warning">Unsigned manifest</span>}
            </p>
            <dl className="grid grid-cols-2 gap-1 text-xs md:grid-cols-3">
              <div><dt className="text-muted-foreground">Org</dt><dd className="font-mono">{manifest.org_name}</dd></div>
              <div><dt className="text-muted-foreground">Format</dt><dd className="font-mono">{manifest.format_version}</dd></div>
              <div><dt className="text-muted-foreground">Generated</dt><dd className="font-mono">{new Date(manifest.generated_at).toLocaleString()}</dd></div>
              <div><dt className="text-muted-foreground">Source</dt><dd className="font-mono">{manifest.source_instance || "—"}</dd></div>
              <div><dt className="text-muted-foreground">Tables</dt><dd className="font-mono">{manifest.tables.length}</dd></div>
              <div><dt className="text-muted-foreground">Root hash</dt><dd className="font-mono truncate">{manifest.root_hash.slice(0, 16)}…</dd></div>
            </dl>
            <details className="mt-2">
              <summary className="cursor-pointer text-xs text-muted-foreground">Per-table breakdown</summary>
              <ul className="mt-1 text-xs font-mono">
                {manifest.tables.map((t) => (
                  <li key={t.name}>{t.name}: {t.rows} rows ({t.bytes} bytes)</li>
                ))}
              </ul>
            </details>
          </div>
        )}
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:gap-4">
          <label className="flex items-center gap-2 text-sm">
            <span className="text-xs text-muted-foreground">On conflict</span>
            <select value={policy} onChange={(e) => setPolicy(e.target.value as "skip" | "overwrite")}
              className="rounded border border-border bg-background px-2 py-1 text-sm">
              <option value="skip">skip (safe)</option>
              <option value="overwrite">overwrite</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={allowUnverified} onChange={(e) => setAllowUnverified(e.target.checked)} />
            <span className="text-xs">Allow unverified (DEV ONLY)</span>
          </label>
        </div>
        <button
          type="button"
          disabled={!file || restoreMutation.isPending}
          onClick={() => {
            if (!window.confirm(`Apply backup of org "${manifest?.org_name ?? "?"}" to THIS instance? Existing rows will be ${policy === "overwrite" ? "OVERWRITTEN" : "preserved"}.`)) return;
            restoreMutation.mutate();
          }}
          className="self-start rounded-md border border-border bg-destructive px-3 py-1.5 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:opacity-50"
        >
          {restoreMutation.isPending ? "Applying…" : "Apply restore"}
        </button>
      </div>
      </Drawer>
    </section>
  );
}
