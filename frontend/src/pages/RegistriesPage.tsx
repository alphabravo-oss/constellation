// RegistriesPage — Wave N2 container-registry CRUD UI.
//
// Sits under Supply Chain → Registries in the cluster-mode sidebar. Drives the
// /api/v1/registries endpoints; add/edit use dedicated form routes.
import { useMemo, useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertTriangle, Boxes, Clock, Database, Plus, RotateCw, Trash2, Beaker, PlayCircle, MoreHorizontal, X, StopCircle,
} from "lucide-react";

import {
  registries as registriesApi,
  scanJobs,
  type RegistryDTO,
  type RegistryKind,
  type RegistryCancelScansResult,
  type RegistrySyncResult,
  type RegistryTestResult,
  type ScanJob,
} from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatusPill } from "@/components/ui/status-pill";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { useCluster } from "@/hooks/useCluster";
import { KINDS } from "@/lib/registry-form";
import { VerdictBanner } from "@/components/ui/verdict-banner";

export function RegistriesPage() {
  const { clusterId } = useCluster();
  const navigate = useNavigate();
  const base = `/clusters/${clusterId}/registries`;
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["registries"], queryFn: () => registriesApi.list() });
  const scanQueue = useQuery({ queryKey: ["scan-jobs", "registries"], queryFn: () => scanJobs.list({ target_type: "image" }) });

  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: (id: string) => registriesApi.remove(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["registries"] }); },
  });
  const test = useMutation({
    mutationFn: (id: string) => registriesApi.test(id),
    onSuccess: (r: RegistryTestResult, id) => {
      setActionMsg(r.ok
        ? `Test ${id.slice(0, 8)}: OK (${r.images_visible ?? 0} images visible)`
        : `Test ${id.slice(0, 8)} failed: ${r.error ?? "unknown"}`);
    },
  });
  const sync = useMutation({
    mutationFn: (id: string) => registriesApi.syncNow(id),
    onSuccess: (r: RegistrySyncResult) => {
      qc.invalidateQueries({ queryKey: ["registries"] });
      qc.invalidateQueries({ queryKey: ["scan-jobs", "registries"] });
      setActionMsg(`Sync ${r.registry_id.slice(0, 8)}: ${r.status} — ${r.images_seen} images, ${r.scan_jobs_enqueued} jobs queued${r.error ? ` (${r.error})` : ""}`);
    },
  });
  const cancelScans = useMutation({
    mutationFn: (id: string) => registriesApi.cancelScans(id),
    onSuccess: (r: RegistryCancelScansResult) => {
      qc.invalidateQueries({ queryKey: ["registries"] });
      qc.invalidateQueries({ queryKey: ["scan-jobs", "registries"] });
      const remaining = r.active_remaining > 0 ? `, ${r.active_remaining} still active` : "";
      setActionMsg(`Stopped scans for ${r.registry_id.slice(0, 8)}: ${r.canceled} canceled${remaining}`);
    },
  });

  const rows = useMemo(() => q.data ?? [], [q.data]);
  const registryJobs = useMemo(() => (scanQueue.data?.jobs ?? []).filter((job) => !!job.registry_id), [scanQueue.data?.jobs]);
  const registryJobCounts = useMemo(() => buildRegistryJobCounts(registryJobs), [registryJobs]);
  const summary = useMemo(() => summarizeRegistries(rows, registryJobs), [rows, registryJobs]);

  const columns = useMemo<Column<RegistryDTO>[]>(() => [
    { id: "name", header: "Name", kind: "name", hideable: false, cell: (r) => <span className="font-medium">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "kind", header: "Kind", kind: "text", size: 176, minSize: 136, maxSize: 216, cell: (r) => <KindBadge kind={r.kind} /> },
    { id: "endpoint", header: "Endpoint", kind: "id", size: 224, minSize: 160, maxSize: 320, cell: (r) => <span className="text-mono text-xs text-muted-foreground">{r.endpoint}</span> },
    { id: "cadence", header: "Cadence", kind: "age", size: 104, minSize: 88, maxSize: 128, cell: (r) => r.scan_cadence },
    { id: "status", header: "Last sync", kind: "status", size: 224, minSize: 208, maxSize: 240, cell: (r) => <SyncPill row={r} />, sort: (a, b) => (a.last_sync_at ?? "").localeCompare(b.last_sync_at ?? "") },
    {
      id: "scan-jobs",
      header: "Scan jobs",
      kind: "badge",
      size: 152,
      minSize: 128,
      maxSize: 192,
      wrap: true,
      cell: (r) => <RegistryJobPills counts={registryJobCounts.get(r.id)} />,
      sort: (a, b) => (registryJobCounts.get(a.id)?.active ?? 0) - (registryJobCounts.get(b.id)?.active ?? 0),
    },
    { id: "images", header: "Images", kind: "count", numeric: true, sort: (a, b) => a.images_seen - b.images_seen,
      cell: (r) => (
        <Link to="." href={clusterId ? `/clusters/${clusterId}/registries/${r.id}` : `/registries/${r.id}`} className="text-mono text-[color:var(--color-primary)] hover:underline" onClick={(e) => e.stopPropagation()}>
          {r.images_seen} →
        </Link>
      ) },
    {
      id: "actions",
      header: "",
      kind: "actions",
      size: 48,
      minSize: 48,
      maxSize: 48,
      hideable: false,
      exportable: false,
      cell: (r) => {
        const activeJobs = registryJobCounts.get(r.id)?.active ?? 0;
        return (
          <DropdownMenu.Root>
            <DropdownMenu.Trigger asChild>
              <button
                type="button"
                className="rounded-md p-1 hover:bg-accent text-muted-foreground hover:text-foreground transition-colors"
                aria-label={`Actions for ${r.name}`}
                data-testid={`registry-actions-${r.id}`}
                onClick={(e) => e.stopPropagation()}
              >
                <MoreHorizontal className="h-4 w-4" />
              </button>
            </DropdownMenu.Trigger>
            <DropdownMenu.Portal>
              <DropdownMenu.Content
                align="end"
                sideOffset={4}
                className="z-50 min-w-[180px] rounded-md border border-border bg-popover p-1 shadow-[var(--elev-popover)]"
              >
                <Item icon={<Beaker className="h-3.5 w-3.5" />} onSelect={() => test.mutate(r.id)}>Test</Item>
                <Item icon={<PlayCircle className="h-3.5 w-3.5" />} onSelect={() => sync.mutate(r.id)}>Sync now</Item>
                <Item
                  icon={<StopCircle className="h-3.5 w-3.5" />}
                  destructive
                  disabled={activeJobs === 0 || cancelScans.isPending}
                  onSelect={() => {
                    if (window.confirm(`Stop ${activeJobs} active scan job${activeJobs === 1 ? "" : "s"} for ${r.name}?`)) {
                      cancelScans.mutate(r.id);
                    }
                  }}
                >
                  Stop active scans
                </Item>
                <Item icon={<RotateCw className="h-3.5 w-3.5" />} onSelect={() => void navigate({ href: `${base}/${r.id}/edit` })}>Edit</Item>
                <DropdownMenu.Separator className="my-1 h-px bg-border" />
                <Item
                  icon={<Trash2 className="h-3.5 w-3.5" />}
                  destructive
                  onSelect={() => { if (window.confirm(`Delete registry ${r.name}?`)) remove.mutate(r.id); }}
                >
                  Delete
                </Item>
              </DropdownMenu.Content>
            </DropdownMenu.Portal>
          </DropdownMenu.Root>
        );
      },
    },
  ], [base, navigate, clusterId, registryJobCounts, test, sync, cancelScans, remove]);

  return (
    <div className="space-y-4" data-testid="registries-page">
      <PageHeader
        title="Container Registries"
        description="Configure registries Constellation should pull image metadata from on a cadence and enqueue new tags for scanning."
        actions={
          <button
            type="button"
            onClick={() => void navigate({ href: `${base}/new` })}
            className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90"
            data-testid="add-registry"
          >
            <Plus className="h-3.5 w-3.5" /> Add registry
          </button>
        }
      />

      {actionMsg && (
        <div
          className="rounded-md border border-border bg-card px-3 py-2 text-xs flex items-center justify-between"
          data-testid="registry-action-message"
        >
          <span>{actionMsg}</span>
          <button type="button" onClick={() => setActionMsg(null)} aria-label="Dismiss">
            <X className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" />
          </button>
        </div>
      )}

      <VerdictBanner status={q.isPending ? "info" : q.isError || scanQueue.isError ? "degraded" : summary.failedSync > 0 || summary.failedJobs > 0 ? "degraded" : summary.total === 0 ? "info" : "ok"}
        title={q.isPending ? "Loading registry inventory" : q.isError ? "Registry inventory could not be loaded" : scanQueue.isError ? "Registry scan jobs could not be loaded" : summary.failedSync > 0 || summary.failedJobs > 0 ? "Registry scans need attention" : summary.total === 0 ? "Add a registry to begin scanning" : "Registry inventory is available"}
        detail="Review synchronization and scan jobs below. Queue metrics cover registry jobs in the latest 200 image jobs. Connection testing uses saved configuration." />
      <StatGrid data-testid="registry-operator-summary">
        <StatCard label="Registries" value={summary.total.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Healthy Sync" value={summary.healthy.toLocaleString()} icon={<PlayCircle className="h-3.5 w-3.5" />} tone={summary.failedSync > 0 ? "medium" : "accent"} hint={`${summary.failedSync} failed`} />
        <StatCard label="Images Seen" value={summary.images.toLocaleString()} icon={<Boxes className="h-3.5 w-3.5" />} />
        <StatCard label="Active Jobs" value={summary.activeJobs.toLocaleString()} icon={<Clock className="h-3.5 w-3.5" />} tone={summary.activeJobs > 0 ? "low" : "neutral"} hint={`${summary.pendingJobs} pending`} />
        <StatCard label="Failed Jobs" value={summary.failedJobs.toLocaleString()} icon={<AlertTriangle className="h-3.5 w-3.5" />} tone={summary.failedJobs > 0 ? "high" : "neutral"} />
      </StatGrid>

      <DataTable<RegistryDTO>
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        emptyState={q.isPending ? "Loading registries..." : q.isError ? "Registry inventory is unavailable. Refresh to try again." : <EmptyState onAdd={() => void navigate({ href: `${base}/new` })} />}
        defaultSort={{ id: "name", dir: "asc" }}
      />
    </div>
  );
}

function KindBadge({ kind }: { kind: RegistryKind }) {
  const meta = KINDS.find((k) => k.kind === kind);
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="grid h-5 w-5 place-items-center rounded-sm bg-muted text-[9px] font-semibold uppercase">
        {kind.slice(0, 2)}
      </span>
      <span className="text-xs">{meta?.label ?? kind}</span>
    </span>
  );
}

function SyncPill({ row }: { row: RegistryDTO }) {
  if (row.scan_cadence === "manual" && !row.last_sync_at) {
    return <StatusPill label="manual" tone="neutral" />;
  }
  const tone =
    row.last_sync_status === "ok" ? "success" :
    row.last_sync_status === "partial" ? "warning" :
    row.last_sync_status === "failed" ? "error" : "neutral";
  return (
    <div className="space-y-1">
      <StatusPill label={row.last_sync_status || "unknown"} tone={tone} />
      {row.last_sync_at && (
        <span className="block text-xs text-muted-foreground" title={new Date(row.last_sync_at).toLocaleString()}>
          {new Date(row.last_sync_at).toLocaleString()}
        </span>
      )}
    </div>
  );
}

type RegistryJobCounts = {
  active: number;
  pending: number;
  running: number;
  paused: number;
  failed: number;
  completed: number;
  canceled: number;
};

function RegistryJobPills({ counts }: { counts?: RegistryJobCounts }) {
  if (!counts || (counts.active === 0 && counts.failed === 0)) {
    return <span className="text-[10px] text-muted-foreground">idle</span>;
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {counts.active > 0 ? <StatusPill label={`${counts.active} active`} tone="pending" /> : null}
      {counts.failed > 0 ? <StatusPill label={`${counts.failed} failed`} tone="error" /> : null}
    </div>
  );
}

function buildRegistryJobCounts(jobs: ScanJob[]) {
  const out = new Map<string, RegistryJobCounts>();
  for (const job of jobs) {
    if (!job.registry_id) continue;
    const counts = out.get(job.registry_id) ?? {
      active: 0,
      pending: 0,
      running: 0,
      paused: 0,
      failed: 0,
      completed: 0,
      canceled: 0,
    };
    switch (job.status) {
      case "pending":
        counts.pending += 1;
        counts.active += 1;
        break;
      case "running":
        counts.running += 1;
        counts.active += 1;
        break;
      case "paused":
        counts.paused += 1;
        counts.active += 1;
        break;
      case "failed":
        counts.failed += 1;
        break;
      case "completed":
        counts.completed += 1;
        break;
      case "canceled":
        counts.canceled += 1;
        break;
    }
    out.set(job.registry_id, counts);
  }
  return out;
}

function summarizeRegistries(rows: RegistryDTO[], jobs: ScanJob[]) {
  let healthy = 0;
  let failedSync = 0;
  let images = 0;
  for (const row of rows) {
    if (row.last_sync_status === "ok") healthy += 1;
    if (row.last_sync_status === "failed" || row.last_sync_status === "partial") failedSync += 1;
    images += row.images_seen;
  }
  let activeJobs = 0;
  let pendingJobs = 0;
  let failedJobs = 0;
  for (const job of jobs) {
    if (job.status === "pending") {
      activeJobs += 1;
      pendingJobs += 1;
    } else if (job.status === "running" || job.status === "paused") {
      activeJobs += 1;
    } else if (job.status === "failed") {
      failedJobs += 1;
    }
  }
  return {
    total: rows.length,
    healthy,
    failedSync,
    images,
    activeJobs,
    pendingJobs,
    failedJobs,
  };
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return (
    <div className="py-10 text-center text-sm text-muted-foreground space-y-2">
      <div>No registries configured.</div>
      <button
        type="button"
        onClick={onAdd}
        className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs hover:bg-accent"
      >
        <Plus className="h-3.5 w-3.5" /> Add your first registry
      </button>
    </div>
  );
}

function Item({
  icon, children, onSelect, destructive, disabled,
}: {
  icon: React.ReactNode;
  children: React.ReactNode;
  onSelect: () => void;
  destructive?: boolean;
  disabled?: boolean;
}) {
  return (
    <DropdownMenu.Item
      disabled={disabled}
      onSelect={onSelect}
      className={
        "flex items-center gap-2 rounded px-2 py-1.5 text-xs cursor-pointer outline-none data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[highlighted]:bg-accent " +
        (destructive ? "text-[color:var(--color-destructive)]" : "")
      }
    >
      <span className="text-muted-foreground">{icon}</span>
      <span className="flex-1">{children}</span>
    </DropdownMenu.Item>
  );
}
