// RegistriesPage — Wave N2 container-registry CRUD UI.
//
// Sits under Supply Chain → Registries in the cluster-mode sidebar. Drives the
// /api/v1/registries endpoints; add/edit use dedicated form routes.
import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Plus,
  RotateCw,
  Trash2,
  Beaker,
  CirclePlay,
  Ellipsis,
  X,
  CircleStop,
} from "lucide-react";

import {
  registries as registriesApi,
  scanJobs,
  type RegistryDTO,
  type RegistryKind,
  type RegistryCancelScansResult,
  type RegistrySyncResult,
  type RegistryTestResult,
  type ScanJobInventoryParams,
  type ScanJobInventoryResponse,
} from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatusPill } from "@/components/ui/status-pill";
import { useCluster } from "@/hooks/useCluster";
import { KINDS } from "@/lib/registry-form";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { scanJobInventoryResponseValid } from "@/lib/scan-job-inventory";
import { Button } from "@/components/ui/button";
import { VerdictBanner } from "@/components/ui/verdict-banner";

export function RegistriesPage() {
  const identity = useTablePreferencesIdentity();
  if (!identity)
    return (
      <div className="space-y-4">
        <PageHeader title="Registries" />
        <p role="status">Resolving organization…</p>
      </div>
    );
  return (
    <RegistriesWorkspace
      key={JSON.stringify(identity)}
      orgID={identity.org_id}
      owner={`${identity.org_id}:${identity.user_id}`}
    />
  );
}

function RegistriesWorkspace({
  orgID,
  owner,
}: {
  orgID: string;
  owner: string;
}) {
  const { clusterId } = useCluster();
  const navigate = useNavigate();
  const base = `/clusters/${clusterId}/registries`;
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["registries", owner],
    queryFn: async () => {
      const registries = await registriesApi.list();
      if (
        !Array.isArray(registries) ||
        new Set(registries.map((row) => row.id)).size !== registries.length ||
        registries.some(
          (row) =>
            !row.id ||
            row.org_id !== orgID ||
            !Number.isSafeInteger(row.images_seen) ||
            row.images_seen < 0,
        )
      )
        throw new Error("Registry inventory does not match this organization");
      return registries;
    },
  });
  const scanQueue = useQuery({
    queryKey: ["scan-jobs", "registries", owner, "organization-image"],
    queryFn: () => loadJobCounts({ target_type: "image", limit: 1 }, orgID),
  });
  const registryReady = q.isSuccess && q.fetchStatus === "idle";
  const queueReady = scanQueue.isSuccess && scanQueue.fetchStatus === "idle";

  const [actionMsg, setActionMsg] = useState<string | null>(null);

  const remove = useMutation({
    mutationFn: (id: string) => registriesApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["registries"] });
    },
  });
  const test = useMutation({
    mutationFn: (id: string) => registriesApi.test(id),
    onSuccess: (r: RegistryTestResult, id) => {
      setActionMsg(
        r.ok
          ? `Test ${id.slice(0, 8)}: OK (${r.images_visible ?? 0} images visible)`
          : `Test ${id.slice(0, 8)} failed: ${r.error ?? "unknown"}`,
      );
    },
  });
  const sync = useMutation({
    mutationFn: (id: string) => registriesApi.syncNow(id),
    onSuccess: (r: RegistrySyncResult) => {
      qc.invalidateQueries({ queryKey: ["registries"] });
      qc.invalidateQueries({
        queryKey: ["scan-jobs"],
        predicate: (query) => query.queryKey.includes(owner),
      });
      setActionMsg(
        `Sync ${r.registry_id.slice(0, 8)}: ${r.status} — ${r.images_seen} images, ${r.scan_jobs_enqueued} jobs queued${r.error ? ` (${r.error})` : ""}`,
      );
    },
  });
  const cancelScans = useMutation({
    mutationFn: (id: string) => registriesApi.cancelScans(id),
    onSuccess: (r: RegistryCancelScansResult) => {
      qc.invalidateQueries({ queryKey: ["registries"] });
      qc.invalidateQueries({
        queryKey: ["scan-jobs"],
        predicate: (query) => query.queryKey.includes(owner),
      });
      const remaining =
        r.active_remaining > 0 ? `, ${r.active_remaining} still active` : "";
      setActionMsg(
        `Stopped scans for ${r.registry_id.slice(0, 8)}: ${r.canceled} canceled${remaining}`,
      );
    },
  });

  const rows = useMemo(
    () => (registryReady ? q.data : []),
    [registryReady, q.data],
  );
  const summary = useMemo(() => summarizeRegistries(rows), [rows]);
  const imageJobs = queueReady ? scanQueue.data : undefined;

  const columns = useMemo<Column<RegistryDTO>[]>(
    () => [
      {
        id: "name",
        exportValue: (r) => r.name,
        header: "Name",
        kind: "name",
        hideable: false,
        cell: (r) => <span className="font-medium">{r.name}</span>,
        sort: (a, b) => a.name.localeCompare(b.name),
      },
      {
        id: "kind",
        exportValue: (r) => r.kind,
        header: "Kind",
        kind: "text",
        size: 176,
        minSize: 136,
        maxSize: 216,
        cell: (r) => <KindBadge kind={r.kind} />,
      },
      {
        id: "endpoint",
        exportValue: (r) => r.endpoint,
        header: "Endpoint",
        kind: "id",
        size: 224,
        minSize: 160,
        maxSize: 320,
        cell: (r) => (
          <span className="text-mono text-xs text-muted-foreground">
            {r.endpoint}
          </span>
        ),
      },
      {
        id: "cadence",
        exportValue: (r) => r.scan_cadence,
        header: "Cadence",
        kind: "age",
        size: 104,
        minSize: 88,
        maxSize: 128,
        cell: (r) => r.scan_cadence,
      },
      {
        id: "status",
        exportValue: (r) =>
          [
            r.last_sync_status || "not reported",
            r.last_sync_at || "",
            r.last_sync_error || "",
          ]
            .filter(Boolean)
            .join("; "),
        header: "Last sync",
        kind: "status",
        size: 224,
        minSize: 208,
        maxSize: 240,
        cell: (r) => <SyncPill row={r} />,
        sort: (a, b) =>
          (a.last_sync_at ?? "").localeCompare(b.last_sync_at ?? ""),
      },
      {
        id: "scan-jobs",
        exportValue: (r) => {
          const counts = readReadyRegistryCounts(qc, owner, r.id);
          const state = qc.getQueryState(registryJobKey(owner, r.id));
          return counts
            ? JSON.stringify(counts)
            : state
              ? "Unavailable"
              : "Not loaded";
        },
        header: "Scan jobs",
        kind: "badge",
        size: 152,
        minSize: 128,
        maxSize: 192,
        wrap: true,
        cell: (r) => (
          <RegistryQueueStatus registryID={r.id} owner={owner} orgID={orgID} />
        ),
      },
      {
        id: "images",
        exportValue: (r) => r.images_seen,
        header: "Images",
        kind: "count",
        numeric: true,
        sort: (a, b) => a.images_seen - b.images_seen,
        cell: (r) => (
          <a
            href={
              clusterId
                ? `/clusters/${encodeURIComponent(clusterId)}/registries/${encodeURIComponent(r.id)}`
                : `/registries/${encodeURIComponent(r.id)}`
            }
            className="text-mono text-[color:var(--color-primary)] hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {r.images_seen} →
          </a>
        ),
      },
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
          return (
            <RegistryQueueStatus registryID={r.id} owner={owner} orgID={orgID}>
              {(counts) => (
                <DropdownMenu.Root>
                  <DropdownMenu.Trigger asChild>
                    <button
                      type="button"
                      className="rounded-md p-1 hover:bg-accent text-muted-foreground hover:text-foreground transition-colors"
                      aria-label={`Actions for ${r.name}`}
                      data-testid={`registry-actions-${r.id}`}
                      onClick={(e) => e.stopPropagation()}
                    >
                      <Ellipsis className="h-4 w-4" />
                    </button>
                  </DropdownMenu.Trigger>
                  <DropdownMenu.Portal>
                    <DropdownMenu.Content
                      align="end"
                      sideOffset={4}
                      className="z-50 min-w-[180px] rounded-md border border-border bg-popover p-1 shadow-[var(--elev-popover)]"
                    >
                      <Item
                        icon={<Beaker className="h-3.5 w-3.5" />}
                        onSelect={() => test.mutate(r.id)}
                      >
                        Test
                      </Item>
                      <Item
                        icon={<CirclePlay className="h-3.5 w-3.5" />}
                        onSelect={() => sync.mutate(r.id)}
                      >
                        Sync now
                      </Item>
                      <Item
                        icon={<CircleStop className="h-3.5 w-3.5" />}
                        destructive
                        disabled={
                          !counts ||
                          counts.active === 0 ||
                          cancelScans.isPending
                        }
                        onSelect={() => {
                          const current = readReadyRegistryCounts(
                            qc,
                            owner,
                            r.id,
                          );
                          if (!current || current.active === 0) return;
                          if (
                            window.confirm(
                              `Stop ${current.active} active scan job${current.active === 1 ? "" : "s"} for ${r.name}?`,
                            )
                          ) {
                            cancelScans.mutate(r.id);
                          }
                        }}
                      >
                        Stop active scans
                      </Item>
                      <Item
                        icon={<RotateCw className="h-3.5 w-3.5" />}
                        onSelect={() =>
                          void navigate({ href: `${base}/${r.id}/edit` })
                        }
                      >
                        Edit
                      </Item>
                      <DropdownMenu.Separator className="my-1 h-px bg-border" />
                      <Item
                        icon={<Trash2 className="h-3.5 w-3.5" />}
                        destructive
                        onSelect={() => {
                          if (window.confirm(`Delete registry ${r.name}?`))
                            remove.mutate(r.id);
                        }}
                      >
                        Delete
                      </Item>
                    </DropdownMenu.Content>
                  </DropdownMenu.Portal>
                </DropdownMenu.Root>
              )}
            </RegistryQueueStatus>
          );
        },
      },
    ],
    [
      base,
      navigate,
      clusterId,
      owner,
      orgID,
      qc,
      test,
      sync,
      cancelScans,
      remove,
    ],
  );

  return (
    <div className="space-y-4" data-testid="registries-page">
      <PageHeader
        title="Registries"
        description="Registries Constellation syncs image metadata from and scans new tags for."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => {
                void qc.invalidateQueries({ queryKey: ["registries", owner] });
                void qc.invalidateQueries({
                  queryKey: ["scan-jobs"],
                  predicate: (query) => query.queryKey.includes(owner),
                });
              }}
            >
              Refresh
            </Button>
            <Button
              variant="primary"
              onClick={() => void navigate({ href: `${base}/new` })}
              data-testid="add-registry"
            >
              <Plus className="h-3.5 w-3.5" /> Add registry
            </Button>
          </div>
        }
      />

      {actionMsg && (
        <div
          className="rounded-md border border-border bg-card px-3 py-2 text-xs flex items-center justify-between"
          data-testid="registry-action-message"
        >
          <span>{actionMsg}</span>
          <button
            type="button"
            onClick={() => setActionMsg(null)}
            aria-label="Dismiss"
          >
            <X className="h-3.5 w-3.5 text-muted-foreground hover:text-foreground" />
          </button>
        </div>
      )}

      <VerdictBanner
        status={
          q.isError ||
          scanQueue.isError ||
          summary.failedSync > 0 ||
          (imageJobs?.failed ?? 0) > 0
            ? "degraded"
            : "info"
        }
        title={
          q.isError
            ? "Registry inventory could not be loaded"
            : !registryReady
              ? "Loading registry inventory"
              : scanQueue.isError
                ? "Organization image jobs could not be loaded"
                : !queueReady
                  ? "Loading organization image queue"
                  : summary.failedSync > 0 || imageJobs!.failed > 0
                    ? "Registry or image scans need attention"
                    : summary.total === 0
                      ? "Add a registry to begin scanning"
                      : "Registry inventory is available"
        }
        numbers={[
          { label: "registries", value: registryReady ? summary.total : "—" },
          { label: "failed syncs", value: registryReady ? summary.failedSync : "—", tone: summary.failedSync > 0 ? "warning" : "default", title: registryReady ? `${summary.healthy} successful last sync` : undefined },
          { label: "images seen", value: registryReady ? summary.images : "—" },
          { label: "failed image jobs", value: imageJobs?.failed ?? "—", tone: imageJobs?.failed ? "error" : "default", title: "Organization image jobs" },
        ]}
        detail={<div className="space-y-1">
          <p data-testid="registry-operator-summary">Registries {registryReady ? summary.total : "—"} · successful last sync {registryReady ? summary.healthy : "—"}{registryReady ? ` (${summary.failedSync} failed or partial)` : ""} · images seen {registryReady ? summary.images : "—"} · active image jobs (organization) {imageJobs?.active ?? "—"}{imageJobs ? ` (${imageJobs.pending} pending)` : ""} · failed image jobs (organization) {imageJobs?.failed ?? "—"}</p>
          <p>Queue KPIs cover all organization image jobs, including manual scans. Row counts cover all jobs linked to that registry and refresh independently.</p>
        </div>}
      />

      <DataTable<RegistryDTO>
        rows={rows}
        columns={columns}
        preferencesKey="registry-inventory"
        exportFileName={
          registryReady ? "constellation-registry-loaded-inventory" : undefined
        }
        exportLabel="Export loaded registries CSV"
        rowKey={(r) => r.id}
        emptyState={
          q.isError ? (
            "Registry inventory is unavailable. Refresh to try again."
          ) : !registryReady ? (
            "Loading registries..."
          ) : (
            <EmptyState onAdd={() => void navigate({ href: `${base}/new` })} />
          )
        }
        defaultSort={{ id: "name", dir: "asc" }}
      />
    </div>
  );
}

function KindBadge({ kind }: { kind: RegistryKind }) {
  const meta = KINDS.find((k) => k.kind === kind);
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="grid h-5 w-5 place-items-center rounded-sm bg-muted text-micro font-semibold ">
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
    row.last_sync_status === "ok"
      ? "success"
      : row.last_sync_status === "partial"
        ? "warning"
        : row.last_sync_status === "failed"
          ? "error"
          : "neutral";
  return (
    <div className="space-y-1">
      <StatusPill label={row.last_sync_status || "unknown"} tone={tone} />
      {row.last_sync_at && (
        <span
          className="block text-xs text-muted-foreground"
          title={new Date(row.last_sync_at).toLocaleString()}
        >
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
    return <span className="text-micro text-muted-foreground">idle</span>;
  }
  return (
    <div className="flex flex-wrap items-center gap-1">
      {counts.active > 0 ? (
        <StatusPill label={`${counts.active} active`} tone="pending" />
      ) : null}
      {counts.failed > 0 ? (
        <StatusPill label={`${counts.failed} failed`} tone="error" />
      ) : null}
    </div>
  );
}

const jobStatuses = [
  "pending",
  "running",
  "paused",
  "failed",
  "completed",
  "canceled",
] as const;
const registryJobKey = (owner: string, registryID: string) => [
  "scan-jobs",
  "registries",
  owner,
  "registry",
  registryID,
];
async function loadJobCounts(
  request: ScanJobInventoryParams,
  orgID: string,
): Promise<RegistryJobCounts> {
  const result: ScanJobInventoryResponse = await scanJobs.list(request);
  if (
    !scanJobInventoryResponseValid(result, request, orgID) ||
    result.jobs.some(
      (job) =>
        job.org_id !== orgID ||
        !jobStatuses.includes(job.status as (typeof jobStatuses)[number]),
    ) ||
    jobStatuses.reduce((sum, status) => sum + result.summary![status], 0) !==
      result.total
  )
    throw new Error("Scan job summary does not match this scope");
  const summary = result.summary!;
  return {
    active: summary.pending + summary.running + summary.paused,
    pending: summary.pending,
    running: summary.running,
    paused: summary.paused,
    failed: summary.failed,
    completed: summary.completed,
    canceled: summary.canceled,
  };
}
function readReadyRegistryCounts(
  client: ReturnType<typeof useQueryClient>,
  owner: string,
  registryID: string,
) {
  const state = client.getQueryState<RegistryJobCounts>(
    registryJobKey(owner, registryID),
  );
  return state?.status === "success" &&
    state.fetchStatus === "idle" &&
    !state.isInvalidated
    ? state.data
    : undefined;
}
function RegistryQueueStatus({
  owner,
  orgID,
  registryID,
  children,
}: {
  owner: string;
  orgID: string;
  registryID: string;
  children?: (counts: RegistryJobCounts | undefined) => React.ReactNode;
}) {
  const query = useQuery({
    queryKey: registryJobKey(owner, registryID),
    queryFn: () => loadJobCounts({ registry_id: registryID, limit: 1 }, orgID),
  });
  const available =
    query.isSuccess && query.fetchStatus === "idle" ? query.data : undefined;
  if (children) return children(available);
  if (query.isError)
    return (
      <span className="text-xs text-muted-foreground">
        Unavailable{" "}
        <button
          className="text-primary underline"
          onClick={() => void query.refetch()}
        >
          Retry
        </button>
      </span>
    );
  if (!available)
    return <span className="text-xs text-muted-foreground">Loading…</span>;
  return <RegistryJobPills counts={available} />;
}

function summarizeRegistries(rows: RegistryDTO[]) {
  let healthy = 0;
  let failedSync = 0;
  let images = 0;
  for (const row of rows) {
    if (row.last_sync_status === "ok") healthy += 1;
    if (row.last_sync_status === "failed" || row.last_sync_status === "partial")
      failedSync += 1;
    images += row.images_seen;
  }
  return {
    total: rows.length,
    healthy,
    failedSync,
    images,
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
  icon,
  children,
  onSelect,
  destructive,
  disabled,
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
