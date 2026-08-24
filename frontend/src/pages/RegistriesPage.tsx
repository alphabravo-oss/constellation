// RegistriesPage — Wave N2 container-registry CRUD UI.
//
// Sits under Supply Chain → Registries in the cluster-mode sidebar. Drives the
// /api/v1/registries endpoints; uses Radix Dialog for the create wizard so the
// kind picker can swap credential fields per registry kind.
import { useMemo, useState, type ChangeEvent } from "react";
import { Link } from "react-router-dom";
import * as Dialog from "@radix-ui/react-dialog";
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
  type RegistryAuthKind,
  type RegistryCadence,
  type RegistryCreateBody,
  type RegistryScanPolicy,
  type RegistryCancelScansResult,
  type RegistrySyncResult,
  type RegistryTestResult,
  type ScanJob,
} from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatusPill } from "@/components/ui/status-pill";
import { StatCard } from "@/components/ui/stat-card";
import { useCluster } from "@/hooks/useCluster";

// Closed catalogue of supported registry kinds with display labels + creds
// field schemas. Keeps the per-kind form rendering tight and self-contained.
const KINDS: Array<{
  kind: RegistryKind;
  label: string;
  endpointHint: string;
  fields: Array<{ key: string; label: string; placeholder?: string; secret?: boolean; helper?: string }>;
}> = [
  { kind: "docker-hub", label: "Docker Hub", endpointHint: "https://registry-1.docker.io",
    fields: [
      { key: "username", label: "Username / namespace", placeholder: "myorg" },
      { key: "password", label: "Password / PAT", secret: true, helper: "Used for listing private repositories" },
    ] },
  { kind: "ghcr", label: "GitHub Container Registry", endpointHint: "https://ghcr.io",
    fields: [
      { key: "username", label: "GitHub owner / org", placeholder: "alphabravocompany" },
      { key: "token", label: "Personal Access Token", secret: true, helper: "scope: read:packages" },
    ] },
  { kind: "ecr", label: "Amazon ECR", endpointHint: "<account>.dkr.ecr.<region>.amazonaws.com",
    fields: [
      { key: "region", label: "AWS region", placeholder: "us-east-1" },
      { key: "role_arn", label: "IAM role ARN (assumed)", placeholder: "arn:aws:iam::123:role/constellation-ecr-reader" },
      { key: "access_key_id", label: "Access key ID", helper: "Static IAM keys (optional — else the ambient/role chain is used)" },
      { key: "secret_access_key", label: "Secret access key", secret: true },
    ] },
  { kind: "gcr", label: "Google Artifact Registry",
    endpointHint: "projects/<id>/locations/<region>/repositories/<repo>",
    fields: [
      { key: "resource_path", label: "GCP repo path", placeholder: "projects/myproj/locations/us-central1/repositories/main" },
      { key: "service_account_json", label: "Service-account JSON key", secret: true, helper: "Paste the SA key — Constellation mints + refreshes OAuth tokens itself (no ~1h expiry)" },
      { key: "token", label: "OAuth2 access token", secret: true, helper: "Alternative: a pre-acquired token (expires in ~1h)" },
    ] },
  { kind: "acr", label: "Azure Container Registry", endpointHint: "myregistry.azurecr.io",
    fields: [
      { key: "tenant_id", label: "Tenant ID" },
      { key: "client_id", label: "Client ID" },
      { key: "client_secret", label: "Client secret", secret: true },
      { key: "token", label: "Pre-acquired bearer token", secret: true, helper: "or paste a fresh `az acr login --expose-token` value" },
    ] },
  { kind: "quay", label: "Quay.io", endpointHint: "quay.io",
    fields: [
      { key: "username", label: "Namespace / robot account", placeholder: "myorg+robot" },
      { key: "token", label: "OAuth bearer token", secret: true },
    ] },
  { kind: "harbor", label: "Harbor (self-hosted)", endpointHint: "https://harbor.example.com",
    fields: [
      { key: "username", label: "Username" },
      { key: "password", label: "Password", secret: true },
    ] },
  { kind: "gitlab", label: "GitLab Container Registry", endpointHint: "https://gitlab.com",
    fields: [
      { key: "token", label: "Personal Access Token", secret: true, helper: "scope: read_registry" },
    ] },
  { kind: "jfrog", label: "JFrog Artifactory", endpointHint: "https://your.jfrog.io/artifactory",
    fields: [
      { key: "username", label: "Docker repo name", placeholder: "docker-local" },
      { key: "token", label: "API key", secret: true },
    ] },
];

const AUTH_KINDS: RegistryAuthKind[] = ["static", "aws-iam-role", "gcp-service-account", "azure-managed-id", "none"];
const CADENCES = ["manual", "auto", "hourly", "6h", "daily", "weekly", "custom", "cron"] as const;
const PROMOTION_THRESHOLDS = ["critical", "high", "medium", "low", "none"];
type RegistryScheduleMode = typeof CADENCES[number];

export function RegistriesPage() {
  const { clusterId } = useCluster();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["registries"], queryFn: () => registriesApi.list() });
  const scanQueue = useQuery({ queryKey: ["scan-jobs", "registries"], queryFn: () => scanJobs.list({ target_type: "image" }) });

  const [createOpen, setCreateOpen] = useState(false);
  const [editing, setEditing] = useState<RegistryDTO | null>(null);
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
    { id: "name", header: "Name", cell: (r) => <span className="font-medium">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "kind", header: "Kind", cell: (r) => <KindBadge kind={r.kind} /> },
    { id: "endpoint", header: "Endpoint", cell: (r) => <span className="text-mono text-xs text-muted-foreground">{r.endpoint}</span> },
    { id: "cadence", header: "Cadence", cell: (r) => r.scan_cadence },
    { id: "status", header: "Last sync", cell: (r) => <SyncPill row={r} />, sort: (a, b) => (a.last_sync_at ?? "").localeCompare(b.last_sync_at ?? "") },
    {
      id: "scan-jobs",
      header: "Scan jobs",
      width: "150px",
      cell: (r) => <RegistryJobPills counts={registryJobCounts.get(r.id)} />,
      sort: (a, b) => (registryJobCounts.get(a.id)?.active ?? 0) - (registryJobCounts.get(b.id)?.active ?? 0),
    },
    { id: "images", header: "Images", numeric: true, sort: (a, b) => a.images_seen - b.images_seen,
      cell: (r) => (
        <Link to={clusterId ? `/clusters/${clusterId}/registries/${r.id}` : `/registries/${r.id}`} className="text-mono text-[color:var(--color-primary)] hover:underline" onClick={(e) => e.stopPropagation()}>
          {r.images_seen} →
        </Link>
      ) },
    {
      id: "actions",
      header: "",
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
                <Item icon={<RotateCw className="h-3.5 w-3.5" />} onSelect={() => setEditing(r)}>Edit</Item>
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
      width: "40px",
    },
  ], [clusterId, registryJobCounts, test, sync, cancelScans, remove]);

  return (
    <div className="space-y-4" data-testid="registries-page">
      <PageHeader
        title="Container Registries"
        description="Configure registries Constellation should pull image metadata from on a cadence and enqueue new tags for scanning."
        actions={
          <button
            type="button"
            onClick={() => setCreateOpen(true)}
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

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5" data-testid="registry-operator-summary">
        <StatCard label="Registries" value={summary.total.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Healthy Sync" value={summary.healthy.toLocaleString()} icon={<PlayCircle className="h-3.5 w-3.5" />} tone={summary.failedSync > 0 ? "medium" : "accent"} hint={`${summary.failedSync} failed`} />
        <StatCard label="Images Seen" value={summary.images.toLocaleString()} icon={<Boxes className="h-3.5 w-3.5" />} />
        <StatCard label="Active Jobs" value={summary.activeJobs.toLocaleString()} icon={<Clock className="h-3.5 w-3.5" />} tone={summary.activeJobs > 0 ? "low" : "neutral"} hint={`${summary.pendingJobs} pending`} />
        <StatCard label="Failed Jobs" value={summary.failedJobs.toLocaleString()} icon={<AlertTriangle className="h-3.5 w-3.5" />} tone={summary.failedJobs > 0 ? "high" : "neutral"} />
      </section>

      <DataTable<RegistryDTO>
        rows={rows}
        columns={columns}
        rowKey={(r) => r.id}
        emptyState={<EmptyState onAdd={() => setCreateOpen(true)} />}
        defaultSort={{ id: "name", dir: "asc" }}
      />

      <CreateOrEditDialog
        open={createOpen || editing !== null}
        editing={editing}
        onOpenChange={(open) => {
          if (!open) {
            setCreateOpen(false);
            setEditing(null);
          }
        }}
        onSaved={() => {
          setCreateOpen(false);
          setEditing(null);
          qc.invalidateQueries({ queryKey: ["registries"] });
        }}
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
    <span className="flex items-center gap-2 min-w-0">
      <StatusPill label={row.last_sync_status || "unknown"} tone={tone} />
      {row.last_sync_at && (
        <span className="text-[10px] text-muted-foreground text-mono truncate">
          {new Date(row.last_sync_at).toLocaleString()}
        </span>
      )}
    </span>
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

function buildScanPolicy(
  includeRepos: string[],
  excludeReposRaw: string,
  tagSelection: RegistryScanPolicy["tag_selection"],
  maxAge: string,
  rescanInterval: string,
  rescanAfterDBUpdate: boolean,
  repoLimit: string,
  tagLimit: string,
  customInterval: string,
  cron: string,
  ignoreProxy: boolean,
  scanLayers: boolean,
  blockPromotionThreshold: string,
): RegistryScanPolicy {
  const excludeRepos = excludeReposRaw.split(/\n+/).map((s) => s.trim()).filter(Boolean);
  return {
    include_repos: includeRepos.length > 0 ? includeRepos : ["*"],
    exclude_repos: excludeRepos,
    tag_selection: tagSelection,
    max_age: maxAge.trim(),
    rescan_interval: rescanInterval.trim(),
    rescan_after_db_update: rescanAfterDBUpdate,
    repo_limit: parsePositiveInt(repoLimit),
    tag_limit: parsePositiveInt(tagLimit),
    custom_interval: customInterval.trim(),
    cron: cron.trim(),
    ignore_proxy: ignoreProxy,
    scan_layers: scanLayers,
    block_promotion_threshold: blockPromotionThreshold,
  };
}

function parsePositiveInt(value: string) {
  const n = Number.parseInt(value.trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

function scheduleFromRegistry(row: RegistryDTO | null): {
  mode: RegistryScheduleMode;
  customInterval: string;
  cron: string;
} {
  const cadence = row?.scan_cadence?.trim() || "manual";
  if (cadence.startsWith("cron:")) {
    return { mode: "cron", customInterval: "", cron: cadence.slice("cron:".length).trim() };
  }
  if ((CADENCES as readonly string[]).includes(cadence) && cadence !== "custom" && cadence !== "cron") {
    return { mode: cadence as RegistryScheduleMode, customInterval: "", cron: "" };
  }
  return { mode: "custom", customInterval: row?.scan_policy?.custom_interval || cadence, cron: "" };
}

function buildScanCadence(mode: RegistryScheduleMode, customInterval: string, cron: string): RegistryCadence {
  if (mode === "custom") return customInterval.trim() || "custom";
  if (mode === "cron") return `cron:${cron.trim()}`;
  return mode;
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

// -----------------------------------------------------------------------------
// Create / Edit dialog
// -----------------------------------------------------------------------------

function CreateOrEditDialog({
  open,
  editing,
  onOpenChange,
  onSaved,
}: {
  open: boolean;
  editing: RegistryDTO | null;
  onOpenChange: (open: boolean) => void;
  onSaved: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(editing?.name ?? "");
  const [kind, setKind] = useState<RegistryKind>(editing?.kind ?? "docker-hub");
  const [endpoint, setEndpoint] = useState(editing?.endpoint ?? "");
  const [authKind, setAuthKind] = useState<RegistryAuthKind>(editing?.auth_kind ?? "static");
  const initialSchedule = scheduleFromRegistry(editing);
  const [scheduleMode, setScheduleMode] = useState<RegistryScheduleMode>(initialSchedule.mode);
  const [customInterval, setCustomInterval] = useState(initialSchedule.customInterval);
  const [cron, setCron] = useState(initialSchedule.cron);
  const [globs, setGlobs] = useState<string>(editing?.image_globs?.join("\n") ?? "");
  const [excludeGlobs, setExcludeGlobs] = useState<string>(editing?.scan_policy?.exclude_repos?.join("\n") ?? "");
  const [tagSelection, setTagSelection] = useState<RegistryScanPolicy["tag_selection"]>(editing?.scan_policy?.tag_selection ?? "all");
  const [maxAge, setMaxAge] = useState(editing?.scan_policy?.max_age ?? "");
  const [rescanInterval, setRescanInterval] = useState(editing?.scan_policy?.rescan_interval ?? "");
  const [rescanAfterDBUpdate, setRescanAfterDBUpdate] = useState(editing?.scan_policy?.rescan_after_db_update ?? true);
  const [repoLimit, setRepoLimit] = useState(String(editing?.scan_policy?.repo_limit || ""));
  const [tagLimit, setTagLimit] = useState(String(editing?.scan_policy?.tag_limit || ""));
  const [ignoreProxy, setIgnoreProxy] = useState(editing?.scan_policy?.ignore_proxy ?? false);
  const [scanLayers, setScanLayers] = useState(editing?.scan_policy?.scan_layers ?? true);
  const [promotionThreshold, setPromotionThreshold] = useState(editing?.scan_policy?.block_promotion_threshold ?? "critical");
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [testResult, setTestResult] = useState<RegistryTestResult | null>(null);

  // Reset form when dialog (re-)opens for a different row.
  useMemo(() => {
    if (open) {
      setName(editing?.name ?? "");
      setKind(editing?.kind ?? "docker-hub");
      setEndpoint(editing?.endpoint ?? "");
      setAuthKind(editing?.auth_kind ?? "static");
      const nextSchedule = scheduleFromRegistry(editing);
      setScheduleMode(nextSchedule.mode);
      setCustomInterval(nextSchedule.customInterval);
      setCron(nextSchedule.cron);
      setGlobs(editing?.image_globs?.join("\n") ?? "");
      setExcludeGlobs(editing?.scan_policy?.exclude_repos?.join("\n") ?? "");
      setTagSelection(editing?.scan_policy?.tag_selection ?? "all");
      setMaxAge(editing?.scan_policy?.max_age ?? "");
      setRescanInterval(editing?.scan_policy?.rescan_interval ?? "");
      setRescanAfterDBUpdate(editing?.scan_policy?.rescan_after_db_update ?? true);
      setRepoLimit(String(editing?.scan_policy?.repo_limit || ""));
      setTagLimit(String(editing?.scan_policy?.tag_limit || ""));
      setIgnoreProxy(editing?.scan_policy?.ignore_proxy ?? false);
      setScanLayers(editing?.scan_policy?.scan_layers ?? true);
      setPromotionThreshold(editing?.scan_policy?.block_promotion_threshold ?? "critical");
      setCreds({});
      setTestResult(null);
    }
  }, [open, editing]);

  const kindMeta = KINDS.find((k) => k.kind === kind);

  const save = useMutation({
    mutationFn: async () => {
      const parsedGlobs = globs.split(/\n+/).map((s) => s.trim()).filter(Boolean);
      const scanPolicy = buildScanPolicy(
        parsedGlobs,
        excludeGlobs,
        tagSelection,
        maxAge,
        rescanInterval,
        rescanAfterDBUpdate,
        repoLimit,
        tagLimit,
        scheduleMode === "custom" ? customInterval : "",
        scheduleMode === "cron" ? cron : "",
        ignoreProxy,
        scanLayers,
        promotionThreshold,
      );
      const resolvedCadence = buildScanCadence(scheduleMode, customInterval, cron);
      const body: RegistryCreateBody = {
        name,
        kind,
        endpoint,
        auth_kind: authKind,
        credentials: authKind === "none" ? undefined : creds,
        scan_cadence: resolvedCadence,
        image_globs: parsedGlobs,
        scan_policy: scanPolicy,
      };
      if (editing) {
        await registriesApi.update(editing.id, {
          name,
          endpoint,
          auth_kind: authKind,
          credentials: Object.keys(creds).length > 0 ? creds : undefined,
          scan_cadence: resolvedCadence,
          image_globs: parsedGlobs,
          scan_policy: scanPolicy,
        });
        return editing.id;
      }
      const r = await registriesApi.create(body);
      return r.id;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["registries"] });
      onSaved();
    },
  });

  const tryTest = useMutation({
    mutationFn: async () => {
      // The handler exposes /test only on persisted rows. For unsaved rows we
      // save first, test, then leave the row in place — same behavior as the
      // common pattern in other receivers UIs.
      const parsedGlobs = globs.split(/\n+/).map((s) => s.trim()).filter(Boolean);
      const scanPolicy = buildScanPolicy(
        parsedGlobs,
        excludeGlobs,
        tagSelection,
        maxAge,
        rescanInterval,
        rescanAfterDBUpdate,
        repoLimit,
        tagLimit,
        scheduleMode === "custom" ? customInterval : "",
        scheduleMode === "cron" ? cron : "",
        ignoreProxy,
        scanLayers,
        promotionThreshold,
      );
      const resolvedCadence = buildScanCadence(scheduleMode, customInterval, cron);
      let id = editing?.id;
      if (!id) {
        const r = await registriesApi.create({
          name, kind, endpoint, auth_kind: authKind,
          credentials: authKind === "none" ? undefined : creds,
          scan_cadence: resolvedCadence, image_globs: parsedGlobs, scan_policy: scanPolicy,
        });
        id = r.id;
      } else {
        await registriesApi.update(id, {
          name, endpoint, auth_kind: authKind,
          credentials: Object.keys(creds).length > 0 ? creds : undefined,
          scan_cadence: resolvedCadence, image_globs: parsedGlobs, scan_policy: scanPolicy,
        });
      }
      return registriesApi.test(id);
    },
    onSuccess: (r) => setTestResult(r),
  });

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-background/70 backdrop-blur-sm" />
        <Dialog.Content
          className="fixed left-1/2 top-1/2 z-50 max-h-[90vh] w-[640px] -translate-x-1/2 -translate-y-1/2 overflow-auto rounded-lg border border-border bg-popover p-5 shadow-[var(--elev-popover)]"
          data-testid="registry-dialog"
        >
          <Dialog.Title className="text-base font-semibold">
            {editing ? `Edit registry — ${editing.name}` : "Add container registry"}
          </Dialog.Title>
          <Dialog.Description className="text-xs text-muted-foreground mt-1">
            Constellation will pull image metadata on the configured cadence and enqueue every newly-discovered tag for scanning.
          </Dialog.Description>

          <div className="mt-4 grid gap-3">
            <Row label="Name">
              <input
                className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                value={name}
                onChange={(e: ChangeEvent<HTMLInputElement>) => setName(e.target.value)}
                placeholder="prod-ecr-us-east-1"
              />
            </Row>

            {!editing && (
              <Row label="Kind">
                <div className="grid grid-cols-3 gap-1.5">
                  {KINDS.map((k) => (
                    <button
                      key={k.kind}
                      type="button"
                      onClick={() => { setKind(k.kind); setEndpoint(k.endpointHint); }}
                      className={
                        "rounded-md border px-2 py-2 text-left text-xs transition-colors " +
                        (kind === k.kind
                          ? "border-[color:var(--color-primary)] bg-accent"
                          : "border-border hover:bg-accent")
                      }
                      data-testid={`kind-${k.kind}`}
                    >
                      <div className="font-medium">{k.label}</div>
                      <div className="text-[10px] text-muted-foreground text-mono truncate">{k.kind}</div>
                    </button>
                  ))}
                </div>
              </Row>
            )}

            <Row label="Endpoint">
              <input
                className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder={kindMeta?.endpointHint}
              />
            </Row>

            <Row label="Auth">
              <select
                className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                value={authKind}
                onChange={(e) => setAuthKind(e.target.value as RegistryAuthKind)}
              >
                {AUTH_KINDS.map((a) => <option key={a} value={a}>{a}</option>)}
              </select>
            </Row>

            {authKind !== "none" && kindMeta && (
              <div className="rounded-md border border-border bg-card p-3 space-y-2">
                <div className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  Credentials for {kindMeta.label}
                </div>
                {kindMeta.fields.map((f) => (
                  <Row key={f.key} label={f.label}>
                    <input
                      className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                      type={f.secret ? "password" : "text"}
                      value={creds[f.key] ?? ""}
                      onChange={(e) => setCreds({ ...creds, [f.key]: e.target.value })}
                      placeholder={f.placeholder ?? (editing?.has_secret ? "(leave blank to keep saved value)" : undefined)}
                    />
                    {f.helper && <div className="text-[10px] text-muted-foreground mt-0.5">{f.helper}</div>}
                  </Row>
                ))}
              </div>
            )}

            <Row label="Scan cadence">
              <select
                className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                value={scheduleMode}
                onChange={(e) => setScheduleMode(e.target.value as RegistryScheduleMode)}
              >
                {CADENCES.map((c) => (
                  <option key={c} value={c}>
                    {c === "custom" ? "custom interval" : c === "cron" ? "cron schedule" : c}
                  </option>
                ))}
              </select>
            </Row>

            {scheduleMode === "custom" && (
              <Row label="Custom interval">
                <input
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={customInterval}
                  onChange={(e) => setCustomInterval(e.target.value)}
                  placeholder="12h"
                />
              </Row>
            )}

            {scheduleMode === "cron" && (
              <Row label="Cron">
                <input
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={cron}
                  onChange={(e) => setCron(e.target.value)}
                  placeholder="0 2 * * *"
                />
              </Row>
            )}

            <Row label="Image globs (one per line)">
              <textarea
                className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs min-h-[64px] font-mono"
                value={globs}
                onChange={(e) => setGlobs(e.target.value)}
                placeholder={"myorg/*\napp:v[0-9]*"}
              />
            </Row>

            <div className="grid gap-3 rounded-md border border-border bg-card p-3 md:grid-cols-2">
              <Row label="Exclude repos">
                <textarea
                  className="block min-h-[58px] w-full rounded-md border border-input bg-background px-2 py-1.5 font-mono text-xs"
                  value={excludeGlobs}
                  onChange={(e) => setExcludeGlobs(e.target.value)}
                  placeholder={"*/scratch\n*/experimental-*"}
                />
              </Row>
              <Row label="Tag selection">
                <select
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={tagSelection}
                  onChange={(e) => setTagSelection(e.target.value as RegistryScanPolicy["tag_selection"])}
                >
                  <option value="all">all tags</option>
                  <option value="latest">latest tag only</option>
                </select>
              </Row>
              <Row label="Max image age">
                <input
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={maxAge}
                  onChange={(e) => setMaxAge(e.target.value)}
                  placeholder="720h"
                />
              </Row>
              <Row label="Rescan interval">
                <input
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={rescanInterval}
                  onChange={(e) => setRescanInterval(e.target.value)}
                  placeholder="168h"
                />
              </Row>
              <Row label="Repo limit">
                <input
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={repoLimit}
                  onChange={(e) => setRepoLimit(e.target.value)}
                  inputMode="numeric"
                  placeholder="unlimited"
                />
              </Row>
              <Row label="Tag limit">
                <input
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={tagLimit}
                  onChange={(e) => setTagLimit(e.target.value)}
                  inputMode="numeric"
                  placeholder="unlimited"
                />
              </Row>
              <Row label="Promotion threshold">
                <select
                  className="block w-full rounded-md border border-input bg-background px-2 py-1.5 text-xs"
                  value={promotionThreshold}
                  onChange={(e) => setPromotionThreshold(e.target.value)}
                >
                  {PROMOTION_THRESHOLDS.map((threshold) => (
                    <option key={threshold} value={threshold}>{threshold}</option>
                  ))}
                </select>
              </Row>
              <label className="flex min-h-[54px] items-center gap-2 rounded-md border border-border bg-background px-2 py-1.5 text-xs">
                <input
                  type="checkbox"
                  checked={rescanAfterDBUpdate}
                  onChange={(e) => setRescanAfterDBUpdate(e.target.checked)}
                />
                <span>Rescan after DB update</span>
              </label>
              <label className="flex min-h-[54px] items-center gap-2 rounded-md border border-border bg-background px-2 py-1.5 text-xs">
                <input
                  type="checkbox"
                  checked={ignoreProxy}
                  onChange={(e) => setIgnoreProxy(e.target.checked)}
                />
                <span>Ignore proxy</span>
              </label>
              <label className="flex min-h-[54px] items-center gap-2 rounded-md border border-border bg-background px-2 py-1.5 text-xs">
                <input
                  type="checkbox"
                  checked={scanLayers}
                  onChange={(e) => setScanLayers(e.target.checked)}
                />
                <span>Scan layers</span>
              </label>
            </div>

            {testResult && (
              <div
                className={
                  "rounded-md border px-3 py-2 text-xs " +
                  (testResult.ok
                    ? "border-[color:var(--color-status-success)]/40 bg-[color:var(--color-status-success)]/5"
                    : "border-[color:var(--color-status-error)]/40 bg-[color:var(--color-status-error)]/5")
                }
                data-testid="registry-test-result"
              >
                {testResult.ok
                  ? `OK — ${testResult.images_visible ?? 0} images visible`
                  : `Failed — ${testResult.error}`}
              </div>
            )}
          </div>

          <div className="mt-5 flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => tryTest.mutate()}
              disabled={tryTest.isPending || save.isPending}
              className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
            >
              <Beaker className="h-3.5 w-3.5" /> Test
            </button>
            <Dialog.Close asChild>
              <button
                type="button"
                className="rounded-md border border-border bg-card px-3 py-1.5 text-xs hover:bg-accent"
              >
                Cancel
              </button>
            </Dialog.Close>
            <button
              type="button"
              onClick={() => save.mutate()}
              disabled={save.isPending}
              className="rounded-md bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
              data-testid="registry-save"
            >
              {save.isPending ? "Saving…" : editing ? "Save" : "Create"}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-[11px] text-muted-foreground">{label}</span>
      {children}
    </label>
  );
}
