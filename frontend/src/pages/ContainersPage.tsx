import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";
// ContainersPage — the per-running-container inventory (NeuVector's Assets → Containers).
// Source snapshots contain running entries; workload enrichment is advisory.
// Constellation previously only aggregated to the deployment level; this lists every
// live container across all nodes with its pod, image, node, state, and workload
// security posture (privileged/root/risk). Closes the #1 structural NV-parity gap.
import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Boxes, ShieldAlert } from "lucide-react";

import { containers, type ContainerRow } from "@/api/client";
import {
  useInventoryScope,
  useInventoryRoute,
  InventoryScopeState,
  InventoryLoadState,
} from "./inventory-workspace";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { PlatformVisibilityToggle } from "@/components/ui/platform-visibility-toggle";
import { cn } from "@/lib/cn";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { Pager } from "@/components/ui/pager";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";
import { Select } from "@/components/ui/form";

export function ContainersPage() {
  const qc = useQueryClient();
  const scope = useInventoryScope();
  const { clusterId } = scope;
  const route = useInventoryRoute();
  const search = route.query;
  const setSearch = route.setQuery;
  const [platformPreference, setPlatformPreference] =
    usePlatformComponentVisibility();
  const visibility = route.params.get("hide_platform");
  const hidePlatformComponents =
    visibility === null
      ? platformPreference
      : ["true", "1", "t"].includes(visibility.toLowerCase());
  const namespace = route.params.get("namespace") ?? "";
  const node = route.params.get("node") ?? "";
  const role = route.params.get("platform_role") ?? "all";
  const sort = route.params.get("sort") ?? "risk";
  const order = route.params.get("order") === "asc" ? "asc" : "desc";
  const rawPage = Number(route.params.get("page") ?? "1");
  const invalidFilters = Boolean(
    (visibility !== null &&
      !["true", "false", "1", "0", "t", "f"].includes(
        visibility.toLowerCase(),
      )) ||
    !["all", "core", "none"].includes(role) ||
    !["name", "pod", "image", "node", "risk", "state", "observed"].includes(
      sort,
    ) ||
    (route.params.has("order") &&
      !["asc", "desc"].includes(route.params.get("order")!)) ||
    !Number.isSafeInteger(rawPage) ||
    rawPage < 1 ||
    rawPage > 10000,
  );
  const setHidePlatformComponents = (hidden: boolean) => {
    setPlatformPreference(hidden);
    route.update({ hide_platform: String(hidden) });
  };
  const filters = {
    q: route.debouncedQuery.trim() || undefined,
    namespace: namespace.trim() || undefined,
    node: node.trim() || undefined,
    hide_platform: hidePlatformComponents,
    platform_role: role === "all" ? undefined : role,
    sort,
    order: order as "asc" | "desc",
  };
  const inventoryKey = ["containers", scope.owner, clusterId, filters, route.page];
  const q = useQuery({
    queryKey: inventoryKey,
    queryFn: async () => {
      const result = await containers.list(clusterId!, {
        ...filters,
        limit: 100,
        offset: route.offset,
      });
      if (
        result.cluster_id !== clusterId ||
        !Array.isArray(result.items) ||
        !Number.isSafeInteger(result.total) ||
        result.total < 0 ||
        result.limit !== 100 ||
        result.offset !== route.offset ||
        result.sort !== sort ||
        result.order !== order ||
        typeof result.has_more !== "boolean" ||
        result.has_more !==
          result.offset + result.items.length < result.total ||
        (result.has_more && result.items.length === 0) ||
        result.items.length > 100 ||
        !result.summary ||
        result.summary.total !== result.total ||
        ["running", "privileged", "run_as_root", "platform_count"].some(
          (key) =>
            !Number.isSafeInteger(
              result.summary[key as keyof typeof result.summary],
            ) || result.summary[key as keyof typeof result.summary] < 0,
        ) ||
        new Set(result.items.map((row) => row.row_id)).size !==
          result.items.length ||
        result.items.some(
          (row) =>
            typeof row.row_id !== "string" ||
            !row.row_id ||
            !["CONTAINER_RUNNING", "running"].includes(row.state) ||
            (namespace.trim() && row.namespace !== namespace.trim()) ||
            (node.trim() && row.node !== node.trim()) ||
            (hidePlatformComponents && row.platform_role === "core") ||
            (role === "core" && row.platform_role !== "core") ||
            (role === "none" && row.platform_role === "core"),
        )
      )
        throw new Error(
          "Container inventory does not match the requested scope, filters or page",
        );
      return result;
    },
    enabled: scope.ready && !route.debouncing && !invalidFilters,
  });
  const available =
    scope.ready &&
    q.isSuccess &&
    !q.isFetching &&
    !route.debouncing &&
    !invalidFilters;
  const rows = useMemo(
    () => (available ? q.data!.items : []),
    [available, q.data],
  );
  const summary = available ? q.data!.summary : undefined;
  const platformCount = summary?.platform_count;
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<{
    scope: string;
    error: unknown;
  } | null>(null);
  const [exportResult, setExportResult] = useState<{
    scope: string;
    exported: number;
    total: number;
    truncated: boolean;
  } | null>(null);
  const exportScope = JSON.stringify([scope.owner, clusterId, filters]);
  const captureExport = useExportGuard(JSON.stringify([exportScope, route.page]), !available, () => !!clusterId && clusterCacheReady(qc, clusterId) && exportQueryReady(qc, inventoryKey, q.data));
  const exportMatching = async () => {
    const shouldDownload = captureExport();
    if (!shouldDownload() || exporting) return;
    setExportError(null);
    setExporting(true);
    try {
      const result = await containers.exportCSV(clusterId!, filters, shouldDownload);
      if (!shouldDownload()) return;
      setExportResult({ scope: exportScope, ...result });
    } catch (error) {
      if (shouldDownload()) setExportError({ scope: exportScope, error });
    } finally {
      setExporting(false);
    }
  };
  const reset = () =>
    route.update({
      q: null,
      namespace: null,
      node: null,
      platform_role: null,
      hide_platform: null,
      sort: null,
      order: null,
    });

  const columns: Column<ContainerRow>[] = [
    {
      id: "name",
      exportValue: (c) => c.name,
      header: "Container",
      kind: "name",
      minSize: 180,
      wrap: true,
      cell: (c) => (
        <div>
          <span className="text-xs font-medium">{c.name || "—"}</span>
          {c.privileged && (
            <span
              className="ml-1.5 rounded px-1 py-px text-micro font-semibold "
              style={{
                background:
                  "color-mix(in oklab, var(--color-severity-critical) 16%, transparent)",
                color: "var(--color-severity-critical)",
              }}
              title="Privileged evidence reported for the attributed workload"
            >
              workload: priv
            </span>
          )}
          {c.run_as_root && (
            <span
              className="ml-1 rounded px-1 py-px text-micro font-semibold "
              style={{
                background:
                  "color-mix(in oklab, var(--color-severity-high) 16%, transparent)",
                color: "var(--color-severity-high)",
              }}
              title="Root-user evidence reported for the attributed workload"
            >
              workload: root
            </span>
          )}
        </div>
      ),
      sort: (a, b) => a.name.localeCompare(b.name),
    },
    {
      id: "pod",
      exportValue: (c) => `${c.namespace}/${c.pod_name}`,
      header: "Pod",
      kind: "id",
      size: 240,
      minSize: 220,
      maxSize: 360,
      cell: (c) =>
        c.workload && clusterId ? (
          <a
            href={`/clusters/${clusterId}/deployments?q=${encodeURIComponent(c.workload)}&namespace=${encodeURIComponent(c.namespace)}&hide_platform=false`}
            className="text-mono text-micro text-[color:var(--color-primary)] hover:underline"
            title={`${c.namespace}/${c.pod_name}`}
          >
            {c.namespace}/{c.pod_name}
          </a>
        ) : (
          <span className="text-mono text-micro text-muted-foreground">
            {c.namespace}/{c.pod_name}
          </span>
        ),
      sort: (a, b) =>
        (a.namespace + a.pod_name).localeCompare(b.namespace + b.pod_name),
    },
    {
      id: "image",
      exportValue: (c) => c.image,
      header: "Image",
      kind: "name",
      size: 280,
      minSize: 260,
      maxSize: 400,
      grow: true,
      wrap: true,
      cell: (c) => (
        <div>
          <span className="text-micro">{displayImage(c.image)}</span>
          <DigestDisclosure digest={imageDigest(c.image)} />
        </div>
      ),
      sort: (a, b) => a.image.localeCompare(b.image),
    },
    {
      id: "node",
      exportValue: (c) => c.node,
      header: "Node",
      kind: "id",
      size: 160,
      minSize: 160,
      cell: (c) =>
        clusterId ? (
          <a
            href={`/clusters/${clusterId}/nodes/${encodeURIComponent(c.node)}`}
            className="text-mono text-micro text-[color:var(--color-primary)] hover:underline"
          >
            {c.node}
          </a>
        ) : (
          <span className="text-mono text-micro">
            {c.node || "Not reported"}
          </span>
        ),
      sort: (a, b) => a.node.localeCompare(b.node),
    },
    {
      id: "risk",
      exportValue: (c) => `critical=${c.critical}; high=${c.high}`,
      header: "Vulns",
      kind: "count",
      size: 112,
      minSize: 96,
      maxSize: 140,
      numeric: true,
      cell: (c) =>
        c.critical + c.high === 0 ? (
          <span className="text-micro text-muted-foreground">—</span>
        ) : (
          <span className="flex items-center justify-end gap-1">
            {c.critical > 0 && (
              <span
                className="rounded px-1.5 py-0.5 text-micro text-mono font-semibold text-white"
                style={{ background: "var(--color-severity-critical)" }}
              >
                {c.critical}C
              </span>
            )}
            {c.high > 0 && (
              <span
                className="rounded px-1.5 py-0.5 text-micro text-mono font-semibold text-white"
                style={{ background: "var(--color-severity-high)" }}
              >
                {c.high}H
              </span>
            )}
          </span>
        ),
      sort: () => 0,
    },
    {
      id: "state",
      exportValue: (c) => c.state,
      header: "State",
      kind: "status",
      cell: (c) => {
        const st = c.state.replace("CONTAINER_", "").toLowerCase();
        return (
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-micro font-medium",
              st === "running"
                ? "bg-[color-mix(in_oklab,var(--color-severity-low)_16%,transparent)] text-[color:var(--color-severity-low)]"
                : "bg-muted text-muted-foreground",
            )}
          >
            {st || "—"}
          </span>
        );
      },
      sort: (a, b) => a.state.localeCompare(b.state),
    },
    {
      id: "platform",
      header: "Platform role",
      kind: "status",
      cell: (c) => (c.platform_role === "core" ? "Platform" : "Customer"),
      exportValue: (c) => c.platform_role ?? "",
    },
    {
      id: "observed",
      header: "Observed",
      kind: "date",
      cell: (c) => new Date(c.observed_at).toLocaleString(),
      sort: () => 0,
      exportValue: (c) => c.observed_at,
    },
  ];

  if (!scope.ready)
    return (
      <div className="space-y-4">
        <PageHeader title="Containers" />
        <InventoryScopeState scope={scope} />
      </div>
    );
  return (
    <div
      className="space-y-4"
      data-cluster-id={clusterId ?? ""}
      data-testid="containers-page"
    >
      <PageHeader
        title="Containers"
        description="Running entries in the latest runtime-agent snapshots, with advisory workload attribution from pod-name prefixes. Vulnerability counts belong to the matched workload and may repeat across its containers."
        actions={
          <div className="flex flex-wrap gap-2">
            <PlatformVisibilityToggle
              hidden={hidePlatformComponents}
              onHiddenChange={setHidePlatformComponents}
              hiddenCount={platformCount}
            />
            <Button
              onClick={() => void q.refetch()}
              disabled={!scope.ready || q.isFetching || invalidFilters}
            >
              Refresh
            </Button>
          </div>
        }
      />
      <VerdictBanner
        status={
          q.isError || invalidFilters
            ? "degraded"
            : (summary?.privileged ?? 0) || (summary?.run_as_root ?? 0)
              ? "degraded"
              : "info"
        }
        title={
          q.isError || invalidFilters
            ? "Container evidence is unavailable"
            : !available
              ? "Loading container evidence"
              : `${q.data.total.toLocaleString()} matching running containers`
        }
        detail="Filters, sorting, matching counts and CSV apply across the source inventory. Recorded workload facts do not establish actual per-container settings or applied protection."
      />
      <StatGrid data-testid="containers-summary">
        <StatCard
          label="Matching running containers"
          value={summary?.total ?? "—"}
          icon={<Boxes className="h-3.5 w-3.5" />}
        />
        <StatCard
          label="Recorded privileged workload fact"
          value={summary?.privileged ?? "—"}
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
        />
        <StatCard
          label="Recorded root workload fact"
          value={summary?.run_as_root ?? "—"}
        />
        <StatCard
          label="Matching platform rows"
          value={platformCount ?? "—"}
          hint="Before platform visibility; other filters apply"
        />
      </StatGrid>
      <p className="text-xs text-muted-foreground">
        Privileged, root and vulnerability evidence comes from the attributed
        workload, rather than a direct measurement of each container’s settings.
        Stopped containers are excluded.
      </p>
      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-card p-3">
        <label className="min-w-0 basis-64 flex-1 text-xs">
          Search
          <input
            aria-label="Search containers"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Container, pod, image, node…"
            className="block w-full min-w-0 rounded-md border border-border bg-background px-3 py-2 text-sm"
          />
        </label>
        <label className="text-xs">
          Namespace
          <input
            aria-label="Container namespace"
            value={namespace}
            onChange={(event) =>
              route.update({ namespace: event.target.value }, true, true)
            }
            className="block rounded-md border border-border bg-background px-3 py-2 text-sm"
          />
        </label>
        <label className="text-xs">
          Node
          <input
            aria-label="Container node"
            value={node}
            onChange={(event) =>
              route.update({ node: event.target.value }, true, true)
            }
            className="block rounded-md border border-border bg-background px-3 py-2 text-sm"
          />
        </label>
        <label className="text-xs">
          Platform role
          <Select
            aria-label="Container platform role"
            value={role}
            onChange={(event) => {
              const value = event.target.value;
              if (value === "core") setPlatformPreference(false);
              route.update({
                platform_role: value === "all" ? null : value,
                ...(value === "core" ? { hide_platform: "false" } : {}),
              });
            }}
            className="block rounded-md border border-border bg-background p-2 text-sm"
          >
            <option value="all">Any role</option>
            <option value="core">Platform</option>
            <option value="none">Customer</option>
          </Select>
        </label>
        <Button variant="outline" onClick={reset}>
          Reset filters
        </Button>
        <Button
          variant="outline"
          disabled={!available || !q.data?.total || exporting}
          onClick={() => void exportMatching()}
        >
          {exporting ? "Exporting…" : "Export matching containers CSV"}
        </Button>
      </div>
      <p className="text-xs text-muted-foreground">
        Full CSV covers up to 100,000 matching running entries. Page CSV follows
        visible columns on this server page.
      </p>
      {exportError?.scope === exportScope && (
        <p role="alert" className="text-sm text-status-error">
          Container export failed.{" "}
          {exportError.error instanceof Error
            ? exportError.error.message
            : "Try again."}
        </p>
      )}
      {exportResult?.scope === exportScope && (
        <p role="status" className="text-xs text-muted-foreground">
          Exported {exportResult.exported} of {exportResult.total} matching
          containers.
          {exportResult.truncated
            ? " The 100,000-row export cap was reached."
            : ""}
        </p>
      )}
      {!available ? (
        <InventoryLoadState
          label="Containers"
          query={q}
          invalid={invalidFilters}
          debouncing={route.debouncing}
        />
      ) : (
        <>
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(row) => row.row_id}
            preferencesKey="containers-inventory"
            manualSorting
            sort={{ id: sort, dir: order }}
            onSortChange={(value) =>
              route.update({
                sort: value?.id ?? "risk",
                order: value?.dir ?? "desc",
              })
            }
            pagination={false}
            exportFileName="constellation-containers-page"
            exportLabel="Export this page CSV"
            testId="containers-table"
            emptyState={
              <EmptyState
                title="No containers match"
                hint={
                  hidePlatformComponents && platformCount
                    ? `${platformCount} matching platform containers are hidden. Show platform rows to inspect them.`
                    : "Change the filters or return to the first page."
                }
              />
            }
          />
          <p
            className="text-xs text-muted-foreground"
            data-testid="containers-page-scope"
          >
            Showing {rows.length ? route.offset + 1 : 0}–
            {rows.length ? route.offset + rows.length : 0} of {q.data.total}{" "}
            matching running containers.
          </p>
          {rows.length > 0 && (
            <Pager
              page={route.page}
              pageSize={100}
              total={q.data.total}
              hasMore={q.data.has_more}
              rowsOnPage={rows.length}
              onPage={route.setPage}
            />
          )}
          {route.page > 0 && !rows.length && (
            <Button onClick={() => route.setPage(0)}>First page</Button>
          )}
        </>
      )}
    </div>
  );
}

function displayImage(value: string): string {
  if (!value) return "Not reported";
  if (value.startsWith("sha256:")) return "Unnamed image";
  return value.split("@sha256:")[0];
}

function imageDigest(value: string): string | undefined {
  if (value.startsWith("sha256:")) return value;
  const suffix = value.indexOf("@sha256:");
  return suffix >= 0 ? value.slice(suffix + 1) : undefined;
}
