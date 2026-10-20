import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { clusterCacheReady } from "@/lib/cluster-evidence";
// ContainersPage — the per-running-container inventory (NeuVector's Assets → Containers).
// Source snapshots contain running entries; workload enrichment is advisory.
// Constellation previously only aggregated to the deployment level; this lists every
// live container across all nodes with its pod, image, node, state, and workload
// security posture (privileged/root/risk). Closes the #1 structural NV-parity gap.
import { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { containers, type ContainerRow } from "@/api/client";
import {
  useInventoryScope,
  useInventoryRoute,
  InventoryScopeState,
  InventoryLoadState,
  FilterLabel,
  InventoryMoreFilters,
} from "./inventory-workspace";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { EmptyState } from "@/components/ui/empty-state";
import { TableSearch } from "@/ui";
import { StatusPill } from "@/components/ui/status-pill";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { Pager } from "@/components/ui/pager";
import { usePlatformComponentVisibility } from "@/hooks/usePlatformComponentVisibility";
import { Select, TextInput } from "@/components/ui/form";

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
              <span className="font-mono text-13 tabular-nums" title={`${c.critical} critical`}>
                <span className="font-semibold text-severity-critical">{c.critical}</span><span className="text-muted-foreground">C</span>
              </span>
            )}
            {c.high > 0 && (
              <span className="font-mono text-13 tabular-nums" title={`${c.high} high`}>
                <span className="font-semibold text-severity-high">{c.high}</span><span className="text-muted-foreground">H</span>
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
          st ? <StatusPill label={st} tone={st === "running" ? "success" : "neutral"} /> : <span className="text-muted-foreground">—</span>
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
  const toolbar = (
    <>
      <TableSearch value={search} onChange={setSearch} placeholder="Search containers" className="max-w-xs" />
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
        className="h-9"
      >
        <option value="all">Any role</option>
        <option value="core">Platform</option>
        <option value="none">Customer</option>
      </Select>
      <TextInput aria-label="Container namespace" placeholder="Namespace" value={namespace} onChange={(event) => route.update({ namespace: event.target.value }, true, true)} className="h-9 w-36" />
      <InventoryMoreFilters count={node ? 1 : 0}>
        <FilterLabel label="Node"><TextInput aria-label="Container node" value={node} onChange={(event) => route.update({ node: event.target.value }, true, true)} /></FilterLabel>
      </InventoryMoreFilters>
      {(namespace || node || role !== "all" || search) && <Button variant="ghost" onClick={reset}>Reset filters</Button>}
    </>
  );
  const exportOptions = [{ label: exporting ? "Exporting matching rows…" : "Matching rows", description: "Every page, up to 100,000 running containers", disabled: !available || !q.data?.total || exporting, onSelect: () => void exportMatching() }];
  return (
    <div
      className="space-y-4"
      data-cluster-id={clusterId ?? ""}
      data-testid="containers-page"
    >
      <PageHeader
        title="Containers"
        description="Running containers from the latest runtime-agent snapshots, with advisory workload attribution from pod-name prefixes. Vulnerability counts belong to the matched workload and may repeat across its containers."
        actions={
          <Button onClick={() => void q.refetch()} disabled={!scope.ready || q.isFetching || invalidFilters}>
            Refresh
          </Button>
        }
      />
      <VerdictBanner
        status={q.isError || invalidFilters ? "degraded" : (summary?.privileged ?? 0) || (summary?.run_as_root ?? 0) ? "degraded" : "info"}
        title={q.isError || invalidFilters ? "Container evidence is unavailable" : !available ? "Loading container evidence" : `${q.data.total.toLocaleString()} matching running containers`}
        numbers={summary ? [
          { label: "privileged", value: (summary.privileged ?? 0).toLocaleString(), tone: summary.privileged ? "warning" : "default", title: "Recorded privileged workload fact" },
          { label: "run as root", value: (summary.run_as_root ?? 0).toLocaleString(), tone: summary.run_as_root ? "warning" : "default", title: "Recorded root workload fact" },
          { label: "platform", value: (platformCount ?? 0).toLocaleString(), tone: "muted", title: "Matching platform rows before the System workloads scope" },
        ] : undefined}
        detail={<div className="space-y-1" data-testid="containers-summary">
          <p>Matching running containers {summary?.total ?? "—"} · recorded privileged workload fact {summary?.privileged ?? "—"} · recorded root workload fact {summary?.run_as_root ?? "—"} · matching platform rows {platformCount ?? "—"}.</p>
          <p>Privileged, root and vulnerability evidence comes from the attributed workload, not a direct measurement of each container. Stopped containers are excluded. Full CSV covers up to 100,000 matching running entries; page CSV follows visible columns.</p>
        </div>}
      />
      {exportError?.scope === exportScope && (
        <p role="alert" className="text-sm text-status-error">
          Container export failed. {exportError.error instanceof Error ? exportError.error.message : "Try again."}
        </p>
      )}
      {exportResult?.scope === exportScope && (
        <p role="status" className="text-sm text-muted-foreground">
          Exported {exportResult.exported} of {exportResult.total} matching containers.
          {exportResult.truncated ? " The 100,000-row export cap was reached." : ""}
        </p>
      )}
      {!available && (q.isError || invalidFilters) ? (
        <InventoryLoadState label="Containers" query={q} invalid={invalidFilters} debouncing={route.debouncing} />
      ) : (
        <>
          <DataTable
            rows={available ? rows : []}
            columns={columns}
            rowKey={(row) => row.row_id}
            preferencesKey="containers-inventory"
            defaultHiddenColumnIds={["observed"]}
            manualSorting
            sort={{ id: sort, dir: order }}
            onSortChange={(value) => route.update({ sort: value?.id ?? "risk", order: value?.dir ?? "desc" })}
            pagination={false}
            toolbar={toolbar}
            exportOptions={exportOptions}
            exportFileName="constellation-containers-page"
            exportLabel="This page"
            testId={available ? "containers-table" : "containers-table-loading"}
            emptyState={!available ? <InventoryLoadState label="Containers" query={q} invalid={invalidFilters} debouncing={route.debouncing} /> :
              <EmptyState
                title="No containers match"
                hint={hidePlatformComponents && platformCount ? `${platformCount} matching platform containers are hidden. Turn on System workloads in the header to inspect them.` : "Change the filters or return to the first page."}
              />
            }
          />
          {available && <>
          <p className="sr-only" data-testid="containers-page-scope">
            Showing {rows.length ? route.offset + 1 : 0}–{rows.length ? route.offset + rows.length : 0} of {q.data!.total} matching running containers.
          </p>
          {rows.length > 0 && (
            <Pager page={route.page} pageSize={100} total={q.data!.total} hasMore={q.data!.has_more} rowsOnPage={rows.length} onPage={route.setPage} />
          )}
          {route.page > 0 && !rows.length && <Button onClick={() => route.setPage(0)}>First page</Button>}
          </>}
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
