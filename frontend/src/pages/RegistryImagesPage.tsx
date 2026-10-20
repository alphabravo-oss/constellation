// Registry-discovered repositories with full server filtering, summaries and exports.
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, Boxes } from "lucide-react";
import { registries, type RegistryImageRow } from "@/api/client";
import {
  useInventoryScope,
  useInventoryRoute,
  InventoryScopeState,
  InventoryLoadState,
  ScanInventoryExport,
} from "./inventory-workspace";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { EmptyState } from "@/components/ui/empty-state";
import { Pager } from "@/components/ui/pager";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { fmtRelative } from "@/lib/format";
import { Select } from "@/components/ui/form";

const sorts = [
  "repository",
  "scanned",
  "vulnerabilities",
  "findings",
  "last_scanned",
  "last_seen",
];
export function RegistryImagesPage() {
  const { regId } = useParams({ strict: false });
  const scope = useInventoryScope();
  const route = useInventoryRoute();
  const scanStatus = route.params.get("scan_status") ?? "all";
  const severity = route.params.get("severity") ?? "all";
  const sort = route.params.get("sort") ?? "findings";
  const order = route.params.get("order") ?? "desc";
  const rawPage = Number(route.params.get("page") ?? "1");
  const invalid =
    !sorts.includes(sort) ||
    !["asc", "desc"].includes(order) ||
    !["all", "scanned", "unscanned"].includes(scanStatus) ||
    !["all", "critical", "high", "none"].includes(severity) ||
    !Number.isSafeInteger(rawPage) ||
    rawPage < 1 ||
    rawPage > 10000;
  const filters = {
    q: route.debouncedQuery.trim() || undefined,
    scan_status: scanStatus === "all" ? undefined : scanStatus,
    severity: severity === "all" ? undefined : severity,
    sort,
    order: order as "asc" | "desc",
  };
  const reg = useQuery({
    queryKey: ["registry", scope.owner, regId],
    queryFn: async () => {
      const registry = await registries.get(regId!);
      if (registry.id !== regId)
        throw new Error("Registry does not match this route");
      return registry;
    },
    enabled: scope.ready && !!regId,
  });
  const registryReady =
    scope.ready && reg.isSuccess && !reg.isFetching && reg.data.id === regId;
  const imgs = useQuery({
    queryKey: ["registry-images", scope.owner, regId, filters, route.page],
    queryFn: async () => {
      const result = await registries.images(regId!, {
        ...filters,
        limit: 100,
        offset: route.offset,
      });
      if (
        result.registry_id !== regId ||
        result.offset !== route.offset ||
        result.limit !== 100 ||
        result.sort !== sort ||
        result.order !== order ||
        !Number.isSafeInteger(result.total) ||
        result.total < 0 ||
        !Array.isArray(result.images) ||
        result.images.length > 100 ||
        result.images.length > Math.max(0, result.total - route.offset) ||
        typeof result.has_more !== "boolean" ||
        result.has_more !==
          route.offset + result.images.length < result.total ||
        (result.has_more && !result.images.length) ||
        !result.summary ||
        result.summary.total !== result.total ||
        ["scanned", "unscanned", "critical", "high"].some(
          (key) =>
            !Number.isSafeInteger(
              result.summary[key as keyof typeof result.summary],
            ) || result.summary[key as keyof typeof result.summary] < 0,
        ) ||
        result.summary.scanned + result.summary.unscanned !== result.total ||
        (scanStatus === "scanned" && result.summary.unscanned !== 0) ||
        (scanStatus === "unscanned" && result.summary.scanned !== 0) ||
        (severity === "none" &&
          (result.summary.critical !== 0 || result.summary.high !== 0)) ||
        new Set(result.images.map((image) => image.id)).size !==
          result.images.length ||
        result.images.some(
          (image) =>
            !image.id ||
            !Array.isArray(image.tags) ||
            !image.digests ||
            Object.values(image.digests).some(
              (value) => typeof value !== "string",
            ) ||
            [image.critical, image.high, image.finding_count].some(
              (value) => !Number.isSafeInteger(value) || value < 0,
            ) ||
            typeof image.scanned !== "boolean" ||
            (scanStatus === "scanned" && !image.scanned) ||
            (scanStatus === "unscanned" && image.scanned) ||
            (severity === "critical" && image.critical <= 0) ||
            (severity === "high" && image.high <= 0) ||
            (severity === "none" &&
              (!image.scanned || image.critical !== 0 || image.high !== 0)),
        )
      )
        throw new Error(
          "Registry image inventory does not match this scope, filters or page",
        );
      return result;
    },
    enabled: registryReady && !invalid && !route.debouncing,
  });
  const ready =
    registryReady &&
    imgs.isSuccess &&
    !imgs.isFetching &&
    !route.debouncing &&
    !invalid;
  const rows = ready ? imgs.data.images : [];
  const summary = ready ? imgs.data.summary : undefined;
  const unavailable = reg.isError || imgs.isError || invalid;
  const columns: Column<RegistryImageRow>[] = [
    {
      id: "repository",
      header: "Repository",
      kind: "name",
      grow: true,
      wrap: true,
      exportValue: (image) => image.repository,
      sort: () => 0,
      cell: (image) => (
        <div>
          <span className="text-xs font-medium">
            {image.repository.startsWith("sha256:")
              ? "Unnamed image"
              : image.repository.split("@sha256:")[0]}
          </span>
          <DigestDisclosure
            digest={[
              ...new Set([
                ...Object.values(image.digests),
                ...(image.repository.includes("@sha256:")
                  ? [image.repository.split("@")[1]]
                  : image.repository.startsWith("sha256:")
                    ? [image.repository]
                    : []),
              ]),
            ]
              .filter(Boolean)
              .join("\n")}
          />
        </div>
      ),
    },
    {
      id: "tags",
      header: "Tags",
      kind: "text",
      wrap: true,
      size: 220,
      maxSize: 280,
      cell: (image) => image.tags.join(", ") || "—",
      exportValue: (image) => image.tags.join("; "),
    },
    {
      id: "scanned",
      header: "Scan",
      kind: "status",
      size: 128,
      minSize: 112,
      sort: () => 0,
      exportValue: (image) => (image.scanned ? "scanned" : "not scanned"),
      cell: (image) => (
        <span
          className={
            image.scanned
              ? "rounded px-1.5 py-0.5 text-micro font-medium bg-[color-mix(in_oklab,var(--color-severity-low)_16%,transparent)] text-[color:var(--color-severity-low)]"
              : "rounded px-1.5 py-0.5 text-micro font-medium bg-muted text-muted-foreground"
          }
        >
          {image.scanned ? "scanned" : "not scanned"}
        </span>
      ),
    },
    {
      id: "vulnerabilities",
      header: "Vulnerabilities",
      kind: "count",
      numeric: true,
      size: 160,
      minSize: 140,
      sort: () => 0,
      exportValue: (image) => `critical=${image.critical}; high=${image.high}`,
      cell: (image) =>
        image.critical + image.high === 0 ? (
          <span className="text-micro text-muted-foreground">
            {image.scanned ? "no crit/high" : "—"}
          </span>
        ) : (
          <span className="flex items-center justify-end gap-1">
            {image.critical > 0 && (
              <span
                className="rounded px-1.5 py-0.5 text-micro text-mono font-semibold text-white"
                style={{ background: "var(--color-severity-critical)" }}
              >
                {image.critical}C
              </span>
            )}
            {image.high > 0 && (
              <span
                className="rounded px-1.5 py-0.5 text-micro text-mono font-semibold text-white"
                style={{ background: "var(--color-severity-high)" }}
              >
                {image.high}H
              </span>
            )}
          </span>
        ),
    },
    {
      id: "findings",
      header: "Findings",
      kind: "count",
      numeric: true,
      sort: () => 0,
      exportValue: (image) => image.finding_count,
      cell: (image) => (image.scanned ? image.finding_count : "—"),
    },
    {
      id: "pushed",
      header: "Last pushed",
      kind: "age",
      minSize: 144,
      exportValue: (image) => image.last_pushed_at ?? "",
      cell: (image) =>
        image.last_pushed_at ? fmtRelative(image.last_pushed_at) : "—",
    },
    {
      id: "last_scanned",
      header: "Last scanned",
      kind: "age",
      minSize: 144,
      sort: () => 0,
      exportValue: (image) => image.last_scanned_at ?? "",
      cell: (image) =>
        image.last_scanned_at ? fmtRelative(image.last_scanned_at) : "—",
    },
    {
      id: "last_seen",
      header: "Last discovered",
      kind: "age",
      minSize: 144,
      sort: () => 0,
      exportValue: (image) => image.last_seen_at,
      cell: (image) =>
        image.last_seen_at ? fmtRelative(image.last_seen_at) : "—",
    },
  ];
  if (!scope.ready)
    return (
      <div className="space-y-4">
        <PageHeader title="Registry images" />
        <InventoryScopeState scope={scope} />
      </div>
    );
  return (
    <div className="space-y-4">
      <PageHeader
        backLink={
          <a
            href={`/clusters/${encodeURIComponent(scope.clusterId!)}/registries`}
            className="inline-flex items-center gap-1 hover:text-foreground"
          >
            <ChevronLeft className="h-3.5 w-3.5" />
            Registries
          </a>
        }
        title={registryReady ? reg.data.name : "Registry images"}
        description="Organization-wide repositories discovered in this registry. Scan evidence uses the latest organization-wide result for each repository."
        actions={
          <Button
            variant="outline"
            disabled={reg.isFetching || imgs.isFetching}
            onClick={() => {
              void reg.refetch();
              if (registryReady) void imgs.refetch();
            }}
          >
            Refresh
          </Button>
        }
      />
      <VerdictBanner
        status={
          unavailable ||
          (summary?.unscanned ?? 0) > 0 ||
          (summary?.critical ?? 0) + (summary?.high ?? 0) > 0
            ? "degraded"
            : "info"
        }
        title={
          unavailable
            ? "Registry inventory could not be loaded"
            : !ready
              ? "Loading registry images"
              : summary!.total === 0
                ? "No repositories match"
                : summary!.unscanned > 0
                  ? "Some matching repositories have no scan evidence"
                  : summary!.critical + summary!.high > 0
                    ? "Image vulnerabilities need attention"
                    : "No recorded critical or high findings"
        }
        detail="Counts cover every matching repository; scan evidence does not establish coverage for every tag or digest."
      />
      <StatGrid>
        <StatCard
          label="Matching repositories"
          value={summary?.total ?? "—"}
          icon={<Boxes className="h-3.5 w-3.5" />}
        />
        <StatCard
          label="With scan evidence"
          value={summary?.scanned ?? "—"}
          hint={
            summary ? `${summary.unscanned} without scan evidence` : undefined
          }
        />
        <StatCard
          label="Critical"
          value={summary?.critical ?? "—"}
          tone={summary?.critical ? "critical" : "neutral"}
        />
        <StatCard
          label="High"
          value={summary?.high ?? "—"}
          tone={summary?.high ? "high" : "neutral"}
        />
      </StatGrid>
      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-card p-3">
        <label className="min-w-0 flex-1 text-xs">
          Repository
          <input
            value={route.query}
            onChange={(event) => route.setQuery(event.target.value)}
            placeholder="Search repository…"
            aria-label="Search registry repositories"
            className="block w-full min-w-0 rounded-md border border-border bg-background px-3 py-2 text-sm"
          />
        </label>
        <label className="text-xs">
          Scan evidence
          <Select
            aria-label="Registry scan status"
            value={scanStatus}
            onChange={(event) =>
              route.update({
                scan_status:
                  event.target.value === "all" ? null : event.target.value,
              })
            }
            className="block rounded-md border border-border bg-background p-2 text-sm"
          >
            <option value="all">Any status</option>
            <option value="scanned">Scanned</option>
            <option value="unscanned">Not scanned</option>
          </Select>
        </label>
        <label className="text-xs">
          Severity
          <Select
            aria-label="Registry image severity"
            value={severity}
            onChange={(event) =>
              route.update({
                severity:
                  event.target.value === "all" ? null : event.target.value,
              })
            }
            className="block rounded-md border border-border bg-background p-2 text-sm"
          >
            <option value="all">Any severity</option>
            <option value="critical">Critical present</option>
            <option value="high">High present</option>
            <option value="none">No critical/high in scan</option>
          </Select>
        </label>
        <Button
          variant="outline"
          onClick={() =>
            route.update({
              q: null,
              scan_status: null,
              severity: null,
              sort: null,
              order: null,
            })
          }
        >
          Reset filters
        </Button>
        <ScanInventoryExport
          context={JSON.stringify([scope.owner, regId, filters])}
          disabled={!ready || !summary?.total}
          download={shouldDownload => registries.imagesCSV(regId!, filters, shouldDownload)}
        />
      </div>
      {!registryReady ? (
        reg.isError ? (
          <p role="alert">
            Image inventory is unavailable.{" "}
            <Button onClick={() => void reg.refetch()}>Retry registry</Button>
          </p>
        ) : (
          <p>Loading registry…</p>
        )
      ) : !ready ? (
        <InventoryLoadState
          label="Registry images"
          query={imgs}
          invalid={invalid}
          debouncing={route.debouncing}
        />
      ) : (
        <>
          <DataTable
            rows={rows}
            columns={columns}
            rowKey={(image) => image.id}
            pagination={false}
            preferencesKey="registry-images"
            manualSorting
            sort={{ id: sort, dir: order as "asc" | "desc" }}
            onSortChange={(value) =>
              route.update({
                sort: value?.id ?? "findings",
                order: value?.dir ?? "desc",
              })
            }
            exportFileName={`registry-images-page-${route.page + 1}`}
            exportLabel="Export this page CSV"
            emptyState={
              <EmptyState
                title={
                  route.page
                    ? "No images on this page"
                    : "No matching repositories"
                }
                hint="Change filters or return to the first page."
              />
            }
          />
          <p className="text-xs text-muted-foreground">
            Showing {rows.length ? route.offset + 1 : 0}–
            {rows.length ? route.offset + rows.length : 0} of {imgs.data.total}{" "}
            matching repositories. Matching CSV covers up to 100,000; page CSV
            follows visible columns.
          </p>
          {rows.length > 0 && (
            <Pager
              page={route.page}
              pageSize={100}
              total={imgs.data.total}
              hasMore={imgs.data.has_more}
              rowsOnPage={rows.length}
              onPage={route.setPage}
            />
          )}
          {!rows.length && route.page > 0 && (
            <Button onClick={() => route.setPage(0)}>First page</Button>
          )}
        </>
      )}
    </div>
  );
}
