import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import {
  api,
  cve as cveApi,
  type CVEAffectedInventoryRows,
  type CVEAffectedInventoryView,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/ui/data-table";
import { KevBadge, EpssBadge } from "@/components/ui/kev-badge";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { Button } from "@/components/ui/button";
import { Pager } from "@/components/ui/pager";
import { ErrorState, LoadingState } from "@/components/ui/states";
import {
  entityDetailError,
  useEntityClusterScope,
} from "./entity-detail-scope";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { useDebounced } from "@/hooks/useDebounced";
import {
  affectedInventoryValid,
  affectedSorts,
} from "@/lib/cve-affected-inventory";
import { ScanInventoryExport } from "./inventory-workspace";
import { Select } from "@/components/ui/form";

interface CVEDetail {
  cve_id: string;
  title?: string;
  description: string;
  cvss_base?: number;
  kev_listed: boolean;
  epss_probability?: number;
  aliases: string[];
}
const WORKSPACES = [
  "images",
  "workloads",
  "clusters",
  "packages",
  "details",
  "remediation",
];
type AffectedRow = CVEAffectedInventoryRows[CVEAffectedInventoryView];
export function CVEDetailPage() {
  const { id, cveId } = useParams({ strict: false });
  const scoped = cveId !== undefined;
  const scope = useEntityClusterScope(scoped);
  const clusterId = scoped ? scope.clusterId : undefined;
  const cveKey = (cveId ?? id ?? "").trim().toUpperCase();
  const identity = useTablePreferencesIdentity();
  const owner = identity ? `${identity.org_id}:${identity.user_id}` : undefined;
  const [requestedTab, setTab] = useTabParam("tab", "images");
  const tab = WORKSPACES.includes(requestedTab) ? requestedTab : "images";
  const isInventory = ["images", "workloads", "clusters", "packages"].includes(
    tab,
  );
  const view = (isInventory ? tab : "images") as CVEAffectedInventoryView;
  const [params, setParams] = useRouteSearchParams();
  const key = (field: string) => `${view}_${field}`;
  const search = params.get(key("q")) ?? "";
  const debounced = useDebounced(search, 250);
  const namespace = params.get(key("namespace")) ?? "";
  const severity = params.get(key("severity")) ?? "all";
  const sort =
    params.get(key("sort")) ?? (view === "clusters" ? "workloads" : "risk");
  const order = params.get(key("order")) ?? "desc";
  const rawPage = Number(params.get(key("page")) ?? "1");
  const page = Number.isSafeInteger(rawPage) && rawPage > 0 ? rawPage - 1 : 0;
  const invalid =
    !WORKSPACES.includes(requestedTab) ||
    !affectedSorts[view].includes(sort) ||
    !["asc", "desc"].includes(order) ||
    !["all", "critical", "high", "medium", "low", "info"].includes(severity) ||
    !Number.isSafeInteger(rawPage) ||
    rawPage < 1 ||
    rawPage > 10000;
  const update = (
    values: Record<string, string | null>,
    resetPage = true,
    replace = false,
  ) =>
    setParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (!WORKSPACES.includes(requestedTab)) next.set("tab", "images");
        for (const [field, value] of Object.entries(values)) {
          if (value === null || value === "") next.delete(key(field));
          else next.set(key(field), value);
        }
        if (resetPage) next.delete(key("page"));
        return next;
      },
      { replace },
    );
  const request = {
    cluster_id: clusterId,
    q: debounced.trim() || undefined,
    namespace: namespace.trim() || undefined,
    severity: severity === "all" ? undefined : severity,
    sort,
    order: order as "asc" | "desc",
    limit: 100,
    offset: page * 100,
  };
  const cveQ = useQuery({
    queryKey: ["cve-detail", owner, clusterId ?? "organization", cveKey],
    queryFn: async () => {
      const { data } = await api.get<CVEDetail>(
        `/cve/${encodeURIComponent(cveKey)}`,
      );
      if (
        typeof data.cve_id !== "string" ||
        data.cve_id.toUpperCase() !== cveKey ||
        !Array.isArray(data.aliases)
      )
        throw new Error("CVE metadata does not match the requested CVE ID.");
      return data;
    },
    enabled: scope.ready && !!owner && !!cveKey,
  });
  const relatedQ = useQuery({
    queryKey: [
      "cve-affected",
      owner,
      cveKey,
      clusterId ?? "organization",
      view,
      request,
    ],
    queryFn: async () => {
      const data = await cveApi.affectedInventory(cveKey, view, request);
      if (!affectedInventoryValid(data, cveKey, view, request))
        throw new Error(
          "Affected evidence does not match the requested CVE and cluster scope, filters or page.",
        );
      return data;
    },
    enabled:
      scope.ready &&
      !!owner &&
      !!cveKey &&
      cveQ.isSuccess &&
      isInventory &&
      !invalid &&
      search === debounced,
  });
  const header = (
    <PageHeader
      title={cveKey || "CVE"}
      mono
    />
  );
  if (!scope.ready)
    return (
      <div className="space-y-4">
        {header}
        {scope.loading ? (
          <LoadingState label="Resolving CVE evidence cluster…" />
        ) : (
          <ErrorState
            title="The requested CVE cluster could not be resolved."
            error={scope.error}
            action={<Button onClick={scope.retry}>Retry cluster</Button>}
          />
        )}
      </div>
    );
  if (!owner)
    return (
      <div className="space-y-4">
        {header}
        <LoadingState label="Resolving organization…" />
      </div>
    );
  if (!cveKey)
    return (
      <div className="space-y-4">
        {header}
        <ErrorState title="An exact CVE ID is required." />
      </div>
    );
  if (cveQ.isError)
    return (
      <div className="space-y-4">
        {header}
        <VerdictBanner
          status="degraded"
          title="CVE intelligence is unavailable"
        />
        <ErrorState
          title="CVE metadata could not be loaded or refreshed."
          error={entityDetailError(cveQ.error)}
          action={
            <Button onClick={() => void cveQ.refetch()}>Retry CVE</Button>
          }
        />
      </div>
    );
  if (
    cveQ.data &&
    (typeof cveQ.data.cve_id !== "string" ||
      cveQ.data.cve_id.toUpperCase() !== cveKey ||
      !Array.isArray(cveQ.data.aliases))
  )
    return (
      <div className="space-y-4">
        {header}
        <ErrorState title="CVE metadata does not match the requested CVE ID." />
      </div>
    );
  if (!cveQ.isSuccess)
    return (
      <div className="space-y-4">
        {header}
        <LoadingState label="Loading CVE intelligence…" />
      </div>
    );
  const cve = cveQ.data;
  const matches = affectedInventoryValid(relatedQ.data, cveKey, view, request);
  const affectedError =
    isInventory &&
    (invalid || relatedQ.isError || (!!relatedQ.data && !matches));
  const ready =
    isInventory &&
    matches &&
    relatedQ.isSuccess &&
    relatedQ.fetchStatus === "idle" &&
    cveQ.fetchStatus === "idle" &&
    search === debounced &&
    !invalid;
  const data = ready ? relatedQ.data : undefined;
  const summary = data?.summary;
  const cohortLabels = {
    images: "image scans",
    workloads: "workload associations",
    clusters: "clusters",
    packages: "package finding instances",
  };
  const sourceState = affectedError ? (
    <ErrorState
      title="Affected evidence could not be loaded or refreshed. Previous affected rows are hidden."
      error={
        invalid
          ? "Invalid affected inventory URL filters."
          : !matches && relatedQ.data
            ? "Affected evidence does not match the requested CVE and cluster scope, filters or page."
            : entityDetailError(relatedQ.error)
      }
      action={
        <Button onClick={() => void relatedQ.refetch()}>
          Retry affected evidence
        </Button>
      }
    />
  ) : !ready ? (
    <LoadingState label="Loading affected evidence…" />
  ) : null;
  const columns = getColumns(view, clusterId);
  const workspace = (
    <section
      className="space-y-3"
      data-testid={
        view === "packages" ? "cve-package-evidence" : `cve-affected-${view}`
      }
    >
      <div className="flex flex-wrap items-end gap-3 rounded-lg border border-border bg-card p-3">
        <label className="min-w-0 flex-1 text-xs">
          Search
          <input
            aria-label="Search affected evidence"
            className="block w-full min-w-0 rounded-md border border-border bg-background px-3 py-2 text-sm"
            value={search}
            onChange={(event) => update({ q: event.target.value }, true, true)}
          />
        </label>
        <label className="text-xs">
          Namespace
          <input
            aria-label="Affected namespace"
            className="block rounded-md border border-border bg-background px-3 py-2 text-sm"
            value={namespace}
            onChange={(event) =>
              update({ namespace: event.target.value }, true, true)
            }
          />
        </label>
        <label className="text-xs">
          Finding severity
          <Select
            aria-label="Affected severity"
            className="block rounded-md border border-border bg-background p-2 text-sm"
            value={severity}
            onChange={(event) =>
              update({
                severity:
                  event.target.value === "all" ? null : event.target.value,
              })
            }
          >
            <option value="all">Any severity</option>
            {["critical", "high", "medium", "low", "info"].map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </Select>
        </label>
        <Button
          variant="outline"
          onClick={() =>
            update({
              q: null,
              namespace: null,
              severity: null,
              sort: null,
              order: null,
            })
          }
        >
          Reset view filters
        </Button>
        <ScanInventoryExport
          context={JSON.stringify([owner, cveKey, view, request])}
          disabled={!ready || !summary?.total}
          download={shouldDownload => {
            const { limit: _limit, offset: _offset, ...filters } = request;
            void _limit;
            void _offset;
            return cveApi.affectedInventoryCSV(cveKey, view, filters, shouldDownload);
          }}
        />
      </div>
      {sourceState ?? (
        <>
          <DataTable
            rows={data!.items}
            columns={columns}
            rowKey={(row) => row.row_id}
            pagination={false}
            preferencesKey={`cve-affected-${view}`}
            defaultHiddenColumnIds={["last_seen"]}
            manualSorting
            sort={{ id: sort, dir: order as "asc" | "desc" }}
            onSortChange={(value) =>
              update({
                sort: value?.id ?? (view === "clusters" ? "workloads" : "risk"),
                order: value?.dir ?? "desc",
              })
            }
            exportFileName={`${cveKey}-${clusterId ?? "organization"}-${view}-page-${page + 1}`}
            exportLabel="Export this page CSV"
            emptyState={
              <p className="p-6 text-sm text-muted-foreground">
                No matching {cohortLabels[view]}.
              </p>
            }
          />
          <p className="text-xs text-muted-foreground">
            Showing {data!.items.length ? page * 100 + 1 : 0}–
            {data!.items.length ? page * 100 + data!.items.length : 0} of{" "}
            {data!.total} matching {cohortLabels[view]}. Matching CSV covers up
            to 100,000 rows.
          </p>
          {data!.items.length > 0 ? (
            <Pager
              page={page}
              pageSize={100}
              total={data!.total}
              hasMore={data!.has_more}
              rowsOnPage={data!.items.length}
              onPage={(next) =>
                update({ page: next ? String(next + 1) : null }, false)
              }
            />
          ) : page > 0 ? (
            <Button onClick={() => update({ page: null }, false)}>
              First page
            </Button>
          ) : null}
        </>
      )}
    </section>
  );
  const scopeLabel = clusterId
    ? `Affected evidence for cluster ${scope.cluster?.name || clusterId}.`
    : "Affected evidence across the organization.";
  return (
    <div
      className="space-y-5"
      data-testid="cve-detail-page"
      data-cluster-id={clusterId ?? ""}
    >
      <PageHeader
        title={cve.cve_id}
        mono
        description={cve.title?.trim() || undefined}
        badges={
          <>
            {cve.kev_listed && <KevBadge />}
            {cve.epss_probability != null && (
              <EpssBadge probability={cve.epss_probability} />
            )}
          </>
        }
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              onClick={() => {
                void cveQ.refetch();
                if (isInventory) void relatedQ.refetch();
              }}
              disabled={cveQ.isFetching || relatedQ.isFetching}
            >
              {cveQ.isFetching || relatedQ.isFetching
                ? "Refreshing…"
                : "Refresh"}
            </Button>
            <Button asChild>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                NVD
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            </Button>
          </div>
        }
      />
      <div data-testid={isInventory ? "cve-detail-stats" : undefined}>
      <VerdictBanner
        status={
          affectedError
            ? "degraded"
            : cve.kev_listed
              ? "critical"
              : summary?.total
                ? "degraded"
                : "info"
        }
        title={
          affectedError
            ? "Affected evidence is unavailable"
            : cve.kev_listed
              ? "This CVE is listed as known exploited"
              : isInventory && !ready
                ? "Affected evidence is loading"
                : summary
                  ? `${summary.total.toLocaleString()} matching ${cohortLabels[view]}`
                  : "Vulnerability intelligence is available"
        }
        numbers={isInventory ? [
          { label: `matching ${cohortLabels[view]}`, value: summary?.total ?? "—" },
          { label: "finding instances", value: summary?.finding_count ?? "—" },
          { label: "max risk", value: summary?.max_risk_score ?? "—" },
          {
            label: view === "workloads" ? "clusters" : view === "clusters" ? "workload associations" : "image scans",
            value: summary?.[view === "workloads" ? "cluster_count" : view === "clusters" ? "workload_count" : "image_count"] ?? "—",
          },
        ] : undefined}
        detail={`${scopeLabel} Intelligence metadata is global. Metrics cover every match in the selected view. Image associations use digest, reference or repository/tag matches; workload and cluster finding totals repeat findings across distinct associations. Absence does not establish scan coverage.`}
      />
      </div>
      {isInventory ? null : (
        <StatGrid>
          <StatCard label="CVSS base" value={cve.cvss_base ?? "Not reported"} />
          <StatCard
            label="Known exploited"
            value={cve.kev_listed ? "Listed" : "Not listed"}
            valueKind="text"
          />
          <StatCard
            label="EPSS probability"
            value={
              cve.epss_probability == null
                ? "Not reported"
                : `${(cve.epss_probability * 100).toFixed(2)}%`
            }
            valueKind="text"
          />
        </StatGrid>
      )}
      {(cveQ.isFetching || relatedQ.isFetching) && (
        <p role="status" className="text-sm text-muted-foreground">
          Refreshing CVE evidence…
        </p>
      )}
      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          ...["images", "workloads", "clusters", "packages"].map((value) => ({
            value,
            label:
              value === "packages" ? "Package evidence" : `Affected ${value}`,
            content: value === view ? workspace : null,
          })),
          {
            value: "details",
            label: "Intelligence",
            content: (
              <section className="space-y-3" data-testid="cve-intelligence">
                <h2 className="text-sm font-semibold">
                  Vulnerability intelligence
                </h2>
                <p>{cve.description || "No description reported."}</p>
                <p className="text-xs text-muted-foreground">
                  Aliases: {cve.aliases.join(", ") || "None reported"}. EPSS
                  estimates exploitation in the wild within 30 days; it does not
                  describe observed cluster activity.
                </p>
                {cve.kev_listed && (
                  <a
                    href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm underline"
                  >
                    CISA known exploited catalog
                  </a>
                )}
              </section>
            ),
          },
          {
            value: "remediation",
            label: "Remediation guidance",
            content: (
              <section className="space-y-3">
                <h2 className="text-sm font-semibold">
                  Review remediation evidence
                </h2>
                <p className="text-sm">
                  Review fixed versions in Package evidence, then inspect the
                  exact image or workload before choosing an update. A missing
                  fixed version means the scan has no fix version to report.
                </p>
                <Button onClick={() => setTab("packages")}>
                  Review package evidence
                </Button>
              </section>
            ),
          },
        ]}
      />
    </div>
  );
}

function getColumns(
  view: CVEAffectedInventoryView,
  clusterID?: string,
): Column<AffectedRow>[] {
  const count = <T,>(
    id: string,
    header: string,
    value: (item: T) => number,
  ): Column<T> => ({
    id,
    header,
    kind: "count",
    sort: () => 0,
    cell: value,
    exportValue: value,
  });
  const lastSeen = <T extends { last_seen_at: string }>(): Column<T> => ({
    id: "last_seen",
    header: "Last seen",
    kind: "date",
    sort: () => 0,
    cell: (item) => date(item.last_seen_at),
    exportValue: (item) => item.last_seen_at,
  });
  if (view === "images")
    return [
      {
        id: "image",
        header: "Image",
        kind: "name",
        size: 320,
        minSize: 260,
        wrap: true,
        grow: true,
        sort: () => 0,
        exportValue: imageName,
        cell: (item) => (
          <div>
            {clusterID ? (
              <a
                href={`/clusters/${encodeURIComponent(clusterID)}/images/${encodeURIComponent(item.image_scan_result_id)}`}
                className="hover:underline"
              >
                <ImageName image={item} />
              </a>
            ) : (
              <ImageName image={item} />
            )}
            <DigestDisclosure digest={item.image_digest} />
          </div>
        ),
      },
      {
        id: "platform",
        header: "Platform",
        kind: "text",
        size: 128,
        minSize: 112,
        cell: (item) => item.platform || "Not reported",
        exportValue: (item) => item.platform ?? "",
      },
      {
        id: "scanner",
        header: "Scanner profile",
        kind: "text",
        size: 160,
        minSize: 128,
        wrap: true,
        cell: (item) => item.scanner_profile,
        exportValue: (item) => item.scanner_profile,
      },
      count("findings", "Finding instances", (item) => item.finding_count),
      count("risk", "Max risk", (item) => item.max_risk_score),
      {
        id: "scanned",
        header: "Last scanned",
        kind: "date",
        sort: () => 0,
        cell: (item) => date(item.last_scanned_at),
        exportValue: (item) => item.last_scanned_at,
      },
      lastSeen<CVEAffectedInventoryRows["images"]>(),
    ] as Column<CVEAffectedInventoryRows["images"]>[] as Column<AffectedRow>[];
  if (view === "workloads")
    return [
      {
        id: "name",
        header: "Workload",
        kind: "name",
        size: 300,
        minSize: 260,
        wrap: true,
        grow: true,
        sort: () => 0,
        cell: (item) => (
          <a
            href={`/clusters/${encodeURIComponent(item.cluster_id)}/deployments/${encodeURIComponent(item.deployment_id)}`}
            className="hover:underline"
          >
            {item.namespace}/{item.name}
            {item.workload_id !== `${item.namespace}/${item.name}` && (
              <span className="block text-xs text-muted-foreground">
                {item.workload_id}
              </span>
            )}
          </a>
        ),
        exportValue: (item) =>
          `${item.namespace}/${item.name} (workload: ${item.workload_id})`,
      },
      {
        id: "cluster",
        header: "Cluster",
        kind: "text",
        wrap: true,
        sort: () => 0,
        cell: (item) => item.cluster_name || item.cluster_id,
        exportValue: (item) => item.cluster_name || item.cluster_id,
      },
      {
        id: "kind",
        header: "Kind",
        kind: "status",
        sort: () => 0,
        cell: (item) => item.kind,
        exportValue: (item) => item.kind,
      },
      {
        id: "image",
        header: "Image evidence",
        kind: "name",
        size: 300,
        minSize: 260,
        wrap: true,
        grow: true,
        cell: (item) => (
          <div>
            {item.image_evidence.map((image) => (
              <div key={JSON.stringify(image)}>
                <ImageName image={image} />
                <DigestDisclosure digest={image.image_digest} />
              </div>
            ))}
          </div>
        ),
        exportValue: (item) => JSON.stringify(item.image_evidence),
      },
      count("findings", "Finding instances", (item) => item.finding_count),
      count("risk", "Max risk", (item) => item.max_risk_score),
      lastSeen<CVEAffectedInventoryRows["workloads"]>(),
    ] as Column<
      CVEAffectedInventoryRows["workloads"]
    >[] as Column<AffectedRow>[];
  if (view === "clusters")
    return [
      {
        id: "name",
        header: "Cluster",
        kind: "name",
        wrap: true,
        grow: true,
        sort: () => 0,
        cell: (item) => (
          <a
            href={`/clusters/${encodeURIComponent(item.cluster_id)}/dashboard`}
            className="hover:underline"
          >
            {item.name || item.cluster_id}
          </a>
        ),
        exportValue: (item) => item.name || item.cluster_id,
      },
      count(
        "workloads",
        "Workload associations",
        (item) => item.workload_count,
      ),
      count("findings", "Finding instances", (item) => item.finding_count),
      count("risk", "Max risk", (item) => item.max_risk_score),
    ] as Column<
      CVEAffectedInventoryRows["clusters"]
    >[] as Column<AffectedRow>[];
  return [
    {
      id: "package",
      header: "Package",
      kind: "name",
      size: 240,
      minSize: 200,
      wrap: true,
      grow: true,
      sort: () => 0,
      cell: (item) => item.package_name || "Not reported",
      exportValue: (item) => item.package_name ?? "",
    },
    {
      id: "image",
      header: "Image scan",
      kind: "name",
      size: 300,
      minSize: 260,
      wrap: true,
      grow: true,
      sort: () => 0,
      cell: (item) => (
        <div>
          <ImageName image={item} />
          <DigestDisclosure digest={item.image_digest} />
        </div>
      ),
      exportValue: (item) => item.image_ref,
    },
    {
      id: "version",
      header: "Version",
      kind: "version",
      wrap: true,
      sort: () => 0,
      cell: (item) => item.package_version || "Not reported",
      exportValue: (item) => item.package_version ?? "",
    },
    {
      id: "fixed",
      header: "Fixed version",
      kind: "version",
      wrap: true,
      sort: () => 0,
      cell: (item) => item.fixed_version || "No fix reported",
      exportValue: (item) => item.fixed_version ?? "",
    },
    {
      id: "severity",
      header: "Severity",
      kind: "status",
      sort: () => 0,
      cell: (item) => item.severity,
      exportValue: (item) => item.severity,
    },
    count("risk", "Risk", (item) => item.risk_score),
    {
      id: "finding",
      header: "Scan finding ID",
      kind: "id",
      wrap: true,
      cell: (item) => item.finding_id,
      exportValue: (item) => item.finding_id,
    },
    lastSeen<CVEAffectedInventoryRows["packages"]>(),
  ] as Column<CVEAffectedInventoryRows["packages"]>[] as Column<AffectedRow>[];
}
function ImageName({ image }: { image: Parameters<typeof imageName>[0] }) {
  const name = imageName(image);
  return (
    <span className="line-clamp-2 break-all" title={name}>
      {name}
    </span>
  );
}
function imageName(image: {
  image_repository?: string;
  image_tag?: string;
  image_ref?: string;
}) {
  const ref = image.image_repository
    ? image.image_tag
      ? `${image.image_repository}:${image.image_tag}`
      : image.image_repository
    : image.image_ref;
  return !ref || ref.startsWith("sha256:")
    ? "Unnamed image"
    : ref.split("@sha256:")[0];
}
function date(value: string) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? "Not reported"
    : parsed.toLocaleString();
}
