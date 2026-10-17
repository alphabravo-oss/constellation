
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { Database, Pencil, Plus, ShieldQuestion } from "lucide-react";
import { toast } from "sonner";

import { connectorCoverage } from "@/api/client";
import type { ConnectorCoverageOverview } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner, type VerdictStatus } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { ScanJobsInventory } from "./ScanJobsInventory";

type CloudConnector = ConnectorCoverageOverview["cloud_connectors"][number];

const cloudColumns: Column<CloudConnector>[] = [
  {
    id: "connector", exportValue: c => c.name,
    header: "Connector", kind: "name", wrap: true,
    cell: (c) => (
      <>
        <div className="font-medium">{c.name}</div>
        <div className="mt-1 text-xs text-muted-foreground">{c.provider} · {c.auth_mode}</div>
      </>
    ),
  },
  { id: "account", exportValue: c => c.account, header: "Account", kind: "text", code: true, wrap: true, size: 192, minSize: 144, maxSize: 280, cell: (c) => <span className="font-mono text-xs">{c.account}</span> },
  { id: "regions", exportValue: c => c.regions.join(", "), header: "Regions", kind: "text", wrap: true, size: 192, minSize: 144, maxSize: 280, cell: (c) => <span className="text-xs">{c.regions.join(", ")}</span> },
  { id: "coverage", exportValue: c => `${c.resources_assessed}/${c.resources_observed}`, header: "Coverage", kind: "count", size: 128, minSize: 112, maxSize: 160, cell: (c) => <span className="text-xs">{c.resources_assessed}/{c.resources_observed}</span> },
  { id: "findings", exportValue: c => c.findings_open, header: "Findings", kind: "count", cell: (c) => <span className="text-xs">{c.findings_open}</span> },
  { id: "status", exportValue: c => c.status, header: "Status", kind: "status", cell: (c) => <Status value={c.status} /> },
];

export function ConnectorCoveragePage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const q = useQuery({ queryKey: ["connector-coverage", owner], queryFn: connectorCoverage.overview });
  const [tab, setTab] = useTabParam("tab", "registries");
  const [params, setParams] = useRouteSearchParams();
  const cacheScannerID = params.get("scanner") ?? "";
  const setCacheScannerID = (id: string) => setParams(current => { const next = new URLSearchParams(current); if (id) next.set("scanner", id); else next.delete("scanner"); return next; });
  const scannerKnown = !q.isError && !q.isFetching && Boolean(q.data?.scanner_pools.some(pool => pool.scanners?.some(scanner => (scanner.instance_id || scanner.hostname) === cacheScannerID)));
  const cacheData = useQuery({
    queryKey: ["scanner-cache-data", owner, cacheScannerID],
    queryFn: () => connectorCoverage.cacheData(cacheScannerID),
    enabled: Boolean(cacheScannerID) && scannerKnown,
  });
  const cacheStat = useQuery({
    queryKey: ["scanner-cache-stat", owner, cacheScannerID],
    queryFn: () => connectorCoverage.cacheStat(cacheScannerID),
    enabled: Boolean(cacheScannerID) && scannerKnown,
  });

  const cacheRecords = !cacheData.isError && !cacheData.isFetching && cacheData.data?.scanner_id === cacheScannerID ? cacheData.data : undefined;
  const invalidateCoverage = () => queryClient.invalidateQueries({ queryKey: ["connector-coverage", owner] });

  const preview = useMutation({ mutationFn: ({ id, type }: { id: string; type: string }) => connectorCoverage.testPreview(id, type) });
  const testConfig = useMutation({
    mutationFn: (id: string) => connectorCoverage.testConfig(id),
    onSuccess: () => {
      toast.success("Connector health updated");
      void invalidateCoverage();
    },
    onError: () => toast.error("Unable to test connector"),
  });

  if (q.isPending || q.isError || q.isFetching || !q.data) return <PageContainer><PageHeader title="Registry & Cloud Connectors" description="Organization-wide connector coverage and scan evidence." />{q.isError ? <ErrorState title="Connector coverage is unavailable or could not be refreshed." action={<Button onClick={() => void q.refetch()}>Retry coverage</Button>} /> : <LoadingState label="Loading connector coverage…" />}</PageContainer>;

  const data = q.data;
  const summary = data?.summary;
  const registryConnectors = data?.registry_connectors ?? [];
  const cloudConnectors = data?.cloud_connectors ?? [];
  const configs = data?.configs ?? [];

  // Verdict: is every connector ready and everything scanned?
  const registriesReady = (summary?.registry_connectors_ready ?? 0) >= (summary?.registry_connectors_total ?? 0);
  const cloudsReady = (summary?.cloud_connectors_ready ?? 0) >= (summary?.cloud_connectors_total ?? 0);
  const unscanned = summary?.images_unscanned ?? 0;
  const rotationsDue = summary?.credential_rotations_due ?? 0;
  const connectorsDegraded = !registriesReady || !cloudsReady;
  const noConnectors = (summary?.registry_connectors_total ?? 0) + (summary?.cloud_connectors_total ?? 0) === 0;
  const verdictStatus: VerdictStatus = noConnectors ? "info" : connectorsDegraded ? "degraded" : unscanned > 0 || rotationsDue > 0 ? "info" : "ok";
  const verdictTitle = noConnectors ? "No connectors configured" : connectorsDegraded
    ? "Some connectors need attention"
    : unscanned > 0
      ? "All connectors ready — images still awaiting scan"
      : "All connectors healthy and covered";
  const verdictDetail = `${summary?.registry_connectors_ready ?? 0}/${summary?.registry_connectors_total ?? 0} registries and ${summary?.cloud_connectors_ready ?? 0}/${summary?.cloud_connectors_total ?? 0} cloud accounts ready · ${unscanned} unscanned image${unscanned === 1 ? "" : "s"}${rotationsDue > 0 ? ` · ${rotationsDue} credential rotation${rotationsDue === 1 ? "" : "s"} due` : ""}`;

  const addButton = (label: string, onClick: () => void) => (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-2.5 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90"
    >
      <Plus className="h-3.5 w-3.5" aria-hidden /> {label}
    </button>
  );

  const tabs = [
    {
      value: "registries",
      label: "Registries",
      count: registryConnectors.length,
      content: (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Registry connectors</h2>
            {addButton("Add registry", () => navigate({ href: "/settings/connectors/new?type=registry" }))}
          </div>

          <section className="grid gap-3 lg:grid-cols-2" data-testid="registry-connectors">
            {registryConnectors.length === 0 && <p className="text-xs text-muted-foreground">No registry connectors yet. Use “Add registry” to connect one.</p>}
            {registryConnectors.map((connector) => (
              <article key={connector.id} className="rounded-lg border border-border bg-card p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold">{connector.name}</h3>
                    <p className="mt-1 text-xs text-muted-foreground">{connector.provider} · {connector.endpoint}</p>
                  </div>
                  <Status value={connector.status} />
                </div>
                <dl className="mt-3 grid grid-cols-2 gap-2 text-xs md:grid-cols-4">
                  <Info label="Repos" value={`${connector.repositories}`} />
                  <Info label="Observed" value={`${connector.images_observed}`} />
                  <Info label="Scanned" value={`${connector.images_scanned}`} />
                  <Info label="Rotation" value={connector.rotation_due_at} />
                </dl>
                <div className="mt-3 flex flex-wrap gap-1">
                  {connector.supported_checks.map((check) => <Badge key={check}>{check}</Badge>)}
                </div>
                <p className="mt-3 text-xs text-muted-foreground">{connector.notes}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    type="button"
                    onClick={() => preview.mutate({ id: connector.id, type: "registry" })}
                    className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent"
                  >
                    <ShieldQuestion className="h-3.5 w-3.5" aria-hidden />
                    Test connection
                  </button>
                  <button
                    type="button"
                    onClick={() => navigate({ href: `/settings/connectors/${connector.id}` })}
                    className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent"
                  >
                    <Pencil className="h-3.5 w-3.5" aria-hidden />
                    Edit
                  </button>
                </div>
              </article>
            ))}
          </section>

          <section className="rounded-lg border border-border bg-card p-4" data-testid="connector-test-preview">
            <h2 className="text-sm font-semibold">Connector test preview</h2>
            <p className="mt-1 text-xs text-muted-foreground">
              Test connection actions are read-only before credentials are saved or scans are started.
            </p>
            {preview.isPending ? <LoadingState label="Loading connector preview…" /> : preview.isError ? <ErrorState title="The connector preview is unavailable." /> : preview.data ? (
              <div className="mt-3 rounded-md bg-muted p-3 text-xs">
                <div className="font-medium">{preview.data.connector_id}</div>
                <p className="mt-1 text-muted-foreground">{preview.data.message}</p>
                <div className="mt-2 flex flex-wrap gap-1">
                  <Badge>secrets: {preview.data.persists_secrets ? "yes" : "no"}</Badge>
                  <Badge>scan: {preview.data.starts_scan ? "yes" : "no"}</Badge>
                  <Badge>rotation: {preview.data.rotates_credential ? "yes" : "no"}</Badge>
                </div>
              </div>
            ) : (
              <p className="mt-3 text-xs text-muted-foreground">Choose Test connection on a registry card.</p>
            )}
          </section>

          <Collapse label="Saved connector metadata">
            <div className="space-y-2" data-testid="saved-connector-configs">
              {configs.length === 0 && <p className="text-xs text-muted-foreground">No saved connector metadata.</p>}
              {configs.map((config) => (
                <article key={`${config.connector_type}-${config.connector_id}`} className="rounded-md bg-muted p-3 text-xs" data-testid="saved-connector-config">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{config.display_name}</span>
                    <div className="flex shrink-0 items-center gap-1" data-testid="connector-config-health">
                      <Status value={config.credential_present ? "saved" : "metadata"} />
                      <Status value={config.last_test_status} />
                    </div>
                  </div>
                  <div className="mt-1 truncate text-muted-foreground">{config.credential_ref || "no credential reference"}</div>
                  <div className="mt-1 text-muted-foreground">owner {config.owner} · cadence {config.scan_cadence}</div>
                  <div className="mt-1 text-muted-foreground" data-testid="connector-config-last-test">
                    last test {config.last_test_at ? formatDateTime(config.last_test_at) : "not tested"}
                  </div>
                  <button
                    type="button"
                    onClick={() => config.id && testConfig.mutate(config.id)}
                    disabled={!config.id || (testConfig.isPending && testConfig.variables === config.id)}
                    className="mt-2 inline-flex items-center gap-1 rounded-md border border-border bg-background px-2.5 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                    data-testid="connector-config-test"
                  >
                    <ShieldQuestion className="h-3.5 w-3.5" aria-hidden />
                    Test saved config
                  </button>
                </article>
              ))}
            </div>
          </Collapse>

          <Collapse label="Enterprise guardrails">
            <div className="space-y-2" data-testid="connector-guardrails">
              {(data?.guardrails ?? []).map((guardrail) => (
                <article key={guardrail.id} className="rounded-md bg-muted p-3 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium">{guardrail.name}</span>
                    <Status value={guardrail.status} />
                  </div>
                  <p className="mt-1 text-muted-foreground">{guardrail.description}</p>
                </article>
              ))}
            </div>
          </Collapse>
        </div>
      ),
    },
    {
      value: "clouds",
      label: "Cloud accounts",
      count: cloudConnectors.length,
      content: (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Cloud accounts</h2>
            {addButton("Add cloud account", () => navigate({ href: "/settings/connectors/new?type=cloud" }))}
          </div>
          <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="cloud-connectors">
            <DataTable<CloudConnector>
              rows={cloudConnectors}
              columns={cloudColumns}
              rowKey={(connector) => connector.id}
              preferencesKey="connector-cloud-accounts" exportFileName="constellation-cloud-connectors" exportLabel="Export loaded accounts CSV"
              emptyState={<div className="p-6 text-sm text-muted-foreground">No cloud accounts connected yet.</div>}
            />
          </div>
        </div>
      ),
    },
    {
      value: "scan-jobs",
      label: "Scan jobs",
      content: (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Scan jobs</h2>
            {addButton("Queue scan", () => navigate({ href: "/settings/connectors/scan/new" }))}
          </div>

          <ScanJobsInventory />

          <Collapse label="Coverage gaps by scope">
            <section className="grid gap-3 lg:grid-cols-3" data-testid="scan-coverage">
              {(data?.scan_coverage ?? []).map((coverage) => (
                <article key={coverage.scope} className="rounded-lg border border-border bg-card p-4">
                  <h3 className="text-sm font-semibold">{coverage.scope}</h3>
                  <dl className="mt-3 grid grid-cols-2 gap-2 text-xs">
                    <Info label="Observed" value={`${coverage.observed}`} />
                    <Info label="Scanned" value={`${coverage.scanned}`} />
                    <Info label="Unscanned" value={`${coverage.unscanned}`} />
                    <Info label="Critical gaps" value={`${coverage.critical_gaps}`} />
                  </dl>
                  <p className="mt-3 text-xs text-muted-foreground">{coverage.recommended_fix}</p>
                </article>
              ))}
            </section>
          </Collapse>
        </div>
      ),
    },
    {
      value: "scanner-cache",
      label: "Scanner cache",
      count: data?.scanner_pools?.length,
      content: (
        <section className="space-y-2" data-testid="scanner-pools">
          <p className="text-xs text-muted-foreground">Scanner worker capacity, layer-cache health, and queue depth. Secondary diagnostics for scan throughput.</p>
          {(data?.scanner_pools ?? []).map((pool) => (
            <article key={pool.id} className="rounded-lg border border-border bg-card p-4 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold">{pool.name}</span>
                <Status value={pool.status} />
              </div>
              <dl className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
                <Info label="Workers" value={`${pool.ready_workers}/${pool.desired_workers}`} />
                <Info label="Active" value={`${pool.active_jobs}`} />
                <Info label="Idle" value={`${pool.idle_capacity}`} />
                <Info label="Queue" value={`${pool.queue_depth}`} />
                <Info label="Stale" value={`${pool.stale_leases}`} />
                <Info label="p95" value={pool.p95_duration} />
                <Info label="Capacity" value={pool.capacity} />
              </dl>
              {pool.scanners && pool.scanners.length > 0 ? (
                <div className="mt-3 overflow-hidden rounded-md border border-border bg-background" data-testid="scanner-workers">
                  <DataTable
                    className="rounded-none border-0"
                    rows={pool.scanners}
                    rowKey={(scanner) => `${scanner.cluster_id ?? "control"}-${scanner.instance_id || scanner.hostname}`}
                    showDensityToggle={false}
                    showColumnChooser={false}
                    columns={[
                      { id: "scanner", header: "Scanner", kind: "name", code: true, cell: (scanner) => scanner.hostname },
                      { id: "cluster", header: "Cluster", kind: "text", size: 140, cell: (scanner) => scanner.cluster_name || scanner.cluster_id?.slice(0, 8) || "-" },
                      { id: "status", header: "Status", kind: "status", cell: (scanner) => <Status value={scanner.status} /> },
                      { id: "jobs", header: "Jobs", kind: "count", cell: (scanner) => `${scanner.active_jobs}/${scanner.max_concurrent || "-"}` },
                      { id: "idle", header: "Idle", kind: "count", cell: (scanner) => scanner.idle_capacity },
                      { id: "vulndb", header: "VulnDB", kind: "text", size: 200, wrap: true, cell: (scanner) => <><Status value={scanner.vulndb_status || "unknown"} />{scanner.vulndb_bundle_version ? <span className="ml-1 font-mono text-muted-foreground">{scanner.vulndb_bundle_version}</span> : null}</> },
                      { id: "cache", header: "Cache", kind: "text", size: 200, wrap: true, cell: (scanner) => { const cache = scannerCacheSummary(scanner.cache_health); return <span title={cache.title}><Status value={cache.status} /><span className="ml-1 text-muted-foreground">{cache.label}</span></span>; } },
                      { id: "actions", header: "", kind: "actions", cell: (scanner) => <button type="button" className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-xs hover:bg-accent" onClick={() => setCacheScannerID(scanner.instance_id || scanner.hostname)} title="Show scanner cache records"><Database className="h-3 w-3" aria-hidden />Cache</button> },
                    ]}
                  />
                </div>
              ) : null}
              {cacheScannerID ? (
                <div className="mt-3 rounded-md border border-border bg-background p-3 text-[11px]" data-testid="scanner-cache-data">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="font-medium">Cache records</div>
                      <div className="text-muted-foreground">
                        {cacheRecords?.hostname ?? cacheScannerID}
                        {cacheRecords?.record_size_bytes ? ` · ${formatBytes(cacheRecords.record_size_bytes)}` : ""}
                        {cacheRecords ? ` · ${cacheRecords.cache_hits} hits / ${cacheRecords.cache_misses} misses` : ""}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="rounded-md border border-border px-2 py-1 text-[10px] hover:bg-accent"
                      onClick={() => setCacheScannerID("")}
                    >
                      Close
                    </button>
                  </div>
                  {!scannerKnown ? <ErrorState title="The selected scanner is unavailable in the loaded organization inventory." /> : cacheData.isFetching || cacheData.isPending ? (
                    <div className="mt-3 text-muted-foreground">Loading cache records...</div>
                  ) : cacheData.isError || cacheRecords?.scanner_id !== cacheScannerID ? (
                    <ErrorState title="Scanner cache records are unavailable." action={<Button onClick={() => void cacheData.refetch()}>Retry cache records</Button>} />
                  ) : (
                    <>
                      {cacheStat.isError || (!cacheStat.isPending && cacheStat.data?.scanner_id !== cacheScannerID) ? <ErrorState title="Scanner cache statistics are unavailable." action={<Button onClick={() => void cacheStat.refetch()}>Retry cache statistics</Button>} /> : !cacheStat.isFetching && cacheStat.data?.caches && cacheStat.data.caches.length > 0 ? (
                        <div className="mt-3 grid gap-2 sm:grid-cols-2">
                          {cacheStat.data.caches.map((cache) => (
                            <div key={cache.name} className="rounded-md bg-muted p-2">
                              <div className="flex items-center justify-between gap-2">
                                <span className="font-mono">{cache.name}</span>
                                <Status value={cache.status || "unknown"} />
                              </div>
                              <div className="mt-1 text-muted-foreground">
                                {cache.record_count ?? 0} records · {formatBytes(cache.record_size_bytes)} · free {formatBytes(cache.free_bytes)}
                                {cache.records_truncated ? " · truncated" : ""}
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : cacheStat.isFetching ? (
                        <div className="mt-3 text-muted-foreground">Loading cache statistics...</div>
                      ) : null}
                      {(cacheRecords?.cache_records ?? []).length === 0 ? (
                        <div className="mt-3 text-muted-foreground">No cache records reported by this scanner.</div>
                      ) : (
                        <div className="mt-3 max-h-56 overflow-y-auto rounded-md border border-border">
                          <DataTable
                            className="rounded-none border-0"
                            rows={cacheRecords?.cache_records ?? []}
                            rowKey={(record) => `${record.cache}-${record.layer}`}
                            showDensityToggle={false}
                            showColumnChooser={false}
                            columns={[
                              { id: "cache", header: "Cache", kind: "id", cell: (record) => record.cache },
                              { id: "record", header: "Record", kind: "name", code: true, cell: (record) => record.layer },
                              { id: "size", header: "Size", kind: "bytes", cell: (record) => formatBytes(record.size) },
                              { id: "refs", header: "Refs", kind: "count", cell: (record) => record.ref_count },
                              { id: "lastRef", header: "Last ref", kind: "date", cell: (record) => record.ref_last ? formatDateTime(record.ref_last) : "-" },
                            ]}
                          />
                        </div>
                      )}
                    </>
                  )}
                </div>
              ) : null}
              {pool.queue_by_target_type && pool.queue_by_target_type.length > 0 ? (
                <div className="mt-3 overflow-hidden rounded-md border border-border bg-background" data-testid="scanner-queue-by-target">
                  <DataTable
                    className="rounded-none border-0"
                    rows={pool.queue_by_target_type}
                    rowKey={(metric) => metric.target_type}
                    showDensityToggle={false}
                    showColumnChooser={false}
                    columns={[
                      { id: "target", header: "Target", kind: "name", code: true, cell: (metric) => metric.target_type },
                      { id: "pending", header: "Pending", kind: "count", cell: (metric) => metric.pending },
                      { id: "delayed", header: "Delayed", kind: "count", cell: (metric) => metric.retry_delayed },
                      { id: "running", header: "Running", kind: "count", cell: (metric) => metric.running },
                      { id: "stale", header: "Stale", kind: "count", cell: (metric) => metric.stale_running },
                      { id: "paused", header: "Paused", kind: "count", cell: (metric) => metric.paused },
                      { id: "canceled", header: "Canceled", kind: "count", cell: (metric) => metric.canceled },
                      { id: "exhausted", header: "Exhausted", kind: "count", cell: (metric) => metric.exhausted },
                      { id: "failed", header: "Failed", kind: "count", cell: (metric) => metric.failed },
                      { id: "oldest", header: "Oldest", kind: "age", numeric: true, cell: (metric) => formatDuration(metric.oldest_pending_seconds) },
                    ]}
                  />
                </div>
              ) : null}
            </article>
          ))}
        </section>
      ),
    },
  ];

  return (
    <PageContainer>
      <PageHeader
        title="Registry & Cloud Connectors"
        description="Connect Constellation to your container registries and cloud accounts so it can discover and scan the images and resources running there."
      />

      <p className="text-xs text-muted-foreground">Organization-wide connector coverage. Registry and cloud evidence is shared across cluster navigation.</p>
      {preview.isError && <ErrorState title="The connector preview failed. Try Test connection again." />}
      {testConfig.isError && <ErrorState title="The saved connector test failed. Retry after reviewing the configuration." />}
      <VerdictBanner status={verdictStatus} title={verdictTitle} detail={verdictDetail} />

      <StatGrid>
        <StatCard label="Registries ready" value={`${summary?.registry_connectors_ready ?? 0}/${summary?.registry_connectors_total ?? 0}`} />
        <StatCard label="Clouds ready" value={`${summary?.cloud_connectors_ready ?? 0}/${summary?.cloud_connectors_total ?? 0}`} />
        <StatCard label="Unscanned images" value={unscanned} tone={unscanned > 0 ? "medium" : "neutral"} />
        <StatCard label="Queued scans" value={summary?.queued_scans ?? 0} />
      </StatGrid>

      {cacheScannerID && !scannerKnown && <ErrorState title="The selected scanner is unavailable in the loaded organization inventory." action={<Button onClick={() => setCacheScannerID("")}>Clear scanner selection</Button>} />}
      <Tabs value={tab} onValueChange={setTab} items={tabs} />
    </PageContainer>
  );
}



function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-muted p-2">
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-medium">{value || "-"}</div>
    </div>
  );
}

function Badge({ children }: { children: ReactNode }) {
  return <span className="rounded-md bg-background px-1.5 py-0.5 text-[10px] text-muted-foreground">{children}</span>;
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function formatDuration(seconds: number) {
  if (!seconds || seconds < 1) return "-";
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const rem = minutes % 60;
  return rem > 0 ? `${hours}h ${rem}m` : `${hours}h`;
}

function formatBytes(bytes?: number) {
  if (!bytes) return "-";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}

function scannerCacheSummary(cacheHealth?: Record<string, { configured?: boolean; writable?: boolean; status?: string; error?: string }>) {
  if (!cacheHealth || Object.keys(cacheHealth).length === 0) {
    return { status: "unknown", label: "not reported", title: "" };
  }
  const configured = Object.entries(cacheHealth).filter(([, item]) => item.configured);
  if (configured.length === 0) {
    return { status: "unknown", label: "not configured", title: "" };
  }
  const bad = configured.filter(([, item]) => item.writable === false || (item.status && item.status !== "ready"));
  if (bad.length > 0) {
    return {
      status: "degraded",
      label: `${bad.length}/${configured.length} bad`,
      title: bad.map(([name, item]) => `${name}: ${item.status ?? item.error ?? "bad"}`).join(", "),
    };
  }
  return { status: "ready", label: `${configured.length} ready`, title: configured.map(([name]) => name).join(", ") };
}

function Status({ value }: { value: string }) {
  const cls = value === "ready" || value === "healthy" || value === "completed" || value === "active" || value === "enforced"
    ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
    : value === "degraded" || value === "queued" || value === "needs-setup" || value === "unhealthy"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : value === "failed"
        ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
        : "bg-muted text-muted-foreground";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`}>{value}</span>;
}
