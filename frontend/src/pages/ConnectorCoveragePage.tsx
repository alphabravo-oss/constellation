import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import type { ReactNode } from "react";
import { Database, Pause, Pencil, Play, Plus, RotateCcw, ShieldQuestion, XCircle } from "lucide-react";
import { toast } from "sonner";

import { connectorCoverage, scanJobs, scanJobsAdmin } from "@/api/client";
import type { ConnectorCoverageOverview, ScanJob } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner, type VerdictStatus } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";

type CloudConnector = ConnectorCoverageOverview["cloud_connectors"][number];

const cloudColumns: Column<CloudConnector>[] = [
  {
    id: "connector",
    header: "Connector",
    cell: (c) => (
      <>
        <div className="font-medium">{c.name}</div>
        <div className="mt-1 text-xs text-muted-foreground">{c.provider} · {c.auth_mode}</div>
      </>
    ),
  },
  { id: "account", header: "Account", cell: (c) => <span className="font-mono text-xs">{c.account}</span> },
  { id: "regions", header: "Regions", cell: (c) => <span className="text-xs">{c.regions.join(", ")}</span> },
  { id: "coverage", header: "Coverage", cell: (c) => <span className="text-xs">{c.resources_assessed}/{c.resources_observed}</span> },
  { id: "findings", header: "Findings", cell: (c) => <span className="text-xs">{c.findings_open}</span> },
  { id: "status", header: "Status", cell: (c) => <Status value={c.status} /> },
];

type ScanJobAction = "pause" | "resume" | "retry" | "cancel";

export function ConnectorCoveragePage() {
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["connector-coverage"], queryFn: connectorCoverage.overview });
  const jobs = useQuery({ queryKey: ["scan-jobs"], queryFn: () => scanJobs.list() });
  const [tab, setTab] = useTabParam("tab", "registries");
  const [cacheScannerID, setCacheScannerID] = useState("");
  const cacheData = useQuery({
    queryKey: ["scanner-cache-data", cacheScannerID],
    queryFn: () => connectorCoverage.cacheData(cacheScannerID),
    enabled: Boolean(cacheScannerID),
  });
  const cacheStat = useQuery({
    queryKey: ["scanner-cache-stat", cacheScannerID],
    queryFn: () => connectorCoverage.cacheStat(cacheScannerID),
    enabled: Boolean(cacheScannerID),
  });

  const invalidateCoverage = () => queryClient.invalidateQueries({ queryKey: ["connector-coverage"] });
  const invalidateJobs = () => queryClient.invalidateQueries({ queryKey: ["scan-jobs"] });

  const preview = useMutation({ mutationFn: ({ id, type }: { id: string; type: string }) => connectorCoverage.testPreview(id, type) });
  const testConfig = useMutation({
    mutationFn: (id: string) => connectorCoverage.testConfig(id),
    onSuccess: () => {
      toast.success("Connector health updated");
      void invalidateCoverage();
    },
    onError: () => toast.error("Unable to test connector"),
  });
  const lifecycle = useMutation({
    mutationFn: ({ action, id }: { action: ScanJobAction; id: string }) => scanJobAction(action, id),
    onSuccess: (_result, variables) => {
      toast.success(scanJobActionLabel(variables.action));
      void invalidateJobs();
      void invalidateCoverage();
    },
    onError: (_error, variables) => toast.error(`Unable to ${variables.action} scan job`),
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading connector coverage...</p>;

  const data = q.data;
  const summary = data?.summary;
  const registryConnectors = data?.registry_connectors ?? [];
  const cloudConnectors = data?.cloud_connectors ?? [];
  const configs = data?.configs ?? [];
  const jobList = jobs.data?.jobs ?? [];

  // Verdict: is every connector ready and everything scanned?
  const registriesReady = (summary?.registry_connectors_ready ?? 0) >= (summary?.registry_connectors_total ?? 0);
  const cloudsReady = (summary?.cloud_connectors_ready ?? 0) >= (summary?.cloud_connectors_total ?? 0);
  const unscanned = summary?.images_unscanned ?? 0;
  const rotationsDue = summary?.credential_rotations_due ?? 0;
  const connectorsDegraded = !registriesReady || !cloudsReady;
  const verdictStatus: VerdictStatus = connectorsDegraded ? "degraded" : unscanned > 0 || rotationsDue > 0 ? "info" : "ok";
  const verdictTitle = connectorsDegraded
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
            {addButton("Add registry", () => navigate("/settings/connectors/new?type=registry"))}
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
                    onClick={() => navigate(`/settings/connectors/${connector.id}`)}
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
            {preview.data ? (
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
            {addButton("Add cloud account", () => navigate("/settings/connectors/new?type=cloud"))}
          </div>
          <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="cloud-connectors">
            <DataTable<CloudConnector>
              rows={cloudConnectors}
              columns={cloudColumns}
              rowKey={(connector) => connector.id}
              emptyState={<div className="p-6 text-sm text-muted-foreground">No cloud accounts connected yet.</div>}
            />
          </div>
        </div>
      ),
    },
    {
      value: "scan-jobs",
      label: "Scan jobs",
      count: jobList.length,
      content: (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Scan jobs</h2>
            {addButton("Queue scan", () => navigate("/settings/connectors/scan/new"))}
          </div>

          <section className="space-y-2" data-testid="recent-scan-jobs">
            {jobList.map((job) => (
              <ScanJobCard
                key={job.id}
                job={job}
                busy={lifecycle.isPending}
                onAction={(action) => lifecycle.mutate({ action, id: job.id })}
              />
            ))}
            {jobList.length === 0 && (data?.recent_jobs ?? []).map((job) => (
              <article key={job.id} className="rounded-md bg-muted p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate font-mono">{job.target_ref}</span>
                  <Status value={job.status} />
                </div>
              </article>
            ))}
            {jobList.length === 0 && (data?.recent_jobs ?? []).length === 0 && (
              <p className="text-xs text-muted-foreground">No scan jobs. Use “Queue scan” to enqueue one.</p>
            )}
          </section>

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
                  <table className="w-full text-[11px]">
                    <thead className="bg-muted/60 text-left text-muted-foreground">
                      <tr>
                        <th className="px-2 py-1.5">Scanner</th>
                        <th className="px-2 py-1.5">Cluster</th>
                        <th className="px-2 py-1.5">Status</th>
                        <th className="px-2 py-1.5 text-right">Jobs</th>
                        <th className="px-2 py-1.5 text-right">Idle</th>
                        <th className="px-2 py-1.5">VulnDB</th>
                        <th className="px-2 py-1.5">Cache</th>
                        <th className="px-2 py-1.5"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {pool.scanners.map((scanner) => {
                        const cache = scannerCacheSummary(scanner.cache_health);
                        const scannerID = scanner.instance_id || scanner.hostname;
                        return (
                          <tr key={`${scanner.cluster_id ?? "control"}-${scannerID}`} className="border-t border-border">
                            <td className="px-2 py-1.5 font-mono">{scanner.hostname}</td>
                            <td className="px-2 py-1.5">{scanner.cluster_name || scanner.cluster_id?.slice(0, 8) || "-"}</td>
                            <td className="px-2 py-1.5"><Status value={scanner.status} /></td>
                            <td className="px-2 py-1.5 text-right font-mono">{scanner.active_jobs}/{scanner.max_concurrent || "-"}</td>
                            <td className="px-2 py-1.5 text-right font-mono">{scanner.idle_capacity}</td>
                            <td className="px-2 py-1.5">
                              <div className="truncate">
                                <Status value={scanner.vulndb_status || "unknown"} />
                                {scanner.vulndb_bundle_version ? <span className="ml-1 font-mono text-muted-foreground">{scanner.vulndb_bundle_version}</span> : null}
                              </div>
                            </td>
                            <td className="px-2 py-1.5">
                              <div className="truncate" title={cache.title}>
                                <Status value={cache.status} />
                                <span className="ml-1 text-muted-foreground">{cache.label}</span>
                              </div>
                            </td>
                            <td className="px-2 py-1.5 text-right">
                              <button
                                type="button"
                                className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-[10px] hover:bg-accent"
                                onClick={() => setCacheScannerID(scannerID)}
                                title="Show scanner cache records"
                              >
                                <Database className="h-3 w-3" aria-hidden />
                                Cache
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              ) : null}
              {cacheScannerID ? (
                <div className="mt-3 rounded-md border border-border bg-background p-3 text-[11px]" data-testid="scanner-cache-data">
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="font-medium">Cache records</div>
                      <div className="text-muted-foreground">
                        {cacheData.data?.hostname ?? cacheScannerID}
                        {cacheData.data?.record_size_bytes ? ` · ${formatBytes(cacheData.data.record_size_bytes)}` : ""}
                        {cacheData.data ? ` · ${cacheData.data.cache_hits} hits / ${cacheData.data.cache_misses} misses` : ""}
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
                  {cacheData.isFetching ? (
                    <div className="mt-3 text-muted-foreground">Loading cache records...</div>
                  ) : cacheData.isError ? (
                    <div className="mt-3 text-[color:var(--color-status-error)]">Unable to load scanner cache records.</div>
                  ) : (
                    <>
                      {cacheStat.data?.caches && cacheStat.data.caches.length > 0 ? (
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
                      {(cacheData.data?.cache_records ?? []).length === 0 ? (
                        <div className="mt-3 text-muted-foreground">No cache records reported by this scanner.</div>
                      ) : (
                        <div className="mt-3 max-h-56 overflow-auto rounded-md border border-border">
                          <table className="w-full text-[11px]">
                            <thead className="bg-muted/60 text-left text-muted-foreground">
                              <tr>
                                <th className="px-2 py-1.5">Cache</th>
                                <th className="px-2 py-1.5">Record</th>
                                <th className="px-2 py-1.5 text-right">Size</th>
                                <th className="px-2 py-1.5 text-right">Refs</th>
                                <th className="px-2 py-1.5">Last ref</th>
                              </tr>
                            </thead>
                            <tbody>
                              {cacheData.data?.cache_records.map((record) => (
                                <tr key={`${record.cache}-${record.layer}`} className="border-t border-border">
                                  <td className="px-2 py-1.5 font-mono">{record.cache}</td>
                                  <td className="px-2 py-1.5 font-mono">{record.layer}</td>
                                  <td className="px-2 py-1.5 text-right font-mono">{formatBytes(record.size)}</td>
                                  <td className="px-2 py-1.5 text-right font-mono">{record.ref_count}</td>
                                  <td className="px-2 py-1.5">{record.ref_last ? formatDateTime(record.ref_last) : "-"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </>
                  )}
                </div>
              ) : null}
              {pool.queue_by_target_type && pool.queue_by_target_type.length > 0 ? (
                <div className="mt-3 overflow-hidden rounded-md border border-border bg-background" data-testid="scanner-queue-by-target">
                  <table className="w-full text-[11px]">
                    <thead className="bg-muted/60 text-left text-muted-foreground">
                      <tr>
                        <th className="px-2 py-1.5">Target</th>
                        <th className="px-2 py-1.5 text-right">Pending</th>
                        <th className="px-2 py-1.5 text-right">Delayed</th>
                        <th className="px-2 py-1.5 text-right">Running</th>
                        <th className="px-2 py-1.5 text-right">Stale</th>
                        <th className="px-2 py-1.5 text-right">Paused</th>
                        <th className="px-2 py-1.5 text-right">Canceled</th>
                        <th className="px-2 py-1.5 text-right">Exhausted</th>
                        <th className="px-2 py-1.5 text-right">Failed</th>
                        <th className="px-2 py-1.5 text-right">Oldest</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pool.queue_by_target_type.map((metric) => (
                        <tr key={metric.target_type} className="border-t border-border">
                          <td className="px-2 py-1.5 font-mono">{metric.target_type}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.pending}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.retry_delayed}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.running}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.stale_running}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.paused}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.canceled}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.exhausted}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{metric.failed}</td>
                          <td className="px-2 py-1.5 text-right font-mono">{formatDuration(metric.oldest_pending_seconds)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
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

      <VerdictBanner status={verdictStatus} title={verdictTitle} detail={verdictDetail} />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Registries ready" value={`${summary?.registry_connectors_ready ?? 0}/${summary?.registry_connectors_total ?? 0}`} />
        <StatCard label="Clouds ready" value={`${summary?.cloud_connectors_ready ?? 0}/${summary?.cloud_connectors_total ?? 0}`} />
        <StatCard label="Unscanned images" value={unscanned} tone={unscanned > 0 ? "medium" : "neutral"} />
        <StatCard label="Queued scans" value={summary?.queued_scans ?? 0} />
      </section>

      <Tabs value={tab} onValueChange={setTab} items={tabs} />
    </PageContainer>
  );
}



function ScanJobCard({ job, busy, onAction }: { job: ScanJob; busy: boolean; onAction: (action: ScanJobAction) => void }) {
  const actions = scanJobActions(job.status);
  return (
    <article className="rounded-md bg-muted p-3 text-xs" data-testid="scan-job-card">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="rounded-sm bg-background px-1.5 py-0.5 font-mono text-[10px]">{job.target_type}</span>
            {job.source_type ? <span className="rounded-sm bg-background px-1.5 py-0.5 text-[10px]">{job.source_type}</span> : null}
          </div>
          <div className="mt-1 truncate font-mono" title={job.target_ref}>{job.target_ref}</div>
        </div>
        <Status value={job.status} />
      </div>
      <div className="mt-1 text-muted-foreground">
        attempt {job.attempt_count}/{job.max_attempts}
        {job.worker_id ? ` · worker ${job.worker_id}` : ""}
        {job.lease_expires_at && job.status === "running" ? ` · lease ${formatDateTime(job.lease_expires_at)}` : ""}
        {job.next_attempt_at ? ` · retry ${formatDateTime(job.next_attempt_at)}` : ""}
        {job.finished_at ? ` · finished ${formatDateTime(job.finished_at)}` : ""}
        {job.error ? ` · ${job.error}` : ""}
      </div>
      {actions.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {actions.map((action) => (
            <button
              key={action}
              type="button"
              className="inline-flex items-center gap-1 rounded-md border border-border bg-background px-2 py-1 text-[10px] hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
              disabled={busy}
              onClick={() => onAction(action)}
              data-testid={`scan-job-${action}`}
            >
              {scanJobActionIcon(action)}
              {scanJobActionText(action)}
            </button>
          ))}
        </div>
      ) : null}
    </article>
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

function scanJobActions(status: string): ScanJobAction[] {
  switch (status) {
    case "pending":
      return ["pause", "cancel"];
    case "paused":
      return ["resume", "cancel"];
    case "running":
      return ["cancel"];
    case "failed":
    case "canceled":
      return ["retry"];
    default:
      return [];
  }
}

function scanJobAction(action: ScanJobAction, id: string) {
  switch (action) {
    case "pause":
      return scanJobsAdmin.pause(id);
    case "resume":
      return scanJobsAdmin.resume(id);
    case "retry":
      return scanJobsAdmin.retry(id);
    case "cancel":
      return scanJobsAdmin.cancel(id);
  }
}

function scanJobActionText(action: ScanJobAction) {
  switch (action) {
    case "pause":
      return "Pause";
    case "resume":
      return "Resume";
    case "retry":
      return "Retry";
    case "cancel":
      return "Cancel";
  }
}

function scanJobActionLabel(action: ScanJobAction) {
  switch (action) {
    case "pause":
      return "Scan job paused";
    case "resume":
      return "Scan job resumed";
    case "retry":
      return "Scan job requeued";
    case "cancel":
      return "Scan job canceled";
  }
}

function scanJobActionIcon(action: ScanJobAction) {
  switch (action) {
    case "pause":
      return <Pause className="h-3 w-3" aria-hidden />;
    case "resume":
      return <Play className="h-3 w-3" aria-hidden />;
    case "retry":
      return <RotateCcw className="h-3 w-3" aria-hidden />;
    case "cancel":
      return <XCircle className="h-3 w-3" aria-hidden />;
  }
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
