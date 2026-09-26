import type { SystemHealthHeartbeat } from "@/api/client";

export function ScannerDbCapacity({ heartbeats, unavailable = false, loading = false }: { heartbeats?: SystemHealthHeartbeat[]; unavailable?: boolean; loading?: boolean }) {
  const scanners = (heartbeats ?? []).filter((heartbeat) => heartbeat.component === "scanner");
  const active = scanners.filter((heartbeat) => heartbeat.status !== "stale" && heartbeat.status !== "crashlooping" && heartbeat.metadata);
  const capacity = active.filter((heartbeat) => heartbeat.metadata?.max_concurrent !== undefined);
  const maxConcurrent = capacity.reduce((total, heartbeat) => total + (heartbeat.metadata?.max_concurrent ?? 0), 0);
  const activeJobs = capacity.reduce((total, heartbeat) => total + (heartbeat.metadata?.active_jobs ?? 0), 0);
  const idleCapacity = capacity.reduce((total, heartbeat) => total + (heartbeat.metadata?.idle_capacity ?? 0), 0);
  const appliedBundles = [...new Set(active.map((heartbeat) => heartbeat.metadata?.vulndb?.bundle_version).filter((version): version is string => Boolean(version)))];
  const unknown = unavailable ? "Unavailable" : loading ? "Loading..." : "Not reported";

  return (
    <dl className="grid gap-2 text-xs sm:grid-cols-2" data-testid="scanner-db-capacity">
      <Status label="Worker capacity" value={capacity.length ? `${idleCapacity} idle / ${maxConcurrent} slots · ${activeJobs} active (${capacity.length} ${capacity.length === 1 ? "worker" : "workers"})` : unknown} />
      <Status label="Host VulnDB applied bundle" value={appliedBundles.length ? appliedBundles.join(", ") : unknown} />
      <Status label="Engine DB download revision" value={unknown} />
      <Status label="Engine DB applied revision" value={unknown} />
    </dl>
  );
}

function Status({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-all font-mono text-foreground">{value}</dd>
    </div>
  );
}
