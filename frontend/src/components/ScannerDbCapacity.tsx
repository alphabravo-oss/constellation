import { Fragment } from "react";
import type { SystemHealthHeartbeat } from "@/api/client";

type Engine = "trivy" | "grype";
type Revision = "download_revision" | "applied_revision";

function engineValue(heartbeats: SystemHealthHeartbeat[], engine: Engine, field: Revision | "status", unknown: string): string {
  const reported = heartbeats
    .map((heartbeat) => heartbeat.metadata?.engine_db?.[engine]?.[field]?.trim())
    .filter((value): value is string => Boolean(value));
  if (!reported.length) return unknown;

  const values = [...new Set(reported)].join(", ");
  return reported.length === heartbeats.length ? values : `${values} (${reported.length}/${heartbeats.length} reporting)`;
}

export function ScannerDbCapacity({ heartbeats, unavailable = false, loading = false }: { heartbeats?: SystemHealthHeartbeat[]; unavailable?: boolean; loading?: boolean }) {
  const scanners = (heartbeats ?? []).filter((heartbeat) => heartbeat.component === "scanner");
  const live = scanners.filter((heartbeat) => heartbeat.status !== "stale" && heartbeat.status !== "crashlooping");
  const active = live.filter((heartbeat) => heartbeat.metadata);
  const capacity = active.filter((heartbeat) => heartbeat.metadata?.max_concurrent !== undefined);
  const maxConcurrent = capacity.reduce((total, heartbeat) => total + (heartbeat.metadata?.max_concurrent ?? 0), 0);
  const activeJobs = capacity.reduce((total, heartbeat) => total + (heartbeat.metadata?.active_jobs ?? 0), 0);
  const idleCapacity = capacity.reduce((total, heartbeat) => total + (heartbeat.metadata?.idle_capacity ?? 0), 0);
  const appliedBundles = [...new Set(active.map((heartbeat) => heartbeat.metadata?.vulndb?.bundle_version).filter((version): version is string => Boolean(version)))];
  const unknown = unavailable ? "Unavailable" : loading ? "Loading..." : "Not reported";
  const engineUnknown = live.length ? unknown : unavailable ? "Unavailable" : loading ? "Loading..." : "No active scanner report";

  return (
    <dl className="grid gap-2 text-xs sm:grid-cols-2" data-testid="scanner-db-capacity">
      <Status label="Worker capacity" value={capacity.length ? `${idleCapacity} idle / ${maxConcurrent} slots · ${activeJobs} active (${capacity.length} ${capacity.length === 1 ? "worker" : "workers"})` : unknown} />
      <Status label="Host VulnDB applied bundle" value={appliedBundles.length ? appliedBundles.join(", ") : unknown} />
      {(["trivy", "grype"] as const).map((engine) => {
        const name = engine === "trivy" ? "Trivy" : "Grype";
        return (
          <Fragment key={engine}>
            <Status label={`${name} DB download revision`} value={engineValue(live, engine, "download_revision", engineUnknown)} />
            <Status label={`${name} DB applied revision`} value={engineValue(live, engine, "applied_revision", engineUnknown)} />
            <Status label={`${name} DB status`} value={engineValue(live, engine, "status", engineUnknown)} />
          </Fragment>
        );
      })}
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
