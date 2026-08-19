// FileTab — B2 per-workload file-activity drill-down.
//
// Pulls the workload's file profile (FIM/file-monitor data) and renders the
// observed file activity plus the active monitor rules. The entityId is used
// directly as the workload id for the file-profile lookup.
// TODO(matrix): asset entities may carry an id distinct from the runtime
// workload id — resolve that mapping so this works for asset-typed drill-downs
// too, not just workload-typed ones.
import { useQuery } from "@tanstack/react-query";
import { fileProfiles } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export default function FileTab({ entityId }: { entityType: string; entityId: string }) {
  const { clusterId } = useCluster();
  const q = useQuery({
    queryKey: ["risk-files", clusterId, entityId],
    queryFn: () => fileProfiles.get(entityId, { cluster_id: clusterId }),
    enabled: !!entityId,
    retry: false,
  });

  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading file activity…</p>;
  if (q.isError) {
    return (
      <p className="text-xs text-muted-foreground" data-testid="risk-file-tab">
        No file profile is available for this entity. File monitoring reports per runtime workload id.
      </p>
    );
  }

  const profile = q.data;
  const files = profile?.files ?? [];
  const rules = profile?.rules ?? [];

  return (
    <div className="space-y-4" data-testid="risk-file-tab">
      <div className="flex flex-wrap gap-4 text-[11px] text-muted-foreground">
        <span>mode <span className="font-mono text-foreground">{profile?.mode}</span></span>
        <span>learned paths <span className="font-mono text-foreground">{profile?.learned_paths_count ?? 0}</span></span>
        <span>sensitive <span className="font-mono text-foreground">{profile?.sensitive_path_count ?? 0}</span></span>
        <span>alerts 24h <span className="font-mono text-foreground">{profile?.monitored_alerts_24h ?? 0}</span></span>
        <span>blocks 24h <span className="font-mono text-foreground">{profile?.enforced_blocks_24h ?? 0}</span></span>
      </div>

      <section className="space-y-1">
        <h3 className="text-xs font-semibold">Observed file activity ({files.length})</h3>
        <ul className="space-y-1 text-xs">
          {files.slice(0, 50).map((f) => (
            <li key={`${f.path}:${f.operation}`} className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2">
              <span className="font-mono truncate">{f.path}</span>
              <span className="text-muted-foreground shrink-0">
                {f.operation}{f.sensitive ? " · sensitive" : ""} · ×{f.observed_count}
              </span>
            </li>
          ))}
          {files.length === 0 && <li className="text-muted-foreground">No file activity observed yet.</li>}
        </ul>
      </section>

      <section className="space-y-1">
        <h3 className="text-xs font-semibold">Monitor rules ({rules.length})</h3>
        <ul className="space-y-1 text-xs">
          {rules.slice(0, 30).map((r) => (
            <li key={r.id} className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2">
              <span className="font-mono truncate">{r.filter}</span>
              <span className="text-muted-foreground shrink-0">
                {r.behavior}{r.recursive ? " · recursive" : ""}{r.enabled ? "" : " · disabled"}
              </span>
            </li>
          ))}
          {rules.length === 0 && <li className="text-muted-foreground">No custom file-monitor rules.</li>}
        </ul>
      </section>
    </div>
  );
}
