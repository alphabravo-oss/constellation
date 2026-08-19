import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { enterprise } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export default function ProcessTab({ entityId }: { entityType: string; entityId: string }) {
  const { clusterId } = useCluster();
  const q = useQuery({
    queryKey: ["risk-process", clusterId, entityId],
    queryFn: () => enterprise.runtime({ hours: 24, cluster_id: clusterId }),
    enabled: !!entityId,
  });

  // B2: the runtime overview returns cluster-wide events; scope them to this
  // workload so the Process tab is entity-specific. Match on workload_id with
  // a substring fallback for id-vs-name skew.
  // TODO(matrix): a per-workload events endpoint would avoid pulling the whole
  // cluster overview just to filter it client-side.
  const events = useMemo(() => {
    const all = q.data?.recent_events ?? [];
    const needle = entityId.toLowerCase();
    return all.filter((e) => {
      const wl = (e.workload_id ?? "").toLowerCase();
      return wl === needle || wl.includes(needle) || needle.includes(wl);
    });
  }, [q.data, entityId]);

  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading runtime events…</p>;
  return (
    <div className="space-y-2" data-testid="risk-process-tab">
      <p className="text-xs text-muted-foreground">
        Recent runtime events for <span className="font-mono">{entityId}</span> ({events.length}).
      </p>
      <ul className="space-y-1 text-xs">
        {events.slice(0, 50).map((e) => (
          <li key={e.id} className="rounded-md border border-border bg-card px-3 py-2">
            <div className="flex items-center justify-between">
              <span className="font-medium">{e.rule_name ?? e.kind}</span>
              <span className="text-muted-foreground">{e.severity}</span>
            </div>
            <p className="text-[11px] text-muted-foreground">{e.message}</p>
          </li>
        ))}
        {events.length === 0 && <li className="text-muted-foreground">No runtime events for this workload in window.</li>}
      </ul>
    </div>
  );
}
