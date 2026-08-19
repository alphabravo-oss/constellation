import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { network } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";

export default function NetworkTab({ entityType, entityId }: { entityType: string; entityId: string }) {
  const { clusterId } = useCluster();
  const q = useQuery({
    queryKey: ["risk-network", clusterId, entityType, entityId],
    queryFn: () => network.map({ hours: 24, cluster_id: clusterId }),
    enabled: !!entityId,
  });

  // B2: the map endpoint returns cluster-wide flows; filter to the ones that
  // actually touch this entity so the drill-down is workload-scoped rather
  // than a duplicate of the cluster network map. Match is by workload
  // identity (src/dst names) with a substring fallback for id-vs-name skew.
  // TODO(matrix): resolve the entity → canonical workload id server-side so
  // this filter is exact instead of best-effort string matching.
  const flows = useMemo(() => {
    const all = q.data?.flows ?? [];
    const needle = entityId.toLowerCase();
    return all.filter((f) => {
      const src = (f.src ?? "").toLowerCase();
      const dst = (f.dst ?? "").toLowerCase();
      return src === needle || dst === needle || src.includes(needle) || dst.includes(needle);
    });
  }, [q.data, entityId]);

  if (q.isPending) return <p className="text-xs text-muted-foreground">Loading flows…</p>;
  return (
    <div className="space-y-2" data-testid="risk-network-tab">
      <p className="text-xs text-muted-foreground">
        Last-24h network flows touching <span className="font-mono">{entityId}</span> ({flows.length}).
      </p>
      <ul className="space-y-1 text-xs">
        {flows.slice(0, 50).map((f) => (
          <li key={f.id} className="flex items-center justify-between rounded-md border border-border bg-card px-3 py-2">
            <span className="font-mono">{f.src} → {f.dst}:{f.dst_port}</span>
            <span className="text-muted-foreground">{f.verdict} · {f.protocol}</span>
          </li>
        ))}
        {flows.length === 0 && <li className="text-muted-foreground">No flows touching this entity in the last 24h.</li>}
      </ul>
    </div>
  );
}
