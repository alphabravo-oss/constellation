interface ClusterActivityInput {
  id: string;
  name: string;
  state?: string;
  deployments?: number;
  max_risk?: number;
  stats?: {
    critical_open?: number;
    high_open?: number;
    open_findings?: number;
    total_findings?: number;
  };
  last_flow_at?: string;
  last_heartbeat_at?: string;
  sensor_health?: {
    ready?: number;
    total?: number;
  };
}

export function clusterActivityScore(cluster: ClusterActivityInput): number {
  const stateScore =
    cluster.state === "connected" || cluster.state === "healthy" || cluster.state === "ready"
      ? 10
      : cluster.state === "degraded" || cluster.state === "warn"
        ? 5
        : 0;

  return (cluster.stats?.critical_open ?? 0) * 100_000
    + (cluster.stats?.high_open ?? 0) * 10_000
    + (cluster.stats?.open_findings ?? 0) * 1_000
    + (cluster.max_risk ?? 0) * 10
    + (cluster.deployments ?? 0) * 100
    + (cluster.last_flow_at ? 25 : 0)
    + (cluster.sensor_health?.ready ?? 0) * 5
    + (cluster.last_heartbeat_at ? 2 : 0)
    + stateScore;
}

export function sortClustersByActivity<T extends ClusterActivityInput>(clusters: T[]): T[] {
  return [...clusters].sort((a, b) => {
    const scoreDelta = clusterActivityScore(b) - clusterActivityScore(a);
    if (scoreDelta !== 0) return scoreDelta;
    const nameDelta = a.name.localeCompare(b.name);
    if (nameDelta !== 0) return nameDelta;
    return a.id.localeCompare(b.id);
  });
}
