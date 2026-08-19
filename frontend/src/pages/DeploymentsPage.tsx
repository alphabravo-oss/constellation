// Risk-prioritized deployment dashboard — StackRox parity.
//
// The center of the platform's operational workflow: show the riskiest
// deployments first and expose the factors behind the score. The discoverer
// rolls image/workload findings and runtime exposure into deployments.risk_score.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Flame, Layers, ShieldAlert } from "lucide-react";
import { deployments, type Deployment } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";

export function DeploymentsPage() {
  const { clusterId } = useCluster();
  const [namespace, setNamespace] = useState("");
  const q = useQuery({
    queryKey: ["deployments", namespace, clusterId],
    queryFn: () => deployments.list({ namespace: namespace || undefined, cluster_id: clusterId }),
  });

  const rows = useMemo(() => q.data?.deployments ?? [], [q.data?.deployments]);
  const summary = useMemo(
    () =>
      rows.reduce(
        (acc, d) => {
          acc.total += 1;
          acc.critical += d.critical_count;
          acc.high += d.high_count;
          if (d.risk_score >= 60) acc.atRisk += 1;
          return acc;
        },
        { total: 0, critical: 0, high: 0, atRisk: 0 },
      ),
    [rows],
  );

  const columns: Column<Deployment>[] = [
    {
      id: "risk",
      header: "Risk",
      className: "font-mono",
      cell: (d) => <span className={`rounded-md px-2 py-0.5 ${riskClass(d.risk_score)}`}>{d.risk_score}</span>,
    },
    {
      id: "deployment",
      header: "Deployment",
      cell: (d) => (
        <>
          <Link to={`/clusters/${clusterId}/deployments/${d.id}`} className="hover:underline">
            <span className="text-foreground font-medium">
              {d.namespace}/{d.name}
            </span>
          </Link>
          <span className="ml-1 text-xs text-muted-foreground">· {d.kind}</span>
          <Link
            to={`/clusters/${clusterId}/risk/deployment/${encodeURIComponent(d.id)}`}
            className="ml-2 text-[10px] text-muted-foreground hover:text-foreground hover:underline"
            data-testid="deployment-risk-workspace-link"
          >
            risk workspace
          </Link>
        </>
      ),
    },
    {
      id: "findings",
      header: "Findings",
      className: "text-xs",
      cell: (d) => (
        <>
          {d.finding_count} total
          {d.critical_count > 0 && (
            <span className="ml-2 rounded-md bg-[color:var(--color-severity-critical)]/15 px-1.5 py-0.5 text-[color:var(--color-severity-critical)]">
              {d.critical_count} critical
            </span>
          )}
          {d.high_count > 0 && (
            <span className="ml-1 rounded-md bg-[color:var(--color-severity-high)]/15 px-1.5 py-0.5 text-[color:var(--color-severity-high)]">
              {d.high_count} high
            </span>
          )}
        </>
      ),
    },
    {
      id: "factors",
      header: "Risk factors",
      className: "text-xs",
      cell: (d) => <FactorBar factors={d.risk_factors} />,
    },
    {
      id: "lastSeen",
      header: "Last seen",
      className: "text-xs text-muted-foreground",
      cell: (d) => <>{new Date(d.last_seen_at).toLocaleString()}</>,
    },
  ];

  return (
    <div className="space-y-4" data-testid="deployments-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Deployments at risk"
        description="Your riskiest deployments first. The score blends open vulnerabilities, exploit signals (CVSS, KEV), runtime exposure, and workload posture."
        actions={
          <label className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground">Namespace</span>
            <input
              type="text"
              value={namespace}
              onChange={(e) => setNamespace(e.target.value)}
              placeholder="(all)"
              className="rounded-md border border-border bg-card px-2 py-1 text-sm"
              data-testid="namespace-filter"
            />
          </label>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4" data-testid="deployments-summary">
        <StatCard label="Deployments" value={summary.total.toLocaleString()} icon={<Layers className="h-3.5 w-3.5" />} />
        <StatCard label="At risk" value={summary.atRisk.toLocaleString()} icon={<AlertTriangle className="h-3.5 w-3.5" />} tone={summary.atRisk > 0 ? "high" : "neutral"} hint="risk score ≥ 60" />
        <StatCard label="Critical findings" value={summary.critical.toLocaleString()} icon={<Flame className="h-3.5 w-3.5" />} tone={summary.critical > 0 ? "critical" : "neutral"} />
        <StatCard label="High findings" value={summary.high.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.high > 0 ? "high" : "neutral"} />
      </section>

      <DataTable
        rows={rows}
        columns={columns}
        rowKey={(d) => d.id}
        testId="deployments-table"
        rowTestId={() => "deployment-row"}
        showDensityToggle={false}
        className="rounded-lg"
        emptyState={
          q.isPending ? (
            <div className="px-3 py-6" />
          ) : (
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No deployments yet. The operator's reconciler discovers deployments per
              ConstellationCluster + persists risk into the deployments table.
            </div>
          )
        }
      />
    </div>
  );
}

function riskClass(score: number): string {
  if (score >= 80) return "bg-[color:var(--color-severity-critical)]/15 text-[color:var(--color-severity-critical)]";
  if (score >= 60) return "bg-[color:var(--color-severity-high)]/15 text-[color:var(--color-severity-high)]";
  if (score >= 30) return "bg-[color:var(--color-severity-medium)]/15 text-[color:var(--color-severity-medium)]";
  return "bg-muted text-foreground";
}

// FactorBar renders a thin stacked bar of risk-factor contributions so the dashboard tells
// a one-glance story: "this deployment is risky because of CVSS+KEV, not because it's
// privileged." Mirrors StackRox's risk-factor list view.
function FactorBar({ factors }: { factors: Record<string, number> }) {
  const entries = Object.entries(factors ?? {}).filter(([, v]) => v > 0);
  const total = entries.reduce((s, [, v]) => s + v, 0) || 1;
  const colors: Record<string, string> = {
    cvss:           "bg-[color:var(--color-severity-critical)]",
    kev:            "bg-[color:var(--color-severity-high)]",
    epss:           "bg-[color:var(--color-severity-medium)]",
    privileged:     "bg-[color:var(--color-status-warning)]",
    net_exposure:   "bg-[color:var(--color-status-info)]",
    reachability:   "bg-[color:var(--color-status-pending)]",
  };
  return (
    <div className="flex items-center gap-2">
      <div className="flex h-2 w-32 overflow-hidden rounded-full bg-muted">
        {entries.map(([k, v]) => (
          <span
            key={k}
            title={`${k}: ${v}`}
            className={`${colors[k] ?? "bg-foreground/40"}`}
            style={{ width: `${(v / total) * 100}%` }}
          />
        ))}
      </div>
      <span className="text-[10px] text-muted-foreground">
        {entries.map(([k, v]) => `${k}=${v}`).join(" · ")}
      </span>
    </div>
  );
}
