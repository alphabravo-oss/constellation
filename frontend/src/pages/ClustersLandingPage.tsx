// ClustersLandingPage — cluster-first IA entry point.
//
// This page replaces the org-mixed /dashboard as the post-login surface. Each cluster
// is presented as a tile with the real DB-backed quick stats (open / critical / high
// findings) plus the top-risk workload and last-seen flow timestamp so an operator
// can triage which cluster needs attention before drilling in.
//
// The "Org overview" callout below the grid links to the surfaces that legitimately
// span clusters (CVE DB, Settings, Federation) so they remain one click away.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Database,
  Globe2,
  Layers,
  Plus,
  RotateCw,
  Settings as SettingsIcon,
  ServerCog,
  Activity,
  ShieldCheck,
  Trash2,
} from "lucide-react";

import {
  clusterInitBundles,
  clusters,
  type ClusterInitBundleSummary,
  type ClusterSummary,
} from "@/api/client";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { RiskScore } from "@/components/ui/risk-score";
import { EmptyState } from "@/components/ui/empty-state";
import { fmtRelative } from "@/lib/format";
import { cn } from "@/lib/cn";
import { ClusterInitBundleWizard } from "@/pages/ClusterInitBundleWizard";

export function ClustersLandingPage() {
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clusters.list(), staleTime: 30_000 });
  const data = useMemo(() => list.data?.clusters ?? [], [list.data?.clusters]);
  const [wizardOpen, setWizardOpen] = useState(false);

  return (
    <PageContainer>
      <PageHeader
        title="Clusters"
        description="Choose a cluster to triage findings, runtime events, network flows, and policy posture. Org-wide surfaces are linked below."
        actions={
          <Button
            variant="primary"
            size="md"
            onClick={() => setWizardOpen(true)}
            data-testid="register-cluster-button"
          >
            <Plus className="h-3.5 w-3.5" />
            Register cluster
          </Button>
        }
      />

      <ClusterInitBundleWizard open={wizardOpen} onOpenChange={setWizardOpen} />

      {list.isPending && (
        <p className="text-sm text-muted-foreground">Loading clusters…</p>
      )}

      {!list.isPending && data.length === 0 && (
        <EmptyState
          title="No clusters registered"
          hint="Register your first cluster via the Helm command in Settings to begin collecting findings."
        />
      )}

      {data.length > 0 && (
        <section
          data-testid="clusters-landing-grid"
          className="grid gap-4 md:grid-cols-2 xl:grid-cols-3"
        >
          {data.map((c) => (
            <ClusterTile key={c.id} cluster={c} />
          ))}
        </section>
      )}

      <InitBundlesPanel />

      <OrgOverviewCallout />
    </PageContainer>
  );
}

// InitBundlesPanel renders the active + historical init-bundles for the org with
// Rotate / Revoke actions. The "single download" semantics mean we don't expose a
// re-fetch action here; operators who lost the YAML must rotate.
function InitBundlesPanel() {
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["cluster-init-bundles"],
    queryFn: () => clusterInitBundles.list(),
    staleTime: 15_000,
  });
  const rotate = useMutation({
    mutationFn: (id: string) => clusterInitBundles.rotate(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cluster-init-bundles"] }),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => clusterInitBundles.revoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cluster-init-bundles"] }),
  });

  const bundles = list.data ?? [];
  if (list.isPending) {
    return null;
  }
  if (bundles.length === 0) {
    return null;
  }
  return (
    <section className="rounded-md border border-border bg-card p-4" data-testid="init-bundles-panel">
      <header className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <ShieldCheck className="h-3.5 w-3.5" />
        Init bundles
        <span className="ml-auto text-[10px] normal-case tracking-normal text-muted-foreground">
          {bundles.filter((b) => b.status === "active").length} active ·{" "}
          {bundles.filter((b) => b.status === "expired").length} expired ·{" "}
          {bundles.filter((b) => b.status === "revoked").length} revoked
        </span>
      </header>
      <DataTable
        rows={bundles}
        columns={bundleColumns()}
        rowKey={(b) => b.id}
        rowTestId={() => "init-bundle-row"}
        rowAttrs={(b) => ({ "data-bundle-id": b.id })}
        showDensityToggle={false}
        className="mt-3 rounded-none border-0"
      />
    </section>
  );

  function bundleTone(status: ClusterInitBundleSummary["status"]): string {
    return status === "active"
      ? "var(--color-status-success)"
      : status === "expired"
        ? "var(--color-status-warning)"
        : "var(--color-status-error)";
  }

  function bundleColumns(): Column<ClusterInitBundleSummary>[] {
    return [
      {
        id: "name",
        header: "Name",
        className: "font-medium",
        cell: (b) => <>{b.name}</>,
      },
      {
        id: "cluster",
        header: "Cluster ID",
        className: "text-mono text-[10px] text-muted-foreground",
        cell: (b) => <>{b.cluster_id.slice(0, 8)}…</>,
      },
      {
        id: "status",
        header: "Status",
        cell: (b) => {
          const tone = bundleTone(b.status);
          return (
            <span
              className="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider"
              style={{
                backgroundColor: `color-mix(in oklab, ${tone} 18%, transparent)`,
                color: tone,
              }}
            >
              {b.status}
            </span>
          );
        },
      },
      {
        id: "expires",
        header: "Expires",
        className: "text-muted-foreground",
        cell: (b) => <>{fmtRelative(b.expires_at)}</>,
      },
      {
        id: "actions",
        header: "",
        cell: (b) => (
          <div className="flex justify-end gap-1.5">
            <Button
              size="sm"
              variant="outline"
              disabled={rotate.isPending || revoke.isPending || b.status === "revoked"}
              onClick={() => rotate.mutate(b.id)}
              data-testid="rotate-bundle"
            >
              <RotateCw className="h-3 w-3" />
              Rotate
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={rotate.isPending || revoke.isPending || b.status === "revoked"}
              onClick={() => {
                if (confirm(`Revoke bundle for ${b.name}? Its scanner + runtime-agent tokens will be invalidated.`)) {
                  revoke.mutate(b.id);
                }
              }}
              data-testid="revoke-bundle"
            >
              <Trash2 className="h-3 w-3" />
              Revoke
            </Button>
          </div>
        ),
      },
    ];
  }
}

function ClusterTile({ cluster }: { cluster: ClusterSummary }) {
  const stats = cluster.stats ?? { critical_open: 0, high_open: 0, open_findings: 0, total_findings: 0 };
  const hasCritical = stats.critical_open > 0;
  const hasHigh = stats.high_open > 0;
  const stateTone =
    cluster.state === "healthy" || cluster.state === "connected" || cluster.state === "ready"
      ? "var(--color-status-success)"
      : cluster.state === "warn" || cluster.state === "degraded"
        ? "var(--color-status-warning)"
        : "var(--color-status-error)";

  return (
    <article
      data-testid="cluster-card"
      data-cluster-id={cluster.id}
      className={cn(
        "group relative flex flex-col gap-3 rounded-md border border-border bg-card p-4 transition-colors",
        "hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]",
      )}
      style={
        hasCritical
          ? { borderColor: "color-mix(in oklab, var(--color-severity-critical) 36%, var(--color-border))" }
          : undefined
      }
    >
      <header className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <ServerCog className="h-4 w-4 text-muted-foreground" aria-hidden />
            <h2 className="truncate text-sm font-semibold" title={cluster.name}>
              {cluster.name}
            </h2>
          </div>
          <p className="mt-1 truncate text-[11px] text-mono text-muted-foreground">
            {cluster.distro}
            {cluster.region ? ` · ${cluster.region}` : ""}
            {cluster.platform?.kubernetes_git_version ? ` · k8s ${cluster.platform.kubernetes_git_version}` : ""}
            {cluster.agent_version ? ` · agent ${cluster.agent_version}` : ""}
          </p>
        </div>
        <span
          className="rounded px-2 py-0.5 text-[10px] uppercase tracking-wider"
          style={{
            backgroundColor: `color-mix(in oklab, ${stateTone} 18%, transparent)`,
            color: stateTone,
          }}
        >
          {cluster.state || "unknown"}
        </span>
      </header>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <Stat
          icon={<AlertOctagon className="h-3 w-3" aria-hidden />}
          label="Critical (open)"
          value={stats.critical_open}
          tone={hasCritical ? "critical" : "muted"}
        />
        <Stat
          icon={<AlertTriangle className="h-3 w-3" aria-hidden />}
          label="High (open)"
          value={stats.high_open}
          tone={hasHigh ? "high" : "muted"}
        />
      </div>

      <div className="grid grid-cols-2 gap-2 text-[11px]">
        <div className="rounded border border-border bg-muted/30 px-2 py-1.5">
          <div className="text-[9px] uppercase tracking-wider text-muted-foreground">
            Top risk workload
          </div>
          <div className="mt-0.5 flex items-center gap-1.5">
            {cluster.top_workload ? (
              <>
                <span className="truncate font-mono" title={cluster.top_workload}>
                  {cluster.top_workload}
                </span>
                {typeof cluster.top_workload_risk === "number" && cluster.top_workload_risk > 0 && (
                  <RiskScore score={cluster.top_workload_risk} size="sm" />
                )}
              </>
            ) : (
              <span className="text-muted-foreground">—</span>
            )}
          </div>
        </div>
        <div className="rounded border border-border bg-muted/30 px-2 py-1.5">
          <div className="text-[9px] uppercase tracking-wider text-muted-foreground">
            Platform facts
          </div>
          <div className="mt-0.5 truncate text-mono">
            {cluster.platform?.observed_at ? fmtRelative(cluster.platform.observed_at) : "not reported"}
          </div>
        </div>
      </div>

      <footer className="mt-1 flex items-center justify-between gap-2">
        <span className="text-[10px] text-muted-foreground">
          {cluster.deployments} workloads · {stats.open_findings} open findings
        </span>
        <Link
          to={`/clusters/${cluster.id}/dashboard`}
          data-testid="cluster-enter"
          className={cn(
            "inline-flex items-center gap-1.5 rounded-md border border-input bg-card px-2 py-1 text-xs font-medium",
            "hover:bg-accent transition-colors",
          )}
        >
          Enter cluster
          <ArrowRight className="h-3 w-3" aria-hidden />
        </Link>
      </footer>
    </article>
  );
}

function Stat({
  icon,
  label,
  value,
  tone,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  tone: "critical" | "high" | "muted";
}) {
  const color =
    tone === "critical"
      ? "var(--color-severity-critical)"
      : tone === "high"
        ? "var(--color-severity-high)"
        : "var(--color-muted-foreground)";
  return (
    <div
      className="rounded border border-border bg-muted/30 px-2 py-1.5"
      style={tone !== "muted" ? { borderColor: `color-mix(in oklab, ${color} 30%, var(--color-border))` } : undefined}
    >
      <div className="flex items-center gap-1 text-[9px] uppercase tracking-wider text-muted-foreground">
        {icon}
        {label}
      </div>
      <div
        className="mt-0.5 text-display text-xl font-semibold tabular-nums"
        style={{ color }}
      >
        {value}
      </div>
    </div>
  );
}

function OrgOverviewCallout() {
  const items: Array<{ to: string; label: string; description: string; icon: React.ReactNode }> = [
    { to: "/cve", label: "CVE DB", description: "Org-wide vulnerability catalog", icon: <Database className="h-4 w-4" /> },
    { to: "/federation", label: "Federation", description: "Multi-cluster joins", icon: <Globe2 className="h-4 w-4" /> },
    { to: "/coverage", label: "Coverage", description: "Feature & connector matrix", icon: <ShieldCheck className="h-4 w-4" /> },
    { to: "/system-health", label: "System Health", description: "Platform components", icon: <Activity className="h-4 w-4" /> },
    { to: "/settings", label: "Settings", description: "Org configuration", icon: <SettingsIcon className="h-4 w-4" /> },
  ];
  return (
    <section className="rounded-md border border-dashed border-border bg-card/50 p-4">
      <header className="flex items-center gap-2 text-xs uppercase tracking-wider text-muted-foreground">
        <Layers className="h-3.5 w-3.5" />
        Org overview
      </header>
      <ul className="mt-3 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
        {items.map((item) => (
          <li key={item.to}>
            <Link
              to={item.to}
              className="flex items-start gap-2 rounded border border-border bg-card p-2.5 text-xs hover:bg-accent transition-colors"
            >
              <span className="text-muted-foreground">{item.icon}</span>
              <span className="min-w-0">
                <span className="block font-medium truncate">{item.label}</span>
                <span className="block text-[10px] text-muted-foreground truncate">
                  {item.description}
                </span>
              </span>
            </Link>
          </li>
        ))}
      </ul>
    </section>
  );
}
