// ClustersLandingPage — cluster-first IA entry point.
//
// This page replaces the org-mixed /dashboard as the post-login surface. Each cluster
// is presented as a tile with the real DB-backed quick stats (open / critical / high
// findings) plus the top-risk workload and last-seen flow timestamp so an operator
// can triage which cluster needs attention before drilling in.
//
// Org-wide surfaces (CVE database, Posture, Audit log, Settings) live in the rail.
import { useMemo } from "react";
import { useRouteSearchParams } from "@/lib/route-search";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Plus, Radar, RotateCw, ShieldCheck, Trash2 } from "lucide-react";

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
import { sortClustersByActivity } from "@/lib/clusters";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useIncludeSystem } from "@/lib/system-scope";
import { clusterStateTone } from "@/components/ClusterSwitcher";
import { sentenceValue, StatusPill } from "@/components/ui/status-pill";
import { StatusDot } from "@/ui";

export function ClustersLandingPage() {
  const [scopeParams] = useRouteSearchParams();
  const includeSystem = useIncludeSystem(scopeParams);
  const workloadScope = includeSystem ? "all" as const : "application" as const;
  const list = useQuery({ queryKey: ["clusters", { workload_scope: workloadScope }], queryFn: () => clusters.list({ workload_scope: workloadScope }), staleTime: 30_000 });
  const data = useMemo(() => sortClustersByActivity(list.data?.clusters ?? []), [list.data?.clusters]);
  const navigate = useNavigate();
  const [requestedTab, setTab] = useTabParam("tab", "overview");
  const tab = requestedTab === "bundles" ? "bundles" : "overview";
  const needsAttention = data.filter((c) => !["healthy", "connected", "ready"].includes(c.state)).length;
  // Fresh clusters contribute current counts; stale ones their last-known counts
  // (Phase 1 exposure.last_known). Any cluster with neither makes the total unknown.
  const countable = list.data && data.length > 0 && data.every((c) => c.exposure?.inventory_status === "fresh" || !!c.exposure?.last_known);
  const anyLastKnown = data.some((c) => c.exposure?.inventory_status !== "fresh" && !!c.exposure?.last_known);
  const critical = countable ? data.reduce((total, c) => total + (c.exposure?.inventory_status === "fresh" ? c.exposure.current_critical : c.exposure?.last_known?.critical ?? 0), 0) : undefined;
  const high = countable ? data.reduce((total, c) => total + (c.exposure?.inventory_status === "fresh" ? c.exposure.current_high : c.exposure?.last_known?.high ?? 0), 0) : undefined;

  return (
    <PageContainer>
      <PageHeader
        title="Clusters"
        actions={
          <Button
            variant="primary"
            size="lg"
            onClick={() => void navigate({ href: "/settings/clusters/new" })}
            data-testid="register-cluster-button"
          >
            <Plus className="h-4 w-4" />
            Register cluster
          </Button>
        }
      />

      <VerdictBanner status={list.isError || needsAttention > 0 ? "degraded" : list.isPending || data.length === 0 ? "info" : "ok"}
        title={list.isError ? "Cluster inventory could not be loaded" : list.isPending ? "Loading clusters" : data.length === 0 ? "Connect your first cluster" : needsAttention > 0 ? `${needsAttention} of ${data.length} clusters need attention` : "All clusters are reporting"}
        numbers={list.data ? [
          { label: "clusters", value: data.length },
          { label: "need attention", value: needsAttention, tone: needsAttention > 0 ? "warning" : "default" },
          { label: anyLastKnown ? "critical (last known)" : "current critical", value: critical ?? "—", tone: critical ? "critical" : "default", testId: "clusters-critical" },
          { label: anyLastKnown ? "high (last known)" : "current high", value: high ?? "—", tone: high ? "high" : "default", testId: "clusters-high" },
        ] : undefined}
        detail="Critical and high count unique vulnerabilities matched to current inventory, across every cluster. Registration credentials live in the Registration bundles tab." />
      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "overview", label: "Clusters", count: list.data ? data.length : undefined, content: <div className="space-y-4">
      {list.isPending && <LoadingState label="Loading clusters" variant="cards" />}
      {list.isError && <ErrorState title="Cluster inventory is unavailable" error={list.error} onRetry={() => void list.refetch()} />}
      {!list.isPending && !list.isError && data.length === 0 && (
        <EmptyState
          title="No clusters registered"
          hint="Register a cluster to generate its installation command."
          icon={<Radar />}
          action={<Button variant="primary" onClick={() => void navigate({ href: "/settings/clusters/new" })}><Plus className="h-4 w-4" /> Register cluster</Button>}
        />
      )}
      {data.length > 0 && (
        <section data-testid="clusters-landing-grid" className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {data.map((c) => <ClusterTile key={c.id} cluster={c} />)}
        </section>
      )}
        </div> },
        { value: "bundles", label: "Registration bundles", content: <InitBundlesPanel /> },
      ]} />
    </PageContainer>
  );
}

// InitBundlesPanel renders the active + historical init-bundles for the org with
// Rotate / Revoke actions. The "single download" semantics mean we don't expose a
// re-fetch action here; operators who lost the YAML must rotate.
function InitBundlesPanel() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const list = useQuery({
    queryKey: ["cluster-init-bundles"],
    queryFn: () => clusterInitBundles.list(),
    staleTime: 15_000,
  });
  const revoke = useMutation({
    mutationFn: (id: string) => clusterInitBundles.revoke(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cluster-init-bundles"] }),
  });

  const bundles = list.data ?? [];
  if (list.isPending) {
    return <LoadingState label="Loading registration bundles" />;
  }
  if (list.isError) return <p role="alert">Registration bundles could not be loaded.</p>;
  if (bundles.length === 0) {
    return <EmptyState title="No registration bundles" hint="Register a cluster to generate its installation credentials." />;
  }
  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="init-bundles-panel">
      <header className="flex items-center gap-2 text-section-title font-semibold">
        <ShieldCheck className="h-3.5 w-3.5" />
        Registration bundles
        <span className="ml-auto text-meta font-normal text-muted-foreground">
          {bundles.filter((b) => b.status === "active").length} active ·{" "}
          {bundles.filter((b) => b.status === "expired").length} expired ·{" "}
          {bundles.filter((b) => b.status === "revoked").length} revoked
        </span>
      </header>
      {revoke.isError && <p role="alert">Could not revoke the bundle. Try again.</p>}
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


  function bundleColumns(): Column<ClusterInitBundleSummary>[] {
    return [
      {
        id: "name", kind: "name", grow: true, minSize: 220,
        header: "Name",
        className: "font-medium",
        cell: (b) => <>{b.name}</>,
      },
      {
        id: "cluster", kind: "id", size: 128, minSize: 112,
        header: "Cluster ID",
        className: "text-mono text-meta text-muted-foreground",
        cell: (b) => <span title={b.cluster_id}>{b.cluster_id.slice(0, 8)}</span>,
      },
      {
        id: "status", kind: "status", size: 112, minSize: 96,
        header: "Status",
        cell: (b) => {
          return <StatusPill label={b.status} tone={b.status === "active" ? "success" : b.status === "expired" ? "warning" : "error"} />;
        },
      },
      {
        id: "expires", kind: "age", size: 160, minSize: 144,
        header: "Expires",
        className: "text-muted-foreground",
        cell: (b) => <>{fmtRelative(b.expires_at)}</>,
      },
      {
        id: "actions", kind: "actions", size: 208, minSize: 208, maxSize: 224,
        header: "",
        cell: (b) => (
          <div className="flex justify-end gap-1.5">
            <Button
              size="sm"
              disabled={revoke.isPending || b.status === "revoked"}
              onClick={() => void navigate({ href: `/settings/clusters/bundles/${b.id}/rotate` })}
              data-testid="rotate-bundle"
            >
              <RotateCw className="h-3 w-3" />
              Rotate
            </Button>
            <Button
              size="sm"
              disabled={revoke.isPending || b.status === "revoked"}
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

export function ClusterTile({ cluster }: { cluster: ClusterSummary }) {
  const stats = cluster.stats ?? { critical_open: 0, high_open: 0, open_findings: 0, total_findings: 0 };
  const exposure = cluster.exposure;
  const freshExposure = exposure?.inventory_status === "fresh";
  const hasCritical = freshExposure && exposure.current_critical > 0;
  const hasHigh = freshExposure && exposure.current_high > 0;
  const lastKnown = !freshExposure ? exposure?.last_known : undefined;
  const version = cluster.platform?.kubernetes_git_version;

  return (
    <article
      data-testid="cluster-card"
      data-cluster-id={cluster.id}
      className="group relative flex flex-col gap-4 rounded-lg border border-border bg-card p-5 transition-colors hover:bg-accent/30"
    >
      <header className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="truncate text-section-title-lg font-semibold" title={cluster.name}>
            <Link to="." href={`/clusters/${cluster.id}/dashboard`} className="focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring rounded-sm after:absolute after:inset-0">
              {cluster.name}
            </Link>
          </h2>
          <p className="mt-1 truncate text-meta text-muted-foreground">
            {[cluster.distro, cluster.region, version].filter(Boolean).join(" · ")}
          </p>
        </div>
        <StatusDot tone={clusterStateTone(cluster.state)} label={sentenceValue(cluster.state || "unknown")} className="shrink-0 text-meta" />
      </header>

      <dl className="grid grid-cols-3 gap-3">
        <TileNumber label="Critical" value={freshExposure ? exposure.current_critical : lastKnown ? lastKnown.critical : "—"} tone={(freshExposure ? hasCritical : (lastKnown?.critical ?? 0) > 0) ? "critical" : undefined} testId="cluster-tile-critical" />
        <TileNumber label="High" value={freshExposure ? exposure.current_high : lastKnown ? lastKnown.high : "—"} tone={(freshExposure ? hasHigh : (lastKnown?.high ?? 0) > 0) ? "high" : undefined} testId="cluster-tile-high" />
        <TileNumber label="Workloads" value={cluster.deployments} />
      </dl>
      {!freshExposure && lastKnown ? (
        <p className="-mt-2 text-meta text-muted-foreground" data-testid="cluster-tile-as-of" title={formatAsOf(lastKnown.as_of)}>
          Last known, as of {fmtRelative(lastKnown.as_of)}
        </p>
      ) : null}

      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-meta text-muted-foreground">
        {cluster.top_workload ? (
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="shrink-0">Top risk</span>
            <span className="truncate font-mono text-foreground" title={cluster.top_workload}>{cluster.top_workload}</span>
            {typeof cluster.top_workload_risk === "number" && cluster.top_workload_risk > 0 && <RiskScore score={cluster.top_workload_risk} size="sm" />}
          </span>
        ) : null}
      </div>

      <footer className="relative mt-auto flex items-center justify-between gap-2 border-t border-border pt-3 text-meta text-muted-foreground">
        <details className="group/exposure relative min-w-0">
          <summary className={cn("cursor-pointer list-none rounded-sm focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring [&::-webkit-details-marker]:hidden", (!freshExposure || (exposure?.unverified_occurrences ?? 0) > 0) && "text-status-warning")}>
            {!freshExposure
              ? exposure?.inventory_status === "stale" ? "Inventory out of date" : "Inventory unavailable"
              : exposure.unverified_occurrences > 0 ? "Partial coverage" : "About these counts"}
          </summary>
          <div className="absolute bottom-full left-0 z-popover mb-2 w-72 space-y-2 rounded-md border border-border bg-popover p-3 text-meta text-popover-foreground shadow-elev-popover">
            <p>Unique critical and high vulnerabilities matched to current inventory.</p>
            {!freshExposure && <p>Counts are unavailable until fresh inventory arrives.</p>}
            {freshExposure && exposure.unverified_occurrences > 0 && <p>Some findings are not yet matched to current inventory, so the counts may be incomplete.</p>}
            <dl className="grid grid-cols-[1fr_auto] gap-x-3 gap-y-1">
              <dt>Total occurrences</dt><dd className="text-right tabular-nums">{(stats.critical_open + stats.high_open).toLocaleString()}</dd>
              {exposure && <><dt>Historical findings</dt><dd className="text-right tabular-nums">{exposure.historical_occurrences.toLocaleString()}</dd>
                <dt>Unverified findings</dt><dd className="text-right tabular-nums">{exposure.unverified_occurrences.toLocaleString()}</dd></>}
              {exposure?.observed_at && <><dt>Inventory updated</dt><dd className="text-right">{fmtRelative(exposure.observed_at)}</dd></>}
            </dl>
          </div>
        </details>
        <Link
          to="." href={`/clusters/${cluster.id}/dashboard`}
          data-testid="cluster-enter"
          className="relative inline-flex items-center gap-1 text-meta font-medium text-foreground hover:underline"
        >
          Open
          <ArrowRight className="h-3.5 w-3.5" aria-hidden />
        </Link>
      </footer>
    </article>
  );
}

function formatAsOf(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function TileNumber({ label, value, tone, testId }: { label: string; value: number | string; tone?: "critical" | "high"; testId?: string }) {
  return (
    <div data-testid={testId}>
      <dt className="text-meta font-medium text-muted-foreground">{label}</dt>
      <dd className={cn("mt-0.5 text-xl font-semibold tabular-nums", tone === "critical" ? "text-severity-critical" : tone === "high" ? "text-severity-high" : "text-foreground")}>{typeof value === "number" ? value.toLocaleString() : value}</dd>
    </div>
  );
}
