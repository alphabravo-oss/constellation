// DashboardPage — security ops console.
//
// Layout (top → bottom):
//
//   ┌──────────────────────────────────────────────────────────────────┐
//   │ Scope bar                                                        │
//   ├──────────────────────────────────────────────────────────────────┤
//   │ Hero band: composite risk gauge · 4 severity tiles + sparklines  │
//   ├───────────────────────────────────┬──────────────────────────────┤
//   │ Action items (top critical/high)  │  Recent activity rail        │
//   ├───────────────────────────────────┴──────────────────────────────┤
//   │ Posture tiles: compliance pass % · runtime threats today          │
//   ├──────────────────────────────────────────────────────────────────┤
//   │ Heatmap matrix (asset id × severity × finding count)             │
//   ├──────────────────────────────────────────────────────────────────┤
//   │ Severity distribution · CVE DB · New-findings trend               │
//   └──────────────────────────────────────────────────────────────────┘
//
// All KPIs link to pre-filtered drill-downs; action items launch the Triage
// drawer in place so the analyst never loses dashboard context.

import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import {
  AlertOctagon, AlertTriangle, ShieldAlert, ShieldCheck, Activity,
  TrendingUp, ArrowUpRight, ExternalLink, Database, FileWarning,
  ServerCog, PackageCheck, RefreshCw,
} from "lucide-react";

import { findings, cve, dashboard, clusters, compliance, enterprise, type Finding, type PlatformFactsResponse, type Severity } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { StatCard } from "@/components/ui/stat-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { RiskGauge, RiskScore } from "@/components/ui/risk-score";
import { Sparkline } from "@/components/ui/sparkline";
import { Button } from "@/components/ui/button";
import { Drawer } from "@/components/ui/drawer";
import { EmptyState } from "@/components/ui/empty-state";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { WhatIfScore } from "@/components/WhatIfScore";
import { fmtRelative } from "@/lib/format";
import { cn } from "@/lib/cn";

const SEVERITY_COLORS: Record<Severity, string> = {
  info:     "var(--color-severity-info)",
  low:      "var(--color-severity-low)",
  medium:   "var(--color-severity-medium)",
  high:     "var(--color-severity-high)",
  critical: "var(--color-severity-critical)",
};

export function DashboardPage() {
  // Under /clusters/:id/dashboard, scope all data fetches to that cluster.
  // At org-level (legacy/back-compat) clusterId is undefined → fetch unscoped.
  const { clusterId, cluster } = useCluster();
  // Severity/lifecycle totals come from dashboard.summary (server-aggregated),
  // so we only need a top slice of open findings for the visuals (composite
  // risk, top actions, heatmap, trend). One 250-row fetch instead of two
  // 1000-row fetches with detail_json — much faster page load.
  const open  = useQuery({
    queryKey: ["findings", "open", clusterId],
    queryFn: () => findings.list({ lifecycle: "open", cluster_id: clusterId, limit: 250 }),
  });
  const bundle = useQuery({ queryKey: ["cve", "bundle"],    queryFn: () => cve.bundle() });
  const cveStats = useQuery({ queryKey: ["cve", "stats"],   queryFn: () => cve.stats(), staleTime: 60_000 });
  const sum   = useQuery({
    queryKey: ["dashboard", clusterId],
    queryFn: () => dashboard.summary({ cluster_id: clusterId }),
  });
  const platform = useQuery({
    queryKey: ["cluster-platform", clusterId],
    queryFn: () => clusters.platformFacts(clusterId!),
    enabled: !!clusterId,
    refetchInterval: 30_000,
  });
  // Compliance posture (pass/fail across frameworks) + runtime threats in the
  // last 24h. Both feed the two posture tiles so the landing represents all
  // four platform pillars (vuln · compliance · runtime · network).
  const complianceSum = useQuery({
    queryKey: ["compliance", "summary", clusterId],
    queryFn: () => compliance.summary(clusterId),
    staleTime: 60_000,
  });
  const runtimeToday = useQuery({
    queryKey: ["runtime", "overview", "24h", clusterId],
    queryFn: () => enterprise.runtime({ hours: 24, cluster_id: clusterId }),
    staleTime: 60_000,
  });
  const qc = useQueryClient();
  const scanPlatform = useMutation({
    mutationFn: () => clusters.scanPlatform(clusterId!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["cluster-platform", clusterId] }),
  });

  const openItems = useMemo(() => open.data?.findings ?? [], [open.data]);
  const allItems  = openItems; // counts/trends fall back to the open slice; authoritative totals come from sum.data
  const clusterPath = (path: string) => clusterId ? `/clusters/${clusterId}${path}` : path;

  // Prefer the server-side summary for severity/lifecycle totals: the findings
  // list is paginated (limit 1000), so tallying it client-side under-counts
  // once a cluster has more findings than one page. Fall back to the client
  // tally only until the summary loads.
  const counts = useMemo(() => {
    const s = sum.data;
    if (s?.findings_by_severity) {
      const base = bucketByLifecycle(allItems);
      return {
        ...base,
        total: s.findings_total ?? base.total,
        open: s.open_findings ?? base.open,
        critical: s.findings_by_severity.critical ?? base.critical,
        high: s.findings_by_severity.high ?? base.high,
        accepted: s.accepted_risks ?? base.accepted,
      };
    }
    return bucketByLifecycle(allItems);
  }, [sum.data, allItems]);
  const severityCounts = useMemo(() => {
    const s = sum.data?.findings_by_severity;
    if (s) {
      return (["critical", "high", "medium", "low", "info"] as Severity[])
        .map((severity) => ({ severity, value: s[severity] ?? 0 }))
        .filter((entry) => entry.value > 0);
    }
    return bucketBySeverity(openItems);
  }, [sum.data, openItems]);
  const compositeRisk = useMemo(() => {
    if (openItems.length === 0) return 0;
    const top = openItems.slice().sort((a, b) => b.risk_score - a.risk_score).slice(0, 10);
    return Math.round(top.reduce((s, f) => s + f.risk_score, 0) / top.length);
  }, [openItems]);

  const trends = useMemo(() => fourteenDayBySeverity(allItems), [allItems]);
  const topActions = useMemo(() => prioritizeActionItems(openItems), [openItems]);
  const heatmap = useMemo(() => buildHeatmap(openItems), [openItems]);
  const recent = sum.data?.recent_activity ?? [];

  // Compliance pass % aggregated across all reported frameworks.
  const compliancePosture = useMemo(() => {
    const frameworks = complianceSum.data?.frameworks ?? [];
    const pass = frameworks.reduce((s, f) => s + (f.pass ?? 0), 0);
    const fail = frameworks.reduce((s, f) => s + (f.fail ?? 0), 0);
    const graded = pass + fail;
    return {
      pct: graded > 0 ? Math.round((pass / graded) * 100) : null,
      fail,
      frameworks: frameworks.length,
    };
  }, [complianceSum.data]);
  // Runtime threats in the last 24h: alerting/blocking events from the overview.
  const runtimeThreats = runtimeToday.data?.summary;

  // Triage drawer (in-place from action items)
  const [drawerFinding, setDrawerFinding] = useState<Finding | null>(null);

  return (
    <div className="space-y-5" data-testid="dashboard-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title={cluster?.name ? `${cluster.name} — Dashboard` : "Security Dashboard"}
        description={
          clusterId
            ? "Risk-first snapshot for this cluster. Click any tile to drill in."
            : "A risk-first snapshot of your fleet. Click any tile to drill in."
        }
      />

      {/* Hero band */}
      <section className="c-rise c-rise-1 grid grid-cols-1 gap-5 rounded-md border border-border bg-card p-5 star-field lg:grid-cols-[260px_1fr]">
        <div className="flex items-center gap-5 border-r border-border/60 pr-5">
          <RiskGauge score={compositeRisk} label="composite" sub={`top-10 avg · ${openItems.length} open`} />
          <div className="hidden md:flex flex-col gap-1.5 min-w-0">
            <div className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Posture</div>
            <div className="text-display text-base font-semibold leading-tight">
              {compositeRisk >= 80 ? "Elevated" : compositeRisk >= 60 ? "Moderate" : compositeRisk >= 40 ? "Watch" : "Healthy"}
            </div>
            <div className="text-[11px] text-muted-foreground leading-snug">
              {counts.critical} crit · {counts.high} high<br />{counts.accepted} accepted-risk
            </div>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          <StatCard
            label="Critical"
            value={counts.critical}
            tone="critical"
            icon={<AlertOctagon className="h-3 w-3" />}
            href={clusterPath("/findings?severity=critical")}
            trend={trends.critical}
          />
          <StatCard
            label="High"
            value={counts.high}
            tone="high"
            icon={<AlertTriangle className="h-3 w-3" />}
            href={clusterPath("/findings?severity=high")}
            trend={trends.high}
          />
          <StatCard
            label="Open"
            value={counts.open}
            tone="accent"
            icon={<Activity className="h-3 w-3" />}
            href={clusterPath("/findings")}
            trend={trends.open}
          />
          <StatCard
            label="Accepted"
            value={counts.accepted}
            tone="neutral"
            icon={<ShieldCheck className="h-3 w-3" />}
            href={clusterPath("/findings?lifecycle=accepted")}
          />
        </div>
      </section>

      {/* Posture tiles — compliance + runtime pillars alongside the vuln hero. */}
      <section className="c-rise c-rise-2 grid grid-cols-1 gap-3 sm:grid-cols-2">
        <StatCard
          label="Compliance pass rate"
          value={
            complianceSum.isPending ? "…" :
            compliancePosture.pct == null ? "—" : `${compliancePosture.pct}%`
          }
          tone={
            compliancePosture.pct == null ? "neutral" :
            compliancePosture.pct >= 90 ? "low" :
            compliancePosture.pct >= 70 ? "medium" : "high"
          }
          icon={<ShieldCheck className="h-3 w-3" />}
          href={clusterPath("/compliance")}
          hint={
            compliancePosture.pct == null
              ? "No graded controls yet"
              : `${compliancePosture.fail} failing · ${compliancePosture.frameworks} framework${compliancePosture.frameworks === 1 ? "" : "s"}`
          }
        />
        <StatCard
          label="Runtime threats · 24h"
          value={runtimeToday.isPending ? "…" : (runtimeThreats?.alerts ?? 0)}
          tone={(runtimeThreats?.alerts ?? 0) > 0 ? "critical" : "neutral"}
          icon={<ShieldAlert className="h-3 w-3" />}
          href={clusterPath("/runtime")}
          hint={
            runtimeToday.isPending
              ? "Loading…"
              : `${runtimeThreats?.blocks ?? 0} blocked · ${runtimeThreats?.affected_workloads ?? 0} workloads`
          }
        />
      </section>

      {/* B8: score what-if — "fix these N → score X→Y" */}
      <section className="c-rise c-rise-2">
        <WhatIfScore />
      </section>

      {clusterId && (
        <section className="c-rise c-rise-2">
          <PlatformPanel
            data={platform.data}
            loading={platform.isPending}
            scanning={scanPlatform.isPending}
            onScan={() => scanPlatform.mutate()}
          />
        </section>
      )}

      {/* Action items + recent activity */}
      <section className="c-rise c-rise-3 grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <Panel
          title="Action Items"
          subtitle="Top 10 open critical and high findings · sorted by composite risk"
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
          rightSlot={<Link to={clusterPath("/findings?severity=critical")} className="text-[11px] text-muted-foreground hover:text-foreground">view all <ArrowUpRight className="inline h-3 w-3" /></Link>}
        >
          {topActions.length === 0 ? (
            <EmptyState
              title="No outstanding critical or high findings"
              hint="When new severe findings appear they'll show up here for one-click triage."
              icon={<ShieldCheck className="h-8 w-8" />}
            />
          ) : (
            <ul className="divide-y divide-border">
              {topActions.map((f) => (
                <li key={f.id} className="accent-slide flex items-center gap-3 px-3 py-2 hover:bg-muted/40 transition-colors">
                  <SeverityBadge severity={f.severity} kev={false} />
                  <div className="min-w-0 flex-1">
                    <Link to={clusterPath(`/findings/${f.id}`)} className="text-sm hover:underline truncate block" title={f.title}>
                      {f.title}
                    </Link>
                    <div className="text-[10px] text-mono text-muted-foreground">
                      {f.external_id ?? f.id.slice(0, 10)} · {f.kind} · {fmtRelative(f.last_seen_at)}
                    </div>
                  </div>
                  <RiskScore score={f.risk_score} size="sm" />
                  <Button size="sm" variant="outline" onClick={() => setDrawerFinding(f)}>Triage</Button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Recent Activity"
          icon={<Activity className="h-3.5 w-3.5" />}
        >
          {recent.length === 0 ? (
            <EmptyState title="No recent activity" hint="Triage actions and runtime events will appear here." />
          ) : (
            <ul className="divide-y divide-border">
              {recent.slice(0, 8).map((r, i) => (
                <li key={i} className="px-3 py-2 text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono">{r.action}</span>
                    <span className="text-muted-foreground text-[10px]">{r.target_kind}</span>
                  </div>
                  <div className="mt-0.5 text-mono text-[10px] text-muted-foreground truncate">
                    {r.target_id} · {fmtRelative(r.at)}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </section>

      {/* Heatmap */}
      <section className="c-rise c-rise-4">
        <Panel
          title="Critical Exposure Matrix"
          subtitle="Open findings by asset · severity (top contributors). Click a cell to drill in."
          icon={<TrendingUp className="h-3.5 w-3.5" />}
        >
          <HeatmapMatrix data={heatmap} />
        </Panel>
      </section>

      {/* Bottom row: distribution · CVE DB · trend */}
      <section className="c-rise c-rise-5 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="Severity Distribution" icon={<AlertTriangle className="h-3.5 w-3.5" />}>
          {severityCounts.length === 0 ? (
            <EmptyState title="No open findings" />
          ) : (
            <div className="grid grid-cols-2 items-center">
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={severityCounts}
                    dataKey="value"
                    nameKey="severity"
                    innerRadius={44}
                    outerRadius={72}
                    strokeWidth={2}
                    stroke="var(--color-card)"
                    paddingAngle={1}
                  >
                    {severityCounts.map((entry) => (
                      <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <ul className="space-y-1.5 text-xs">
                {severityCounts.map((s) => (
                  <li key={s.severity} className="flex items-center justify-between gap-2">
                    <span className="flex items-center gap-1.5">
                      <span aria-hidden className="h-2 w-2 rounded-sm" style={{ background: SEVERITY_COLORS[s.severity] }} />
                      <span className="capitalize">{s.severity}</span>
                    </span>
                    <span className="text-mono">{s.value}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Panel>

        <Panel title="CVE Database" icon={<Database className="h-3.5 w-3.5" />}>
          {bundle.data?.available || (cveStats.data?.total ?? 0) > 0 ? (
            <dl className="space-y-2 text-xs">
              <Row
                k="CVE rows"
                v={
                  <Link to="/cve" className="text-mono text-[color:var(--color-primary)] hover:underline">
                    {(cveStats.data?.total ?? bundle.data?.row_count ?? 0).toLocaleString()}
                  </Link>
                }
              />
              {cveStats.data && (
                <Row
                  k="KEV / EPSS>0.5"
                  v={
                    <span className="text-mono">
                      {cveStats.data.kev_listed.toLocaleString()}
                      <span className="text-muted-foreground"> · </span>
                      {cveStats.data.epss_gt_50.toLocaleString()}
                    </span>
                  }
                />
              )}
              {bundle.data?.available && (
                <>
                  <Row k="Bundle"   v={<span className="text-mono">{String(bundle.data.version)}</span>} />
                  <Row k="Bundle records" v={<span className="text-mono text-muted-foreground">{Number(bundle.data.record_count).toLocaleString()}</span>} />
                  <Row k="Signed"  v={
                    bundle.data.signed ? (
                      <span className="rounded bg-[color-mix(in_oklab,var(--color-status-success)_18%,transparent)] px-1.5 py-0.5 text-[10px] text-[color:var(--color-status-success)] text-mono">cosign · {String(bundle.data.signer_identity ?? "—")}</span>
                    ) : <span className="text-muted-foreground">unsigned</span>
                  } />
                  <Row k="Imported" v={<span className="text-mono text-muted-foreground">{new Date(String(bundle.data.imported_at)).toLocaleString()}</span>} />
                </>
              )}
            </dl>
          ) : (
            <EmptyState
              title="No CVE bundle imported"
              hint="The Helm chart runs the importer on a 6-hour CronJob."
              icon={<FileWarning className="h-8 w-8" />}
              action={<Link to="/cve" className="text-xs text-[color:var(--color-primary)] hover:underline">Open CVE DB <ExternalLink className="inline h-3 w-3" /></Link>}
            />
          )}
        </Panel>

        <Panel title="New Findings · 14 day trend" icon={<TrendingUp className="h-3.5 w-3.5" />}>
          <div className="px-2">
            <Sparkline data={trends.openSeries} width={300} height={80} color="var(--color-primary)" />
            <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
              <span>14d ago</span>
              <span>today</span>
            </div>
            <div className="mt-2 text-mono text-[11px]">
              <span className="text-foreground">Total this window: </span>
              <span className="text-foreground">{trends.openSeries.reduce((a, b) => a + b, 0)}</span>
              <span className="text-muted-foreground"> · peak {Math.max(0, ...trends.openSeries)}</span>
            </div>
          </div>
        </Panel>
      </section>

      <TriageDrawer finding={drawerFinding} onClose={() => setDrawerFinding(null)} />
    </div>
  );
}

// ─────────────────────────── helpers + subcomponents ───────────────────────────

const tooltipStyle = {
  background: "var(--color-popover)",
  borderColor: "var(--color-border)",
  borderRadius: "6px",
  fontSize: 11,
};

function Panel({
  title, subtitle, icon, children, rightSlot, className,
}: {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode;
  children: React.ReactNode;
  rightSlot?: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("rounded-md border border-border bg-card", className)}>
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2 min-w-0">
          {icon && <span className="text-muted-foreground">{icon}</span>}
          <div className="min-w-0">
            <h2 className="text-display text-sm font-semibold tracking-tight truncate">{title}</h2>
            {subtitle && <p className="text-[10px] text-muted-foreground truncate">{subtitle}</p>}
          </div>
        </div>
        {rightSlot}
      </header>
      <div className="p-3">{children}</div>
    </section>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">{k}</dt>
      <dd className="text-right">{v}</dd>
    </div>
  );
}

function PlatformPanel({
  data,
  loading,
  scanning,
  onScan,
}: {
  data?: PlatformFactsResponse;
  loading: boolean;
  scanning: boolean;
  onScan: () => void;
}) {
  const facts = data?.facts;
  const packages = data?.evidence?.packages ?? [];
  const components = facts?.components ?? [];
  const bundle = data?.latest_job?.bundle_metadata;
  const canScan = !!data?.evidence && !scanning;
  type PkgRow = (typeof packages)[number] & { _rk: string };
  const pkgRows: PkgRow[] = packages
    .slice(0, 8)
    .map((pkg, index) => ({ ...pkg, _rk: `${pkg.namespace_name}-${pkg.name}-${pkg.version}-${index}` }));
  const packageColumns: Column<PkgRow>[] = [
    { id: "name", header: "Package", cell: (r) => <span className="font-mono">{r.name || "-"}</span> },
    { id: "version", header: "Version", cell: (r) => <span className="font-mono text-muted-foreground">{r.version || "-"}</span> },
    { id: "namespace", header: "Namespace", cell: (r) => <span className="font-mono text-muted-foreground">{r.namespace_name || r.ecosystem || "generic"}</span> },
  ];
  return (
    <Panel
      title="Platform Scan"
      subtitle="Kubernetes control plane, kubelet, and platform add-on package evidence"
      icon={<ServerCog className="h-3.5 w-3.5" />}
      rightSlot={
        <Button size="sm" variant="outline" disabled={!canScan} onClick={onScan}>
          <RefreshCw className={cn("h-3 w-3", scanning && "animate-spin")} />
          Scan platform
        </Button>
      }
    >
      {loading ? (
        <p className="text-xs text-muted-foreground">Loading platform facts...</p>
      ) : !facts ? (
        <EmptyState
          title="No platform facts reported"
          hint="The discoverer reports Kubernetes platform facts from the installed cluster."
          icon={<ServerCog className="h-8 w-8" />}
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)_300px]">
          <dl className="space-y-2 text-xs">
            <Row k="Status" v={<StatusChip value={data?.status ?? "reported"} />} />
            <Row k="Kubernetes" v={<span className="text-mono">{facts.kubernetes_git_version || "unknown"}</span>} />
            <Row k="Distro" v={<span className="text-mono">{facts.distro}</span>} />
            <Row k="Provider" v={<span className="text-mono">{facts.platform_provider || "unknown"}</span>} />
            <Row k="Nodes" v={<span className="text-mono">{facts.node_count}</span>} />
            <Row k="Observed" v={<span className="text-mono text-muted-foreground">{fmtRelative(facts.observed_at)}</span>} />
          </dl>

          <div className="min-w-0">
            <div className="mb-2 flex items-center gap-2 text-[10px] uppercase tracking-wider text-muted-foreground">
              <PackageCheck className="h-3 w-3" />
              Evidence packages
              <span className="ml-auto text-mono">{data?.evidence?.package_count ?? packages.length}</span>
            </div>
            <DataTable<PkgRow>
              rows={pkgRows}
              columns={packageColumns}
              rowKey={(r) => r._rk}
              showDensityToggle={false}
              emptyState={<div className="px-2 py-3 text-center text-xs text-muted-foreground">No package evidence</div>}
            />
            {components.length > packages.length && (
              <p className="mt-1 text-[10px] text-muted-foreground">{components.length} reported platform components</p>
            )}
          </div>

          <dl className="space-y-2 text-xs">
            <Row k="Job" v={<StatusChip value={data?.latest_job?.status ?? "not queued"} />} />
            <Row k="Findings" v={<span className="text-mono">{data?.findings_summary.open ?? 0} open</span>} />
            <Row k="Critical / High" v={<span className="text-mono">{data?.findings_summary.critical ?? 0} / {data?.findings_summary.high ?? 0}</span>} />
            <Row k="Inventory" v={<span className="text-mono text-muted-foreground">{shortHash(data?.evidence?.inventory_hash)}</span>} />
            <Row k="Bundle" v={<span className="text-mono text-muted-foreground">{bundle?.bundle_version || "pending"}</span>} />
            <Row k="Bundle rows" v={<span className="text-mono text-muted-foreground">{bundle?.record_count?.toLocaleString() ?? "-"}</span>} />
          </dl>
        </div>
      )}
    </Panel>
  );
}

function StatusChip({ value }: { value: string }) {
  const tone =
    ["ready", "scanned", "completed", "connected"].includes(value)
      ? "var(--color-status-success)"
      : ["pending", "running", "reported", "degraded"].includes(value)
        ? "var(--color-status-warning)"
        : "var(--color-status-error)";
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider"
      style={{
        backgroundColor: `color-mix(in oklab, ${tone} 18%, transparent)`,
        color: tone,
      }}
    >
      {value}
    </span>
  );
}

function shortHash(value?: string) {
  if (!value) return "pending";
  return value.length > 18 ? `${value.slice(0, 15)}...` : value;
}

function HeatmapMatrix({ data }: { data: { rows: string[]; cols: string[]; values: number[][] } }) {
  const { clusterId } = useCluster();
  const clusterPath = (path: string) => clusterId ? `/clusters/${clusterId}${path}` : path;
  if (data.rows.length === 0 || data.cols.length === 0) {
    return <EmptyState title="No open findings" hint="The asset × severity matrix lights up when new findings land." />;
  }
  const max = Math.max(1, ...data.values.flat());
  return (
    <div className="overflow-auto px-2 py-1">
      <table className="text-xs border-separate border-spacing-1">
        <thead>
          <tr>
            <th className="pr-3 pb-2 text-left text-[10px] font-medium uppercase tracking-wider text-muted-foreground">asset id</th>
            {data.cols.map((c) => (
              <th key={c} className="px-2 pb-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground whitespace-nowrap text-center">
                {c}
              </th>
            ))}
            <th className="px-2 pb-2 text-[10px] font-medium uppercase tracking-wider text-muted-foreground text-center">total</th>
          </tr>
        </thead>
        <tbody>
          {data.rows.map((r, i) => {
            const rowTotal = data.values[i].reduce((a, b) => a + b, 0);
            return (
              <tr key={r}>
                <th className="pr-3 text-left text-[11px] font-medium whitespace-nowrap" title={`asset ${r}`}>
                  <Link to={clusterPath(`/risk/asset/${encodeURIComponent(r)}`)} className="text-mono text-muted-foreground hover:text-foreground hover:underline">
                    {r.slice(0, 12)}
                  </Link>
                </th>
                {data.cols.map((c, j) => {
                  const v = data.values[i][j];
                  const intensity = v === 0 ? 0 : 0.18 + (v / max) * 0.72;
                  const sevToken = `var(--color-severity-${c})`;
                  return (
                    <td key={c} className="p-0">
                      <Link
                        to={clusterPath(`/risk/asset/${encodeURIComponent(r)}`)}
                        className="flex h-9 w-12 items-center justify-center rounded text-[11px] text-mono transition-all hover:scale-[1.06]"
                        style={{
                          background: v === 0
                            ? "color-mix(in oklab, var(--color-muted) 40%, transparent)"
                            : `color-mix(in oklab, ${sevToken} ${(intensity * 100).toFixed(0)}%, transparent)`,
                          color: v === 0 ? "var(--color-muted-foreground)" : "white",
                        }}
                        title={`asset ${r} · ${v} ${c} · open risk workspace`}
                      >
                        {v === 0 ? "·" : v}
                      </Link>
                    </td>
                  );
                })}
                <td className="pl-3 text-right text-[11px] text-mono text-muted-foreground">{rowTotal}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function TriageDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const qc = useQueryClient();
  const { clusterId } = useCluster();
  const clusterPath = (path: string) => clusterId ? `/clusters/${clusterId}${path}` : path;
  const [reason, setReason] = useState("");
  const suppress = useMutation({
    mutationFn: () => findings.suppress(finding!.id, { reason: reason || "dashboard quick-suppress" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); onClose(); },
  });
  const acceptRisk = useMutation({
    mutationFn: () => findings.acceptRisk(finding!.id, {
      reason: reason || "dashboard quick-accept",
      accepted_until: new Date(Date.now() + 30 * 86400_000).toISOString(),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); onClose(); },
  });
  const triage = useMutation({
    mutationFn: () => findings.triage(finding!.id, { priority: "high" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); onClose(); },
  });

  return (
    <Drawer
      open={!!finding}
      onOpenChange={(o) => { if (!o) onClose(); }}
      title={finding?.title}
      description={finding ? `${finding.external_id ?? finding.id.slice(0, 10)} · ${finding.kind}` : undefined}
    >
      {finding && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <LifecycleBadge lifecycle={finding.lifecycle} />
            <RiskScore score={finding.risk_score} />
          </div>
          <dl className="space-y-1.5 text-xs">
            <Row k="Asset"    v={<Link to={clusterPath(`/risk/asset/${encodeURIComponent(finding.asset_id)}`)} className="text-mono text-[color:var(--color-primary)] hover:underline">{finding.asset_id.slice(0, 16)}</Link>} />
            <Row k="First seen" v={<span className="text-mono text-muted-foreground">{fmtRelative(finding.first_seen_at)}</span>} />
            <Row k="Last seen"  v={<span className="text-mono text-muted-foreground">{fmtRelative(finding.last_seen_at)}</span>} />
            <Row k="Techniques" v={<span className="text-mono text-[10px] text-muted-foreground">{finding.attack_techniques.join(", ") || "—"}</span>} />
          </dl>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Reason (optional)</label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Why are you taking this action?"
              className="w-full min-h-[64px] rounded-md border border-input bg-card px-2 py-1.5 text-xs outline-none focus:border-[color:var(--color-primary)]"
            />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary"     size="sm" onClick={() => triage.mutate()}>Triage</Button>
            <Button variant="outline"     size="sm" onClick={() => suppress.mutate()}>Suppress</Button>
            <Button variant="outline"     size="sm" onClick={() => acceptRisk.mutate()}>Accept risk · 30d</Button>
            <Link to={clusterPath(`/findings/${finding.id}`)} className="ml-auto text-[11px] text-muted-foreground hover:text-foreground inline-flex items-center gap-1">
              Open detail <ExternalLink className="h-3 w-3" />
            </Link>
          </div>
        </div>
      )}
    </Drawer>
  );
}

// ─────────────────────────── pure helpers ───────────────────────────

function bucketByLifecycle(items: Finding[]) {
  const out = { total: 0, open: 0, critical: 0, high: 0, suppressed: 0, accepted: 0 };
  for (const f of items) {
    out.total++;
    if (f.severity === "critical") out.critical++;
    if (f.severity === "high") out.high++;
    if (f.lifecycle === "suppressed") out.suppressed++;
    if (f.lifecycle === "accepted") out.accepted++;
    if (f.lifecycle === "open" || f.lifecycle === "triaged" || f.lifecycle === "in_progress") out.open++;
  }
  return out;
}

function bucketBySeverity(items: Finding[]) {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of items) counts[f.severity]++;
  return (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((severity) => ({ severity, value: counts[severity] }))
    .filter((entry) => entry.value > 0);
}

function prioritizeActionItems(items: Finding[]): Finding[] {
  return items
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .sort((a, b) => b.risk_score - a.risk_score)
    .slice(0, 10);
}

interface SeverityTrend {
  critical: number[];
  high: number[];
  open: number[];
  openSeries: number[];
}

function fourteenDayBySeverity(items: Finding[]): SeverityTrend {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const day = (d: Date) => d.toISOString().slice(0, 10);
  const days: string[] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86400 * 1000);
    days.push(day(d));
  }
  const idx = new Map(days.map((d, i) => [d, i]));
  const critical = new Array(14).fill(0);
  const high     = new Array(14).fill(0);
  const open     = new Array(14).fill(0);
  for (const f of items) {
    const k = day(new Date(f.first_seen_at));
    const i = idx.get(k);
    if (i == null) continue;
    if (f.severity === "critical") critical[i]++;
    if (f.severity === "high") high[i]++;
    if (f.lifecycle === "open") open[i]++;
  }
  return { critical, high, open, openSeries: open };
}

function buildHeatmap(items: Finding[]): { rows: string[]; cols: string[]; values: number[][] } {
  // Rows are keyed by the real asset_id (a UUID — the Finding type carries no
  // asset name/namespace), columns are the real finding severity, and each cell
  // is the real count of open findings of that severity on the asset.
  const sevOrder = ["critical", "high", "medium", "low", "info"] as const;
  const rowSet = new Map<string, number>();
  const cells = new Map<string, number>();
  for (const f of items) {
    if (!sevOrder.includes(f.severity as typeof sevOrder[number])) continue;
    const row = f.asset_id;
    if (!rowSet.has(row)) rowSet.set(row, rowSet.size);
    const k = `${row}|${f.severity}`;
    cells.set(k, (cells.get(k) ?? 0) + 1);
  }
  const rows = Array.from(rowSet.keys()).slice(0, 10);
  // Always render the canonical severity axis so the matrix has consistent
  // columns even when only one severity is currently present.
  const cols = sevOrder.filter((s) => rows.some((r) => (cells.get(`${r}|${s}`) ?? 0) > 0)) as unknown as string[];
  const values = rows.map((r) => cols.map((c) => cells.get(`${r}|${c}`) ?? 0));
  return { rows, cols, values };
}
