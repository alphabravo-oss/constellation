// RiskDetailPage — entity-centric drill-down.
//
// Header uses the shared EntityHeader (breadcrumbs · title · risk gauge · 4 stat
// tiles · action bar). Tabs are Radix-driven, lazy-loaded, with badge counts
// pulled from the relevant entity slice.
import { Suspense, lazy, useMemo } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink, ShieldCheck, AlertTriangle } from "lucide-react";

import { findings, type Finding } from "@/api/client";
import { EntityHeader } from "@/components/EntityHeader";
import { EmptyState } from "@/components/ui/empty-state";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge, StatusPill } from "@/components/ui/status-pill";
import { Button } from "@/components/ui/button";
import { ScopeBar } from "@/components/ScopeBar";
import { fmtRelative } from "@/lib/format";
import { useCluster } from "@/hooks/useCluster";

const OverviewTab   = lazy(() => import("./risk/OverviewTab"));
const FindingsTab   = lazy(() => import("./risk/FindingsTab"));
const NetworkTab    = lazy(() => import("./risk/NetworkTab"));
const ProcessTab    = lazy(() => import("./risk/ProcessTab"));
const FileTab       = lazy(() => import("./risk/FileTab"));
const ComplianceTab = lazy(() => import("./risk/ComplianceTab"));

export function RiskDetailPage() {
  const { entityType = "asset", entityId = "" } = useParams<{ entityType: string; entityId: string }>();
  const [tab, setTab] = useTabParam("tab", "overview");
  const navigate = useNavigate();
  const { clusterId } = useCluster();
  const clusterPath = (path: string) => clusterId ? `/clusters/${clusterId}${path}` : path;

  // For a finding entity, we already have rich data via /findings/:id elsewhere.
  // For dashboard purposes we re-derive a slim header by listing related findings
  // for the asset/entity. Keeps the header useful without a new endpoint.
  const relatedQ = useQuery({
    queryKey: ["risk-related", entityType, entityId],
    queryFn: () => findings.list({ limit: 200 }),
    enabled: !!entityId,
  });

  const related = useMemo<Finding[]>(() => {
    const all = relatedQ.data?.findings ?? [];
    if (entityType === "asset") return all.filter((f) => f.asset_id === entityId);
    return all.filter((f) => f.id === entityId);
  }, [relatedQ.data, entityType, entityId]);

  const stats = useMemo(() => {
    const crit = related.filter((f) => f.severity === "critical").length;
    const high = related.filter((f) => f.severity === "high").length;
    const open = related.filter((f) => f.lifecycle === "open" || f.lifecycle === "in_progress").length;
    const maxRisk = Math.max(0, ...related.map((f) => f.risk_score));
    const lastSeen = related.reduce<string | null>((acc, f) => acc && acc > f.last_seen_at ? acc : f.last_seen_at, null);
    return { crit, high, open, maxRisk, lastSeen };
  }, [related]);

  const top = useMemo(() => related.slice().sort((a, b) => b.risk_score - a.risk_score).slice(0, 5), [related]);

  // Per-entity-type list label + path (breadcrumb) and detail-page path (action).
  const listLabel =
    entityType === "asset" ? "Assets" :
    entityType === "node" ? "Nodes" :
    entityType === "deployment" ? "Deployments" : "Findings";
  const listPath =
    entityType === "asset" ? "/assets" :
    entityType === "node" ? "/nodes" :
    entityType === "deployment" ? "/deployments" : "/findings";
  const detailPath =
    entityType === "asset" ? `/assets/${entityId}` :
    entityType === "node" ? `/nodes/${encodeURIComponent(entityId)}` :
    entityType === "deployment" ? `/deployments/${entityId}` : null;

  if (!entityId) {
    return (
      <div className="space-y-5" data-testid="risk-detail-page">
        <ScopeBar />
        <EmptyState
          title="No entity selected"
          hint="Open a risk workspace from an asset, finding, node, or workload."
          icon={<AlertTriangle className="h-8 w-8" />}
        />
      </div>
    );
  }
  if (relatedQ.isPending) {
    return (
      <div className="space-y-5" data-testid="risk-detail-page">
        <ScopeBar />
        <p className="px-1 py-16 text-center text-sm text-muted-foreground">Loading risk workspace…</p>
      </div>
    );
  }
  if (relatedQ.isError) {
    return (
      <div className="space-y-5" data-testid="risk-detail-page">
        <ScopeBar />
        <EmptyState
          title="Couldn't load risk context"
          hint="The related-findings query failed. Retry in a moment."
          icon={<AlertTriangle className="h-8 w-8" />}
          action={<Button size="sm" variant="outline" onClick={() => relatedQ.refetch()}>Retry</Button>}
        />
      </div>
    );
  }

  return (
    <div className="space-y-5" data-testid="risk-detail-page">
      <ScopeBar />

      <EntityHeader
        breadcrumbs={[
          { label: "Dashboard", to: "/dashboard" },
          { label: listLabel, to: listPath },
          { label: entityId.slice(0, 16) },
        ]}
        title={<span className="text-mono">{entityId.length > 36 ? entityId.slice(0, 36) + "…" : entityId}</span>}
        subtitle={`${entityType} · ${related.length} related finding${related.length === 1 ? "" : "s"}`}
        badges={
          <div className="flex items-center gap-1.5">
            <StatusPill label={entityType} tone="info" />
            {stats.crit > 0 && <SeverityBadge severity="critical" />}
            {related[0]?.lifecycle && <LifecycleBadge lifecycle={related[0].lifecycle} />}
          </div>
        }
        riskScore={stats.maxRisk}
        subfactors={[
          { label: "Exploitability",  value: Math.min(100, stats.maxRisk + 4) },
          { label: "Impact",          value: stats.maxRisk },
          { label: "Exposure",        value: Math.max(0, stats.maxRisk - 10) },
          { label: "Asset criticality", value: Math.max(0, stats.maxRisk - 20) },
        ]}
        stats={[
          { label: "Critical", value: stats.crit, tone: stats.crit ? "critical" : "neutral" },
          { label: "High",     value: stats.high, tone: stats.high ? "high" : "neutral" },
          { label: "Open",     value: stats.open, tone: "accent" },
          { label: "Last seen", value: fmtRelative(stats.lastSeen), tone: "neutral" },
        ]}
        actions={
          <>
            <Button size="sm" variant="outline" onClick={() => navigate(clusterPath(`/findings?asset=${entityId}`))}>View findings</Button>
            {detailPath && (
              <Button size="sm" variant="primary" asChild>
                <Link to={clusterPath(detailPath)}>
                  {listLabel.replace(/s$/, "")} detail <ExternalLink className="h-3 w-3" />
                </Link>
              </Button>
            )}
          </>
        }
      />

      <Tabs
        value={tab}
        onValueChange={setTab}
        items={[
          {
            value: "overview",
            label: "Overview",
            content: (
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1fr_320px]">
                <Suspense fallback={<p className="text-xs text-muted-foreground">Loading overview…</p>}>
                  <OverviewTab entityType={entityType} entityId={entityId} />
                </Suspense>
                <aside className="space-y-3">
                  <SidePanel title="Top Contributing Findings" icon={<AlertTriangle className="h-3.5 w-3.5" />}>
                    {top.length === 0 ? (
                      <p className="text-[11px] text-muted-foreground px-3 py-4">No related findings.</p>
                    ) : (
                      <ul className="divide-y divide-border">
                        {top.map((f) => (
                          <li key={f.id} className="px-3 py-2">
                            <Link to={clusterPath(`/findings/${f.id}`)} className="flex items-start gap-2 hover:bg-muted/40 -mx-1 px-1 py-1 rounded">
                              <SeverityBadge severity={f.severity} size="xs" />
                              <div className="min-w-0 flex-1">
                                <div className="text-xs truncate">{f.title}</div>
                                <div className="text-[10px] text-mono text-muted-foreground">
                                  risk {f.risk_score} · {fmtRelative(f.last_seen_at)}
                                </div>
                              </div>
                            </Link>
                          </li>
                        ))}
                      </ul>
                    )}
                  </SidePanel>
                  <SidePanel title="Recommended Actions" icon={<ShieldCheck className="h-3.5 w-3.5" />}>
                    <ul className="space-y-2 px-3 py-2 text-xs">
                      {stats.crit > 0 && <li>• Triage {stats.crit} critical finding{stats.crit === 1 ? "" : "s"} — top contributor first.</li>}
                      {stats.high > 0 && <li>• Review {stats.high} high finding{stats.high === 1 ? "" : "s"}.</li>}
                      <li>• Pin to a watch list for stakeholder review.</li>
                      <li>• Generate runbook (forensic snapshot + SBOM).</li>
                    </ul>
                  </SidePanel>
                </aside>
              </div>
            ),
          },
          {
            value: "findings",
            label: "Findings",
            count: related.length,
            content: (
              <Suspense fallback={<p className="text-xs text-muted-foreground">Loading…</p>}>
                <FindingsTab entityType={entityType} entityId={entityId} />
              </Suspense>
            ),
          },
          {
            value: "network",
            label: "Network",
            content: (
              <Suspense fallback={<p className="text-xs text-muted-foreground">Loading…</p>}>
                <NetworkTab entityType={entityType} entityId={entityId} />
              </Suspense>
            ),
          },
          {
            value: "process",
            label: "Process",
            content: (
              <Suspense fallback={<p className="text-xs text-muted-foreground">Loading…</p>}>
                <ProcessTab entityType={entityType} entityId={entityId} />
              </Suspense>
            ),
          },
          {
            value: "files",
            label: "File Activity",
            content: (
              <Suspense fallback={<p className="text-xs text-muted-foreground">Loading…</p>}>
                <FileTab entityType={entityType} entityId={entityId} />
              </Suspense>
            ),
          },
          {
            value: "compliance",
            label: "Compliance",
            content: (
              <Suspense fallback={<p className="text-xs text-muted-foreground">Loading…</p>}>
                <ComplianceTab entityType={entityType} entityId={entityId} />
              </Suspense>
            ),
          },
        ]}
      />
    </div>
  );
}

function SidePanel({ title, icon, children }: { title: string; icon?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="rounded-md border border-border bg-card">
      <header className="flex items-center gap-2 border-b border-border px-3 py-2">
        {icon && <span className="text-muted-foreground">{icon}</span>}
        <h3 className="text-display text-sm font-semibold tracking-tight">{title}</h3>
      </header>
      {children}
    </section>
  );
}
