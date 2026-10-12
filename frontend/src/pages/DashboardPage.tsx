import { useMemo, useRef } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { downloadCsv } from "@/lib/csv";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis } from "recharts";
import {
  AlertOctagon, AlertTriangle, ShieldAlert, ShieldCheck, Activity,
  TrendingUp, ArrowUpRight, ExternalLink, Database, FileWarning,
  ServerCog, PackageCheck, RefreshCw, ScanSearch, GitBranch,
} from "lucide-react";

import {
  findings,
  cve,
  dashboard,
  clusters,
  compliance,
  enterprise,
  federation,
  network,
  downloadAPIFile,
  scannerOperations,
  systemHealth,
  type CVEBundleStatus,
  type ClusterSummary,
  type ClusterDetail,
  type FedMember,
  type FedMembership,
  type Finding,
  type NetworkConversation,
  type PlatformFactsResponse,
  type ScanLifecycleStatus,
  type ScannerWorker,
  type Severity,
  type SystemHealthHeartbeat,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { RiskScore, RiskGauge } from "@/components/ui/risk-score";
import { Sparkline } from "@/components/ui/sparkline";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { ScannerDbCapacity } from "@/components/ScannerDbCapacity";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState } from "@/components/ui/states";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { fmtBytes, fmtRelative } from "@/lib/format";
import { cn } from "@/lib/cn";

const SEVERITY_COLORS: Record<Severity, string> = {
  info:     "var(--color-severity-info)",
  low:      "var(--color-severity-low)",
  medium:   "var(--color-severity-medium)",
  high:     "var(--color-severity-high)",
  critical: "var(--color-severity-critical)",
};

// NeuVector's Security Risk Score factors and their point caps (sum = 100). Exposure
// dominates because external attack surface is the top container risk.
const SCORE_FACTORS = [
  { k: "protection_mode", label: "Protection mode", cap: 30 },
  { k: "exposure",        label: "Ingress/Egress",  cap: 42 },
  { k: "vulnerabilities", label: "Vulnerabilities", cap: 16 },
  { k: "privileged",      label: "Privileged",      cap: 4 },
  { k: "root",            label: "Run as root",     cap: 4 },
  { k: "admission",       label: "Admission",       cap: 4 },
] as const;

export function DashboardPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError;
  const [requestedTab, setTab] = useTabParam("tab", "overview");
  const tab = ["overview", "posture", "network", "operations", "trends"].includes(requestedTab) ? requestedTab : "overview";
  // Severity/lifecycle totals come from dashboard.summary (server-aggregated),
  // so we only need a top slice of open findings for the visuals (composite
  // risk, top actions, heatmap, trend). One 250-row fetch instead of two
  // 1000-row fetches with detail_json — much faster page load.
  const open  = useQuery({
    queryKey: ["findings", "open", clusterId],
    queryFn: () => findings.list({ lifecycle: "open", cluster_id: clusterId, limit: 250 }),
    enabled: scopeReady,
  });
  const bundle = useQuery({ queryKey: ["cve", "bundle"],    queryFn: () => cve.bundle(), enabled: scopeReady });
  const cveStats = useQuery({ queryKey: ["cve", "stats"],   queryFn: () => cve.stats(), enabled: scopeReady, staleTime: 60_000 });
  const sum   = useQuery({
    queryKey: ["dashboard", clusterId],
    queryFn: () => dashboard.summary({ cluster_id: clusterId }),
    enabled: scopeReady,
  });
  const platform = useQuery({
    queryKey: ["cluster-platform", clusterId],
    queryFn: () => clusters.platformFacts(clusterId!),
    enabled: scopeReady,
    refetchInterval: 30_000,
  });
  const clusterHealth = useQuery({
    queryKey: ["system-health", "cluster", clusterId],
    queryFn: () => systemHealth.cluster(clusterId!),
    enabled: scopeReady,
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
  const fleetHealth = useQuery({
    queryKey: ["system-health"],
    queryFn: systemHealth.overview,
    enabled: scopeReady && tab === "operations",
    staleTime: 30_000,
    refetchInterval: 30_000,
  });
  const scanStatus = useQuery({
    queryKey: ["scan-status", "dashboard"],
    queryFn: scannerOperations.status,
    enabled: scopeReady,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });
  const scannerWorkers = useQuery({
    queryKey: ["scan-scanner-workers", "dashboard"],
    queryFn: scannerOperations.workers,
    enabled: scopeReady,
    staleTime: 60_000,
    refetchInterval: 60_000,
  });
  const federationState = useQuery({
    queryKey: ["fed-state", "dashboard"],
    queryFn: federation.state,
    enabled: scopeReady,
    staleTime: 60_000,
  });
  const federationMembers = useQuery({
    queryKey: ["fed-members", "dashboard"],
    queryFn: federation.members,
    enabled: scopeReady && !federationState.isError && federationState.data?.state === "master",
    staleTime: 60_000,
  });
  // Compliance posture (pass/fail across frameworks) + runtime threats in the
  // last 24h. Both feed the two posture tiles so the landing represents all
  // four platform pillars (vuln · compliance · runtime · network).
  const complianceSum = useQuery({
    queryKey: ["compliance", "summary", clusterId],
    queryFn: () => compliance.summary(clusterId),
    enabled: scopeReady,
    staleTime: 60_000,
  });
  const runtimeToday = useQuery({
    queryKey: ["runtime", "overview", "24h", clusterId],
    queryFn: () => enterprise.runtime({ hours: 24, cluster_id: clusterId }),
    enabled: scopeReady,
    staleTime: 60_000,
  });
  const qc = useQueryClient();
  const scanInFlight = useRef(false);
  const canSubmitPlatformScan = (id: string) => {
    const registry = qc.getQueryState<{ clusters: ClusterSummary[] }>(["clusters"]);
    const detail = qc.getQueryState<ClusterDetail>(["cluster", id]);
    const source = qc.getQueryState<PlatformFactsResponse>(["cluster-platform", id]);
    if (registry?.status === "error" || registry?.fetchStatus === "fetching" || registry?.isInvalidated || detail?.status === "error" || detail?.fetchStatus === "fetching" || detail?.isInvalidated) return false;
    const resolved = (registry?.status === "success" && registry.data?.clusters?.some((entry) => entry.id === id))
      || (detail?.status === "success" && detail.data?.id === id);
    return !!resolved && source?.status === "success" && source.fetchStatus === "idle" && !source.isInvalidated && source.data?.cluster_id === id && !!source.data.evidence;
  };
  const scanPlatform = useMutation({
    mutationFn: (id: string) => {
      if (!canSubmitPlatformScan(id)) throw new Error("Cluster or platform evidence changed before submission.");
      return clusters.scanPlatform(id);
    },
    onSuccess: (_result, id) => qc.invalidateQueries({ queryKey: ["cluster-platform", id] }),
  });
  const summaryData = scopeReady && !sum.isError ? sum.data : undefined;
  const healthData = scopeReady && !clusterHealth.isError ? clusterHealth.data : undefined;
  const complianceData = scopeReady && !complianceSum.isError ? complianceSum.data : undefined;
  const runtimeData = scopeReady && !runtimeToday.isError ? runtimeToday.data : undefined;
  const openData = scopeReady && !open.isError ? open.data : undefined;
  const platformData = scopeReady && !platform.isError && platform.data?.cluster_id === clusterId ? platform.data : undefined;
  const scannerUnavailable = scanStatus.isError || scannerWorkers.isError || bundle.isError;
  const federationUnavailable = federationState.isError || (federationState.data?.state === "master" && federationMembers.isError);
  const currentScan = scanPlatform.variables === clusterId;
  const requestPlatformScan = async () => {
    if (!scopeReady || !clusterId || !platformData?.evidence || platform.isFetching || scanPlatform.isPending || scanInFlight.current || !canSubmitPlatformScan(clusterId)) return;
    scanInFlight.current = true;
    try { await scanPlatform.mutateAsync(clusterId); } catch { /* Mutation feedback is rendered below. */ }
    finally { scanInFlight.current = false; }
  };
  const openItems = useMemo(() => openData?.findings ?? [], [openData]);
  const allItems = openItems; // Finding trends describe only this loaded sample.
  const clusterPath = (path: string) => clusterId ? `/clusters/${clusterId}${path}` : path;

  // Counts always come from the complete server aggregate, never the loaded sample.
  const counts = {
    open: summaryData?.open_findings ?? 0,
    critical: summaryData?.findings_by_severity?.critical ?? 0,
    high: summaryData?.findings_by_severity?.high ?? 0,
    accepted: summaryData?.accepted_risks ?? 0,
  };
  const severityCounts = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((severity) => ({ severity, value: summaryData?.findings_by_severity?.[severity] ?? 0 }))
    .filter((entry) => entry.value > 0);
  const posture = summaryData?.posture;
  const risk = posture?.security_score ?? 0;
  const eventsTimelineQ = useQuery({
    queryKey: ["events-timeline", clusterId],
    queryFn: () => dashboard.eventsTimeline({ cluster_id: clusterId }),
    enabled: scopeReady,
    staleTime: 300_000, // 5min — heavy query, secondary widget
  });
  const exposureQ = useQuery({
    queryKey: ["exposure", clusterId],
    queryFn: () => network.exposure({ cluster_id: clusterId }),
    enabled: scopeReady,
  });
  const conversationsQ = useQuery({
    queryKey: ["network-conversations", "dashboard-denies", clusterId],
    queryFn: () => network.conversations({ hours: 24, cluster_id: clusterId, verdict_group: "blocked", limit: 5000 }),
    enabled: scopeReady,
    staleTime: 60_000,
  });
  const trends = useMemo(() => fourteenDayBySeverity(allItems), [allItems]);
  const topActions = useMemo(() => prioritizeActionItems(openItems), [openItems]);
  const recent = summaryData?.recent_activity ?? [];
  const activityCohortAvailable = recent.every(row => row.id && /^[1-9]\d*$/.test(row.id));
  const activityPath = activityCohortAvailable ? `/organization/audit?event_ids=${encodeURIComponent(recent.map(row => row.id).join(","))}` : "/organization/audit";
  const componentHealth = useMemo(
    () => summarizeComponentHealth(healthData?.heartbeats ?? []),
    [healthData?.heartbeats],
  );
  const scannerFreshness = useMemo(
    () => summarizeScannerFreshness(scannerUnavailable ? undefined : scanStatus.data, scannerUnavailable ? [] : scannerWorkers.data ?? [], scannerUnavailable ? undefined : bundle.data),
    [scannerUnavailable, scanStatus.data, scannerWorkers.data, bundle.data],
  );
  const conversationData = scopeReady && !conversationsQ.isError ? conversationsQ.data : undefined;
  const topNetworkDenies = useMemo(
    () => topDeniedConversations(conversationData?.conversations ?? []),
    [conversationData?.conversations],
  );
  const federationHealth = useMemo(
    () => summarizeFederationHealth(federationUnavailable ? undefined : federationState.data, federationUnavailable ? [] : federationMembers.data?.members ?? []),
    [federationUnavailable, federationState.data, federationMembers.data?.members],
  );

  // Compliance pass % aggregated across all reported frameworks.
  const compliancePosture = useMemo(() => {
    const frameworks = complianceData?.frameworks ?? [];
    const pass = frameworks.reduce((s, f) => s + (f.pass ?? 0), 0);
    const fail = frameworks.reduce((s, f) => s + (f.fail ?? 0), 0);
    const graded = pass + fail;
    return {
      pct: graded > 0 ? Math.round((pass / graded) * 100) : null,
      fail,
      frameworks: frameworks.length,
    };
  }, [complianceData]);
  // Runtime threats in the last 24h: alerting/blocking events from the overview.
  const runtimeThreats = runtimeData?.summary;
  const runtimeEvidencePath = clusterPath(`/timeline?${new URLSearchParams({ tab: "event", ...(runtimeThreats?.window_start ? { after: runtimeThreats.window_start } : { hours: "24" }), verdict: "alert,block,quarantine" })}`);
  const eventEvidencePath = clusterPath(`/timeline?${new URLSearchParams({ tab: "event", ...(eventsTimelineQ.data?.window_start ? { after: eventsTimelineQ.data.window_start } : { hours: "336" }), severity: "high,critical", after_exclusive: "true" })}`);
  const countFrom = (query: {isError:boolean;isPending:boolean},value: number|string|undefined) => !scopeReady ? "Scope unavailable" : query.isError ? "Unavailable" : query.isPending ? "Loading" : value ?? "Not reported";
  const evidenceSources = [
    {id:"risk",metric:"Risk score",count:countFrom(sum,posture?.security_score),source:"Dashboard summary",population:"Cluster posture model, capped at 100; higher is worse",destination:clusterPath("/dashboard?tab=posture"),destinationLabel:"Review score factors"},
    ...(["critical","high"] as const).map(severity=>({id:severity,metric:`${severity} open records`,count:countFrom(sum,summaryData?.findings_by_severity?.[severity]),source:"Dashboard summary",population:"Cluster open finding records; canonical vulnerability set excludes workload duplicates",destination:clusterPath(`/findings?view=instances&severity=${severity}&lifecycle=open`),destinationLabel:`Exact ${severity} open record cohort`})),
    {id:"open",metric:"Open records",count:countFrom(sum,summaryData?.open_findings),source:"Dashboard summary",population:"All cluster open finding records; canonical vulnerability deduplication",destination:clusterPath("/findings?view=instances&lifecycle=open"),destinationLabel:"Exact open record cohort"},
    {id:"accepted",metric:"Accepted records",count:countFrom(sum,summaryData?.accepted_risks),source:"Dashboard summary",population:"All cluster accepted finding records; canonical vulnerability deduplication",destination:clusterPath("/findings?view=instances&lifecycle=accepted"),destinationLabel:"Exact accepted record cohort"},
    {id:"compliance",metric:"Compliance pass percentage",count:countFrom(complianceSum,compliancePosture.pct==null?undefined:`${compliancePosture.pct}%`),source:"Compliance summary",population:"Cluster pass / (pass + fail) across reported frameworks; manual and exempted controls excluded",destination:clusterPath("/compliance?tab=controls&framework=all&status=graded"),destinationLabel:"Exact graded records across frameworks"},
    {id:"runtime",metric:"Runtime alert records · 24h",count:countFrom(runtimeToday,runtimeThreats?.alerts),source:"Runtime overview · hours=24",population:"Cluster event records with alert, block or quarantine verdict; precise source lower bound is retained when reported",destination:runtimeEvidencePath,destinationLabel:"Exact runtime alert event cohort"},
    {id:"image",metric:"Open image CVE records",count:countFrom(sum,posture?.vulns_by_location?.image),source:"Dashboard summary",population:"Cluster open vulnerability records with exact image-workload target",destination:clusterPath("/findings?view=instances&kind=vulnerability&lifecycle=open&target_type=image-workload"),destinationLabel:"Exact open image CVE record cohort"},
    {id:"host",metric:"Open host CVE records",count:countFrom(sum,posture?.vulns_by_location?.host),source:"Dashboard summary",population:"Cluster open vulnerability records with exact host target, including unnamed nodes",destination:clusterPath("/findings?view=instances&kind=vulnerability&lifecycle=open&target_type=host"),destinationLabel:"Exact open host CVE record cohort"},
    {id:"fixable",metric:"Fixable open CVE records",count:countFrom(sum,posture?.vuln_signals?.fixable),source:"Dashboard summary",population:"Cluster canonical open vulnerabilities with supported fixed-version metadata",destination:clusterPath("/findings?view=instances&kind=vulnerability&lifecycle=open&fixable=true"),destinationLabel:"Exact fixable open vulnerability cohort"},
    ...(["privileged","run_as_root","exposed"] as const).map(fact=>({id:fact,metric:`${fact} risk facts`,count:countFrom(sum,posture?.hardening?.[fact]),source:"Dashboard summary",population:`Cluster deployments reporting the ${fact === "exposed" ? "net_exposure" : fact} risk-factor key; numeric value is not tested by this counter`,destination:clusterPath(`/deployments?hide_platform=false&risk_fact=${fact === "exposed" ? "net_exposure" : fact}`),destinationLabel:"Exact recorded risk-factor cohort"})),
    {id:"deny",metric:"Loaded blocked conversation pairs",count:countFrom(conversationsQ,conversationData?.conversations.length),source:"Network conversations · blocked · 24h",population:`Cluster loaded sample, up to 5,000 pairs; matching server total ${conversationData?.total ?? "not reported"}; panel ranks up to five`,destination:clusterPath("/network?tab=conversations&hours=24&verdict_group=blocked&hide_platform=false"),destinationLabel:"Exact blocked-pair cohort with server pages"},
    {id:"exposure",metric:"Returned exposure rows",count:countFrom(exposureQ,exposureQ.data ? exposureQ.data.ingress.length+exposureQ.data.egress.length : undefined),source:"Network exposure · 168h",population:"Cluster observed external traffic; up to 50 workloads per direction. A workload may appear in both directions; CSV covers returned rows",destination:clusterPath("/dashboard?tab=network"),destinationLabel:"Review returned exposure evidence and exact directed links"},
    {id:"findings-sample",metric:"Loaded open finding sample",count:countFrom(open,openData?.findings?.length),source:"Findings list · open · limit=250",population:"Cluster top 250 by risk; action items and 14-day first-seen charts describe this loaded sample",destination:clusterPath("/findings?view=instances&lifecycle=open"),destinationLabel:"Browse full open record cohort with server pages"},
    {id:"top-workloads",metric:"Top vulnerable workload rows",count:countFrom(sum,posture?.top_vulnerable?.length),source:"Dashboard summary",population:"Cluster top six inventory rows by critical/high counts; per-row links resolve exact deployment ID, or labeled search for legacy responses",destination:clusterPath("/dashboard?tab=network"),destinationLabel:"Review returned top-workload evidence"},
    {id:"components",metric:"Returned component reports",count:countFrom(clusterHealth,healthData?.heartbeats?.length),source:"Cluster system health",population:"Cluster component heartbeat reports; role health uses declared role expectations",destination:clusterPath("/components"),destinationLabel:"Review component reports and roles"},
    {id:"scanner",metric:"Returned scanner workers",count:countFrom(scannerWorkers,scannerUnavailable?undefined:scannerWorkers.data?.length),source:"Scanner worker inventory",population:"Organization-wide worker reports; capacity is broader than the selected cluster",destination:"/settings/scanner",destinationLabel:"Review organization scanner capacity"},
    {id:"federation",metric:"Returned federation members",count:federationUnavailable?"Unavailable":federationState.data?.state!=="master"?countFrom(federationState,"Not master; member inventory not requested"):countFrom(federationMembers,federationMembers.data?.members.length),source:"Federation state / members",population:"Organization-wide membership; member inventory is requested only on the master",destination:"/federation",destinationLabel:"Review organization federation state"},
    {id:"platform",metric:"Returned platform package records",count:countFrom(platform,platformData?.evidence?.packages?.length),source:"Cluster platform facts",population:"Current cluster's returned platform evidence; package count and returned rows can differ",destination:clusterPath("/dashboard?tab=operations"),destinationLabel:"Review platform evidence, source status and scan job"},
    {id:"events-14d",metric:"Security event records · 14d",count:countFrom(eventsTimelineQ,eventsTimelineQ.data?.events_timeline?.reduce((total,row)=>total+row.total,0)),source:"Dashboard event timeline",population:"Cluster aggregate of high/critical events over fourteen days, distinct from the loaded finding first-seen chart",destination:eventEvidencePath,destinationLabel:"Exact high/critical event cohort"},
    {id:"activity",metric:"Returned organization audit records",count:countFrom(sum,summaryData?.recent_activity?.length),source:"Dashboard summary · recent activity",population:"Organization-wide latest 20 audit rows; landing panel displays up to eight. Selected record IDs preserve the returned cohort",destination:activityPath,destinationLabel:activityCohortAvailable ? "Exact returned organization audit records" : "Browse organization audit history"},
  ];
  const sourceColumns: Column<typeof evidenceSources[number]>[] = [
    {id:"metric",header:"Metric or view",kind:"name",wrap:true,cell:row=>row.metric,exportValue:row=>row.metric},
    {id:"count",header:"Reported / loaded count",kind:"count",cell:row=>row.count,exportValue:row=>row.count},
    {id:"source",header:"Source",kind:"text",wrap:true,cell:row=>row.source,exportValue:row=>row.source},
    {id:"population",header:"Scope and source limits",kind:"text",wrap:true,cell:row=>row.population,exportValue:row=>row.population},
    {id:"destination",header:"Destination contract",kind:"text",wrap:true,cell:row=><a href={row.destination} className="text-primary hover:underline">{row.destinationLabel}</a>,exportValue:row=>`${row.destinationLabel} · ${row.destination}`},
  ];


  const navigate = useNavigate();

  const overviewView = <div className="space-y-5">
      {/* Action items + recent activity */}
      <section className="c-rise c-rise-3 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel
          className="min-w-0"
          title="Action Items"
          subtitle="Top 10 critical/high findings from 250 open findings ranked by risk"
          icon={<ShieldAlert className="h-3.5 w-3.5" />}
          rightSlot={<a href={clusterPath("/findings?view=instances&lifecycle=open")} className="text-[11px] text-muted-foreground hover:text-foreground">view all <ArrowUpRight className="inline h-3 w-3" /></a>}
        >
          {open.isError ? <ErrorState title="Could not load action items." action={<Button onClick={() => void open.refetch()}>Retry</Button>} /> : open.isPending ? <p className="p-3 text-sm text-muted-foreground">Loading action items…</p> : topActions.length === 0 ? (
            <EmptyState
              title="No critical or high findings in the loaded sample"
              hint="When new severe findings appear they'll show up here for one-click triage."
              icon={<ShieldCheck className="h-8 w-8" />}
            />
          ) : (
            <ul className="divide-y divide-border">
              {topActions.map((f) => (
                <li key={f.id} className="accent-slide flex items-center gap-3 px-3 py-2 hover:bg-muted/40 transition-colors">
                  <SeverityBadge severity={f.severity} kev={false} />
                  <div className="min-w-0 flex-1">
                    <a href={clusterPath(`/findings/${f.id}`)} className="text-sm hover:underline truncate block" title={f.title}>
                      {f.title}
                    </a>
                    <div className="text-[10px] text-mono text-muted-foreground">
                      {f.external_id ?? f.id.slice(0, 10)} · {f.kind} · {fmtRelative(f.last_seen_at)}
                    </div>
                  </div>
                  <RiskScore score={f.risk_score} size="sm" />
                  <Button size="sm" variant="outline" onClick={() => navigate({ href: clusterPath(`/findings/${f.id}`) })}>Triage</Button>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Security Events"
          rightSlot={<a href={eventEvidencePath} className="text-xs text-primary hover:underline">View matching events</a>}
          subtitle="High + critical alerts · last 14 days"
          icon={<AlertTriangle className="h-3.5 w-3.5" />}
        >
          {(() => {
            if (eventsTimelineQ.isError) return <ErrorState title="Could not load event history." />;
            if (eventsTimelineQ.isPending) return <p className="p-3 text-xs text-muted-foreground">Loading events…</p>;
            const raw = eventsTimelineQ.data?.events_timeline ?? [];
            const totalAlerts = raw.reduce((a, d) => a + d.total, 0);
            if (totalAlerts === 0) return <EmptyState title="No alerting events" hint="No high/critical security events in the last 14 days." />;
            const tl = raw.map((d) => ({ date: d.date, high: Math.max(0, d.total - d.critical), critical: d.critical }));
            return (
              <div className="p-3">
                <div className="mb-1 text-xs text-muted-foreground">{totalAlerts.toLocaleString()} alerts · {raw.reduce((a, d) => a + d.critical, 0).toLocaleString()} critical</div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={tl} barCategoryGap={2}>
                    <XAxis dataKey="date" tickFormatter={(d: string) => d.slice(5)} tick={{ fontSize: 9, fill: "var(--color-muted-foreground)" }} interval={1} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={tooltipStyle} labelFormatter={(d) => d} formatter={(v: number, n: string) => [v, n === "critical" ? "Critical" : "High"]} />
                    <Bar dataKey="high" stackId="a" fill="var(--color-severity-high)" radius={[0, 0, 0, 0]} />
                    <Bar dataKey="critical" stackId="a" fill="var(--color-severity-critical)" radius={[2, 2, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            );
          })()}
        </Panel>

        <Panel
          title="Organization Recent Activity"
          rightSlot={<a href={activityPath} className="text-xs text-primary hover:underline">{activityCohortAvailable ? "View selected activity" : "View organization audit history"}</a>}
          subtitle="Latest 20 organization audit records; showing up to eight"
          icon={<Activity className="h-3.5 w-3.5" />}
        >
          {sum.isError ? <ErrorState title="Could not load recent activity." /> : sum.isPending ? <p className="p-3 text-xs text-muted-foreground">Loading activity…</p> : recent.length === 0 ? (
            <EmptyState title="No recent activity" hint="Triage actions and runtime events will appear here." />
          ) : (
            <ul className="divide-y divide-border">
              {recent.slice(0, 8).map((r, i) => (
                <li key={i} className="px-3 py-2 text-xs">
                  <div className="flex items-center gap-1.5">
                    <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono">{r.id ? <a href={`/organization/audit?event_id=${encodeURIComponent(r.id)}`} className="hover:underline">{r.action}</a> : r.action}</span>
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


  </div>;
  const postureView = <div className="space-y-5">
      {/* Hero band — Security RISK Score (NV model: higher = worse) + its 6 weighted factors */}
      <section className="c-rise c-rise-1 grid grid-cols-1 gap-6 rounded-md border border-border bg-card p-5 star-field lg:grid-cols-2">
        <div className="flex flex-col items-center justify-center gap-3 border-b border-border/60 pb-5 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-5">
          {posture ? <RiskGauge score={risk} label="risk score" size={132} /> : <p className="text-sm text-muted-foreground">Risk score unavailable</p>}
          <div className="text-center">
            <div className="text-display text-sm font-semibold leading-none" style={{ color: risk <= 20 ? "var(--color-severity-low)" : risk <= 50 ? "var(--color-severity-medium)" : "var(--color-severity-critical)" }}>
              {!posture ? "—" : risk <= 20 ? "Good" : risk <= 50 ? "Fair" : "Poor"}
            </div>
            <div className="mt-1 text-[11px] text-muted-foreground">{summaryData?.open_findings ?? "—"} open findings</div>
          </div>
        </div>
        <div className="flex flex-col justify-between gap-5">
          <StatGrid>
            <StatCard label="Critical" value={summaryData ? counts.critical : "—"} tone="critical" icon={<AlertOctagon className="h-3 w-3" />} href={clusterPath("/findings?severity=critical&lifecycle=open")} trend={trends.critical} />
            <StatCard label="High" value={summaryData ? counts.high : "—"} tone="high" icon={<AlertTriangle className="h-3 w-3" />} href={clusterPath("/findings?severity=high&lifecycle=open")} trend={trends.high} />
            <StatCard label="Open" value={summaryData ? counts.open : "—"} tone="accent" icon={<Activity className="h-3 w-3" />} href={clusterPath("/findings?view=instances&lifecycle=open")} trend={trends.open} />
            <StatCard label="Accepted" value={summaryData ? counts.accepted : "—"} tone="neutral" icon={<ShieldCheck className="h-3 w-3" />} href={clusterPath("/findings?lifecycle=accepted")} />
          </StatGrid>
          {/* Risk factors — NV's 6 weighted contributors (bar = share of its cap). */}
          <div>
            <div className="mb-2 text-[10px] uppercase tracking-[0.14em] text-muted-foreground">Risk factors · points of 100</div>
            <div className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2 xl:grid-cols-3">
              {SCORE_FACTORS.map(({ k, label, cap }) => {
                const v = posture?.score_breakdown?.[k] ?? 0;
                const ratio = v / cap;
                return (
                  <div key={k} className="flex items-center gap-2 text-[11px]">
                    <span className="w-[104px] shrink-0 text-muted-foreground">{label}</span>
                    <div className="h-1.5 flex-1 rounded-full bg-muted overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${Math.round(ratio * 100)}%`, background: ratio >= 0.66 ? "var(--color-severity-critical)" : ratio >= 0.33 ? "var(--color-severity-high)" : "var(--color-severity-medium)" }} />
                    </div>
                    <span className="w-11 shrink-0 text-right text-mono tabular-nums text-muted-foreground">{posture ? v : "—"}/{cap}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </section>

      <Collapse label="Additional posture metrics">
      {/* Posture metrics — one uniform, scannable grid (compliance · runtime · vuln location · hardening) */}
      <StatGrid className="c-rise c-rise-2">
        <StatCard label="Compliance" value={complianceSum.isPending ? "…" : compliancePosture.pct == null ? "—" : `${compliancePosture.pct}%`}
          tone={compliancePosture.pct == null ? "neutral" : compliancePosture.pct >= 90 ? "low" : compliancePosture.pct >= 70 ? "medium" : "high"}
          icon={<ShieldCheck className="h-3 w-3" />} href={clusterPath("/compliance?tab=controls&framework=all&status=graded")}
          hint={complianceSum.isError ? "Unavailable" : compliancePosture.pct == null ? "no graded controls" : `${compliancePosture.fail} failing`} />
        <StatCard label="Runtime · 24h" value={runtimeToday.isPending ? "…" : (runtimeThreats?.alerts ?? "—")}
          tone={(runtimeThreats?.alerts ?? 0) > 0 ? "critical" : "neutral"} icon={<ShieldAlert className="h-3 w-3" />} href={runtimeEvidencePath}
          hint={runtimeThreats ? `${runtimeThreats.blocks} blocked` : "Unavailable"} />
        <StatCard label="Image CVEs" value={posture?.vulns_by_location?.image ?? "—"} tone="accent" icon={<AlertTriangle className="h-3 w-3" />} href={clusterPath("/findings?view=instances&kind=vulnerability&lifecycle=open&target_type=image-workload")} hint="Open image CVE records" />
        <StatCard label="Host CVEs" value={posture?.vulns_by_location?.host ?? "—"} tone={(posture?.vulns_by_location?.host ?? 0) > 0 ? "high" : "neutral"} icon={<AlertTriangle className="h-3 w-3" />} href={clusterPath("/findings?view=instances&kind=vulnerability&lifecycle=open&target_type=host")} hint="Open host CVE records" />
        <StatCard label="Fixable now" value={posture?.vuln_signals?.fixable ?? "—"} tone="low" icon={<ShieldCheck className="h-3 w-3" />} href={clusterPath("/findings?view=instances&kind=vulnerability&lifecycle=open&fixable=true")} hint="patched version exists" />
        <StatCard label="Privileged facts" value={posture?.hardening?.privileged ?? "—"} tone={(posture?.hardening?.privileged ?? 0) > 0 ? "critical" : "low"} icon={<ShieldAlert className="h-3 w-3" />} href={clusterPath("/deployments?hide_platform=false&risk_fact=privileged")} hint="Workloads reporting this risk-factor key" />
        <StatCard label="Root facts" value={posture?.hardening?.run_as_root ?? "—"} tone={(posture?.hardening?.run_as_root ?? 0) > 0 ? "high" : "low"} icon={<ShieldAlert className="h-3 w-3" />} href={clusterPath("/deployments?hide_platform=false&risk_fact=run_as_root")} hint="Workloads reporting this risk-factor key" />
        <StatCard label="Exposure facts" value={posture?.hardening?.exposed ?? "—"} tone={(posture?.hardening?.exposed ?? 0) > 0 ? "medium" : "low"} icon={<Activity className="h-3 w-3" />} href={clusterPath("/deployments?hide_platform=false&risk_fact=net_exposure")} hint="Workloads reporting this risk-factor key" />
      </StatGrid>

      </Collapse>

  </div>;
  const networkView = <div className="space-y-5">
      {/* Exposed services (ingress/egress) + enforcement coverage — NV signature panels */}
      <section className="c-rise c-rise-2 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          <Panel title="Exposed Services" subtitle="Observed over seven days · up to 50 workloads per direction; CSV covers returned rows" rightSlot={<Button size="sm" disabled={!exposureQ.data || exposureQ.isError || exposureQ.isFetching} onClick={() => downloadCsv("constellation-exposure", ["Direction", "Workload", "Namespace", "Platform role", "External peers", "Sessions", "Policy mode"], [
            ...(exposureQ.data?.ingress ?? []).map((service) => ["ingress", service.workload, service.namespace, service.platform_role ?? "", service.external_peers, service.sessions, service.policy_mode]),
            ...(exposureQ.data?.egress ?? []).map((service) => ["egress", service.workload, service.namespace, service.platform_role ?? "", service.external_peers, service.sessions, service.policy_mode]),
          ])}>Export CSV</Button>} icon={<Activity className="h-3.5 w-3.5" />}>
            {exposureQ.isError ? <ErrorState title="Could not load exposure." action={<Button onClick={() => void exposureQ.refetch()}>Retry</Button>} /> : exposureQ.isPending ? (
              <p className="p-3 text-xs text-muted-foreground">Loading exposure…</p>
            ) : ((exposureQ.data?.ingress.length ?? 0) + (exposureQ.data?.egress.length ?? 0)) === 0 ? (
              <EmptyState title="No external exposure observed" hint="No ingress/egress traffic to external endpoints in the last 7 days." />
            ) : (
              <div className="divide-y divide-border">
                {(exposureQ.data?.ingress ?? []).map((s) => <ExposedRow key={"in" + s.workload} s={s} dir="ingress" clusterPath={clusterPath} />)}
                {(exposureQ.data?.egress ?? []).map((s) => <ExposedRow key={"eg" + s.workload} s={s} dir="egress" clusterPath={clusterPath} />)}
              </div>
            )}
          </Panel>

          <Panel
            title="Top Network Denies"
            subtitle="Top blocked service pairs in the loaded last-24h sample (up to 5,000 pairs)"
            icon={<ShieldAlert className="h-3.5 w-3.5" />}
            rightSlot={<a href={clusterPath("/network?tab=conversations&hours=24&verdict_group=blocked&hide_platform=false")} className="text-[11px] text-muted-foreground hover:text-foreground">view conversations <ArrowUpRight className="inline h-3 w-3" /></a>}
          >
            <div data-testid="dashboard-network-denies">
              {conversationsQ.isError ? <ErrorState title="Could not load network conversations." /> : conversationsQ.isPending ? (
                <p className="p-3 text-xs text-muted-foreground">Loading denied conversations...</p>
              ) : topNetworkDenies.length === 0 ? (
                <EmptyState title="No network denies observed" hint="Denied or blocked service pairs will rank here when enforcement drops traffic." />
              ) : (
                <ul className="divide-y divide-border">
                  {topNetworkDenies.map((row, index) => (
                    <li key={`${row.from}-${row.to}-${index}`}>
                      <a href={clusterPath(`/network?tab=conversations&hours=24&verdict_group=blocked&from=${encodeURIComponent(row.from)}&to=${encodeURIComponent(row.to)}&hide_platform=false`)} className="flex items-center gap-3 px-3 py-2 hover:bg-muted/40 transition-colors">
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-xs font-medium">
                            <span className="font-mono">{row.from}</span>
                            <span className="px-1.5 text-muted-foreground">→</span>
                            <span className="font-mono">{row.to}</span>
                          </div>
                          <div className="mt-0.5 truncate text-[10px] text-muted-foreground">
                            {fmtBytes(row.bytes)} · {row.packets.toLocaleString()} packets
                            {(row.apps?.length ?? 0) > 0 && ` · ${row.apps?.slice(0, 3).join(", ")}`}
                            {row.last_seen && ` · ${fmtRelative(row.last_seen)}`}
                          </div>
                        </div>
                        <span className="shrink-0 rounded bg-[color-mix(in_oklab,var(--color-status-error)_16%,transparent)] px-1.5 py-0.5 text-[9px] font-medium uppercase tracking-wide text-[color:var(--color-status-error)]">
                          {row.verdict || "deny"}
                        </span>
                      </a>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Panel>
        </div>
        <div className="space-y-4">
        <Panel title="Policy Mode Maturity" subtitle="Current group enforcement modes" icon={<ShieldCheck className="h-3.5 w-3.5" />}>
          <div className="p-3 space-y-4">
            {(() => {
              if (!posture) return <p className="text-sm text-muted-foreground">Enforcement summary unavailable.</p>;
              const e = posture.enforcement;
              if (!e || typeof e.groups !== "number") return <div className="space-y-3"><p className="text-sm text-muted-foreground">Configured group modes not reported.</p><div className="flex flex-wrap gap-4 text-xs"><a href={clusterPath("/groups")} className="text-primary hover:underline">Manage group modes</a><a href={clusterPath("/groups/settings")} className="text-primary hover:underline">Edit new-service defaults</a></div></div>;
              const groups = e.groups;
              return (
                <>
                  <ModeMaturity label="Network mode" groups={groups} discover={e.discover ?? 0} monitor={e.monitor ?? 0} protect={e.protect ?? 0} />
                  <ModeMaturity label="Process / File mode" groups={groups} discover={e.profile_discover ?? 0} monitor={e.profile_monitor ?? 0} protect={e.profile_protect ?? 0} />
                  {(() => {
                    const cm = posture?.cves_by_mode ?? {};
                    const em = posture?.exposed_by_mode ?? {};
                    const modeRows = ["discover", "monitor", "protect"].map(mode => ({ mode, cves: cm[mode], exposed: em[mode] }));
                    return <div className="border-t border-border pt-3 space-y-2"><p className="text-xs text-muted-foreground">Reported risk by configured group mode · these counters are not applier health. Vulnerability IDs are deduplicated within each mode and may occur in more than one mode. Workloads use their strongest configured group mode; workloads without a matching group are excluded. Exposure counts workloads reporting a net_exposure risk-factor key, including zero or null values.</p><DataTable rows={modeRows} columns={[
                      { id: "mode", header: "Configured mode", kind: "name", cell: row => row.mode },
                      { id: "cves", header: "Distinct open vulnerability IDs", kind: "count", cell: row => row.cves == null ? "Not reported" : <a className="text-primary hover:underline" href={clusterPath(`/findings?view=cve&kind=vulnerability&lifecycle=open&target_type=image-workload&group_mode=${row.mode}&id_scope=all`)}>{row.cves}</a> },
                      { id: "exposed", header: "Exposed workloads", kind: "count", cell: row => row.exposed == null ? "Not reported" : <a className="text-primary hover:underline" href={clusterPath(`/deployments?hide_platform=false&risk_fact=net_exposure&group_mode=${row.mode}`)}>{row.exposed}</a> },
                    ]} rowKey={row => row.mode} showDensityToggle={false} showColumnChooser={false} pagination={false} testId="dashboard-risk-by-mode"/><p className="text-xs text-muted-foreground">Platform / Host distinct open vulnerability IDs: {cm.platform == null ? "Not reported" : <a href={clusterPath("/findings?view=cve&kind=vulnerability&lifecycle=open&target_type=platform&id_scope=all")} className="text-primary hover:underline">{cm.platform}</a>} / {cm.host == null ? "Not reported" : <a href={clusterPath("/findings?view=cve&kind=vulnerability&lifecycle=open&target_type=host&id_scope=all")} className="text-primary hover:underline">{cm.host}</a>}.</p></div>;
                  })()}
                  <div className="flex flex-wrap gap-4 border-t border-border pt-3 text-xs">
                    <a href={clusterPath("/groups")} className="text-primary hover:underline">Manage group modes</a>
                    <a href={clusterPath("/groups/settings")} className="text-primary hover:underline">Edit new-service defaults</a>
                  </div>
                  <div className="flex items-center justify-between border-t border-border pt-2 text-xs">
                    <span className="text-muted-foreground">Admission control</span>
                    {(e.admission_enforcing ?? 0) > 0 ? (
                      <span className="flex items-center gap-1.5 text-[color:var(--color-severity-low)]"><span className="inline-block h-2 w-2 rounded-full" style={{ background: "var(--color-severity-low)" }} />configured enforce · {e.admission_enforcing} rule{(e.admission_enforcing ?? 0) === 1 ? "" : "s"}</span>
                    ) : (e.admission_policies ?? 0) > 0 ? (
                      <span className="text-[color:var(--color-severity-medium)]">configured monitor</span>
                    ) : (
                      <span className="text-[color:var(--color-severity-high)]">no enforce setting reported</span>
                    )}
                  </div>
                </>
              );
            })()}
          </div>
        </Panel>
        <Panel title="Top Vulnerable Assets" subtitle="Up to six reported workloads ranked by critical/high inventory counts" icon={<AlertOctagon className="h-3.5 w-3.5" />}
          rightSlot={(posture?.top_vulnerable?.length ?? 0) > 0 ? (
            <button type="button"
              onClick={() => downloadCsv("constellation-vulnerable-workloads", ["Namespace", "Workload", "Critical", "High"],
                (posture?.top_vulnerable ?? []).map((t) => [t.namespace, t.name, t.critical, t.high]))}
              className="rounded-md border border-border bg-card px-2 py-1 text-[10px] font-medium hover:bg-accent">
              Export CSV
            </button>
          ) : undefined}
        >
          {!posture ? <p className="p-3 text-xs text-muted-foreground">Vulnerability summary unavailable.</p> : (posture.top_vulnerable?.length ?? 0) === 0 ? (
            <EmptyState title="No vulnerable workloads" hint="Workloads with critical/high CVEs will rank here." />
          ) : (
            <ul className="divide-y divide-border">
              {(posture?.top_vulnerable ?? []).map((t) => (
                <li key={`${t.namespace}/${t.name}`}>
                  <a href={t.id ? clusterPath(`/deployments/${encodeURIComponent(t.id)}`) : clusterPath(`/deployments?q=${encodeURIComponent(t.name)}&namespace=${encodeURIComponent(t.namespace)}&hide_platform=false`)} className="flex items-center gap-2 px-3 py-2 hover:bg-muted/40 transition-colors">
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-medium truncate">{t.name}</div>
                      <div className="text-[10px] text-muted-foreground truncate">{t.namespace}{!t.id && " · namespace + name search"}</div>
                    </div>
                    {t.critical > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-critical)" }}>{t.critical}C</span>}
                    {t.high > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-high)" }}>{t.high}H</span>}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Panel>
        </div>
      </section>


  </div>;
  const operationsView = <div className="space-y-5">
      {scopeReady && (
        <Collapse label="Organization scanner database and capacity"><section className="rounded-md border border-border bg-card p-4" data-testid="dashboard-scanner-db-capacity">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold">Organization scanner database and capacity</h2>
            <Link to="/settings/scanner" className="text-xs text-[color:var(--color-primary)] hover:underline">Scanner details</Link>
          </div>
          <ScannerDbCapacity heartbeats={fleetHealth.isError ? undefined : fleetHealth.data?.heartbeats} unavailable={fleetHealth.isError} loading={fleetHealth.isPending} />
          {fleetHealth.isError && <ErrorState title="Could not refresh organization scanner capacity." action={<Button onClick={() => void fleetHealth.refetch()}>Retry</Button>} />}
        </section></Collapse>
      )}

      {clusterId && (
        <section className="c-rise c-rise-1 space-y-4" data-testid="dashboard-operator-strip">
          <StatGrid data-testid="dashboard-component-health">
            {COMPONENT_ROLES.map((role) => {
              const health = componentHealth.roles[role.id];
              return (
                <div key={role.id} data-testid={`dashboard-component-link-${role.id}`}>
                  <StatCard
                    label={role.label}
                    value={!healthData ? "—" : `${health.healthy}/${health.total}`}
                    tone={componentRoleTone(health)}
                    icon={role.icon}
                    href={clusterPath(`/components?role=${role.id}`)}
                    hint={clusterHealth.isError ? "Unavailable" : clusterHealth.isPending ? "Loading…" : componentRoleHint(health)}
                  />
                </div>
              );
            })}
          </StatGrid>

          <div className="grid gap-4 lg:grid-cols-2">
            <Link
              to="/settings/scanner"
              className="group block rounded-md border border-border bg-card p-3 transition-colors hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]"
              data-testid="dashboard-scanner-freshness"
            >
              <div className="mb-3 flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                    <Database className="h-3 w-3" />
                    Organization Scanner DB
                  </div>
                  <div className="mt-1 truncate text-display text-xl font-semibold">
                    {scannerUnavailable ? "Unavailable" : scanStatus.isPending || scannerWorkers.isPending || bundle.isPending ? "Loading..." : scannerFreshness.version || "Not reported"}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-2">
                  <StatusChip value={scannerUnavailable ? "unavailable" : scanStatus.isPending || scannerWorkers.isPending || bundle.isPending ? "pending" : scannerFreshness.status} />
                  <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                </div>
              </div>
              {!scannerUnavailable && !scanStatus.isPending && !scannerWorkers.isPending && !bundle.isPending && <dl className="space-y-2 text-xs">
                <Row k="Freshness" v={<span className="text-mono text-muted-foreground">{scannerFreshness.freshnessLabel}</span>} />
                <Row k="Workers" v={<span className="text-mono">{scannerFreshness.workersWithDb}/{scannerFreshness.workers}</span>} />
                <Row k="Queue" v={<span className="text-mono text-muted-foreground">{scannerFreshness.scheduled.toLocaleString()} queued · {scannerFreshness.scanning.toLocaleString()} running</span>} />
                <Row
                  k="Failures"
                  v={
                    <span className={cn("text-mono", scannerFreshness.failed > 0 ? "text-[color:var(--color-severity-high)]" : "text-muted-foreground")}>
                      {scannerFreshness.failed.toLocaleString()}
                    </span>
                  }
                />
              </dl>}
              <p className="mt-3 text-xs text-muted-foreground">Scanner database and queue cover the organization; capacity below covers this cluster.</p>
              <div className="mt-3 border-t border-border pt-3">
                <ScannerDbCapacity heartbeats={healthData?.heartbeats} unavailable={clusterHealth.isError} loading={clusterHealth.isPending} />
              </div>
            </Link>

            {(federationUnavailable || federationState.isPending || federationHealth.participating) && (
              <Link
                to="/federation"
                className="group block rounded-md border border-border bg-card p-3 transition-colors hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]"
                data-testid="dashboard-federation-health"
              >
                <div className="mb-3 flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-muted-foreground">
                      <GitBranch className="h-3 w-3" />
                      Organization Federation
                    </div>
                    <div className="mt-1 truncate text-display text-xl font-semibold capitalize">
                      {federationUnavailable ? "Unavailable" : federationState.isPending ? "Loading…" : federationHealth.state}
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <StatusChip value={federationUnavailable ? "unavailable" : federationState.isPending || (federationState.data?.state === "master" && federationMembers.isPending) ? "pending" : federationHealth.status} />
                    <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                  </div>
                </div>
                {!federationUnavailable && !federationState.isPending && !(federationState.data?.state === "master" && federationMembers.isPending) && <dl className="space-y-2 text-xs">
                  <Row k="Members" v={<span className="text-mono">{federationHealth.activeMembers}/{federationHealth.members}</span>} />
                  <Row k="Revision" v={<span className="text-mono text-muted-foreground">{federationHealth.revision}</span>} />
                  <Row k="Stale" v={<span className={cn("text-mono", federationHealth.staleMembers > 0 ? "text-[color:var(--color-severity-high)]" : "text-muted-foreground")}>{federationHealth.staleMembers}</span>} />
                  <Row k="Updated" v={<span className="text-mono text-muted-foreground">{federationHealth.updatedLabel}</span>} />
                </dl>}
                <p className="mt-3 text-xs text-muted-foreground">Federation membership and revision cover the organization.</p>
              </Link>
            )}
          </div>
        </section>
      )}

      {clusterHealth.isError && <ErrorState title="Could not refresh cluster component health." action={<Button onClick={() => void clusterHealth.refetch()}>Retry</Button>} />}
      {scannerUnavailable && <ErrorState title="Could not refresh organization scanner health." action={<Button onClick={() => { void scanStatus.refetch(); void scannerWorkers.refetch(); void bundle.refetch(); }}>Retry</Button>} />}
      {federationUnavailable && <ErrorState title="Could not refresh organization federation health." action={<Button onClick={() => { void federationState.refetch(); if (federationState.data?.state === "master") void federationMembers.refetch(); }}>Retry</Button>} />}
      {clusterId && (
        <section className="c-rise c-rise-2">
          <PlatformPanel
            data={platformData}
            loading={platform.isPending}
            failed={platform.isError || (!platform.isPending && !!platform.data && platform.data.cluster_id !== clusterId)}
            refreshing={platform.isFetching}
            scanning={scanPlatform.isPending}
            scanError={currentScan && scanPlatform.isError}
            scanResult={currentScan ? scanPlatform.data : undefined}
            onRetry={() => void platform.refetch()}
            onScan={() => void requestPlatformScan()}
          />
        </section>
      )}


  </div>;
  const trendsView = <div className="space-y-5">
      {/* Bottom row: distribution · CVE DB · trend */}
      <section className="c-rise c-rise-5 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Panel title="Severity Distribution" icon={<AlertTriangle className="h-3.5 w-3.5" />}>
          {sum.isError ? <ErrorState title="Could not load severity totals." /> : sum.isPending ? <p className="p-3 text-xs text-muted-foreground">Loading severity totals…</p> : severityCounts.length === 0 ? (
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
          {bundle.isError || cveStats.isError ? <ErrorState title="Could not refresh organization vulnerability database status." action={<Button onClick={() => { void bundle.refetch(); void cveStats.refetch(); }}>Retry</Button>} /> : bundle.isPending || cveStats.isPending ? <p className="text-xs text-muted-foreground">Loading vulnerability database…</p> : bundle.data?.available || (cveStats.data?.total ?? 0) > 0 ? (
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

        <Panel title="Loaded findings · 14 day trend" icon={<TrendingUp className="h-3.5 w-3.5" />}>
          <div className="px-2">
            <Sparkline data={trends.openSeries} width={300} height={80} color="var(--color-primary)" />
            <div className="mt-2 flex items-center justify-between text-[10px] text-muted-foreground">
              <span>250 open findings ranked by risk · 14d ago</span>
              <span>today</span>
            </div>
            <div className="mt-2 text-mono text-[11px]">
              <span className="text-foreground">Records in loaded sample with first-seen dates in this window: </span>
              <span className="text-foreground">{trends.openSeries.reduce((a, b) => a + b, 0)}</span>
              <span className="text-muted-foreground"> · peak {Math.max(0, ...trends.openSeries)}</span>
            </div>
          </div>
        </Panel>
      </section>
  </div>;
  return (
    <div className="space-y-5" data-testid="dashboard-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title={scopeReady && cluster?.name ? `${cluster.name} — Dashboard` : "Security Dashboard"}
        description={
          clusterId
            ? "Risk-first snapshot for this cluster. Click any tile to drill in."
            : "A risk-first snapshot of your fleet. Click any tile to drill in."
        }
        actions={
          <button
            type="button"
            title="Download the organization-wide executive security report"
            onClick={() => downloadAPIFile("/reports/executive.pdf", "constellation-executive-report.html")}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent"
          >
            <FileWarning className="h-4 w-4" /> Organization report
          </button>
        }
      />


      <VerdictBanner status={clusterError || sum.isError ? "degraded" : !posture ? "info" : risk > 50 ? "critical" : risk > 20 ? "degraded" : "ok"}
        title={clusterError ? "Cluster context unavailable" : !scopeReady ? clusterLoading ? "Resolving cluster" : "Select a resolved cluster" : sum.isError ? "Security summary unavailable" : !posture ? sum.isPending ? "Loading security posture" : "Security posture not reported" : `Security risk: ${risk}/100`}
        detail={`Higher scores indicate more risk. Summary counts cover ${clusterId ? "this cluster" : "the organization"}; action items and finding trends use a bounded sample.`} />
      <StatGrid data-testid="dashboard-summary">
        <StatCard label="Risk score" value={posture?.security_score ?? "—"} href={scopeReady ? clusterPath("/dashboard?tab=posture") : undefined} />
        <StatCard label="Critical" value={summaryData ? counts.critical : "—"} tone="critical" href={scopeReady ? clusterPath("/findings?severity=critical&lifecycle=open") : undefined} />
        <StatCard label="High" value={summaryData ? counts.high : "—"} tone="high" href={scopeReady ? clusterPath("/findings?severity=high&lifecycle=open") : undefined} />
        <StatCard label="Open" value={summaryData?.open_findings ?? "—"} href={scopeReady ? clusterPath("/findings?view=instances&lifecycle=open") : undefined} />
        <StatCard label="Accepted" value={summaryData?.accepted_risks ?? "—"} href={scopeReady ? clusterPath("/findings?lifecycle=accepted") : undefined} />
      </StatGrid>
      {scopeReady && sum.isError && <ErrorState title="Could not refresh dashboard totals." action={<Button onClick={() => void sum.refetch()}>Retry</Button>} />}
      {!scopeReady ? clusterError ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={() => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId] }); }}>Retry</Button>} /> : <p role="status" className="text-sm text-muted-foreground">{clusterLoading ? "Resolving cluster…" : "Select a resolved cluster to view the dashboard."}</p> : <Tabs value={tab} onValueChange={setTab} items={[
        { value: "overview", label: "Overview", content: overviewView },
        { value: "posture", label: "Posture", content: postureView },
        { value: "network", label: "Network", content: networkView },
        { value: "operations", label: "Operations", content: operationsView },
        { value: "trends", label: "Trends", content: trendsView },
      ]} />}
      {scopeReady && <Collapse label="Advanced: metric sources and destination scope"><DataTable rows={evidenceSources} columns={sourceColumns} rowKey={row=>row.id} preferencesKey="dashboard-evidence-sources" exportFileName="dashboard-source-matrix.csv" exportLabel="Export source matrix" testId="dashboard-source-matrix"/></Collapse>}

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

type ComponentRoleID = "controller" | "enforcer" | "scanner" | "admission" | "discoverer";

interface ComponentRoleHealth {
  total: number;
  healthy: number;
  degraded: number;
  stale: number;
  drift: number;
  crashlooping: number;
  unhealthy: number;
  lastSeenAt?: string;
}

interface ComponentHealthSummary {
  roles: Record<ComponentRoleID, ComponentRoleHealth>;
}

interface ScannerFreshnessSummary {
  status: string;
  version: string;
  freshnessLabel: string;
  workers: number;
  workersWithDb: number;
  scheduled: number;
  scanning: number;
  failed: number;
}

interface FederationHealthSummary {
  participating: boolean;
  state: string;
  status: string;
  revision: number;
  members: number;
  activeMembers: number;
  staleMembers: number;
  updatedLabel: string;
}

const COMPONENT_ROLES: Array<{ id: ComponentRoleID; label: string; icon: React.ReactNode }> = [
  { id: "controller", label: "Controllers", icon: <ServerCog className="h-3 w-3" /> },
  { id: "enforcer", label: "Enforcers", icon: <ShieldAlert className="h-3 w-3" /> },
  { id: "scanner", label: "Scanners", icon: <ScanSearch className="h-3 w-3" /> },
  { id: "admission", label: "Admission", icon: <ShieldCheck className="h-3 w-3" /> },
  { id: "discoverer", label: "Import/Disc", icon: <PackageCheck className="h-3 w-3" /> },
];


function ExposedRow({ s, dir, clusterPath }: { s: import("@/api/client").ExposedService; dir: "ingress" | "egress"; clusterPath: (p: string) => string }) {
  return (
    <a href={clusterPath(`/network?tab=conversations&hours=168&from=${encodeURIComponent(dir === "ingress" ? "external" : s.workload)}&to=${encodeURIComponent(dir === "ingress" ? s.workload : "external")}&hide_platform=false`)} className="flex items-center gap-3 px-3 py-2 hover:bg-muted/40 transition-colors">
      <span className={cn("shrink-0 rounded px-1.5 py-0.5 text-[9px] uppercase tracking-wide font-medium",
        dir === "ingress" ? "bg-[color-mix(in_oklab,var(--color-severity-high)_16%,transparent)] text-[color:var(--color-severity-high)]" : "bg-muted text-muted-foreground")}>
        {dir === "ingress" ? "in" : "out"}
      </span>
      <div className="min-w-0 flex-1">
        <div className="text-xs font-medium truncate">{s.namespace ? `${s.namespace}/` : ""}{s.name}</div>
        <div className="text-[10px] text-muted-foreground truncate">
          {s.external_peers} external {dir === "ingress" ? "clients" : "dests"}
          {s.protocols.length > 0 && ` · ${s.protocols.join("/")}`}
          {s.ports.length > 0 && ` · :${s.ports.slice(0, 6).join(", :")}`}
          {s.sessions > 0 && ` · ${s.sessions.toLocaleString()} sessions`}
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {s.policy_mode && (
          <span title={`Network policy mode: ${s.policy_mode}`}
            className={cn("rounded px-1.5 py-0.5 text-[9px] uppercase tracking-wide font-medium",
              s.policy_mode === "protect" ? "bg-[color-mix(in_oklab,var(--color-severity-low)_18%,transparent)] text-[color:var(--color-severity-low)]"
                : s.policy_mode === "monitor" ? "bg-[color-mix(in_oklab,var(--color-severity-medium)_18%,transparent)] text-[color:var(--color-severity-medium)]"
                : "bg-[color-mix(in_oklab,var(--color-severity-high)_18%,transparent)] text-[color:var(--color-severity-high)]")}>
            {s.policy_mode}
          </span>
        )}
        {s.critical > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-critical)" }}>{s.critical}C</span>}
        {s.high > 0 && <span className="rounded px-1.5 py-0.5 text-[10px] text-mono font-semibold text-white" style={{ background: "var(--color-severity-high)" }}>{s.high}H</span>}
        {s.critical === 0 && s.high === 0 && <span className="text-[10px] text-muted-foreground">no crit/high</span>}
      </div>
    </a>
  );
}

// Read-only distribution; mode changes live in the Groups workflow.
function ModeMaturity({ label, groups, discover, monitor, protect }: {
  label: string; groups: number; discover: number; monitor: number; protect: number;
}) {
  const total = groups || 1;
  const modes = [
    { label: "Protect", color: "var(--color-severity-low)", v: protect },
    { label: "Monitor", color: "var(--color-severity-medium)", v: monitor },
    { label: "Discover", color: "var(--color-severity-high)", v: discover },
  ];
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium text-foreground">{label}</span>

      </div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-muted">
        {modes.map((m) => m.v > 0 && <div key={m.label} style={{ width: `${(m.v / total) * 100}%`, background: m.color }} title={`${m.label}: ${m.v}`} />)}
      </div>
      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
        {modes.map((m) => <span key={m.label} className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full" style={{ background: m.color }} />{m.label} {m.v}</span>)}
      </div>
    </div>
  );
}

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
  data, loading, failed, refreshing, scanning, scanError, scanResult, onRetry, onScan,
}: {
  data?: PlatformFactsResponse;
  loading: boolean;
  failed: boolean;
  refreshing: boolean;
  scanning: boolean;
  scanError: boolean;
  scanResult?: Awaited<ReturnType<typeof clusters.scanPlatform>>;
  onRetry: () => void;
  onScan: () => void;
}) {
  const facts = data?.facts;
  const packages = data?.evidence?.packages ?? [];
  const components = facts?.components ?? [];
  const bundle = data?.latest_job?.bundle_metadata;
  const canScan = !!data?.evidence && !failed && !refreshing && !scanning;
  type PkgRow = (typeof packages)[number] & { _rk: string };
  const pkgRows: PkgRow[] = packages.map((pkg, index) => ({ ...pkg, _rk: `${pkg.namespace_name}-${pkg.name}-${pkg.version}-${index}` }));
  const packageColumns: Column<PkgRow>[] = [
    { id: "name", header: "Package", kind: "name", wrap: true, code: true, exportValue: (r) => r.name || "-", cell: (r) => <span className="font-mono">{r.name || "-"}</span> },
    { id: "version", header: "Version", kind: "version", size: 160, minSize: 112, maxSize: 224, wrap: true, exportValue: (r) => r.version || "-", cell: (r) => <span className="font-mono text-muted-foreground">{r.version || "-"}</span> },
    { id: "namespace", header: "Namespace / ecosystem", kind: "text", code: true, wrap: true, size: 184, minSize: 144, maxSize: 240, exportValue: (r) => r.namespace_name || r.ecosystem || "generic", cell: (r) => <span className="font-mono text-muted-foreground">{r.namespace_name || r.ecosystem || "generic"}</span> },
  ];
  return (
    <Panel
      title="Platform Scan"
      subtitle="Kubernetes control plane, kubelet, and platform add-on evidence for this cluster"
      icon={<ServerCog className="h-3.5 w-3.5" />}
      rightSlot={<Button size="sm" variant="outline" disabled={!canScan} onClick={onScan}>
        <RefreshCw className={cn("h-3 w-3", scanning && "animate-spin")} />
        {scanning ? "Requesting scan…" : "Scan platform"}
      </Button>}
    >
      <div className="space-y-4" data-testid="dashboard-platform-workspace">
        {scanError && <ErrorState title="Platform scan request failed. Try again when platform facts are available." />}
        {scanResult && !scanError && <p role="status" className="text-sm text-muted-foreground">
          {scanResult.scan_job_enqueued ? "Platform scan queued. Results will appear after the scan completes." : "No new platform scan job was queued for this inventory. Check the latest job status."}
        </p>}
        {failed ? <ErrorState title="Could not refresh platform facts." action={<Button disabled={refreshing} onClick={onRetry}>Retry</Button>} /> : loading ? (
          <p role="status" className="text-xs text-muted-foreground">Loading platform facts…</p>
        ) : !facts ? (
          <EmptyState title="No platform facts reported" hint="The discoverer reports Kubernetes platform facts from the installed cluster." icon={<ServerCog className="h-8 w-8" />} />
        ) : <>
          {refreshing && <p role="status" className="text-xs text-muted-foreground">Refreshing platform facts… Scan is paused until the refresh succeeds.</p>}
          <dl className="grid gap-4 text-xs sm:grid-cols-2 xl:grid-cols-3">
            <Row k="Status" v={<StatusChip value={data?.status ?? "reported"} />} />
            <Row k="Kubernetes" v={<span className="text-mono">{facts.kubernetes_git_version || "unknown"}</span>} />
            <Row k="Distro" v={<span className="text-mono">{facts.distro}</span>} />
            <Row k="Provider" v={<span className="text-mono">{facts.platform_provider || "unknown"}</span>} />
            <Row k="Nodes" v={<span className="text-mono">{facts.node_count}</span>} />
            <Row k="Observed" v={<span className="text-mono text-muted-foreground">{fmtRelative(facts.observed_at)}</span>} />
          </dl>
          <div className="min-w-0 space-y-3">
            <div className="flex flex-wrap items-center gap-2 text-sm font-medium"><PackageCheck className="h-4 w-4" /> Evidence packages</div>
            <p className="text-xs text-muted-foreground" data-testid="dashboard-platform-package-scope">
              All {packages.length.toLocaleString()} returned packages are available in this table and its CSV export.
              {data?.evidence?.package_count !== undefined && data.evidence.package_count !== packages.length && ` Reported inventory contains ${data.evidence.package_count.toLocaleString()} packages; this response includes ${packages.length.toLocaleString()}.`}
            </p>
            <DataTable<PkgRow> rows={pkgRows} columns={packageColumns} rowKey={(r) => r._rk}
              testId="dashboard-platform-packages" preferencesKey="dashboard-platform-packages"
              exportFileName="constellation-platform-packages" exportLabel="Export returned packages"
              emptyState={<EmptyState title="No package evidence" />} />
          </div>
          <Collapse label="Advanced: scan job and platform components">
            <dl className="grid gap-4 text-xs sm:grid-cols-2 xl:grid-cols-3">
              <Row k="Job" v={<StatusChip value={data?.latest_job?.status ?? "not queued"} />} />
              <Row k="Findings" v={<span className="text-mono">{data?.findings_summary?.open ?? 0} open</span>} />
              <Row k="Critical / High" v={<span className="text-mono">{data?.findings_summary?.critical ?? 0} / {data?.findings_summary?.high ?? 0}</span>} />
              <Row k="Inventory" v={<span className="text-mono text-muted-foreground">{shortHash(data?.evidence?.inventory_hash)}</span>} />
              <Row k="Bundle" v={<span className="text-mono text-muted-foreground">{bundle?.bundle_version || "pending"}</span>} />
              <Row k="Bundle rows" v={<span className="text-mono text-muted-foreground">{bundle?.record_count?.toLocaleString() ?? "-"}</span>} />
            </dl>
            {components.length > 0 && <p className="mt-3 text-xs text-muted-foreground">{components.length} reported platform components</p>}
            {data?.latest_job?.error && <p role="alert" className="mt-3 text-xs text-muted-foreground">Latest scan job failed: {data.latest_job.error}</p>}
          </Collapse>
        </>}
      </div>
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


// ─────────────────────────── pure helpers ───────────────────────────

function summarizeComponentHealth(heartbeats: SystemHealthHeartbeat[]): ComponentHealthSummary {
  const roles = Object.fromEntries(COMPONENT_ROLES.map((role) => [role.id, emptyComponentRoleHealth()])) as Record<ComponentRoleID, ComponentRoleHealth>;
  for (const heartbeat of heartbeats) {
    const role = componentRoleFromHeartbeat(heartbeat);
    if (!role) continue;
    const bucket = roles[role];
    bucket.total++;
    const status = String(heartbeat.status || "healthy").toLowerCase();
    if (status === "healthy") {
      bucket.healthy++;
    } else {
      bucket.unhealthy++;
      if (status === "degraded") bucket.degraded++;
      if (status === "stale") bucket.stale++;
      if (status === "drift") bucket.drift++;
      if (status === "crashlooping") bucket.crashlooping++;
    }
    bucket.lastSeenAt = newestISO(bucket.lastSeenAt, heartbeat.last_seen_at);
  }
  return { roles };
}

function emptyComponentRoleHealth(): ComponentRoleHealth {
  return { total: 0, healthy: 0, degraded: 0, stale: 0, drift: 0, crashlooping: 0, unhealthy: 0 };
}

function componentRoleFromHeartbeat(heartbeat: SystemHealthHeartbeat): ComponentRoleID | null {
  const text = [heartbeat.component, heartbeat.hostname, heartbeat.metadata?.vulndb ? "scanner" : ""].join(" ").toLowerCase();
  if (/\b(scanner|scan-worker|vuln|cve)\b/.test(text)) return "scanner";
  if (/\b(admission|webhook)\b/.test(text)) return "admission";
  if (/\b(enforcer|runtime-agent|agent|sensor|node-agent)\b/.test(text)) return "enforcer";
  if (/\b(discoverer|discovery|importer|collector|inventory)\b/.test(text)) return "discoverer";
  if (/\b(controller|control-plane|api|server)\b/.test(text)) return "controller";
  return null;
}

function componentRoleTone(health: ComponentRoleHealth): "neutral" | "critical" | "high" | "medium" | "low" | "accent" {
  if (health.total === 0) return "neutral";
  if (health.crashlooping > 0 || health.stale > 0) return "critical";
  if (health.degraded > 0 || health.drift > 0 || health.unhealthy > 0) return "medium";
  return "low";
}

function componentRoleHint(health: ComponentRoleHealth): string {
  if (health.total === 0) return "not observed";
  const parts: string[] = [];
  if (health.unhealthy > 0) parts.push(`${health.unhealthy} need attention`);
  if (health.stale > 0) parts.push(`${health.stale} stale`);
  if (health.drift > 0) parts.push(`${health.drift} drift`);
  if (parts.length === 0) parts.push("all healthy");
  if (health.lastSeenAt) parts.push(fmtRelative(health.lastSeenAt));
  return parts.join(" · ");
}

function summarizeScannerFreshness(
  lifecycle: ScanLifecycleStatus | undefined,
  workers: ScannerWorker[],
  bundleStatus: CVEBundleStatus | undefined,
): ScannerFreshnessSummary {
  const workerWithDb = workers.find((worker) => worker.cvedb_version);
  const workerWithDbTime = workers.find((worker) => worker.cvedb_create_time);
  const version = lifecycle?.cvedb_version || workerWithDb?.cvedb_version || bundleStatus?.version || "";
  const dbTime = lifecycle?.cvedb_create_time || workerWithDbTime?.cvedb_create_time || bundleStatus?.imported_at || bundleStatus?.published_at;
  const workersWithDb = workers.filter((worker) => worker.cvedb_version).length;
  const failed = lifecycle?.failed ?? 0;
  let status = "ready";
  if (!version) {
    status = "missing";
  } else if (failed > 0 || (workers.length > 0 && workersWithDb < workers.length)) {
    status = "degraded";
  }
  const ageHours = hoursSince(dbTime);
  if (version && ageHours != null) {
    if (ageHours > 72) status = "stale";
    else if (ageHours > 24 && status === "ready") status = "degraded";
  }
  return {
    status,
    version,
    freshnessLabel: dbTime ? fmtRelative(dbTime) : "not reported",
    workers: workers.length,
    workersWithDb,
    scheduled: lifecycle?.scheduled ?? 0,
    scanning: lifecycle?.scanning ?? 0,
    failed,
  };
}

function summarizeFederationHealth(state: FedMembership | undefined, members: FedMember[]): FederationHealthSummary {
  const fedState = state?.state ?? "standalone";
  const activeMembers = members.filter((member) => member.status === "active").length;
  const staleMembers = members.filter((member) => member.status !== "active").length;
  let status = "ready";
  if (fedState === "master" && staleMembers > 0) status = "degraded";
  const ageHours = hoursSince(state?.updated_at);
  if (fedState === "joint" && ageHours != null && ageHours > 24) status = "stale";
  return {
    participating: fedState !== "standalone",
    state: fedState,
    status,
    revision: state?.revision ?? 0,
    members: fedState === "master" ? members.length : state?.master_id ? 1 : 0,
    activeMembers: fedState === "master" ? activeMembers : state?.master_id ? 1 : 0,
    staleMembers,
    updatedLabel: state?.updated_at ? fmtRelative(state.updated_at) : "not reported",
  };
}

function hoursSince(iso?: string): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  return (Date.now() - t) / 3_600_000;
}

function newestISO(a?: string, b?: string): string | undefined {
  if (!a) return b;
  if (!b) return a;
  const at = Date.parse(a);
  const bt = Date.parse(b);
  if (!Number.isFinite(at)) return b;
  if (!Number.isFinite(bt)) return a;
  return bt > at ? b : a;
}

function topDeniedConversations(conversations: NetworkConversation[]): NetworkConversation[] {
  return conversations
    .filter((row) => isDeniedVerdict(row.verdict))
    .sort((a, b) => (
      (b.severity ?? 0) - (a.severity ?? 0)
      || b.bytes - a.bytes
      || timeValue(b.last_seen) - timeValue(a.last_seen)
    ))
    .slice(0, 5);
}

function isDeniedVerdict(verdict?: string): boolean {
  const v = String(verdict ?? "").toLowerCase();
  return v === "deny" || v === "denied" || v === "block" || v === "blocked";
}

function timeValue(iso?: string): number {
  const t = Date.parse(iso ?? "");
  return Number.isFinite(t) ? t : 0;
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
