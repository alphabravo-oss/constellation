// CoveragePage — scoped posture workspace backed by bounded API evidence.
//
// Lists reported records, source timestamps and navigation per capability.
// Source availability and bounded samples stay separate from enforcement health. Org-scoped rows (CVE Intelligence,
// Federation, audit-derived rows) ignore the cluster picker; cluster-scoped rows
// (Network Map, Auto NetworkPolicy) thread the picker through their API calls.
import { useMemo, isValidElement, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowUpRight,
  CircleCheck,
  CircleDot,
  Clock3,
  CircleMinus,
  Radio,
} from "lucide-react";

import {
  api,
  baselines,
  clusters as clustersApi,
  cve,
  dashboard,
  federation,
  network,
  compliance,
  connectorCoverage,
  scanJobs,
} from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatusPill } from "@/components/ui/status-pill";
import { Button } from "@/components/ui/button";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState } from "@/components/ui/states";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { useRouteSearchParams } from "@/lib/route-search";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { sortClustersByActivity } from "@/lib/clusters";
import { Select } from "@/components/ui/form";

// --- types -----------------------------------------------------------------

type CapStatus = "active" | "partial" | "idle" | "missing" | "pending" | "unavailable";

interface CapabilityRow {
  id: string;
  name: string;
  pillar: string;
  /** Whether the row is scoped to a cluster (some rows are org-only). */
  scope: "org" | "cluster";
  /** Short data-driven sentence: e.g. "332,641 CVE rows · 1,591 KEV". */
  evidence: ReactNode;
  /** Numeric count for sorting (best-effort headline number). */
  signal: number;
  status: CapStatus;
  lastAt?: string; // ISO timestamp; undefined means unknown / no events.
  href?: string;
  loading?: boolean;
  retry?: () => void;
  actionLabel?: string;
}

// --- helpers ---------------------------------------------------------------

const NUM = new Intl.NumberFormat();

function relTime(iso?: string): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t) || t <= 0) return "—";
  const diffMs = Date.now() - t;
  if (diffMs < 0) return "Future timestamp";
  const s = Math.floor(diffMs / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(iso).toLocaleDateString();
}

function withinHours(iso: string | undefined, hours: number): boolean {
  if (!iso) return false;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return false;
  const age = Date.now() - t;
  return age >= 0 && age < hours * 3600_000;
}

function latestISO(values: Array<string | undefined>): string | undefined {
  return values
    .filter((value): value is string => Boolean(value))
    .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0];
}

function shortHash(hash: string): string {
  const [algorithm, value] = hash.includes(":") ? hash.split(":", 2) : ["sha256", hash];
  if (!value) return hash;
  return `${algorithm}:${value.slice(0, 12)}`;
}

function tone(status: CapStatus): "success" | "warning" | "pending" | "neutral" | "info" {
  switch (status) {
    case "active":
      return "success";
    case "partial":
      return "warning";
    case "idle":
      return "pending";
    case "missing":
      return "neutral";
    case "unavailable":
      return "warning";
    case "pending":
      return "info";
  }
}

function statusLabel(s: CapStatus): string {
  switch (s) {
    case "active":
      return "Evidence reported";
    case "partial":
      return "Partial";
    case "idle":
      return "Records reported";
    case "missing":
      return "No records";
    case "unavailable":
      return "Unavailable";
    case "pending":
      return "Loading";
  }
}

// --- one-off query helpers --------------------------------------------------

interface AuditEvent {
  id: number;
  actor_id?: string;
  action: string;
  target_kind?: string;
  target_id?: string;
  at: string;
}

async function fetchAudit(action: string, limit = 100): Promise<{ count: number; lastAt?: string }> {
  const r = await api.get<{ events: AuditEvent[] }>("/audit/events", { params: { action, limit } });
  const events = r.data.events ?? [];
  return { count: events.length, lastAt: events[0]?.at };
}

// --- page -------------------------------------------------------------------

const SEVERE_PARTIAL_THRESHOLD_HOURS = 24;

export function CoveragePage() {
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const [params, setParams] = useRouteSearchParams();
  const [tab, setTab] = useTabParam("tab", "all");
  const pillarFilter = params.get("pillar") ?? "";
  const selectedCluster = params.get("cluster") || undefined;
  const update = (key: string, value: string) => setParams(current => { const next = new URLSearchParams(current); if (value) next.set(key, value); else next.delete(key); return next; });
  const qClusters = useQuery({ queryKey: ["posture", owner, "clusters"], queryFn: () => clustersApi.list(), staleTime: 30_000 });
  const clusterList = useMemo(() => !qClusters.isError && !qClusters.isFetching ? sortClustersByActivity(qClusters.data?.clusters ?? []) : [], [qClusters.data, qClusters.isError, qClusters.isFetching]);
  const clusterId = selectedCluster;
  const clusterName = clusterList.find(c => c.id === clusterId)?.name;
  const clusterReady = Boolean(clusterId && qClusters.isSuccess && !qClusters.isError && !qClusters.isFetching && clusterList.some(c => c.id === clusterId));

  const qCveStats = useQuery({ queryKey: ["posture", owner, "cve-stats"], queryFn: () => cve.stats() });
  const qCveBundle = useQuery({ queryKey: ["posture", owner, "cve-bundle"], queryFn: () => cve.bundle() });
  const qDashboard = useQuery({ queryKey: ["posture", owner, "dashboard-summary"], queryFn: () => dashboard.summary() });

  const qScanJobs = useQuery({
    queryKey: ["posture", owner, "scan-jobs-coverage"],
    queryFn: () => scanJobs.list(),
  });

  const qFindingsLifecycle = useQuery({
    queryKey: ["posture", owner, "findings-lifecycle"],
    queryFn: () =>
      api
        .get<{ findings: unknown[]; lifecycle_counts?: Record<string, number> }>("/findings", { params: { limit: 1 } })
        .then((r) => r.data),
  });

  const qRrV2 = useQuery({ queryKey: ["posture", owner, "rr-v2"], queryFn: () => api.get<{ rules: Array<{ id: string; enabled: boolean }> }>("/response-rules-v2").then((r) => r.data) });
  const qVulnProfiles = useQuery({ queryKey: ["posture", owner, "vuln-profiles"], queryFn: () => api.get<{ profiles: Array<{ id: string; active?: boolean }> }>("/vuln-profiles").then((r) => r.data) });
  const qGroups = useQuery({ queryKey: ["posture", owner, "groups-coverage"], queryFn: () => api.get<{ groups: Array<{ id: string }> }>("/groups").then((r) => r.data) });
  const qFed = useQuery({ queryKey: ["posture", owner, "fed-state"], queryFn: () => federation.state() });
  const qFedMembers = useQuery({ queryKey: ["posture", owner, "fed-members"], queryFn: () => federation.members() });
  const qReceivers = useQuery({
    queryKey: ["posture", owner, "receivers-coverage"],
    queryFn: () => api.get<{ receivers: Array<{ id: string; status: string }> }>("/integrations/receivers").then((r) => r.data),
  });
  const qCompliance = useQuery({ queryKey: ["posture", owner, "compliance-summary"], queryFn: () => compliance.summary() });
  const qAdmissionDeny = useQuery({ queryKey: ["posture", owner, "audit", "admission.deny"], queryFn: () => fetchAudit("admission.deny") });
  const qGitopsDrift = useQuery({ queryKey: ["posture", owner, "audit", "gitops.drift.detected"], queryFn: () => fetchAudit("gitops.drift.detected") });
  const qRecentAudit = useQuery({
    queryKey: ["posture", owner, "recent-audit-count"],
    queryFn: () => api.get<{ events: AuditEvent[] }>("/audit/events", { params: { limit: 100 } }).then((r) => r.data),
  });

  const qRuntimeEvents = useQuery({
    queryKey: ["posture", owner, "runtime-events-coverage"],
    queryFn: () =>
      api.get<{ events: Array<{ id: string; at: string }> }>("/events", { params: { limit: 50 } }).then((r) => r.data),
  });

  const qAiAssets = useQuery({
    queryKey: ["posture", owner, "ai-assets-coverage"],
    queryFn: () =>
      api.get<{ assets: Array<{ id: string; ai_workload: boolean }> }>("/assets", { params: { ai_workload: true, limit: 50 } }).then((r) => r.data),
  });

  // cluster-scoped
  const qNetMap = useQuery({
    queryKey: ["posture", owner, "net-map-coverage", clusterId],
    enabled: clusterReady,
    queryFn: () => network.map({ cluster_id: clusterId }),
  });
  const qNetLifecycle = useQuery({
    queryKey: ["posture", owner, "net-policies-lifecycle-coverage", clusterId],
    enabled: clusterReady,
    queryFn: () => network.lifecycle({ cluster_id: clusterId }),
  });
  const qBaselines = useQuery({
    queryKey: ["posture", owner, "runtime-baselines-coverage", clusterId],
    enabled: clusterReady,
    queryFn: () => baselines.list({ cluster_id: clusterId }),
  });
  const qConnectorCoverage = useQuery({
    queryKey: ["posture", owner, "connector-coverage-summary"],
    queryFn: () => connectorCoverage.overview(),
  });

  // --- build rows ---
  const rawRows = useMemo<CapabilityRow[]>(() => {
    const out: CapabilityRow[] = [];

    // 1) CVE Intelligence — org-scoped
    {
      const s = qCveStats.data;
      const b = qCveBundle.data;
      const importedAt = b?.imported_at;
      const fresh = withinHours(importedAt, 24);
      const status: CapStatus = s
        ? (s.total ?? 0) > 0
          ? fresh
            ? "active"
            : "partial"
          : "missing"
        : qCveStats.isPending
          ? "pending"
          : "missing";
      out.push({
        id: "cve-intel",
        name: "CVE Intelligence",
        pillar: "Vulnerabilities",
        scope: "org",
        signal: s?.total ?? 0,
        status,
        lastAt: importedAt ?? s?.latest_published_at,
        evidence: s ? (
          <>
            <strong className="text-foreground">{NUM.format(s.total ?? 0)}</strong> CVE rows ·{" "}
            <span className="text-[color:var(--color-severity-critical)]">{NUM.format(s.kev_listed ?? 0)} KEV</span> ·{" "}
            {NUM.format(s.epss_gt_50 ?? 0)} EPSS&gt;.5 · {NUM.format(s.cvss_gt_70 ?? 0)} CVSS&gt;7
            {b?.version && <span className="text-muted-foreground"> · bundle {b.version}</span>}
          </>
        ) : (
          "—"
        ),
        href: "/cve",
        loading: qCveStats.isPending,
      });
    }

    // 2) Image Scanning
    {
      const jobs = qScanJobs.data?.jobs ?? [];
      const completed = jobs.filter((j) => j.status === "completed").length;
      const metrics = qScanJobs.data?.queue_metrics ?? [];
      const pending = metrics.reduce((sum, item) => sum + item.pending, 0);
      const delayed = metrics.reduce((sum, item) => sum + item.retry_delayed, 0);
      const exhausted = metrics.reduce((sum, item) => sum + item.exhausted, 0);
      const stale = metrics.reduce((sum, item) => sum + item.stale_running, 0);
      const last24 = jobs.filter((j) => withinHours(j.finished_at ?? j.requested_at, 24)).length;
      const lastAt = jobs.map((j) => j.finished_at ?? j.requested_at).filter(Boolean).sort().reverse()[0];
      const latestBundle = jobs
        .filter((j) => j.bundle_metadata)
        .sort((a, b) => (new Date(b.finished_at ?? b.requested_at ?? 0).getTime()) - (new Date(a.finished_at ?? a.requested_at ?? 0).getTime()))[0]
        ?.bundle_metadata;
      const status: CapStatus = jobs.length === 0
        ? qScanJobs.isPending ? "pending" : "missing"
        : last24 > 0 ? "active" : "idle";
      out.push({
        id: "image-scan",
        name: "Scan jobs",
        pillar: "Vulnerabilities",
        scope: "org",
        signal: jobs.length,
        status,
        lastAt,
        evidence: jobs.length > 0
          ? (
            <>
              <strong className="text-foreground">{completed}</strong> completed in up to 200 loaded jobs · {pending} reported pending · {last24} loaded records within 24h
              {(delayed > 0 || exhausted > 0 || stale > 0) && (
                <span className="text-muted-foreground"> · {delayed} delayed · {exhausted} exhausted · {stale} stale</span>
              )}
              {latestBundle?.bundle_version && <span className="text-muted-foreground"> · bundle {latestBundle.bundle_version}</span>}
              {latestBundle?.payload_hash && <span className="text-muted-foreground"> · {shortHash(latestBundle.payload_hash)}</span>}
            </>
          )
          : "No scan jobs",
        href: "/settings/connectors",
        loading: qScanJobs.isPending,
      });
    }

    // 3) Findings & Triage
    {
      const d = qDashboard.data;
      const lc = qFindingsLifecycle.data?.lifecycle_counts ?? {};
      const total = d?.findings_total ?? 0;
      const triaged = (lc.triaged ?? 0) + (lc.in_progress ?? 0);
      const status: CapStatus = total > 0 ? "active" : qDashboard.isPending ? "pending" : "missing";
      out.push({
        id: "findings",
        name: "Findings & Triage",
        pillar: "Vulnerabilities",
        scope: "org",
        signal: total,
        status,
        lastAt: d?.generated_at,
        evidence: d ? (
          <>
            <strong className="text-foreground">{NUM.format(total)}</strong> open findings ·{" "}
            <span className="text-[color:var(--color-severity-critical)]">{NUM.format(d.findings_by_severity?.critical ?? 0)} crit</span> ·{" "}
            {NUM.format(d.findings_by_severity?.high ?? 0)} high · {triaged} triaged / in progress (lifecycle counts)
          </>
        ) : "—",
        href: "/findings",
        loading: qDashboard.isPending,
      });
    }

    // 4) Admission Control — audit-driven
    {
      const a = qAdmissionDeny.data;
      const status: CapStatus = a == null
        ? qAdmissionDeny.isPending ? "pending" : "missing"
        : (a.count ?? 0) > 0
          ? withinHours(a.lastAt, 24) ? "active" : "idle"
          : "missing";
      out.push({
        id: "admission",
        name: "Admission audit evidence",
        pillar: "Posture",
        scope: "org",
        signal: a?.count ?? 0,
        status,
        lastAt: a?.lastAt,
        evidence: a ? (
          <><strong className="text-foreground">{NUM.format(a.count ?? 0)}</strong> loaded admission.deny records (up to 100; not an enforcement-health check)</>
        ) : "—",
        href: "/audit",
        loading: qAdmissionDeny.isPending,
      });
    }

    // 5) WAF removed (WS-G G1) — DPI Signatures cover the L7/DPI ruleset.
    //    The DLP-sensor tile was removed (P0-01) — code-seeded runtime_dlp_rules
    //    are the enforced DLP surface.

    // 7) Runtime BPF Events
    {
      const events = qRuntimeEvents.data?.events ?? [];
      const lastAt = events[0]?.at;
      const last24 = events.filter((e) => withinHours(e.at, 24)).length;
      const status: CapStatus = events.length === 0
        ? qRuntimeEvents.isPending ? "pending" : "missing"
        : last24 > 0 ? "active" : "idle";
      out.push({
        id: "runtime-bpf",
        name: "Runtime events",
        pillar: "Runtime",
        scope: "org",
        signal: events.length,
        status,
        lastAt,
        evidence: events.length > 0
          ? <><strong className="text-foreground">{NUM.format(events.length)}</strong> loaded runtime records (up to 50) · {last24} within 24h</>
          : "No records in the loaded runtime sample",
        href: "/runtime",
        loading: qRuntimeEvents.isPending,
      });
    }

    // 8) Network Map — cluster-scoped
    {
      const m = qNetMap.data;
      const summary = m?.summary;
      const workloads = summary?.workloads ?? 0;
      const flows = summary?.flows ?? 0;
      const alerted = summary?.alerted ?? 0;
      const lastAt = m?.flows?.[0]?.last_seen_at ?? m?.recent_flows?.[0]?.observed_at;
      const status: CapStatus = !clusterId
        ? "pending"
        : flows > 0
          ? withinHours(lastAt, 24) ? "active" : "idle"
          : qNetMap.isPending ? "pending" : "missing";
      out.push({
        id: "net-map",
        name: "Network Map",
        pillar: "Network",
        scope: "cluster",
        signal: flows,
        status,
        lastAt,
        evidence: m ? (
          <>
            <strong className="text-foreground">{NUM.format(workloads)}</strong> reported workloads · {NUM.format(flows)} reported flows (bounded map source) ·{" "}
            <span className="text-[color:var(--color-severity-high)]">{alerted} alerted</span>
            {clusterName && <span className="text-muted-foreground"> · {clusterName}</span>}
          </>
        ) : "—",
        href: clusterId ? `/clusters/${clusterId}/network` : "/clusters",
        loading: qNetMap.isPending,
      });
    }

    // 9) Auto NetworkPolicy lifecycle
    {
      const lc = qNetLifecycle.data;
      const s = lc?.summary;
      const total = s?.total ?? 0;
      const status: CapStatus = total === 0
        ? qNetLifecycle.isPending ? "pending" : "missing"
        : (s?.pending_approval ?? 0) > 0 || (s?.protect ?? 0) > 0 ? "active" : "idle";
      out.push({
        id: "auto-netpolicy",
        name: "Auto NetworkPolicy",
        pillar: "Network",
        scope: "cluster",
        signal: total,
        status,
        evidence: s ? (
          <>
            <strong className="text-foreground">{s.discover ?? 0}</strong> discover · {s.monitor ?? 0} monitor ·{" "}
            <span className="text-[color:var(--color-status-success)]">{s.protect ?? 0} protect</span>
            {(s.pending_approval ?? 0) > 0 && <> · {s.pending_approval} pending approval</>}
          </>
        ) : "—",
        href: clusterId ? `/clusters/${clusterId}/network` : "/clusters",
        loading: qNetLifecycle.isPending,
      });
    }

    // 10) Process Baseline
    {
      const summary = qBaselines.data?.summary;
      const profiles = qBaselines.data?.profiles ?? [];
      const totalAlerts = profiles.reduce((sum, profile) => sum + (profile.monitored_alerts_24h ?? 0), 0);
      const totalBlocks = profiles.reduce((sum, profile) => sum + (profile.enforced_blocks_24h ?? 0), 0);
      const lastAt = latestISO(
        profiles.flatMap((profile) => [
          profile.last_new_process_at,
          profile.enforce_started_at,
          profile.monitor_started_at,
          profile.learn_started_at,
        ]),
      );
      const total = summary?.total ?? profiles.length;
      const status: CapStatus = qBaselines.isPending
        ? "pending"
        : total === 0
          ? "missing"
          : totalBlocks > 0 || totalAlerts > 0 || (summary?.enforce ?? 0) > 0
            ? "active"
            : "idle";
      out.push({
        id: "proc-baseline",
        name: "Process Baseline",
        pillar: "Runtime",
        scope: "cluster",
        signal: total,
        status,
        lastAt,
        evidence: summary ? (
          <>
            <strong className="text-foreground">{summary.total}</strong> workloads · {summary.learn} learn ·{" "}
            {summary.monitor} configured monitor · <span className="text-[color:var(--color-status-success)]">{summary.enforce} configured enforce</span>
            {(totalAlerts > 0 || totalBlocks > 0) && <> · {totalAlerts} alerts · {totalBlocks} blocks</>}
          </>
        ) : "—",
        href: clusterId ? `/clusters/${clusterId}/runtime/baselines` : "/clusters",
        loading: qBaselines.isPending,
      });
    }

    // 11) Vulnerability Profiles
    {
      const profiles = qVulnProfiles.data?.profiles ?? [];
      const active = profiles.filter((p) => p.active).length;
      const status: CapStatus = profiles.length === 0
        ? qVulnProfiles.isPending ? "pending" : "missing"
        : "idle";
      out.push({
        id: "vuln-profiles",
        name: "Vulnerability Profiles",
        pillar: "Vulnerabilities",
        scope: "org",
        signal: profiles.length,
        status,
        evidence: profiles.length > 0
          ? <><strong className="text-foreground">{profiles.length}</strong> profiles · {active} active</>
          : "No profiles",
        href: "/vuln-profiles",
        loading: qVulnProfiles.isPending,
      });
    }

    // 12) Groups
    {
      const groups = qGroups.data?.groups ?? [];
      const status: CapStatus = groups.length === 0
        ? qGroups.isPending ? "pending" : "missing"
        : "idle";
      out.push({
        id: "groups",
        name: "Groups",
        pillar: "Posture",
        scope: "org",
        signal: groups.length,
        status,
        evidence: groups.length > 0
          ? <><strong className="text-foreground">{groups.length}</strong> groups defined</>
          : "No groups",
        href: "/groups",
        loading: qGroups.isPending,
      });
    }

    // 13) Response Rules
    {
      const rules = qRrV2.data?.rules ?? [];
      const enabled = rules.filter((r) => r.enabled).length;
      const status: CapStatus = rules.length === 0
        ? qRrV2.isPending ? "pending" : "missing"
        : "idle";
      out.push({
        id: "response-rules",
        name: "Response Rules",
        pillar: "Response",
        scope: "org",
        signal: rules.length,
        status,
        evidence: rules.length > 0
          ? <><strong className="text-foreground">{rules.length}</strong> rules · {enabled} enabled</>
          : "No rules",
        href: "/response-rules",
        loading: qRrV2.isPending,
      });
    }

    // 14) GitOps Drift — audit-driven
    {
      const a = qGitopsDrift.data;
      const status: CapStatus = a == null
        ? qGitopsDrift.isPending ? "pending" : "missing"
        : (a.count ?? 0) > 0
          ? withinHours(a.lastAt, 24) ? "active" : "idle"
          : "missing";
      out.push({
        id: "gitops-drift",
        name: "GitOps Drift",
        pillar: "Posture",
        scope: "org",
        signal: a?.count ?? 0,
        status,
        lastAt: a?.lastAt,
        evidence: a ? (
          <><strong className="text-foreground">{NUM.format(a.count ?? 0)}</strong> loaded drift audit records (up to 100)</>
        ) : "—",
        href: "/audit",
        loading: qGitopsDrift.isPending,
      });
    }

    // 15) Federation
    {
      const f = qFed.data;
      const members = qFedMembers.data?.members ?? [];
      const isOn = f && f.state !== "standalone";
      const status: CapStatus = f == null
        ? qFed.isPending ? "pending" : "missing"
        : isOn ? "active" : "idle";
      out.push({
        id: "federation",
        name: "Federation",
        pillar: "Platform",
        scope: "org",
        signal: members.length,
        status,
        lastAt: f?.updated_at,
        evidence: f ? (
          <>State <strong className="text-foreground">{f.state}</strong> · {members.length} members · rev {f.revision}</>
        ) : "—",
        href: "/federation",
        loading: qFed.isPending,
      });
    }

    // 16) Compliance Frameworks
    {
      const frameworks = qCompliance.data?.frameworks ?? [];
      const avg = frameworks.length
        ? frameworks.reduce((a, f) => a + (f.pass_pct ?? 0), 0) / frameworks.length
        : 0;
      const status: CapStatus = frameworks.length === 0
        ? qCompliance.isPending ? "pending" : "missing"
        : "active";
      out.push({
        id: "compliance",
        name: "Compliance Frameworks",
        pillar: "Posture",
        scope: "org",
        signal: frameworks.length,
        status,
        evidence: frameworks.length > 0 ? (
          <>
            <strong className="text-foreground">{frameworks.length}</strong> frameworks ·{" "}
            avg <span className="text-[color:var(--color-status-success)]">{Math.round(avg)}% pass</span> ·{" "}
            {frameworks.map((f) => `${f.framework} ${Math.round(f.pass_pct)}%`).slice(0, 3).join(" · ")}
          </>
        ) : "No framework runs yet",
        href: "/compliance",
        loading: qCompliance.isPending,
      });
    }

    // 17) Cloud CSPM
    {
      const summary = qConnectorCoverage.data?.summary;
      const cloudConnectors = qConnectorCoverage.data?.cloud_connectors ?? [];
      const lastAt = latestISO(cloudConnectors.map((connector) => connector.last_assessment_at));
      const total = summary?.cloud_connectors_total ?? cloudConnectors.length;
      const ready = summary?.cloud_connectors_ready ?? cloudConnectors.filter((connector) => connector.status === "ready").length;
      const openFindings = cloudConnectors.reduce((sum, connector) => sum + (connector.findings_open ?? 0), 0);
      const status: CapStatus = qConnectorCoverage.isPending
        ? "pending"
        : total === 0
          ? "missing"
          : ready === total
            ? "active"
            : "partial";
      out.push({
        id: "cspm",
        name: "Cloud CSPM",
        pillar: "Posture",
        scope: "org",
        signal: summary?.cloud_resources_assessed ?? 0,
        status,
        lastAt,
        evidence: summary ? (
          <>
            <strong className="text-foreground">{ready}/{total}</strong> cloud connectors ready ·{" "}
            {NUM.format(summary.cloud_resources_assessed)} / {NUM.format(summary.cloud_resources_observed)} resources assessed ·{" "}
            {openFindings} open findings
          </>
        ) : "—",
        href: "/settings/connectors",
        loading: qConnectorCoverage.isPending,
      });
    }

    // 18) AI/ML Workload Tagging
    {
      const aiAssets = qAiAssets.data?.assets ?? [];
      const tagged = aiAssets.filter((a) => a.ai_workload).length;
      const status: CapStatus = aiAssets.length === 0
        ? qAiAssets.isPending ? "pending" : "missing"
        : tagged > 0 ? "active" : "idle";
      out.push({
        id: "ai-workload",
        name: "AI/ML Workload Tagging",
        pillar: "Platform",
        scope: "org",
        signal: tagged,
        status,
        evidence: aiAssets.length > 0
          ? <><strong className="text-foreground">{tagged}</strong> assets tagged ai_workload of {aiAssets.length} loaded (up to 50)</>
          : "No records in the loaded AI asset sample",
        href: "/assets",
        loading: qAiAssets.isPending,
      });
    }

    // 19) Integrations
    {
      const rec = qReceivers.data?.receivers ?? [];
      const healthy = rec.filter((r) => r.status === "active" || r.status === "ok").length;
      const status: CapStatus = rec.length === 0
        ? qReceivers.isPending ? "pending" : "missing"
        : healthy > 0 ? "active" : "idle";
      out.push({
        id: "integrations",
        name: "Integrations",
        pillar: "Response",
        scope: "org",
        signal: rec.length,
        status,
        evidence: rec.length > 0
          ? <>
              <strong className="text-foreground">{rec.length}</strong> receivers ·{" "}
              {healthy} healthy ·{" "}
              <span className="text-muted-foreground">{[...new Set(rec.map((r) => r.status))].join(", ")}</span>
            </>
          : "No receivers",
        href: "/settings/integrations",
        loading: qReceivers.isPending,
      });
    }

    return out;
  }, [
    qCveStats.data, qCveStats.isPending,
    qCveBundle.data,
    qScanJobs.data, qScanJobs.isPending,
    qDashboard.data, qDashboard.isPending,
    qFindingsLifecycle.data,
    qAdmissionDeny.data, qAdmissionDeny.isPending,
    qRuntimeEvents.data, qRuntimeEvents.isPending,
    qNetMap.data, qNetMap.isPending,
    qNetLifecycle.data, qNetLifecycle.isPending,
    qBaselines.data, qBaselines.isPending,
    qVulnProfiles.data, qVulnProfiles.isPending,
    qGroups.data, qGroups.isPending,
    qRrV2.data, qRrV2.isPending,
    qGitopsDrift.data, qGitopsDrift.isPending,
    qFed.data, qFed.isPending,
    qFedMembers.data,
    qCompliance.data, qCompliance.isPending,
    qConnectorCoverage.data, qConnectorCoverage.isPending,
    qAiAssets.data, qAiAssets.isPending,
    qReceivers.data, qReceivers.isPending,
    clusterId, clusterName,
  ]);

  const dependencies: Record<string, Array<{ isError: boolean; isPending: boolean; isFetching: boolean; refetch: () => unknown }>> = {
    "cve-intel": [qCveStats, qCveBundle], "image-scan": [qScanJobs], findings: [qDashboard, qFindingsLifecycle],
    admission: [qAdmissionDeny], "runtime-bpf": [qRuntimeEvents], "net-map": [qNetMap], "auto-netpolicy": [qNetLifecycle],
    "proc-baseline": [qBaselines], "vuln-profiles": [qVulnProfiles], groups: [qGroups], "response-rules": [qRrV2],
    "gitops-drift": [qGitopsDrift], federation: [qFed, qFedMembers], compliance: [qCompliance], cspm: [qConnectorCoverage],
    "ai-workload": [qAiAssets], integrations: [qReceivers],
  };
  const clusterBrowse: Record<string, string> = { findings: "findings?lifecycle=open&view=instances", admission: "audit?action=admission.deny", "runtime-bpf": "runtime", "vuln-profiles": "vuln-profiles", groups: "groups", "response-rules": "response-rules", "gitops-drift": "audit?action=gitops.drift.detected", compliance: "compliance", "ai-workload": "assets" };
  const rows = rawRows.map(original => {
    const destination = clusterBrowse[original.id];
    const row = destination ? { ...original, href: clusterReady ? `/clusters/${encodeURIComponent(clusterId!)}/${destination}` : "/clusters", actionLabel: clusterReady ? "Browse cluster" : "Choose cluster" } : original;
    const sources = dependencies[row.id] ?? [];
    const retry = () => { for (const source of sources) void source.refetch(); };
    if (row.scope === "cluster" && !clusterReady) return { ...row, status: "unavailable" as const, evidence: selectedCluster ? "The selected cluster is unavailable or unresolved." : "Choose a cluster to load this evidence.", lastAt: undefined, signal: 0, loading: false, href: "/clusters" };
    const scopeMismatch = row.id === "net-map" ? Boolean(qNetMap.data?.summary.selected_cluster_id && qNetMap.data.summary.selected_cluster_id !== clusterId) : row.id === "auto-netpolicy" ? Boolean(qNetLifecycle.data?.summary.selected_cluster_id && qNetLifecycle.data.summary.selected_cluster_id !== clusterId) : row.id === "proc-baseline" ? Boolean(qBaselines.data?.profiles.some(profile => profile.cluster_id && profile.cluster_id !== clusterId)) : false;
    if (sources.some(source => source.isError) || scopeMismatch) return { ...row, status: "unavailable" as const, evidence: "Source unavailable or refresh failed.", lastAt: undefined, signal: 0, loading: false, retry };
    if (sources.some(source => source.isPending || source.isFetching)) return { ...row, status: "pending" as const, evidence: "Loading source evidence…", lastAt: undefined, signal: 0, loading: true };
    return { ...row, loading: false };
  });
  const allSources = [qClusters, qCveStats, qCveBundle, qDashboard, qScanJobs, qFindingsLifecycle, qRrV2, qVulnProfiles, qGroups, qFed, qFedMembers, qReceivers, qCompliance, qAdmissionDeny, qGitopsDrift, qRecentAudit, qRuntimeEvents, qAiAssets, qConnectorCoverage, ...(clusterReady ? [qNetMap, qNetLifecycle, qBaselines] : [])];
  const sampleCount = (source: { isError: boolean; isPending: boolean; isFetching: boolean }, dates: Array<string | undefined>) => source.isError ? "Unavailable" : source.isPending || source.isFetching ? "Loading" : dates.filter(date => withinHours(date, 24)).length;
  const audit24 = sampleCount(qRecentAudit, qRecentAudit.data?.events.map(event => event.at) ?? []);
  const runtime24 = sampleCount(qRuntimeEvents, qRuntimeEvents.data?.events.map(event => event.at) ?? []);
  const scans24 = sampleCount(qScanJobs, qScanJobs.data?.jobs.map(job => job.finished_at ?? job.requested_at) ?? []);
  const pillars = useMemo(() => Array.from(new Set(rows.map((r) => r.pillar))).sort(), [rows]);
  const scopeRows = tab === "cluster" ? rows.filter(row => row.scope === "cluster") : tab === "organization" ? rows.filter(row => row.scope === "org") : rows;
  const filtered = pillarFilter ? scopeRows.filter(row => row.pillar === pillarFilter) : scopeRows;

  // table columns
  const columns: Column<CapabilityRow>[] = [
    {
      id: "name",
      header: "Capability", exportValue: row => `${row.name} [${row.scope === "org" ? "organization-wide" : `selected cluster: ${clusterId ?? "none"}`}]`, kind: "name", size: 264, minSize: 200, grow: false,

      sort: (a, b) => a.name.localeCompare(b.name),
      cell: (r) => (
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-foreground">{r.name}</span>
          <span className="text-micro  text-muted-foreground">
            {r.pillar} · {r.scope === "cluster" ? "selected cluster" : "organization-wide"}
          </span>
        </div>
      ),
    },
    {
      id: "evidence",
      header: "Source evidence", exportValue: row => evidenceText(row.evidence), kind: "text", grow: true, minSize: 240, wrap: true,
      sort: (a, b) => a.signal - b.signal,
      cell: (r) => <div className="text-sm text-muted-foreground">{r.loading ? <Skeleton /> : r.evidence}</div>,
    },
    {
      id: "status",
      header: "Status", exportValue: row => statusLabel(row.status), kind: "status", size: 192, minSize: 180, maxSize: 208,

      sort: (a, b) => statusOrder(a.status) - statusOrder(b.status),
      cell: (r) => <StatusPill label={statusLabel(r.status)} tone={tone(r.status)} />,
    },
    {
      id: "last",
      header: "Source timestamp", exportValue: row => row.lastAt ?? "Not reported", kind: "age", size: 144, minSize: 120, maxSize: 176,

      sort: (a, b) => (new Date(a.lastAt ?? 0).getTime()) - (new Date(b.lastAt ?? 0).getTime()),
      cell: (r) => (
        <span className="text-mono text-xs text-muted-foreground" title={r.lastAt ?? ""}>
          {relTime(r.lastAt)}
        </span>
      ),
    },
    {
      id: "action",
      header: "Open / retry", kind: "actions", size: 176, minSize: 152, maxSize: 192, exportable: false,

      cell: (r) =>
        r.retry ? <Button size="sm" onClick={r.retry}>Retry {r.name}</Button> : r.href ? (
          <a
            href={r.href}
            className="inline-flex h-7 items-center gap-1 rounded border border-border bg-card px-2 text-xs text-muted-foreground transition-colors hover:bg-accent hover:text-foreground"
          >
            {r.actionLabel ?? "Open"} <ArrowUpRight className="h-3 w-3" />
          </a>
        ) : null,
    },
  ];

  const workspace = (<div data-testid="coverage-table">
        <DataTable<CapabilityRow>
          rows={filtered}
          columns={columns}
          rowKey={(r) => r.id}
          preferencesKey="posture-capability-evidence"
          exportFileName="constellation-posture-listed-evidence"
          exportLabel="Export listed evidence CSV"
          defaultSort={{ id: "status", dir: "asc" }}
          rowTestId={() => "coverage-row"}
          rowAttrs={row => ({ "data-capability-id": row.id, "data-scope": row.scope })}
        />
      </div>);

  return (
    <div className="space-y-4" data-testid="coverage-page">
      <PageHeader
        title="Posture"
        description="Reported evidence per capability, with organization sources and selected-cluster sources shown separately."
        actions={<Button onClick={() => { for (const source of allSources) void source.refetch(); }} disabled={allSources.some(source => source.isFetching)}>Refresh evidence</Button>}
      />

      <VerdictBanner status={rows.some(row => row.status === "unavailable") ? "degraded" : "info"} title={rows.some(row => row.status === "unavailable") ? "Some posture evidence is unavailable" : "Review reported capability evidence"} detail="Records and configured modes do not prove policy delivery, enforcement or protection. Organization-wide sources remain separate from the selected cluster." />
      <StatGrid data-testid="coverage-stats">
        <StatCard label="Rows with evidence" value={rows.filter(row => row.status === "active" || row.status === "partial" || row.status === "idle").length} icon={<CircleCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Unavailable capability rows" value={rows.filter(row => row.status === "unavailable").length} icon={<CircleMinus className="h-3.5 w-3.5" />} />
        <StatCard label="Loaded audit records · 24h" value={audit24} valueKind={typeof audit24 === "number" ? "number" : "text"} hint="Up to 100 loaded audit records" />
        <StatCard label="Loaded runtime records · 24h" value={runtime24} valueKind={typeof runtime24 === "number" ? "number" : "text"} hint="Up to 50 loaded runtime records" icon={<Radio className="h-3.5 w-3.5" />} />
        <StatCard label="Loaded scan jobs · 24h" value={scans24} valueKind={typeof scans24 === "number" ? "number" : "text"} hint="Up to 200 loaded scan jobs" icon={<Clock3 className="h-3.5 w-3.5" />} />
      </StatGrid>
      {qClusters.isError && <ErrorState title="The cluster inventory is unavailable." action={<Button onClick={() => void qClusters.refetch()}>Retry clusters</Button>} />}
      {selectedCluster && !clusterReady && !qClusters.isFetching && !qClusters.isPending && <ErrorState title="The requested cluster is not available in the current organization." />}
      <div className="flex min-w-0 flex-col gap-3 rounded-md border border-border bg-card p-3 lg:flex-row lg:items-start">
        <div className="flex min-w-0 flex-1 flex-col gap-2">
          <label htmlFor="coverage-cluster-select" className="text-micro  text-muted-foreground">Cluster scope</label>
          <Select
            id="coverage-cluster-select"
            className="h-8 w-full min-w-0 max-w-full rounded-md border border-border bg-background px-2 text-sm"
            value={clusterId ?? ""}
            onChange={(e) => update("cluster", e.target.value)}
            aria-label="Cluster picker"
            data-testid="coverage-cluster-picker"
          >
            <option value="">Organization sources only — choose a cluster</option>
            {selectedCluster && !clusterList.some(cluster => cluster.id === selectedCluster) && <option value={selectedCluster}>Unavailable cluster</option>}
            {clusterList.map((c) => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </Select>
          <span className="text-micro text-muted-foreground">applies to network · auto-netpolicy · process baseline</span>
        </div>
        <div className="flex min-w-0 flex-col gap-2 lg:w-48 lg:flex-none">
          <label htmlFor="coverage-pillar-select" className="text-micro  text-muted-foreground">Pillar</label>
          <Select
            id="coverage-pillar-select"
            className="h-8 w-full min-w-0 max-w-full rounded-md border border-border bg-background px-2 text-sm"
            value={pillarFilter}
            onChange={(e) => update("pillar", e.target.value)}
            aria-label="Pillar filter"
          >
            <option value="">All pillars</option>
            {pillars.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </Select>
        </div>
      </div>

      {pillarFilter && !pillars.includes(pillarFilter) && <ErrorState title="The requested pillar filter is invalid." action={<Button onClick={() => update("pillar", "")}>Clear pillar filter</Button>} />}
      <Tabs value={tab} onValueChange={setTab} items={[{ value: "all", label: "All sources", content: workspace }, { value: "organization", label: "Organization", content: workspace }, { value: "cluster", label: "Selected cluster", content: workspace }]} />
      {!['all', 'organization', 'cluster'].includes(tab) && <ErrorState title="The requested workspace tab is invalid." action={<Button onClick={() => setTab("all")}>Show all sources</Button>} />}
      <div className="flex items-center gap-3 text-micro text-muted-foreground">
        <CircleDot className="h-3 w-3" />
        <span>
          Source limits: audit 100, runtime 50, scan jobs 200, AI assets 50. These are samples, not complete 24-hour totals. Source records may overlap. Status: <strong>Evidence reported</strong> = source-specific records or activity ·{" "}
          <strong>Partial</strong> = stale (&gt;{SEVERE_PARTIAL_THRESHOLD_HOURS}h) or incomplete source evidence ·{" "}
          <strong>Records reported</strong> = listed records without a recent-event claim ·{" "}
          <strong>No records</strong> = a successful source returned no applicable records. Unavailable and refreshing sources are never treated as empty or healthy.
        </span>
      </div>
    </div>
  );
}

function statusOrder(s: CapStatus): number {
  return s === "active" ? 0 : s === "partial" ? 1 : s === "idle" ? 2 : s === "pending" ? 3 : 4;
}

function Skeleton() {
  return <span className="inline-block h-3 w-40 animate-pulse rounded bg-muted" aria-hidden />;
}

function evidenceText(node: ReactNode): string {
  if (node === null || node === undefined || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(evidenceText).join("");
  return isValidElement<{ children?: ReactNode }>(node) ? evidenceText(node.props.children) : "";
}
