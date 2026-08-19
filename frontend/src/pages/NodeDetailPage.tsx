import { useMemo } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Boxes, ChevronLeft, Database, Layers, Server, ShieldAlert, ShieldCheck, TerminalSquare } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { nodes as nodesApi, type HostVulnerability, type NodeSummary } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { cn } from "@/lib/cn";

export function NodeDetailPage() {
  const { nodeName: nodeParam } = useParams<{ nodeName: string }>();
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const nodeName = useMemo(() => safeDecode(nodeParam ?? ""), [nodeParam]);

  const q = useQuery({
    queryKey: ["node-detail", clusterId, nodeName],
    queryFn: () => nodesApi.get(clusterId!, nodeName),
    enabled: !!clusterId && !!nodeName,
  });

  const detail = q.data;
  const node = detail?.node;

  if (clusterLoading || q.isPending) {
    return <p className="text-sm text-muted-foreground" data-testid="node-detail-loading">Loading node...</p>;
  }
  if (q.isError || !node) {
    return <p className="text-sm text-status-error">Node not found.</p>;
  }

  return (
    <div className="space-y-4" data-testid="node-detail-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <Link to={`/clusters/${clusterId}/nodes`} className="inline-flex items-center gap-1 hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            Nodes
          </Link>
        }
        title={node.node}
        mono
        badges={
          <>
            <NodeBadge item={node} />
            {node.coverage_gaps?.length ? <Pill tone="warn">{node.coverage_gaps.length} coverage gap{node.coverage_gaps.length === 1 ? "" : "s"}</Pill> : null}
            {node.cis_failed > 0 ? <Pill tone="danger">{node.cis_failed} CIS fail{node.cis_failed === 1 ? "" : "s"}</Pill> : null}
          </>
        }
        description={<>{displayOS(node)} · kernel {node.kernel_release || "unknown"} · {node.arch || "arch unknown"} — host vulnerabilities, CIS benchmark results, and agent-collected inventory for this node.</>}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5" data-testid="node-stats">
        <StatCard label="Open CVEs" value={node.open_vulns} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={node.open_vulns > 0 ? "high" : "neutral"} />
        <StatCard label="Packages" value={node.package_count} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Containers" value={node.container_count} icon={<Layers className="h-3.5 w-3.5" />} />
        <StatCard label="Processes" value={node.process_count} icon={<TerminalSquare className="h-3.5 w-3.5" />} />
        <StatCard label="CIS Failed" value={node.cis_failed} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={node.cis_failed > 0 ? "critical" : "neutral"} />
      </section>

      <div className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <HostPosture node={node} />
          <ScanState node={node} />
        </div>

        <HostVulnerabilitiesTable vulnerabilities={detail.vulnerabilities ?? []} />

        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <JsonPanel title="CIS evidence" payload={detail.cis} observedAt={node.cis_observed_at} icon={ShieldCheck} />
          <JsonPanel title="Host facts" payload={detail.facts} observedAt={node.host_facts_observed_at} icon={Server} />
          <JsonPanel title="Package inventory" payload={detail.packages} observedAt={node.packages_observed_at} icon={Database} />
          <JsonPanel title="Container inventory" payload={detail.containers} observedAt={node.containers_observed_at} icon={Boxes} />
          <JsonPanel title="Process inventory" payload={detail.processes} observedAt={node.processes_observed_at} icon={TerminalSquare} />
        </div>
      </div>
    </div>
  );
}

function HostPosture({ node }: { node: NodeSummary }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Host posture</h2>
      <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
        <Field label="Operating system" value={displayOS(node)} />
        <Field label="Kernel" value={node.kernel_release || "-"} />
        <Field label="Architecture" value={node.arch || "-"} />
        <Field label="CRI runtime" value={node.cri_runtime || "-"} />
        <Field label="CNI" value={node.cni_name || "-"} />
        <Field label="CIS profile" value={node.cis_profile || "-"} />
        <Field label="BTF available" value={formatBool(node.btf_present)} />
        <Field label="NFQUEUE capable" value={formatBool(node.nfqueue_capable)} />
        <Field label="Inventory hash" value={node.inventory_hash || "-"} wide />
      </dl>
      <div className="mt-4 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
        <StatusMetric label="CIS pass" value={node.cis_passed} tone="ok" />
        <StatusMetric label="CIS fail" value={node.cis_failed} tone={node.cis_failed > 0 ? "danger" : "ok"} />
        <StatusMetric label="CIS warn" value={node.cis_warned} tone={node.cis_warned > 0 ? "warn" : "ok"} />
        <StatusMetric label="CIS skip" value={node.cis_skipped} tone="neutral" />
      </div>
    </section>
  );
}

function ScanState({ node }: { node: NodeSummary }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Scan and agent state</h2>
      <div className="mt-3 flex flex-wrap gap-2">
        <StatusPill status={node.runtime_agent_status} />
        <StatusPill status={node.scan_status || "missing"} />
      </div>
      <dl className="mt-4 grid gap-2 text-sm">
        <Field label="Agent version" value={node.runtime_agent_version || "-"} />
        <Field label="Agent last seen" value={formatDate(node.runtime_agent_last_seen_at)} />
        <Field label="Scan target" value={node.scan_target_id || "-"} />
        <Field label="Last scanned" value={formatDate(node.last_scanned_at)} />
        <Field label="Packages observed" value={formatDate(node.packages_observed_at)} />
        <Field label="Containers observed" value={formatDate(node.containers_observed_at)} />
        <Field label="Processes observed" value={formatDate(node.processes_observed_at)} />
        <Field label="CIS observed" value={formatDate(node.cis_observed_at)} />
      </dl>
      <div className="mt-4">
        <h3 className="text-xs font-semibold uppercase text-muted-foreground">Coverage gaps</h3>
        {node.coverage_gaps?.length ? (
          <div className="mt-2 flex flex-wrap gap-2">
            {node.coverage_gaps.map((gap) => <Pill key={gap} tone="warn">{gap}</Pill>)}
          </div>
        ) : (
          <p className="mt-2 text-xs text-muted-foreground">No coverage gaps reported.</p>
        )}
      </div>
    </section>
  );
}

function HostVulnerabilitiesTable({ vulnerabilities }: { vulnerabilities: HostVulnerability[] }) {
  const columns: Column<HostVulnerability>[] = [
    {
      id: "cve",
      header: "CVE",
      cell: (vulnerability) => (
        <>
          {vulnerability.vuln_id ? (
            <Link to={`/cve/${encodeURIComponent(vulnerability.vuln_id)}`} className="font-mono text-xs font-medium hover:underline">
              {vulnerability.vuln_id}
            </Link>
          ) : (
            <span className="font-mono text-xs">-</span>
          )}
          <div className="mt-1 max-w-[420px] truncate text-xs text-muted-foreground">{vulnerability.summary || vulnerability.aliases?.join(", ") || "-"}</div>
        </>
      ),
    },
    {
      id: "package",
      header: "Package",
      cell: (vulnerability) => (
        <>
          <div className="font-mono text-xs">{vulnerability.package_name || "-"}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">{vulnerability.package_version || "-"}</div>
        </>
      ),
    },
    {
      id: "severity",
      header: "Severity",
      cell: (vulnerability) => <SeverityPill severity={vulnerability.severity || "unknown"} />,
    },
    {
      id: "fix",
      header: "Fix",
      cell: (vulnerability) => <span className="font-mono text-xs">{vulnerability.fixed_version || "-"}</span>,
    },
    {
      id: "observed",
      header: "Observed",
      cell: (vulnerability) => (
        <div className="text-xs">
          <div>{formatDate(vulnerability.observed_at)}</div>
          <div className="mt-1 text-muted-foreground">{vulnerability.source}</div>
        </div>
      ),
    },
  ];

  return (
    <section className="space-y-2" data-testid="node-vulnerabilities">
      <div>
        <h2 className="text-sm font-semibold">Host vulnerabilities</h2>
        <p className="mt-1 text-xs text-muted-foreground">VulnDB-backed package matches for this node inventory.</p>
      </div>
      <DataTable
        rows={vulnerabilities}
        columns={columns}
        rowKey={(vulnerability) => `${vulnerability.vuln_id}:${vulnerability.package_name}:${vulnerability.package_version}`}
        emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No open host vulnerabilities recorded for this node.</div>}
      />
    </section>
  );
}

function JsonPanel({ title, payload, observedAt, icon: Icon }: { title: string; payload: unknown; observedAt?: string; icon: LucideIcon }) {
  const preview = useMemo(() => renderPayload(payload), [payload]);
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">{title}</h2>
          <p className="mt-1 text-xs text-muted-foreground">{payloadSummary(payload)} · observed {formatDate(observedAt)}</p>
        </div>
        <Icon className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      {preview ? (
        <pre className="mt-3 max-h-[360px] overflow-auto rounded-md border border-border bg-background p-3 text-[11px] leading-5 text-muted-foreground">
          {preview}
        </pre>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground">No payload reported.</p>
      )}
    </section>
  );
}

function StatusMetric({ label, value, tone }: { label: string; value: number; tone: "neutral" | "ok" | "warn" | "danger" }) {
  return (
    <div className={cn("rounded-md border border-border p-2", tone === "ok" && "border-status-ok/30 bg-status-ok/10", tone === "warn" && "border-status-warn/30 bg-status-warn/10", tone === "danger" && "border-status-error/30 bg-status-error/10")}>
      <div className="text-lg font-semibold">{value.toLocaleString()}</div>
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
    </div>
  );
}

function Field({ label, value, wide }: { label: string; value: ReactNode; wide?: boolean }) {
  return (
    <div className={cn("grid gap-1", wide && "sm:col-span-2")}>
      <dt className="text-[10px] uppercase text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono text-xs">{value}</dd>
    </div>
  );
}

function NodeBadge({ item }: { item: NodeSummary }) {
  const healthy = item.runtime_agent_status === "healthy" && item.scan_status === "completed" && !(item.coverage_gaps?.length);
  return (
    <Pill tone={healthy ? "ok" : item.runtime_agent_status === "missing" ? "danger" : "warn"}>
      {healthy ? "covered" : item.runtime_agent_status || "unknown"}
    </Pill>
  );
}

function StatusPill({ status }: { status: string }) {
  const normalized = status || "missing";
  return (
    <Pill tone={normalized === "healthy" || normalized === "completed" ? "ok" : normalized === "missing" || normalized === "failed" ? "danger" : "warn"}>
      {normalized}
    </Pill>
  );
}

function SeverityPill({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase();
  return (
    <Pill tone={normalized === "critical" ? "danger" : normalized === "high" || normalized === "medium" ? "warn" : "neutral"}>
      {normalized}
    </Pill>
  );
}

function Pill({ tone, children }: { tone: "neutral" | "ok" | "warn" | "danger"; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium",
        tone === "neutral" && "bg-muted text-muted-foreground",
        tone === "ok" && "bg-status-ok/10 text-status-ok",
        tone === "warn" && "bg-status-warn/10 text-status-warn",
        tone === "danger" && "bg-status-error/10 text-status-error",
      )}
    >
      {children}
    </span>
  );
}

function payloadSummary(payload: unknown): string {
  if (!payload) return "no payload";
  if (Array.isArray(payload)) return `${payload.length} records`;
  if (typeof payload !== "object") return "scalar payload";
  const objectPayload = payload as Record<string, unknown>;
  for (const key of ["packages", "containers", "processes", "checks", "items", "results"]) {
    const value = objectPayload[key];
    if (Array.isArray(value)) return `${value.length} ${key}`;
  }
  return `${Object.keys(objectPayload).length} keys`;
}

function renderPayload(payload: unknown): string {
  if (!payload) return "";
  const rendered = JSON.stringify(payload, null, 2);
  if (!rendered || rendered === "null") return "";
  if (rendered.length <= 12000) return rendered;
  return `${rendered.slice(0, 12000)}\n... truncated for display`;
}

function displayOS(item: NodeSummary): string {
  if (item.os_id && item.os_version_id) return `${item.os_id} ${item.os_version_id}`;
  return item.os_id || item.os_version_id || "OS unknown";
}

function formatBool(value?: boolean): string {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "-";
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
