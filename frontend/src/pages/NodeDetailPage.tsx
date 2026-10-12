import { useEffect, useMemo, useRef } from "react";
import type { ReactNode } from "react";
import { useParams } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Boxes, ChevronLeft, Database, Layers, Server, ShieldAlert, ShieldCheck, TerminalSquare, RefreshCw } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import { nodes as nodesApi, type HostVulnerability, type NodeSummary, type NodeDetail } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { fmtBytes } from "@/lib/format";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { entityDetailError, useEntityClusterScope } from "./entity-detail-scope";

export function NodeDetailPage() {
  const { nodeName = "" } = useParams({ strict: false });
  const scope = useEntityClusterScope();
  const { clusterId } = scope;
  const key = ["node-detail", clusterId, nodeName];
  const q = useQuery({
    queryKey: key,
    queryFn: async () => {
      const data = await nodesApi.get(clusterId!, nodeName);
      if (data.node.node !== nodeName || data.node.cluster_id !== clusterId || data.vulnerabilities.some((item) => item.cluster_id && item.cluster_id !== clusterId)) throw new Error("The node evidence does not match the requested node and cluster.");
      return data;
    },
    enabled: scope.ready && !!nodeName,
  });
  const backPath = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/nodes` : "/clusters";
  const header = <PageHeader title="Node evidence" description="Review reported host vulnerabilities, inventory and benchmark results for an exact cluster node." backLink={<a href={backPath}>Nodes</a>} />;
  if (!scope.ready) return <div className="space-y-4">{header}{scope.loading ? <LoadingState label="Resolving node cluster…" /> : <ErrorState title="The requested node cluster could not be resolved." error={scope.error} action={<Button onClick={scope.retry}>Retry cluster</Button>} />}</div>;
  if (!nodeName) return <div className="space-y-4">{header}<ErrorState title="An exact node name is required." /></div>;
  if (q.isError) return <div className="space-y-4">{header}<VerdictBanner status="degraded" title="Node evidence is unavailable" detail="Previously loaded evidence is hidden after a failed refresh." /><ErrorState title="Node evidence could not be loaded or refreshed." error={entityDetailError(q.error)} action={<Button onClick={() => void q.refetch()}>Retry node</Button>} /></div>;
  if (q.data && (q.data.node.node !== nodeName || q.data.node.cluster_id !== clusterId || q.data.vulnerabilities.some((item) => item.cluster_id && item.cluster_id !== clusterId))) return <div className="space-y-4">{header}<ErrorState title="The node evidence does not match the requested node and cluster." action={<Button onClick={() => void q.refetch()}>Retry node</Button>} /></div>;
  if (!q.isSuccess || !q.data) return <div className="space-y-4">{header}<LoadingState label="Loading node evidence…" /></div>;
  return <NodeEvidence key={`${clusterId}:${nodeName}`} detail={q.data} clusterId={clusterId!} backPath={backPath} refreshing={q.isFetching} refresh={() => void q.refetch()} scopeReady={scope.recheck} />;
}

function NodeEvidence({ detail, clusterId, backPath, refreshing, refresh, scopeReady }: { detail: NodeDetail; clusterId: string; backPath: string; refreshing: boolean; refresh: () => void; scopeReady: () => boolean }) {
  const node = detail.node;
  const exportScope = `node-${clusterId}-${encodeURIComponent(node.node)}`;
  const qc = useQueryClient();
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const scopeCheck = useRef(scopeReady);
  scopeCheck.current = scopeReady;
  const submitting = useRef(false);
  const scanMut = useMutation({
    mutationFn: async () => {
      const target = node.scan_target_id;
      const current = () => {
        const state = qc.getQueryState<NodeDetail>(["node-detail", clusterId, node.node]);
        return active.current && scopeCheck.current() && state?.status === "success" && state.fetchStatus === "idle" && state.data?.node.node === node.node && state.data.node.cluster_id === clusterId && state.data.node.scan_target_id === target;
      };
      if (!target || !current()) throw new Error("Current node evidence is unavailable or refreshing. Reload before queuing a scan.");
      const latest = await nodesApi.get(clusterId, node.node);
      if (!current() || latest.node.node !== node.node || latest.node.cluster_id !== clusterId || latest.node.scan_target_id !== target) throw new Error("The node or scan target changed before the scan could be queued.");
      return nodesApi.scan(target);
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["node-detail", clusterId, node.node], exact: true }); },
    onSettled: () => { submitting.current = false; },
  });
  const [requestedTab, setTab] = useTabParam("tab", "vulnerabilities");
  const tab = ["vulnerabilities", "cis", "containers", "processes", "packages", "details"].includes(requestedTab) ? requestedTab : "vulnerabilities";
  const incomplete = !node.last_scanned_at || !!node.coverage_gaps?.length;
  const attention = node.open_vulns > 0 || node.cis_failed > 0;
  return <div className="space-y-5" data-testid="node-detail-page" data-cluster-id={clusterId}>
    <PageHeader title={node.node} mono backLink={<a href={backPath} className="inline-flex items-center gap-1"><ChevronLeft className="h-3.5 w-3.5" />Nodes</a>}
      description={`${displayOS(node)} · kernel ${node.kernel_release || "unknown"} · ${node.arch || "arch unknown"} — reported evidence for this exact node and cluster.`}
      badges={<><NodeBadge item={node} />{node.coverage_gaps?.length ? <Pill tone="warn">{node.coverage_gaps.length} coverage gaps</Pill> : null}</>}
      actions={<div className="flex flex-wrap gap-2"><Button onClick={refresh} disabled={refreshing}>{refreshing ? "Refreshing…" : "Refresh evidence"}</Button>{node.scan_target_id && <Button variant="outline" disabled={refreshing || scanMut.isPending} onClick={() => { if (!submitting.current) { submitting.current = true; scanMut.mutate(); } }}><RefreshCw className="h-3.5 w-3.5" />{scanMut.isPending ? "Queuing…" : "Scan node"}</Button>}</div>} />
    <VerdictBanner status={attention ? "degraded" : "info"} title={incomplete ? "Node evidence has collection or scan gaps" : attention ? "Reported node findings need review" : "No open node vulnerabilities or failed CIS checks reported"} detail="Counts reflect the latest reported node evidence, not proof of complete coverage or current enforcement. Host vulnerability detail is capped at 2,000 rows." />
    <StatGrid data-testid="node-stats">
      <StatCard label="Open CVEs reported" value={node.last_scanned_at ? node.open_vulns : "Not scanned"} valueKind={node.last_scanned_at ? "number" : "text"} tone={node.open_vulns > 0 ? "high" : "neutral"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
      <StatCard label="Packages reported" value={node.packages_observed_at ? node.package_count : "Not collected"} valueKind={node.packages_observed_at ? "number" : "text"} icon={<Database className="h-3.5 w-3.5" />} />
      <StatCard label="Containers reported" value={node.containers_observed_at ? node.container_count : "Not collected"} valueKind={node.containers_observed_at ? "number" : "text"} icon={<Layers className="h-3.5 w-3.5" />} />
      <StatCard label="Processes reported" value={node.processes_observed_at ? node.process_count : "Not collected"} valueKind={node.processes_observed_at ? "number" : "text"} icon={<TerminalSquare className="h-3.5 w-3.5" />} />
      <StatCard label="CIS failures reported" value={node.cis_observed_at ? node.cis_failed : "Not collected"} valueKind={node.cis_observed_at ? "number" : "text"} tone={node.cis_failed > 0 ? "critical" : "neutral"} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
    </StatGrid>
    {refreshing && <p role="status" className="text-sm text-muted-foreground">Refreshing node evidence; previously loaded evidence remains visible until the request settles.</p>}
    {scanMut.isError && <p role="alert" className="text-sm text-status-error">Scan request failed: {entityDetailError(scanMut.error)}</p>}
    {scanMut.isSuccess && <p role="status" className="text-sm">Scan queued. Completion will be reported separately.</p>}
    <Tabs value={tab} onValueChange={setTab} items={[
      { value: "vulnerabilities", label: "Host vulnerabilities", content: <HostVulnerabilitiesTable vulnerabilities={detail.vulnerabilities} exportScope={exportScope} /> },
      { value: "cis", label: "CIS benchmark", content: <CisBenchmarkTable cis={detail.cis} observedAt={node.cis_observed_at} exportScope={exportScope} /> },
      { value: "containers", label: "Containers", content: <NodeContainersTable containers={detail.containers} observedAt={node.containers_observed_at} clusterId={clusterId} exportScope={exportScope} /> },
      { value: "processes", label: "Processes", content: <NodeProcessesTable processes={detail.processes} observedAt={node.processes_observed_at} exportScope={exportScope} /> },
      { value: "packages", label: "Packages", content: <NodePackagesTable payload={detail.packages} observedAt={node.packages_observed_at} exportScope={exportScope} /> },
      { value: "details", label: "Host details", content: <div className="space-y-4"><HostPosture node={node} /><ScanState node={node} /><Collapse label="Raw host facts"><JsonPanel title="Host facts" payload={detail.facts} observedAt={node.host_facts_observed_at} icon={Server} /></Collapse></div> },
    ]} />
  </div>;
}

function HostPosture({ node }: { node: NodeSummary }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Host posture</h2>
      <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
        <Field label="Operating system" value={displayOS(node)} />
        <Field label="Kernel" value={node.kernel_release || "-"} />
        <Field label="Architecture" value={node.arch || "-"} />
        <Field label="CPUs" value={node.cpu_count ? String(node.cpu_count) : "-"} />
        <Field label="Memory" value={node.memory_bytes ? fmtBytes(node.memory_bytes) : "-"} />
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

function HostVulnerabilitiesTable({ vulnerabilities, exportScope }: { vulnerabilities: HostVulnerability[]; exportScope: string }) {
  const columns: Column<HostVulnerability>[] = [
    {
      id: "cve",
      header: "CVE", kind: "name", wrap: true,
      exportValue: (vulnerability) => vulnerability.vuln_id,
      cell: (vulnerability) => (
        <>
          {vulnerability.vuln_id ? (
            <a href={`/cve/${encodeURIComponent(vulnerability.vuln_id)}`} className="font-mono text-xs font-medium hover:underline">
              {vulnerability.vuln_id}
            </a>
          ) : (
            <span className="font-mono text-xs">-</span>
          )}
          <div className="mt-1 text-xs text-muted-foreground">{vulnerability.summary || vulnerability.aliases?.join(", ") || "-"}</div>
        </>
      ),
    },
    {
      id: "package",
      header: "Package", kind: "text", code: true, wrap: true, size: 200, minSize: 144, maxSize: 280,
      cell: (vulnerability) => (
        <>
          <div className="font-mono text-xs">{vulnerability.package_name || "-"}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">{vulnerability.package_version || "-"}</div>
        </>
      ),
    },
    {
      id: "severity",
      header: "Severity", kind: "status",
      cell: (vulnerability) => <SeverityPill severity={vulnerability.severity || "unknown"} />,
    },
    {
      id: "fix",
      header: "Fix", kind: "version", size: 160, minSize: 112, maxSize: 224, wrap: true,
      cell: (vulnerability) => <span className="font-mono text-xs">{vulnerability.fixed_version || "-"}</span>,
    },
    {
      id: "observed",
      header: "Observed", kind: "date", size: 224, minSize: 208, maxSize: 240, wrap: true,
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
        <p className="mt-1 text-xs text-muted-foreground">Package vulnerabilities returned for this node. The server returns at most 2,000 rows; table filters and CSV export cover loaded rows only. The reported open-CVE summary can exceed this detail limit.</p>
      </div>
      <DataTable
        rows={vulnerabilities}
        sourceLimit={2000}
        sourceCount={vulnerabilities.length}
        preferencesKey="node-host-vulnerabilities"
        exportFileName={`${exportScope}-host-vulnerabilities-loaded`}
        columns={columns}
        rowKey={(vulnerability) => `${vulnerability.vuln_id}:${vulnerability.package_name}:${vulnerability.package_version}`}
        emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No host vulnerability rows returned. This does not establish a successful or complete scan.</div>}
      />
    </section>
  );
}

// NodeContainersTable renders the node's running containers as a table (name · pod ·
// image · state) linked to workloads — replacing the old raw-JSON dump.
function NodeContainersTable({ containers, observedAt, clusterId, exportScope }: { containers?: unknown; observedAt?: string; clusterId?: string; exportScope: string }) {
  const items = useMemo(() => {
    const raw = (containers as { items?: Array<Record<string, unknown>> } | undefined)?.items;
    return Array.isArray(raw) ? raw : [];
  }, [containers]);
  const columns: Column<Record<string, unknown>>[] = [
    { id: "name", header: "Container", kind: "name", wrap: true, cell: (c) => <span className="text-xs font-medium">{String(c.name ?? "—")}</span>, sort: (a, b) => String(a.name ?? "").localeCompare(String(b.name ?? "")) },
    { id: "pod", header: "Pod", kind: "text", code: true, wrap: true, size: 240, minSize: 176, maxSize: 360, cell: (c) => (
        clusterId && c.pod_name
          ? <a href={`/clusters/${clusterId}/deployments?q=${encodeURIComponent(String(c.pod_name).replace(/-[a-z0-9]+-[a-z0-9]+$/, ""))}`} className="text-mono text-[11px] text-[color:var(--color-primary)] hover:underline">{String(c.pod_namespace ?? "")}/{String(c.pod_name ?? "")}</a>
          : <span className="text-mono text-[11px] text-muted-foreground">{String(c.pod_namespace ?? "")}/{String(c.pod_name ?? "—")}</span>
      ) },
    { id: "image", header: "Image", kind: "text", code: true, wrap: true, size: 240, minSize: 176, maxSize: 360, cell: (c) => <span className="text-mono text-[11px] text-muted-foreground block" title={String(c.image_ref ?? c.image ?? "")}>{String(c.image_ref ?? c.image ?? "—")}</span> },
    { id: "state", header: "State", kind: "status",  cell: (c) => {
        const st = String(c.state ?? "").replace("CONTAINER_", "").toLowerCase();
        return <span className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium", st === "running" ? "bg-[color-mix(in_oklab,var(--color-severity-low)_16%,transparent)] text-[color:var(--color-severity-low)]" : "bg-muted text-muted-foreground")}>{st || "—"}</span>;
      }, sort: (a, b) => String(a.state ?? "").localeCompare(String(b.state ?? "")) },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2"><Boxes className="h-3.5 w-3.5 text-muted-foreground" /><h2 className="text-sm font-semibold">Running containers</h2></div>
        <span className="text-mono text-xs text-muted-foreground">{items.length}{observedAt ? ` · ${formatDate(observedAt)}` : ""}</span>
      </header>
      {items.length === 0 ? <p className="px-3 py-6 text-center text-xs text-muted-foreground">No container inventory recorded.</p>
        : <div className="p-2"><DataTable rows={items} columns={columns} rowKey={(c) => String(c.id ?? c.name)} defaultSort={{ id: "name", dir: "asc" }} preferencesKey="node-containers" exportFileName={`${exportScope}-container-inventory-loaded`} /></div>}
    </section>
  );
}

// NodeProcessesTable renders the node's process inventory as a table — replacing raw JSON.
function NodeProcessesTable({ processes, observedAt, exportScope }: { processes?: unknown; observedAt?: string; exportScope: string }) {
  const items = useMemo(() => {
    const raw = (processes as { items?: Array<Record<string, unknown>> } | undefined)?.items;
    return Array.isArray(raw) ? raw : [];
  }, [processes]);
  const columns: Column<Record<string, unknown>>[] = [
    { id: "pid", header: "PID", kind: "count",  numeric: true, cell: (p) => <span className="text-mono text-[11px]">{String(p.pid ?? "—")}</span>, sort: (a, b) => Number(a.pid ?? 0) - Number(b.pid ?? 0) },
    { id: "comm", header: "Process", kind: "name", wrap: true, code: true,  cell: (p) => <span className="text-xs font-medium">{String(p.comm ?? "—")}</span>, sort: (a, b) => String(a.comm ?? "").localeCompare(String(b.comm ?? "")) },
    { id: "uid", header: "User", kind: "text", wrap: true, size: 104, minSize: 88, maxSize: 144,  cell: (p) => <span className={cn("text-mono text-[11px]", Number(p.uid) === 0 && "text-[color:var(--color-severity-high)]")}>{Number(p.uid) === 0 ? "root" : String(p.uid ?? "—")}</span>, sort: (a, b) => Number(a.uid ?? 0) - Number(b.uid ?? 0) },
    { id: "cmdline", header: "Command line", kind: "text", code: true, wrap: true, size: 320, minSize: 240, maxSize: 640, grow: true, cell: (p) => <span className="text-mono text-[10px] text-muted-foreground block" title={String(p.cmdline ?? "")}>{String(p.cmdline ?? "—")}</span> },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2"><TerminalSquare className="h-3.5 w-3.5 text-muted-foreground" /><h2 className="text-sm font-semibold">Processes</h2></div>
        <span className="text-mono text-xs text-muted-foreground">{items.length}{observedAt ? ` · ${formatDate(observedAt)}` : ""}</span>
      </header>
      {items.length === 0 ? <p className="px-3 py-6 text-center text-xs text-muted-foreground">No process inventory recorded.</p>
        : <div className="p-2"><DataTable rows={items} columns={columns} rowKey={(p) => String(p.pid)} defaultSort={{ id: "pid", dir: "asc" }} preferencesKey="node-processes" exportFileName={`${exportScope}-process-inventory-loaded`} /></div>}
    </section>
  );
}

// CisBenchmarkTable renders CIS host-benchmark checks as a real, sortable table (fails
// first) with per-control remediation detail — replacing the old raw-JSON dump and
// matching NeuVector's compliance list.
function CisBenchmarkTable({ cis, observedAt, exportScope }: { cis?: unknown; observedAt?: string; exportScope: string }) {
  const checks = useMemo(() => {
    const raw = (cis as { checks?: Array<{ id?: string; title?: string; result?: string; detail?: string }> } | undefined)?.checks;
    return Array.isArray(raw) ? raw : [];
  }, [cis]);
  const rank: Record<string, number> = { fail: 0, warn: 1, info: 2, note: 2, pass: 3, skip: 4 };
  const columns: Column<{ id?: string; title?: string; result?: string; detail?: string }>[] = [
    { id: "result", header: "Result", kind: "status",
      cell: (c) => <CisResultBadge result={c.result} />,
      sort: (a, b) => (rank[(a.result || "").toLowerCase()] ?? 9) - (rank[(b.result || "").toLowerCase()] ?? 9) },
    { id: "id", header: "Control", kind: "id", size: 144, minSize: 112, maxSize: 192,  cell: (c) => <span className="text-mono text-xs">{c.id || "—"}</span>, sort: (a, b) => (a.id || "").localeCompare(b.id || "") },
    { id: "title", header: "Title", kind: "name", wrap: true, cell: (c) => <span className="text-xs">{c.title || "—"}</span>, sort: (a, b) => (a.title || "").localeCompare(b.title || "") },
    { id: "detail", header: "Remediation / detail", kind: "text", wrap: true, size: 320, minSize: 240, maxSize: 560, grow: true, cell: (c) => <span className="block text-[11px] text-muted-foreground" title={c.detail}>{c.detail || "—"}</span> },
  ];
  const fails = checks.filter((c) => (c.result || "").toLowerCase() === "fail").length;
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div className="flex items-center gap-2"><ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" /><h2 className="text-sm font-semibold">CIS Benchmark</h2></div>
        <span className="text-mono text-xs text-muted-foreground">{fails} failing / {checks.length} checks{observedAt ? ` · ${formatDate(observedAt)}` : ""}</span>
      </header>
      {checks.length === 0 ? (
        <p className="px-3 py-6 text-center text-xs text-muted-foreground">No CIS benchmark results recorded.</p>
      ) : (
        <div className="p-2">
          <DataTable rows={checks} columns={columns} rowKey={(c) => `${c.id ?? ""}-${c.title ?? ""}`} defaultSort={{ id: "result", dir: "asc" }} preferencesKey="node-cis-checks" exportFileName={`${exportScope}-cis-checks-loaded`} />
        </div>
      )}
    </section>
  );
}

function NodePackagesTable({ payload, observedAt, exportScope }: { payload: unknown; observedAt?: string; exportScope: string }) {
  const value = payload as { items?: unknown; packages?: unknown } | undefined;
  const rows = Array.isArray(payload) ? payload : Array.isArray(value?.packages) ? value.packages : Array.isArray(value?.items) ? value.items : [];
  const records = rows.filter((item): item is Record<string, unknown> => !!item && typeof item === "object" && !Array.isArray(item)).map((item, index) => ({ item, rowId: index }));
  return <section className="space-y-3" data-testid="node-package-inventory"><div><h2 className="text-sm font-semibold">Reported package inventory</h2><p className="text-xs text-muted-foreground">Latest collected payload · {observedAt ? formatDate(observedAt) : "collection time not reported"}. CSV covers structured rows returned in this payload, not an independent inventory scan.</p></div><DataTable rows={records} rowKey={(row) => row.rowId} preferencesKey="node-package-inventory" exportFileName={`${exportScope}-package-inventory-loaded`} columns={[
    { id: "name", header: "Package", kind: "name", code: true, wrap: true, cell: ({ item }) => String(item.name ?? item.package_name ?? "Not reported") },
    { id: "version", header: "Version", kind: "version", code: true, wrap: true, cell: ({ item }) => String(item.version ?? item.package_version ?? "Not reported") },
    { id: "ecosystem", header: "Ecosystem / type", kind: "text", wrap: true, size: 176, maxSize: 240, cell: ({ item }) => String(item.ecosystem ?? item.type ?? item.manager ?? "Not reported") },
    { id: "purl", header: "Package URL", kind: "id", size: 280, grow: true, maxSize: 640, wrap: true, cell: ({ item }) => String(item.purl ?? "Not reported") },
  ]} emptyState={<p className="p-6 text-sm text-muted-foreground">No structured package rows returned. Inspect the raw payload for other inventory formats.</p>} /><Collapse label="Raw package payload"><JsonPanel title="Package inventory payload" payload={payload} observedAt={observedAt} icon={Database} /></Collapse></section>;
}

function CisResultBadge({ result }: { result?: string }) {
  const r = (result || "").toLowerCase();
  const color = r === "fail" ? "var(--color-severity-critical)" : r === "warn" ? "var(--color-severity-high)" : r === "pass" ? "var(--color-severity-low)" : "var(--color-severity-medium)";
  return <span className="rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase" style={{ background: `color-mix(in oklab, ${color} 16%, transparent)`, color }}>{result || "—"}</span>;
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
