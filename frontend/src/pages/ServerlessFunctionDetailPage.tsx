import type { ReactNode } from "react";
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, Database, KeyRound, Layers, ShieldAlert } from "lucide-react";

import {
  serverlessFunctions,
  type ScanPackage,
  type ServerlessEvidence,
  type ServerlessFinding,
  type ServerlessFunction,
  type ServerlessJob,
} from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { cn } from "@/lib/cn";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { entityDetailError, useEntityClusterScope } from "./entity-detail-scope";

export function ServerlessFunctionDetailPage() {
  const { functionId } = useParams({ strict: false });
  const scope = useEntityClusterScope();
  const { clusterId } = scope;
  const [requestedTab, setTab] = useTabParam("tab", "findings");
  const tab = ["findings", "packages", "permissions", "jobs", "details"].includes(requestedTab) ? requestedTab : "findings";
  const q = useQuery({
    queryKey: ["serverless-function", clusterId, functionId],
    queryFn: async () => {
      const data = await serverlessFunctions.get(functionId!);
      if (data.serverless_function.id !== functionId) throw new Error("The returned serverless function does not match the requested function ID.");
      return data;
    },
    enabled: scope.ready && !!functionId,
  });
  const backPath = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/serverless` : "/clusters";
  const header = <PageHeader title="Serverless function evidence" description="Inspect organization-wide cloud inventory and scan evidence for an exact function. The selected cluster provides navigation context only." backLink={<a href={backPath}>Serverless</a>} />;
  if (!scope.ready) return <div className="space-y-4">{header}{scope.loading ? <LoadingState label="Resolving serverless navigation cluster…" /> : <ErrorState title="The requested navigation cluster could not be resolved." error={scope.error} action={<Button onClick={scope.retry}>Retry cluster</Button>} />}</div>;
  if (!functionId) return <div className="space-y-4">{header}<ErrorState title="An exact serverless function ID is required." /></div>;
  if (q.isError) return <div className="space-y-4">{header}<VerdictBanner status="degraded" title="Serverless evidence is unavailable" detail="Previously loaded evidence is hidden after a failed refresh." /><ErrorState title="Serverless function evidence could not be loaded or refreshed." error={entityDetailError(q.error)} action={<Button onClick={() => void q.refetch()}>Retry function</Button>} /></div>;
  if (q.data && q.data.serverless_function.id !== functionId) return <div className="space-y-4">{header}<ErrorState title="The returned serverless function does not match the requested function ID." action={<Button onClick={() => void q.refetch()}>Retry function</Button>} /></div>;
  if (!q.isSuccess || !q.data) return <div className="space-y-4">{header}<LoadingState label="Loading serverless function evidence…" /></div>;
  const detail = q.data;
  const fn = detail.serverless_function;
  const evidence = detail.latest_evidence;
  const packages = evidence?.packages ?? [];
  const exportScope = `organization-function-${encodeURIComponent(fn.id)}`;
  return <div className="space-y-5" data-testid="serverless-function-detail-page" data-cluster-id={clusterId}>
    <PageHeader title={fn.function_name || fn.function_ref} mono backLink={<a href={backPath} className="inline-flex items-center gap-1"><ChevronLeft className="h-3.5 w-3.5" />Serverless</a>}
      description="Organization-wide cloud evidence; the selected cluster provides navigation context only. This API does not establish a cluster association for the function."
      badges={<><Pill tone="neutral">{fn.provider || "serverless"}</Pill>{fn.region && <Pill tone="accent">{fn.region}</Pill>}<PostureBadge level={fn.permission_level} /></>}
      actions={<Button onClick={() => void q.refetch()} disabled={q.isFetching}>{q.isFetching ? "Refreshing…" : "Refresh evidence"}</Button>} />
    <VerdictBanner status={fn.open_findings > 0 ? "degraded" : "info"} title={!evidence ? "No collected package evidence returned" : fn.open_findings > 0 ? `${fn.open_findings} open findings reported for this function` : "No open findings reported for this function"} detail="Reported counts are organization-wide. Finding detail is capped at 100 rows and recent jobs at 25; missing evidence does not establish a clean scan or safe execution role." />
    <StatGrid data-testid="serverless-function-stats">
      <StatCard label="Open findings reported" value={fn.open_findings} tone={fn.open_findings > 0 ? "high" : "neutral"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
      <StatCard label="Packages reported" value={evidence ? evidence.package_count : "Not collected"} valueKind={evidence ? "number" : "text"} icon={<Database className="h-3.5 w-3.5" />} />
      <StatCard label="Layers reported" value={fn.layers?.length ?? "Not reported"} valueKind={fn.layers ? "number" : "text"} icon={<Layers className="h-3.5 w-3.5" />} />
      <StatCard label="High / critical findings" value={fn.critical_findings + fn.high_findings} tone={fn.critical_findings + fn.high_findings > 0 ? "high" : "neutral"} icon={<KeyRound className="h-3.5 w-3.5" />} />
    </StatGrid>
    {q.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing serverless evidence; previously loaded evidence remains visible until the request settles.</p>}
    <Tabs value={tab} onValueChange={setTab} items={[
      { value: "findings", label: "Findings", content: <FindingsTable findings={detail.findings} exportScope={exportScope} /> },
      { value: "packages", label: "Packages", content: <PackagesPanel evidence={evidence ?? null} packages={packages} exportScope={exportScope} /> },
      { value: "permissions", label: "Execution role", content: <PermissionPanel fn={fn} exportScope={exportScope} /> },
      { value: "jobs", label: "Scan jobs", content: <JobHistory jobs={detail.jobs} exportScope={exportScope} /> },
      { value: "details", label: "Function details", content: <div className="space-y-4"><FunctionIdentity fn={fn} /><EvidencePanel evidence={evidence ?? null} fn={fn} /><Collapse label="Raw function metadata"><pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(fn.metadata ?? {}, null, 2)}</pre></Collapse></div> },
    ]} />
  </div>;
}

function FunctionIdentity({ fn }: { fn: ServerlessFunction }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Function identity</h2>
      <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Account" value={fn.account_id || "-"} />
        <Field label="Region" value={fn.region || "-"} />
        <Field label="Runtime" value={fn.runtime || "-"} />
        <Field label="Architecture" value={fn.architecture || "-"} />
        <Field label="Handler" value={fn.handler || "-"} />
        <Field label="Package Type" value={fn.package_type || "-"} />
        <Field label="Source" value={sourceLabel(fn)} />
        <Field label="Source Ref" value={fn.source_ref || "-"} />
        <Field label="Inventory Hash" value={fn.inventory_hash || "-"} wide />
        <Field label="Execution Role" value={fn.role || "-"} wide />
      </dl>
      {fn.layers && fn.layers.length > 0 ? (
        <div className="mt-4">
          <h3 className="text-xs font-semibold text-muted-foreground">Layers</h3>
          <ul className="mt-2 space-y-1">
            {fn.layers.map((layer) => (
              <li key={layer} className="break-all rounded-md border border-border px-2 py-1 font-mono text-xs">{layer}</li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function PermissionPanel({ fn, exportScope }: { fn: ServerlessFunction; exportScope: string }) {
  const analysis = (fn.permission_analysis ?? {}) as Record<string, unknown>;
  const findings = Array.isArray(analysis.findings) ? analysis.findings as Array<Record<string, unknown>> : [];
  const attached = Array.isArray(analysis.attached_policies) ? analysis.attached_policies as Array<Record<string, unknown>> : [];
  const inline = Array.isArray(analysis.inline_policies) ? analysis.inline_policies as string[] : [];

  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Execution-role posture</h2>
        <PostureBadge level={fn.permission_level} />
      </div>
      <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Analysis Status" value={fn.permission_status || "-"} />
        <Field label="Role" value={String(analysis.role_name || fn.role || "-")} />
        <Field label="Sensitive Actions" value={Array.isArray(analysis.sensitive_actions) ? String(analysis.sensitive_actions.length) : "Not reported"} />
        <Field label="Action Count" value={String(analysis.action_count ?? "-")} />
      </dl>
      {analysis.error ? <p className="mt-3 rounded-md border border-border bg-muted p-2 text-xs text-muted-foreground">{String(analysis.error)}</p> : null}

      <Collapse label="Attached policy evidence">
        <div className="space-y-4">
          <DataTable rows={attached.map((item, index) => ({ item, rowId: index }))} rowKey={(row) => row.rowId} preferencesKey="serverless-managed-policies" exportFileName={`${exportScope}-managed-policies-loaded`} columns={[
            { id: "name", header: "Managed policy", kind: "name", code: true, wrap: true, cell: ({ item }) => String(item.name || item.arn || "Not reported") },
            { id: "arn", header: "Policy ARN", kind: "id", size: 320, grow: true, maxSize: 640, wrap: true, cell: ({ item }) => String(item.arn || "Not reported") },
          ]} emptyState={<p className="p-6 text-sm text-muted-foreground">No managed policy rows returned.</p>} />
          <DataTable rows={inline.map((name, index) => ({ name, rowId: index }))} rowKey={(row) => row.rowId} preferencesKey="serverless-inline-policies" exportFileName={`${exportScope}-inline-policies-loaded`} columns={[{ id: "name", header: "Inline policy", kind: "name", code: true, wrap: true, cell: (row) => row.name }]} emptyState={<p className="p-6 text-sm text-muted-foreground">No inline policy rows returned.</p>} />
        </div>
      </Collapse>

      {findings.length > 0 ? (
        <div className="mt-4 overflow-hidden rounded-md border border-border">
          <DataTable
            className="rounded-none border-0"
            rows={findings.map((item, index) => ({ item, rowKey: `${item.id || "permission"}:${index}` }))}
            rowKey={(row) => row.rowKey}
            preferencesKey="serverless-role-issues"
            exportFileName={`${exportScope}-role-issues-loaded`}
            columns={[
              { id: "issue", header: "Issue", kind: "name", wrap: true, cell: ({ item }) => <><div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={normalizeSeverity(String(item.severity || "low")) ?? "low"} size="xs" /><span className="font-medium">{String(item.title || item.id || "permission issue")}</span></div><div className="mt-1 break-all font-mono text-xs text-muted-foreground">{String(item.id || "")}</div></> },
              { id: "policy", header: "Policy", kind: "text", code: true, size: 280, minSize: 160, maxSize: 480, grow: true, wrap: true, cell: ({ item }) => `${String(item.policy_type || "-")} / ${String(item.policy_name || item.policy_arn || "-")}` },
            ]}
          />
        </div>
      ) : null}
    </section>
  );
}

const packageColumns: Column<ScanPackage>[] = [
  {
    id: "package",
    header: "Package", kind: "name", code: true, wrap: true,
    cell: (pkg) => (
      <div>
        <div className="break-all font-mono text-xs">{pkg.name || "-"}</div>
        {pkg.purl ? <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{pkg.purl}</div> : null}
      </div>
    ),
    sort: (a, b) => (a.name || "").localeCompare(b.name || ""),
  },
  {
    id: "version",
    header: "Version", kind: "version", code: true, size: 140, maxSize: 220, wrap: true,
    cell: (pkg) => <span className="font-mono text-xs">{pkg.version || "-"}</span>,
    sort: (a, b) => (a.version || "").localeCompare(b.version || ""),
  },
  {
    id: "ecosystem",
    header: "Ecosystem", kind: "badge", size: 128,
    cell: (pkg) => <span className="font-mono text-xs">{pkg.ecosystem || "-"}</span>,
    sort: (a, b) => (a.ecosystem || "").localeCompare(b.ecosystem || ""),
  },
];

function PackagesPanel({ evidence, packages, exportScope }: { evidence: ServerlessEvidence | null; packages: ScanPackage[]; exportScope: string }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Package inventory</h2>
        <span className="font-mono text-xs text-muted-foreground">{evidence?.package_count ?? 0} packages</span>
      </header>
      <DataTable
        rows={packages}
        preferencesKey="serverless-function-packages"
        exportFileName={`${exportScope}-packages-loaded`}
        columns={packageColumns}
        rowKey={(pkg) => `${pkg.ecosystem}:${pkg.name}:${pkg.version}:${pkg.purl}`}
        emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No package rows returned in the latest evidence.</div>}
      />
    </section>
  );
}

function FindingsTable({ findings, exportScope }: { findings: ServerlessFinding[]; exportScope: string }) {
  const columns: Column<ServerlessFinding>[] = [
    {
      id: "finding",
      header: "Finding", kind: "name", wrap: true,
      cell: (finding) => (
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} size="xs" />
            <span className="font-medium">{finding.title}</span>
          </div>
          <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{finding.external_id || finding.kind} · {finding.id}</div>
        </div>
      ),
      sort: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: "status",
      header: "Status", kind: "status", size: 200, minSize: 160, maxSize: 260, wrap: true,
      cell: (finding) => (
        <div className="text-xs">
          <div className="font-medium">{finding.lifecycle}</div>
          <div className="mt-1 text-muted-foreground">{formatDate(finding.last_seen_at)}</div>
        </div>
      ),
    },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Findings</h2>
        <span className="font-mono text-xs text-muted-foreground">{findings.length}</span>
      </header>
      <DataTable
        rows={findings}
        sourceLimit={100}
        sourceCount={findings.length}
        preferencesKey="serverless-function-findings"
        exportFileName={`${exportScope}-findings-loaded`}
        columns={columns}
        rowKey={(finding) => finding.id}
        emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No finding rows returned for this function. This does not establish complete scan coverage.</div>}
      />
    </section>
  );
}

function EvidencePanel({ evidence, fn }: { evidence: ServerlessEvidence | null; fn: ServerlessFunction }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Latest evidence</h2>
      <dl className="mt-3 grid gap-2 text-sm">
        <Field label="Evidence ID" value={evidence?.id || fn.latest_evidence_id || "-"} />
        <Field label="Observed" value={formatDate(evidence?.observed_at || fn.latest_observed_at)} />
        <Field label="Runtime" value={evidence?.runtime || fn.runtime || "-"} />
        <Field label="Version" value={evidence?.version || fn.version || "-"} />
        <Field label="Inventory Hash" value={evidence?.inventory_hash || fn.inventory_hash || "-"} />
      </dl>
    </section>
  );
}

function JobHistory({ jobs, exportScope }: { jobs: ServerlessJob[]; exportScope: string }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Scan jobs</h2>
        <span className="font-mono text-xs text-muted-foreground">{jobs.length}</span>
      </header>
      <DataTable rows={jobs} sourceLimit={25} sourceCount={jobs.length} rowKey={(job) => job.id} preferencesKey="serverless-function-jobs" exportFileName={`${exportScope}-recent-jobs`} columns={[
        { id: "id", header: "Job", kind: "name", code: true, wrap: true, cell: (job) => job.id },
        { id: "status", header: "Status", kind: "status", cell: (job) => job.status },
        { id: "packages", header: "Packages", kind: "count", cell: (job) => job.package_count },
        { id: "findings", header: "Findings", kind: "count", cell: (job) => job.finding_count },
        { id: "requested", header: "Requested", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (job) => formatDate(job.requested_at), exportValue: (job) => job.requested_at, sort: (a, b) => a.requested_at.localeCompare(b.requested_at) },
        { id: "finished", header: "Finished", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (job) => formatDate(job.finished_at), exportValue: (job) => job.finished_at || "" },
        { id: "error", header: "Error", kind: "text", size: 260, grow: true, maxSize: 560, wrap: true, cell: (job) => job.error || "None reported" },
      ]} emptyState={<p className="p-6 text-sm text-muted-foreground">No recent scan jobs returned.</p>} />
    </section>
  );
}

function Field({ label, value, wide }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={cn("rounded-md border border-border p-2", wide && "sm:col-span-2")}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
}

function PostureBadge({ level }: { level?: string }) {
  const severity = normalizeSeverity(level);
  if (severity) return <SeverityBadge severity={severity} size="xs" />;
  return <Pill tone="neutral">unknown</Pill>;
}

function Pill({ children, tone }: { children: ReactNode; tone: "neutral" | "accent" | "warn" | "danger" }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded px-1.5 text-micro font-medium",
        tone === "neutral" && "bg-muted text-muted-foreground",
        tone === "accent" && "bg-primary/10 text-primary",
        tone === "warn" && "bg-status-warning/10 text-status-warning",
        tone === "danger" && "bg-destructive/10 text-destructive",
      )}
    >
      {children}
    </span>
  );
}

function normalizeSeverity(level?: string) {
  const normalized = (level || "").toLowerCase();
  switch (normalized) {
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "info":
      return normalized as "critical" | "high" | "medium" | "low" | "info";
    default:
      return null;
  }
}

function sourceLabel(item: ServerlessFunction): string {
  if (item.source_type === "discoverer") return "Cloud discoverer";
  return item.source_type || "Manual";
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
