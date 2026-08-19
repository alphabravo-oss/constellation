import { useMemo } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
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
import { StatCard } from "@/components/ui/stat-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";

export function ServerlessFunctionDetailPage() {
  const { functionId } = useParams<{ functionId: string }>();
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: ["serverless-function", functionId],
    queryFn: () => serverlessFunctions.get(functionId!),
    enabled: !!functionId,
  });

  const detail = q.data;
  const fn = detail?.serverless_function;
  const evidence = detail?.latest_evidence;
  const packages = useMemo(() => evidence?.packages ?? [], [evidence?.packages]);

  if (clusterLoading || q.isPending) return <p className="text-sm text-muted-foreground">Loading serverless function...</p>;
  if (q.isError || !fn) return <p className="text-sm text-status-error">Serverless function not found.</p>;

  return (
    <div className="space-y-4" data-testid="serverless-function-detail-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <Link to={`/clusters/${clusterId}/serverless`} className="inline-flex items-center gap-1 hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            Serverless
          </Link>
        }
        title={fn.function_name || fn.function_ref}
        mono
        badges={
          <>
            <Pill tone="neutral">{fn.provider || "serverless"}</Pill>
            {fn.region ? <Pill tone="accent">{fn.region}</Pill> : null}
            <PostureBadge level={fn.permission_level} />
          </>
        }
        description={<span className="break-all font-mono">{fn.function_ref}</span>}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4" data-testid="serverless-function-stats">
        <StatCard label="Open Findings" value={fn.open_findings} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={fn.open_findings > 0 ? "high" : "neutral"} />
        <StatCard label="Packages" value={fn.package_count} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Layers" value={fn.layers?.length ?? 0} icon={<Layers className="h-3.5 w-3.5" />} />
        <StatCard label="Role Risk" value={fn.critical_findings + fn.high_findings} icon={<KeyRound className="h-3.5 w-3.5" />} tone={fn.critical_findings + fn.high_findings > 0 ? "critical" : "neutral"} />
      </section>

      <div className="space-y-4">
        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <FunctionIdentity fn={fn} />
          <EvidencePanel evidence={evidence ?? null} fn={fn} />
        </div>
        <PermissionPanel fn={fn} />
        <PackagesPanel evidence={evidence ?? null} packages={packages} />
        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <FindingsTable findings={detail?.findings ?? []} clusterId={clusterId} />
          <JobHistory jobs={detail?.jobs ?? []} />
        </div>
      </div>
    </div>
  );
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

function PermissionPanel({ fn }: { fn: ServerlessFunction }) {
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
        <Field label="Sensitive Actions" value={String((analysis.sensitive_actions as string[] | undefined)?.length ?? 0)} />
        <Field label="Action Count" value={String(analysis.action_count ?? "-")} />
      </dl>
      {analysis.error ? <p className="mt-3 rounded-md border border-border bg-muted p-2 text-xs text-muted-foreground">{String(analysis.error)}</p> : null}

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground">Managed policies</h3>
          <ul className="mt-2 space-y-1">
            {attached.slice(0, 6).map((policy, index) => (
              <li key={`${policy.arn || policy.name || index}`} className="break-all rounded-md border border-border px-2 py-1 font-mono text-xs">
                {String(policy.name || policy.arn || "-")}
              </li>
            ))}
            {attached.length === 0 ? <li className="text-xs text-muted-foreground">No managed policies reported.</li> : null}
          </ul>
        </div>
        <div>
          <h3 className="text-xs font-semibold text-muted-foreground">Inline policies</h3>
          <ul className="mt-2 space-y-1">
            {inline.slice(0, 6).map((policy) => (
              <li key={policy} className="break-all rounded-md border border-border px-2 py-1 font-mono text-xs">{policy}</li>
            ))}
            {inline.length === 0 ? <li className="text-xs text-muted-foreground">No inline policies reported.</li> : null}
          </ul>
        </div>
      </div>

      {findings.length > 0 ? (
        <div className="mt-4 overflow-hidden rounded-md border border-border">
          <table className="w-full text-sm">
            <thead className="bg-muted text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-3 py-2 text-left">Issue</th>
                <th className="px-3 py-2 text-left">Policy</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((item, index) => (
                <tr key={`${item.id || index}`} className="border-t border-border">
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={normalizeSeverity(String(item.severity || "low")) ?? "low"} size="xs" />
                      <span className="font-medium">{String(item.title || item.id || "permission issue")}</span>
                    </div>
                    <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{String(item.id || "")}</div>
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">
                    {String(item.policy_type || "-")} / {String(item.policy_name || item.policy_arn || "-")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}

const packageColumns: Column<ScanPackage>[] = [
  {
    id: "package",
    header: "Package",
    cell: (pkg) => (
      <div>
        <div className="break-all font-mono text-xs">{pkg.name || "-"}</div>
        {pkg.purl ? <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{pkg.purl}</div> : null}
      </div>
    ),
    sort: (a, b) => (a.name || "").localeCompare(b.name || ""),
  },
  {
    id: "version",
    header: "Version",
    cell: (pkg) => <span className="font-mono text-xs">{pkg.version || "-"}</span>,
    sort: (a, b) => (a.version || "").localeCompare(b.version || ""),
  },
  {
    id: "ecosystem",
    header: "Ecosystem",
    cell: (pkg) => <span className="font-mono text-xs">{pkg.ecosystem || "-"}</span>,
    sort: (a, b) => (a.ecosystem || "").localeCompare(b.ecosystem || ""),
  },
];

function PackagesPanel({ evidence, packages }: { evidence: ServerlessEvidence | null; packages: ScanPackage[] }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Package inventory</h2>
        <span className="font-mono text-xs text-muted-foreground">{evidence?.package_count ?? 0} packages</span>
      </header>
      <DataTable
        rows={packages.slice(0, 100)}
        columns={packageColumns}
        rowKey={(pkg) => `${pkg.ecosystem}:${pkg.name}:${pkg.version}:${pkg.purl}`}
        showDensityToggle={false}
        emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No package evidence recorded.</div>}
      />
    </section>
  );
}

function FindingsTable({ findings, clusterId }: { findings: ServerlessFinding[]; clusterId?: string }) {
  const columns: Column<ServerlessFinding>[] = [
    {
      id: "finding",
      header: "Finding",
      cell: (finding) => (
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} size="xs" />
            <Link to={`/clusters/${clusterId}/findings/${finding.id}`} className="font-medium hover:underline">{finding.title}</Link>
          </div>
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{finding.external_id || finding.kind}</div>
        </div>
      ),
      sort: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: "status",
      header: "Status",
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
        columns={columns}
        rowKey={(finding) => finding.id}
        showDensityToggle={false}
        emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No findings recorded for this function.</div>}
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

function JobHistory({ jobs }: { jobs: ServerlessJob[] }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Scan jobs</h2>
        <span className="font-mono text-xs text-muted-foreground">{jobs.length}</span>
      </header>
      <div className="divide-y divide-border">
        {jobs.map((job) => (
          <div key={job.id} className="p-3 text-sm">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-medium">{job.status}</span>
              <span className="font-mono text-xs text-muted-foreground">{job.package_count} packages · {job.finding_count} findings</span>
            </div>
            <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{job.id}</div>
            <div className="mt-2 grid gap-1 text-xs text-muted-foreground">
              <span>Requested {formatDate(job.requested_at)}</span>
              {job.finished_at ? <span>Finished {formatDate(job.finished_at)}</span> : null}
              {job.error ? <span className="text-status-error">{job.error}</span> : null}
            </div>
          </div>
        ))}
        {jobs.length === 0 ? <p className="p-4 text-xs text-muted-foreground">No scan jobs recorded.</p> : null}
      </div>
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
        "inline-flex h-5 items-center rounded px-1.5 text-[10px] font-medium",
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
