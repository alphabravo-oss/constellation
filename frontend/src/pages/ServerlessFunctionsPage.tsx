import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { CloudCog, Database, KeyRound, Search, ShieldAlert } from "lucide-react";

import { serverlessFunctions, type ServerlessFunction } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";

const postureLevels = ["all", "critical", "high", "medium", "low", "info", "unknown"];

export function ServerlessFunctionsPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [query, setQuery] = useState("");
  const [posture, setPosture] = useState("all");
  const [selectedID, setSelectedID] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["serverless-functions"],
    queryFn: () => serverlessFunctions.list({ limit: 500 }),
  });

  const functions = useMemo(() => q.data?.serverless_functions ?? [], [q.data?.serverless_functions]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return functions.filter((item) => {
      const level = item.permission_level || "unknown";
      if (posture !== "all" && level !== posture) return false;
      if (!needle) return true;
      return [
        item.function_ref,
        item.function_name ?? "",
        item.provider ?? "",
        item.account_id ?? "",
        item.region ?? "",
        item.runtime ?? "",
        item.role ?? "",
        item.latest_job_status ?? "",
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [functions, posture, query]);
  const selected = filtered.find((item) => item.id === selectedID) ?? filtered[0] ?? null;
  const summary = useMemo(() => summarize(functions), [functions]);

  const columns: Column<ServerlessFunction>[] = [
    {
      id: "function",
      header: "Function",
      cell: (item) => (
        <div>
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill tone="neutral">{item.provider || "serverless"}</Pill>
            {item.region ? <Pill tone="accent">{item.region}</Pill> : null}
            {isStale(item.latest_observed_at || item.last_seen_at) ? <Pill tone="warn">stale evidence</Pill> : null}
          </div>
          <Link to={`/clusters/${clusterId}/serverless/${item.id}`} className="mt-2 block break-all font-mono text-xs font-medium hover:underline">
            {item.function_name || item.function_ref}
          </Link>
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.function_ref}</div>
        </div>
      ),
      sort: (a, b) => (a.function_name || a.function_ref).localeCompare(b.function_name || b.function_ref),
    },
    {
      id: "posture",
      header: "Posture",
      cell: (item) => <PostureCell item={item} />,
    },
    {
      id: "packages",
      header: "Packages",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.package_count} packages</div>
          <div className="mt-1 text-muted-foreground">{item.runtime || "runtime unknown"}</div>
        </div>
      ),
      sort: (a, b) => a.package_count - b.package_count,
    },
    {
      id: "scan",
      header: "Scan",
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.latest_job_status || "not queued"}</div>
          <div className="mt-1 text-muted-foreground">{formatDate(item.latest_observed_at || item.last_seen_at)}</div>
          <div className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{item.inventory_hash || "hash pending"}</div>
        </div>
      ),
    },
  ];

  if (clusterLoading) return <p className="text-sm text-muted-foreground">Loading cluster...</p>;

  return (
    <div className="space-y-4" data-testid="serverless-functions-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Serverless"
        description="Lambda function package inventory and execution-role posture."
        actions={
          <Link
            to={selected ? `/clusters/${clusterId}/serverless/${selected.id}` : `/clusters/${clusterId}/serverless`}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
              !selected && "pointer-events-none opacity-50",
            )}
          >
            <CloudCog className="h-4 w-4" aria-hidden />
            Open Function
          </Link>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4" data-testid="serverless-summary">
        <StatCard label="Functions" value={summary.total.toLocaleString()} icon={<CloudCog className="h-3.5 w-3.5" />} hint={`${summary.providers} providers · ${summary.regions} regions`} />
        <StatCard label="Open Findings" value={summary.findings.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.criticalHigh > 0 ? "high" : "neutral"} hint={`${summary.criticalHigh} critical/high`} />
        <StatCard label="Packages" value={summary.packages.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} hint={`${summary.scanned} with evidence`} />
        <StatCard label="Role Risks" value={summary.roleRisks.toLocaleString()} icon={<KeyRound className="h-3.5 w-3.5" />} tone={summary.roleRisks > 0 ? "high" : "neutral"} hint="critical/high role posture" />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search function, account, region, runtime, role"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="serverless-search"
            />
          </label>
          <select
            value={posture}
            onChange={(event) => setPosture(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="serverless-posture-filter"
          >
            {postureLevels.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All posture" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <div data-testid="serverless-table">
          <DataTable
            rows={filtered}
            columns={columns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={selected ? new Set([selected.id]) : undefined}
            showDensityToggle={false}
            emptyState={
              q.isPending ? (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">Loading serverless functions...</div>
              ) : (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">No serverless functions match the current filters.</div>
              )
            }
          />
        </div>

        <ServerlessPreview item={selected} clusterId={clusterId} />
      </section>
    </div>
  );
}

function ServerlessPreview({ item, clusterId }: { item: ServerlessFunction | null; clusterId?: string }) {
  if (!item) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="serverless-preview">
        <h2 className="text-sm font-semibold">Serverless inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select a function to inspect package inventory, role posture, and scan history.</p>
      </aside>
    );
  }
  return (
    <aside className="space-y-4" data-testid="serverless-preview">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <PostureBadge level={item.permission_level} />
            <h2 className="mt-2 break-all font-mono text-sm font-semibold">{item.function_name || item.function_ref}</h2>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.role || "execution role unknown"}</p>
          </div>
          <Link to={`/clusters/${clusterId}/serverless/${item.id}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
            Full Details
          </Link>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2">
          <MiniMetric label="Critical" value={item.critical_findings} tone={item.critical_findings > 0 ? "danger" : "normal"} />
          <MiniMetric label="High" value={item.high_findings} tone={item.high_findings > 0 ? "warn" : "normal"} />
          <MiniMetric label="Packages" value={item.package_count} tone="normal" />
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Function identity</h3>
        <dl className="mt-3 grid gap-2 text-sm">
          <Field label="Account" value={item.account_id || "-"} />
          <Field label="Region" value={item.region || "-"} />
          <Field label="Runtime" value={item.runtime || "-"} />
          <Field label="Handler" value={item.handler || "-"} />
          <Field label="Package Type" value={item.package_type || "-"} />
          <Field label="Source" value={sourceLabel(item)} />
        </dl>
      </div>
    </aside>
  );
}

function summarize(items: ServerlessFunction[]) {
  const providers = new Set(items.map((item) => item.provider).filter(Boolean));
  const regions = new Set(items.map((item) => item.region).filter(Boolean));
  return {
    total: items.length,
    providers: providers.size,
    regions: regions.size,
    findings: items.reduce((sum, item) => sum + item.open_findings, 0),
    criticalHigh: items.reduce((sum, item) => sum + item.critical_findings + item.high_findings, 0),
    packages: items.reduce((sum, item) => sum + item.package_count, 0),
    scanned: items.filter((item) => !!item.latest_evidence_id).length,
    roleRisks: items.filter((item) => item.permission_level === "critical" || item.permission_level === "high").length,
  };
}

function PostureCell({ item }: { item: ServerlessFunction }) {
  return (
    <div className="space-y-1 text-xs">
      <PostureBadge level={item.permission_level} />
      <div className="text-muted-foreground">{item.permission_status || "not analyzed"}</div>
      <div className="flex flex-wrap gap-1">
        {item.critical_findings > 0 ? <Pill tone="danger">C {item.critical_findings}</Pill> : null}
        {item.high_findings > 0 ? <Pill tone="warn">H {item.high_findings}</Pill> : null}
      </div>
    </div>
  );
}

function PostureBadge({ level }: { level?: string }) {
  const severity = normalizeSeverity(level);
  if (severity) return <SeverityBadge severity={severity} size="xs" />;
  return <Pill tone="neutral">unknown</Pill>;
}

function MiniMetric({ label, value, tone }: { label: string; value: number; tone: "normal" | "warn" | "danger" }) {
  return (
    <div className={cn("rounded-md border border-border p-2", tone === "danger" && "border-destructive/40 bg-destructive/10", tone === "warn" && "border-status-warning/40 bg-status-warning/10")}>
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
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

function isStale(value?: string): boolean {
  if (!value) return false;
  const t = new Date(value).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t > 7 * 86400 * 1000;
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
