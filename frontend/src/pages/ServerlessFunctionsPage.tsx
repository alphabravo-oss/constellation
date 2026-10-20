import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { CloudCog, Database, KeyRound, Search, ShieldAlert } from "lucide-react";

import { serverlessFunctions, type ServerlessFunction } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { INVENTORY_PAGE_SIZE, scanInventoryResponseValid, ScanInventoryExport, useInventoryScope, useInventoryRoute, InventoryScopeState, InventoryLoadState, ScanInventoryContinuation } from "./inventory-workspace";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { cn } from "@/lib/cn";
import { Select } from "@/components/ui/form";

const postureLevels = ["all", "critical", "high", "medium", "low", "info", "unknown"];

export function ServerlessFunctionsPage() {
  const scope = useInventoryScope();
  const { clusterId } = scope;
  const route = useInventoryRoute();
  const { query, setQuery, selectedID, setSelectedID } = route;
  const posture = route.params.get("posture") || "all";
  const setPosture = (value: string) => route.update({ posture: value === "all" ? null : value });
  const sort = route.params.get("sort") || "scan";
  const order = route.params.get("order") || "desc";
  const validFilters = postureLevels.includes(posture) && ['function', 'posture', 'packages', 'scan'].includes(sort) && ["asc", "desc"].includes(order);
  const request = { q: route.debouncedQuery || undefined, provider: route.params.get("provider") || undefined, account_id: route.params.get("account_id") || undefined, region: route.params.get("region") || undefined, limit: INVENTORY_PAGE_SIZE, offset: route.offset, posture: posture === "all" ? undefined : posture, sort, order: order as "asc" | "desc" };
  const q = useQuery({
    queryKey: ["serverless-functions", scope.owner, clusterId, request],
    queryFn: () => serverlessFunctions.list(request),
    enabled: scope.ready && !route.debouncing && validFilters,
  });
  const rawRows = q.data?.serverless_functions ?? [];
  const invalid = Boolean(q.data && (!Array.isArray(q.data.serverless_functions) || !scanInventoryResponseValid(q.data, rawRows.length, route.offset, sort, order, ['total', 'packages', 'findings', 'critical_high', 'scanned', 'role_risks', 'providers', 'regions'])));
  const available = scope.ready && q.isSuccess && !route.debouncing && validFilters && !invalid;
  const filtered = available ? rawRows : [];
  const hasMore = available && q.data?.has_more === true;
  const selected = filtered.find((item) => item.id === selectedID) ?? null;
  const summary = available ? q.data!.summary! : {};
  const functions = filtered;

  const columns: Column<ServerlessFunction>[] = [
    {
      id: "function", exportValue: item => item.function_name || item.function_ref,
      header: "Function", kind: "name", size: 320, minSize: 240, wrap: true,
      cell: (item) => (
        <div>
          <div className="flex flex-wrap items-center gap-1.5">
            <Pill tone="neutral">{item.provider || "serverless"}</Pill>
            {item.region ? <Pill tone="accent">{item.region}</Pill> : null}
            {isStale(item.latest_observed_at || item.last_seen_at) ? <Pill tone="warn">stale evidence</Pill> : null}
          </div>
          <a href={`/clusters/${clusterId}/serverless/${item.id}`} className="mt-2 block break-all font-mono text-xs font-medium hover:underline">
            {item.function_name || item.function_ref}
          </a>
          <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{item.function_ref}</div>
        </div>
      ),
      sort: (a, b) => (a.function_name || a.function_ref).localeCompare(b.function_name || b.function_ref),
    },
    {
      id: "posture", sort: () => 0, exportValue: item => `${item.permission_level || "unknown"}; ${item.permission_status || "not analyzed"}; ${item.critical_findings} critical; ${item.high_findings} high`,
      header: "Posture", kind: "text", size: 220, minSize: 160, maxSize: 280, wrap: true,
      cell: (item) => <PostureCell item={item} />,
    },
    {
      id: "packages", exportValue: item => `${item.package_count} packages; ${item.runtime || "runtime unknown"}`,
      header: "Packages", kind: "count", size: 160, minSize: 128, maxSize: 220, wrap: true,
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.package_count} packages</div>
          <div className="mt-1 text-muted-foreground">{item.runtime || "runtime unknown"}</div>
        </div>
      ),
      sort: (a, b) => a.package_count - b.package_count,
    },
    {
      id: "scan", sort: () => 0, exportValue: item => [item.latest_job_status, item.latest_observed_at || item.last_seen_at, item.latest_job_id].filter(Boolean).join(" · "),
      header: "Scan", kind: "text", size: 220, minSize: 180, maxSize: 300, wrap: true,
      cell: (item) => (
        <div className="text-xs">
          <div className="font-medium">{item.latest_job_status || "not queued"}</div>
          <div className="mt-1 text-muted-foreground">{formatDate(item.latest_observed_at || item.last_seen_at)}</div>
          <div className="mt-1 truncate font-mono text-micro text-muted-foreground">{item.inventory_hash || "hash pending"}</div>
        </div>
      ),
    },
  ];

  if (!scope.ready) return <div className="space-y-4"><PageHeader title="Serverless Functions" description="Organization-wide cloud evidence; the selected cluster provides navigation context only." /><InventoryScopeState scope={scope} /></div>;

  return (
    <div className="space-y-4" data-testid="serverless-functions-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Serverless"
        description="Lambda function package inventory and execution-role posture."
        actions={
          <a
            href={selected ? `/clusters/${clusterId}/serverless/${selected.id}` : `/clusters/${clusterId}/serverless`}
            className={cn(
              "inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent",
              !selected && "pointer-events-none opacity-50",
            )}
          >
            <CloudCog className="h-4 w-4" aria-hidden />
            Open Function
          </a>
        }
      />

      <VerdictBanner status={q.isError || invalid || !validFilters ? "degraded" : "info"} title={q.isError || invalid || !validFilters ? "Serverless functions are unavailable" : !available ? "Loading serverless functions" : summary.total ? "Review matching serverless functions" : "No matching serverless functions"} detail="Metrics cover all organization-wide records matching the server filters." />
      {available && <StatGrid data-testid="serverless-summary">
        <StatCard label="Matching functions" value={summary.total.toLocaleString()} icon={<CloudCog className="h-3.5 w-3.5" />} hint={`${summary.providers} providers · ${summary.regions} regions`} />
        <StatCard label="Open Findings" value={summary.findings.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.critical_high > 0 ? "high" : "neutral"} hint={`${summary.critical_high} critical/high`} />
        <StatCard label="Packages" value={summary.packages.toLocaleString()} icon={<Database className="h-3.5 w-3.5" />} hint={`${summary.scanned} with evidence`} />
        <StatCard label="Role Risks" value={summary.role_risks.toLocaleString()} icon={<KeyRound className="h-3.5 w-3.5" />} tone={summary.role_risks > 0 ? "high" : "neutral"} hint="critical/high role posture" />
      </StatGrid>}

      <div className="flex flex-wrap gap-3"><Button disabled={q.isFetching || route.debouncing || !scope.ready || !validFilters} onClick={() => void q.refetch()}>Refresh</Button><ScanInventoryExport context={JSON.stringify([scope.owner, clusterId, request])} disabled={!available || q.isFetching} download={shouldDownload => serverlessFunctions.exportCSV(request, shouldDownload)} /></div>
      {q.isFetching && q.isSuccess && <p role="status" className="text-sm text-muted-foreground">Refreshing scan inventory…</p>}
      <p className="text-xs text-muted-foreground">Matching CSV includes fixed inventory columns across all matching pages (up to 100,000 records). The table’s page CSV follows visible columns.</p>
      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search function name or reference"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="serverless-search"
            />
          </label>
          <Select
            value={posture}
            onChange={(event) => setPosture(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="serverless-posture-filter"
          >
            {postureLevels.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All posture" : item}</option>
            ))}
          </Select>
        </div>
      </section>

      <div className="flex flex-wrap gap-3"><label className="text-xs">Provider<input aria-label="Provider filter" className="ml-2 rounded border border-input bg-background px-2 py-1" value={route.params.get("provider") ?? ""} onChange={event => route.update({ provider: event.target.value }, true, true)} /></label><label className="text-xs">Account Id<input aria-label="Account Id filter" className="ml-2 rounded border border-input bg-background px-2 py-1" value={route.params.get("account_id") ?? ""} onChange={event => route.update({ account_id: event.target.value }, true, true)} /></label><label className="text-xs">Region<input aria-label="Region filter" className="ml-2 rounded border border-input bg-background px-2 py-1" value={route.params.get("region") ?? ""} onChange={event => route.update({ region: event.target.value }, true, true)} /></label></div>
      <p className="text-xs text-muted-foreground">Organization-wide cloud evidence; the selected cluster provides navigation context only. Search runs on the server. Role posture and sorting run on the server before pagination.</p>
      {!validFilters && <ErrorState title="The requested server filter or sort is invalid. Choose a listed value to recover." action={<Button onClick={() => route.update({ sort: null, order: null, posture: null })}>Reset filters and sort</Button>} />}
      {available && <ScanInventoryContinuation total={q.data?.total} page={route.page} rows={functions.length} matching={filtered.length} hasMore={hasMore} onPage={route.setPage} />}
      {available && selectedID && !selected && <ErrorState title="The selected record is unavailable on this page or hidden by its filters." action={<Button onClick={() => setSelectedID(null)}>Clear selection</Button>} />}
      <section className="flex flex-col gap-4">
        <div data-testid="serverless-table">
          {!available ? validFilters ? <InventoryLoadState label="Serverless functions" query={q} invalid={invalid} debouncing={route.debouncing} /> : null : <DataTable
            rows={filtered}
            pagination={false}
            manualSorting
            sort={{ id: sort, dir: order as "asc" | "desc" }}
            onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })}
            preferencesKey="serverless-functions-inventory"
            exportFileName="constellation-serverless-functions-server-page"
            exportLabel="Export this page CSV"
            columns={columns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={selected ? new Set([selected.id]) : undefined}
            emptyState={
              q.isPending ? (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">Loading serverless functions...</div>
              ) : (
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">No serverless functions match the current filters.</div>
              )
            }
          />}
        </div>

        {selected && <Collapse label="Selected record summary"><ServerlessPreview item={selected} clusterId={clusterId} /></Collapse>}
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
          <a href={`/clusters/${clusterId}/serverless/${item.id}`} className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
            Full Details
          </a>
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
      <div className="text-micro text-muted-foreground">{label}</div>
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
