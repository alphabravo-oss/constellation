import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import { Activity, ArrowRight, Clock3, Copy, Database, Download, Globe2, Mail, ScanSearch, SlidersHorizontal } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { componentsInventory, systemConfigApi, type ComponentInstance, type ConfigProvenance } from "@/api/client";
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";

type BackendConfigSource = "default" | "environment_bootstrap" | "database";
type ConfigSource = BackendConfigSource | "unknown";

interface ConfigItem {
  key: string;
  value: unknown;
  source: ConfigSource;
  redacted: boolean | undefined;
}

interface ConfigGroup {
  title: string;
  icon: ReactNode;
  editTo?: string;
  items: ConfigItem[];
}

interface AppliedRevisionRow {
  id: string;
  component: string;
  role: string;
  hostname: string;
  cluster: string;
  reportedRevision: number | null;
  status: "current" | "behind" | "ahead" | "unknown";
  lastSeenAt: string;
}

export function EffectiveConfigPage() {
  const q = useQuery({
    queryKey: ["system-config"],
    queryFn: () => systemConfigApi.get(),
  });
  const componentsQ = useQuery({
    queryKey: ["components-inventory", "effective-config"],
    queryFn: () => componentsInventory.list({ limit: 1000 }),
    staleTime: 30_000,
  });

  if (q.isPending) {
    return (
      <PageContainer>
        <PageHeader title="Effective Config" description="System configuration and backend-reported provenance." />
        <LoadingState label="Loading system config..." />
      </PageContainer>
    );
  }

  if (q.isError) {
    return (
      <PageContainer>
        <PageHeader title="Effective Config" description="System configuration and backend-reported provenance." />
        <ErrorState title="Failed to load system config" error={q.error} />
      </PageContainer>
    );
  }

  const config = q.data.config ?? {};
  const items = buildConfigItems(config, q.data.provenance);
  const groups = buildGroups(items);
  const sourceSummary = summarizeSources(items);
  const nonDefaultItems = items.filter((item) => item.source === "database" || item.source === "environment_bootstrap");
  const unknownItems = items.filter((item) => item.source === "unknown").length;
  const provider = q.data.applied?.provider;
  const appliedRows = buildAppliedRevisionRows(componentsQ.data?.components ?? [], q.data.revision);
  const reportingApplied = appliedRows.filter((row) => row.reportedRevision !== null).length;
  const redactedJson = JSON.stringify(config, null, 2);
  const source = q.data.source === "system_config" ? "System config row" : q.data.source === "default" ? "No persisted row" : "Unknown";

  return (
    <PageContainer data-testid="effective-config-page">
      <PageHeader
        title="Effective Config"
        description="Redacted system configuration, per-key sources, and the serving replica's provider state."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={() => void copyText(redactedJson).catch(() => undefined)}>
              <Copy className="h-4 w-4" />
              Copy JSON
            </Button>
            <Button variant="outline" onClick={() => downloadJson("constellation-effective-config.json", redactedJson)}>
              <Download className="h-4 w-4" />
              Export JSON
            </Button>
            <Button asChild variant="outline">
              <Link to="/settings/network"><Globe2 className="h-4 w-4" />Network & Proxy</Link>
            </Button>
            <Button asChild variant="outline">
              <Link to="/settings/scanner"><ScanSearch className="h-4 w-4" />Scanner</Link>
            </Button>
          </div>
        }
      />

      <section className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <StatCard label="Config revision" value={q.data.revision} hint="Revision returned by the API" icon={<SlidersHorizontal className="h-3.5 w-3.5" />} />
        <StatCard label="Persistence" value={source} hint="Per-key sources are listed below" icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Last changed" value={formatDateTime(q.data.updated_at)} hint={q.data.updated_by_email || q.data.updated_by || "Not recorded"} icon={<Clock3 className="h-3.5 w-3.5" />} />
        <StatCard label="Database values" value={items.filter((item) => item.source === "database").length} hint="Keys attributed to the database" icon={<Database className="h-3.5 w-3.5" />} />
      </section>

      <section className="rounded-md border border-border bg-card p-4" data-testid="effective-config-provider-applied">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-base font-semibold">Provider applied revision</h2>
          <AppliedStatusPill status={provider?.status ?? "unavailable"} />
        </div>
        <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-3">
          <div><dt className="text-muted-foreground">Component</dt><dd className="mt-1 font-mono">{provider?.component ?? "Unknown"}</dd></div>
          <div><dt className="text-muted-foreground">Scope</dt><dd className="mt-1">{provider?.scope === "serving_replica" ? "Serving replica (serving_replica)" : "Unknown"}</dd></div>
          <div><dt className="text-muted-foreground">Applied revision</dt><dd className="mt-1 font-mono">{provider?.revision ?? "Unknown"}</dd></div>
        </dl>
        <p className="mt-3 text-xs text-muted-foreground">
          This reports the system config provider on the replica serving this response. It does not confirm scanner or other component adoption, or a reload by every network client.
        </p>
      </section>

      <PageSection title="Configuration Sources" description="Sources and redaction are reported independently by the backend for each configuration key.">
        <div className="grid gap-4 xl:grid-cols-[280px_minmax(0,1fr)]">
          <section className="rounded-md border border-border bg-card p-3" data-testid="effective-config-source-summary">
            <h2 className="text-sm font-semibold">Source distribution</h2>
            <dl className="mt-3 space-y-2 text-xs">
              {sourceSummary.map((item) => (
                <div key={item.source} className="flex items-center justify-between gap-3">
                  <dt><SourcePill source={item.source} /></dt>
                  <dd className="font-mono text-foreground">{item.count}</dd>
                </div>
              ))}
            </dl>
            <p className="mt-3 text-xs text-muted-foreground">{items.filter((item) => item.redacted === true).length} keys marked redacted by the backend.</p>
          </section>

          <section className="rounded-md border border-border bg-card p-3" data-testid="effective-config-default-diff">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-semibold">Values from non-default sources</h2>
              <span className="text-xs text-muted-foreground">{nonDefaultItems.length} keys</span>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">
              Database and environment bootstrap values may equal a built-in default. The API does not provide default values for a value comparison.
            </p>
            {unknownItems > 0 ? <p className="mt-2 text-xs text-muted-foreground">Source unavailable for {unknownItems} keys; their default status is unknown.</p> : null}
            {nonDefaultItems.length === 0 ? (
              <p className="mt-3 text-xs text-muted-foreground">No keys are reported with a non-default source.</p>
            ) : (
              <div className="mt-3 overflow-x-auto">
                <table className="app-semantic-table min-w-full text-xs">
                  <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                    <tr>
                      <th className="px-2 py-1.5 font-medium">Key</th>
                      <th className="px-2 py-1.5 font-medium">Current value</th>
                      <th className="px-2 py-1.5 font-medium">Source / redaction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {nonDefaultItems.map((item) => (
                      <tr key={item.key} className="border-t border-border">
                        <td className="break-all px-2 py-2 font-mono">{item.key}</td>
                        <td className="max-w-[260px] break-all px-2 py-2 font-mono">{configValue(item)}</td>
                        <td className="px-2 py-2"><ProvenancePills item={item} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      </PageSection>

      <PageSection title="Component Revision Reports" description="Only an explicit system_config_revision in component heartbeat metadata is used here.">
        <section className="rounded-md border border-border bg-card p-3" data-testid="effective-config-applied-revisions">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold">Reported system config revision</h2>
            <span className="text-xs text-muted-foreground">
              {componentsQ.isError ? "Inventory unavailable" : componentsQ.isPending ? "Loading inventory" : `${reportingApplied}/${appliedRows.length} components report a revision`} · target revision {q.data.revision}
            </span>
          </div>
          <p className="mt-2 text-xs text-muted-foreground">Reports reflect the last heartbeat and do not establish current component health.</p>
          {componentsQ.isError ? (
            <div className="mt-3">
              <ErrorState title="Component inventory unavailable" error={componentsQ.error} />
              <Button className="mt-2" variant="outline" onClick={() => void componentsQ.refetch()}>Retry inventory</Button>
            </div>
          ) : componentsQ.isPending ? (
            <p className="mt-3 text-xs text-muted-foreground">Loading component reports...</p>
          ) : appliedRows.length === 0 ? (
            <p className="mt-3 text-xs text-muted-foreground">No component heartbeats are available.</p>
          ) : (
            <div className="mt-3 overflow-x-auto">
              <table className="app-semantic-table min-w-full text-xs">
                <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-2 py-1.5 font-medium">Component</th>
                    <th className="px-2 py-1.5 font-medium">Host</th>
                    <th className="px-2 py-1.5 font-medium">Reported revision</th>
                    <th className="px-2 py-1.5 font-medium">Compared with target</th>
                    <th className="px-2 py-1.5 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {appliedRows.slice(0, 12).map((row) => (
                    <tr key={row.id} className="border-t border-border">
                      <td className="px-2 py-2">
                        <div className="font-medium">{row.component}</div>
                        <div className="text-[10px] text-muted-foreground">{row.role} · {row.cluster}</div>
                      </td>
                      <td className="px-2 py-2 font-mono text-muted-foreground">{row.hostname}</td>
                      <td className="px-2 py-2 font-mono">{row.reportedRevision ?? "Unknown"}</td>
                      <td className="px-2 py-2"><AppliedStatusPill status={row.status} /></td>
                      <td className="px-2 py-2 text-muted-foreground">{formatDateTime(row.lastSeenAt)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {appliedRows.length > 12 ? <p className="mt-2 text-xs text-muted-foreground">Showing 12 of {appliedRows.length} components.</p> : null}
            </div>
          )}
        </section>
      </PageSection>

      <PageSection title="Configuration Groups" description="Each row represents one configuration key. Missing provenance remains unknown.">
        <div className="grid gap-4 xl:grid-cols-2">
          {groups.map((group) => (
            <Card
              key={group.title}
              title={<span className="inline-flex items-center gap-2"><span className="text-muted-foreground [&_svg]:h-4 [&_svg]:w-4">{group.icon}</span>{group.title}</span>}
              action={group.editTo ? (
                <Button asChild variant="ghost" size="sm">
                  <Link to={group.editTo}>Edit<ArrowRight className="h-3.5 w-3.5" /></Link>
                </Button>
              ) : undefined}
            >
              <dl className="divide-y divide-border">
                {group.items.map((item) => (
                  <div key={item.key} className="grid gap-2 py-3 text-sm">
                    <dt className="break-all font-mono text-xs text-muted-foreground">{item.key}</dt>
                    <dd className="flex flex-wrap items-start justify-between gap-2">
                      <span className="min-w-0 break-all">{configValue(item)}</span>
                      <ProvenancePills item={item} />
                    </dd>
                  </div>
                ))}
              </dl>
            </Card>
          ))}
        </div>
      </PageSection>

      <Card title="Redacted JSON" description="The config object returned by /system/config after backend redaction.">
        <pre className="max-h-[460px] overflow-auto rounded-md border border-border bg-muted p-3 text-xs">{redactedJson}</pre>
      </Card>
    </PageContainer>
  );
}

function buildConfigItems(config: Record<string, unknown>, provenance?: Record<string, ConfigProvenance>): ConfigItem[] {
  const values = new Map<string, unknown>();
  function flatten(record: Record<string, unknown>, prefix = "") {
    for (const [key, value] of Object.entries(record)) {
      const path = prefix ? `${prefix}.${key}` : key;
      if (value !== null && typeof value === "object" && !Array.isArray(value)) {
        flatten(value as Record<string, unknown>, path);
      } else {
        values.set(path, value);
      }
    }
  }
  flatten(config);
  const keys = new Set([...values.keys(), ...Object.keys(provenance ?? {})]);
  return [...keys].sort().map((key) => {
    const entry = provenance?.[key];
    const source = entry?.source;
    return {
      key,
      value: values.get(key),
      source: source === "database" || source === "environment_bootstrap" || source === "default" ? source : "unknown",
      redacted: typeof entry?.redacted === "boolean" ? entry.redacted : undefined,
    };
  });
}

function buildGroups(items: ConfigItem[]): ConfigGroup[] {
  const definitions = [
    { title: "Network & TLS", icon: <Globe2 />, editTo: "/settings/network", matches: (key: string) => key.startsWith("egress_proxy.") || key === "tls_verify" || key === "ca_bundle_pem" },
    { title: "Syslog / SIEM", icon: <Activity />, editTo: "/settings/network", matches: (key: string) => key.startsWith("syslog_siem_target.") },
    { title: "Scanner & CVE Sources", icon: <ScanSearch />, editTo: "/settings/scanner", matches: (key: string) => key.startsWith("scanner_") || key.startsWith("nvd_") },
    { title: "SMTP", icon: <Mail />, matches: (key: string) => key.startsWith("smtp.") },
    { title: "Workload Image Scanning", icon: <ScanSearch />, editTo: "/registries", matches: (key: string) => key.startsWith("auto_scan_") },
    { title: "Retention", icon: <Database />, editTo: "/settings/retention", matches: (key: string) => key.endsWith("_retention_days") },
  ];
  const groups: ConfigGroup[] = definitions.map((definition) => ({
    ...definition,
    items: items.filter((item) => definition.matches(item.key)),
  }));
  const other = items.filter((item) => !definitions.some((definition) => definition.matches(item.key)));
  if (other.length > 0) groups.push({ title: "Other Configuration", icon: <SlidersHorizontal />, items: other });
  return groups.filter((group) => group.items.length > 0);
}

function summarizeSources(items: ConfigItem[]): Array<{ source: ConfigSource; count: number }> {
  const order: ConfigSource[] = ["database", "environment_bootstrap", "default", "unknown"];
  return order.map((source) => ({ source, count: items.filter((item) => item.source === source).length }));
}

function configValue(item: ConfigItem): string {
  if (item.redacted === true) return "Redacted";
  if (item.value === undefined) return "Not included in response";
  if (item.value === "") return "(empty)";
  return typeof item.value === "string" ? item.value : JSON.stringify(item.value);
}

function buildAppliedRevisionRows(components: ComponentInstance[], targetRevision: number): AppliedRevisionRow[] {
  return components.map((component) => {
    const revision = extractAppliedRevision(component.metadata ?? {});
    return {
      id: component.id,
      component: component.display_name || component.component,
      role: component.role,
      hostname: component.hostname,
      cluster: component.cluster_name || component.cluster_id || "org",
      reportedRevision: revision,
      status: appliedRevisionStatus(revision, targetRevision),
      lastSeenAt: component.last_seen_at,
    };
  }).sort((a, b) => statusRank(a.status) - statusRank(b.status) || a.component.localeCompare(b.component));
}

function extractAppliedRevision(metadata: Record<string, unknown>): number | null {
  const value = metadata.system_config_revision;
  const revision = typeof value === "number" ? value : typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value.trim()) : NaN;
  return Number.isSafeInteger(revision) && revision >= 0 ? revision : null;
}

function appliedRevisionStatus(revision: number | null, targetRevision: number): AppliedRevisionRow["status"] {
  if (revision === null) return "unknown";
  if (revision < targetRevision) return "behind";
  if (revision > targetRevision) return "ahead";
  return "current";
}

function statusRank(status: AppliedRevisionRow["status"]): number {
  return { behind: 0, ahead: 1, unknown: 2, current: 3 }[status];
}

function ProvenancePills({ item }: { item: ConfigItem }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      <SourcePill source={item.source} />
      {item.redacted === true ? <span className="rounded border border-status-warning/30 bg-status-warning/10 px-1.5 py-0.5 text-[10px] font-medium text-status-warning">Redacted</span> : null}
      {item.redacted === undefined ? <span className="text-[10px] text-muted-foreground">Redaction unknown</span> : null}
    </span>
  );
}

function SourcePill({ source }: { source: ConfigSource }) {
  const label = { database: "Database", environment_bootstrap: "Environment bootstrap", default: "Default", unknown: "Unknown" }[source];
  const cls = source === "database" ? "border-primary/30 bg-primary/10 text-primary" :
    source === "environment_bootstrap" ? "border-status-info/30 bg-status-info/10 text-status-info" :
    "border-border bg-muted text-muted-foreground";
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>{label}</span>;
}

function AppliedStatusPill({ status }: { status: AppliedRevisionRow["status"] | "unavailable" }) {
  const cls = status === "current" ? "border-primary/30 bg-primary/10 text-primary" :
    status === "behind" ? "border-status-warning/30 bg-status-warning/10 text-status-warning" :
    status === "ahead" ? "border-status-info/30 bg-status-info/10 text-status-info" :
    "border-border bg-muted text-muted-foreground";
  const label = { current: "Current", behind: "Behind", ahead: "Ahead", unknown: "Unknown", unavailable: "Unavailable" }[status];
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>{label}</span>;
}

function formatDateTime(value?: string): string {
  if (!value) return "Not recorded";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function copyText(value: string) {
  await navigator.clipboard.writeText(value);
}

function downloadJson(filename: string, value: string) {
  const blob = new Blob([value], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}
