import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { Activity, ArrowRight, Clock3, Copy, Database, Download, Globe2, Mail, ScanSearch, SlidersHorizontal } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { componentsInventory, systemConfigApi, type ComponentInstance, type ConfigProvenance } from "@/api/client";
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page";
import { DataTable } from "@/components/ui/data-table";
import { Card } from "@/components/ui/card";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";

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
  const [requestedTab, setTab] = useTabParam("tab", "values");
  const tab = ["values", "sources", "reports", "json"].includes(requestedTab) ? requestedTab : "values";
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
        <ErrorState title="Failed to load system config" error={q.error} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
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
  const appliedRows = buildAppliedRevisionRows(componentsQ.isSuccess ? componentsQ.data.components : [], q.data.revision);
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
            <Button variant="outline" disabled={q.isFetching || componentsQ.isFetching} onClick={() => { void q.refetch(); void componentsQ.refetch(); }}>Refresh</Button>
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

      <VerdictBanner status={provider?.status === "behind" ? "degraded" : "info"} title={`System configuration revision ${q.data.revision}`} detail="Inspect redacted values and their reported sources. Component heartbeat reports establish reported adoption, not current health or fleet-wide enforcement." />
      <StatGrid>
        <StatCard label="Config revision" value={q.data.revision} hint="Revision returned by the API" icon={<SlidersHorizontal className="h-3.5 w-3.5" />} />
        <StatCard label="Persistence" valueKind="text" value={source} hint="Per-key sources are listed below" icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Last changed" valueKind="text" value={formatDateTime(q.data.updated_at)} hint={q.data.updated_by_email || q.data.updated_by || "Not recorded"} icon={<Clock3 className="h-3.5 w-3.5" />} />
        <StatCard label="Database values" value={items.filter((item) => item.source === "database").length} hint="Keys attributed to the database" icon={<Database className="h-3.5 w-3.5" />} />
      </StatGrid>

      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "values", label: "Values", count: items.length, content: (<Card title="Configuration values" description="All returned keys, with backend-reported source and redaction. Edit links open the owning settings page.">
        <DataTable<ConfigItem> rows={items} rowKey={item => item.key} preferencesKey="effective-config-values" exportFileName="effective-config-redacted-values" columns={[
          { id: "key", header: "Key", kind: "name", code: true, wrap: true, cell: item => item.key, exportValue: item => item.key },
          { id: "value", header: "Value", kind: "text", wrap: true, grow: true, cell: configValue, exportValue: configValue },
          { id: "source", header: "Source / redaction", kind: "badge", size: 240, maxSize: 300, wrap: true, cell: item => <ProvenancePills item={item} />, exportValue: item => `${item.source}; redacted=${item.redacted ?? "unknown"}` },
          { id: "edit", header: "Settings", kind: "actions", exportable: false, cell: item => { const group = groups.find(group => group.items.includes(item)); return group?.editTo ? <a href={group.editTo} className="text-primary hover:underline">Edit<ArrowRight className="inline h-3.5 w-3.5" /></a> : "—"; } },
        ]} />
      </Card>) },
        { value: "sources", label: "Provenance", content: (<PageSection title="Configuration Sources" description="Sources and redaction are reported independently by the backend for each configuration key.">
        <div className="space-y-4">
          <section className="rounded-md border border-border bg-card p-3" data-testid="effective-config-source-summary">
            <h2 className="text-sm font-semibold">Source distribution</h2>
            <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-2 xl:grid-cols-4">
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
              <div className="mt-3 min-w-0">
                <DataTable<ConfigItem>
                  rows={nonDefaultItems}
                  rowKey={(item) => item.key}
                  preferencesKey="effective-config-non-default"
                  exportFileName="effective-config-non-default"
                  columns={[
                    { id: "key", header: "Key", kind: "name", code: true, wrap: true, exportValue: (item) => item.key, cell: (item) => item.key },
                    { id: "value", header: "Current value", kind: "text", code: true, wrap: true, grow: true, exportValue: configValue, cell: configValue },
                    { id: "source", header: "Source / redaction", kind: "badge", size: 240, maxSize: 300, wrap: true, exportValue: (item) => `${item.source}; redacted=${item.redacted ?? "unknown"}`, cell: (item) => <ProvenancePills item={item} /> },
                  ]}
                />
              </div>
            )}
          </section>
        </div>
      </PageSection>) },
        { value: "reports", label: "Revision reports", content: (<div className="space-y-4"><section className="rounded-md border border-border bg-card p-4" data-testid="effective-config-provider-applied">
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
      </section><PageSection title="Component Revision Reports" description="Only an explicit system_config_revision in component heartbeat metadata is used here.">
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
            <div className="mt-3 min-w-0">
              <DataTable<AppliedRevisionRow>
                rows={appliedRows}
                rowKey={(row) => row.id}
                preferencesKey="effective-config-reports"
                exportFileName="effective-config-loaded-reports"
                exportLabel="Export loaded reports CSV"
                sourceLimit={1000} sourceCount={appliedRows.length}
                columns={[
                  { id: "component", header: "Component", kind: "name", exportValue: (row) => `${row.component}; role=${row.role}; cluster=${row.cluster}`, cell: (row) => <><div className="font-medium">{row.component}</div><div className="text-xs text-muted-foreground">{row.role} · {row.cluster}</div></> },
                  { id: "host", header: "Host", kind: "id", exportValue: (row) => row.hostname, cell: (row) => row.hostname },
                  { id: "revision", header: "Reported revision", kind: "count", exportValue: (row) => row.reportedRevision ?? "", cell: (row) => row.reportedRevision ?? "Unknown" },
                  { id: "status", header: "Compared with target", kind: "status", size: 200, exportValue: (row) => row.status, cell: (row) => <AppliedStatusPill status={row.status} /> },
                  { id: "lastSeen", header: "Last seen", kind: "date", exportValue: (row) => row.lastSeenAt, cell: (row) => formatDateTime(row.lastSeenAt) },
                ]}
              />
            </div>
          )}
        </section>
      </PageSection></div>) },
        { value: "json", label: "JSON", content: (<Card title="Redacted JSON" description="The config object returned by /system/config after backend redaction.">
        <pre className="max-h-[460px] overflow-auto rounded-md border border-border bg-muted p-3 text-xs">{redactedJson}</pre>
      </Card>) },
      ]} />
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
    { title: "SMTP", icon: <Mail />, editTo: "/settings/integrations/smtp/edit", matches: (key: string) => key.startsWith("smtp.") },
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
