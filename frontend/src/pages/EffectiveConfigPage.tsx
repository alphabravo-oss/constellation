import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import {
  Activity,
  ArrowRight,
  Clock3,
  Copy,
  Database,
  Download,
  Globe2,
  KeyRound,
  Mail,
  Network,
  RefreshCw,
  Save,
  ScanSearch,
  ShieldCheck,
  SlidersHorizontal,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { componentsInventory, systemConfigApi, type ComponentInstance } from "@/api/client";
import { PageContainer, PageHeader, PageSection } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { StatCard } from "@/components/ui/stat-card";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";

type ConfigSource = "default" | "stored" | "secret" | "disabled" | "managed";

interface ConfigItem {
  label: string;
  value: ReactNode;
  source: ConfigSource;
  detail?: string;
}

interface ConfigGroup {
  title: string;
  description: string;
  icon: ReactNode;
  editTo?: string;
  items: ConfigItem[];
}

interface ConfigDiffRow {
  key: string;
  label: string;
  current: string;
  baseline: string;
  source: ConfigSource;
}

interface AppliedRevisionRow {
  id: string;
  component: string;
  role: string;
  hostname: string;
  cluster: string;
  reportedRevision: string;
  status: "current" | "behind" | "ahead" | "unknown";
  lastSeenAt: string;
}

export function EffectiveConfigPage() {
  const q = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const componentsQ = useQuery({
    queryKey: ["components-inventory", "effective-config"],
    queryFn: () => componentsInventory.list({ limit: 1000 }),
    staleTime: 30_000,
  });

  if (q.isPending) {
    return (
      <PageContainer>
        <PageHeader title="Effective Config" description="Live platform configuration loaded from the system config API." />
        <LoadingState label="Loading system config..." />
      </PageContainer>
    );
  }

  if (q.isError) {
    return (
      <PageContainer>
        <PageHeader title="Effective Config" description="Live platform configuration loaded from the system config API." />
        <ErrorState title="Failed to load system config" error={q.error} />
      </PageContainer>
    );
  }

  const config = q.data.config ?? {};
  const groups = buildGroups(config);
  const proxy = asRecord(config.egress_proxy);
  const syslog = asRecord(config.syslog_siem_target);
  const smtp = asRecord(config.smtp);
  const redactedJson = JSON.stringify(config, null, 2);
  const proxyConfigured = stringValue(proxy.https_proxy) !== "";
  const syslogConfigured = stringValue(syslog.host) !== "";
  const smtpConfigured = stringValue(smtp.host) !== "";
  const scannerMinutes = numberValue(config.scanner_db_refresh_minutes);
  const source = q.data.source === "system_config" ? "System config row" : "Built-in defaults";
  const updatedAt = formatDateTime(q.data.updated_at);
  const updatedBy = q.data.updated_by_email || q.data.updated_by || "Not recorded";
  const allConfigItems = groups.flatMap((group) => group.items);
  const storedItems = allConfigItems.filter((item) => item.source === "stored" || item.source === "secret").length;
  const sourceSummary = summarizeSources(allConfigItems);
  const diffRows = buildDefaultDiff(config);
  const appliedRows = buildAppliedRevisionRows(componentsQ.data?.components ?? [], q.data.revision);
  const reportingApplied = appliedRows.filter((row) => row.status !== "unknown").length;
  const coverage = buildCoverage(config, { proxyConfigured, syslogConfigured, smtpConfigured });

  return (
    <PageContainer data-testid="effective-config-page">
      <PageHeader
        title="Effective Config"
        description="Redacted live system configuration with the operator controls NeuVector users expect in one place."
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
              <Link to="/settings/network">
                <Globe2 className="h-4 w-4" />
                Network & Proxy
              </Link>
            </Button>
            <Button asChild variant="outline">
              <Link to="/settings/scanner">
                <ScanSearch className="h-4 w-4" />
                Scanner
              </Link>
            </Button>
          </div>
        }
      />

      <section className="grid grid-cols-2 gap-3 xl:grid-cols-6">
        <StatCard label="Revision" value={q.data.revision} hint="Optimistic config version" icon={<SlidersHorizontal className="h-3.5 w-3.5" />} />
        <StatCard label="Source" value={source} hint={q.data.source === "system_config" ? "Hot-reloaded DB row" : "No persisted row"} tone={q.data.source === "system_config" ? "accent" : "neutral"} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Last changed" value={updatedAt} hint={updatedBy} icon={<Clock3 className="h-3.5 w-3.5" />} />
        <StatCard label="Stored values" value={storedItems} hint="Explicit or secret-backed entries" icon={<ShieldCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Applied reports" value={`${reportingApplied}/${appliedRows.length}`} hint="components reporting config revision" tone={reportingApplied === appliedRows.length && appliedRows.length > 0 ? "accent" : "neutral"} icon={<SlidersHorizontal className="h-3.5 w-3.5" />} />
        <StatCard label="Egress proxy" value={proxyConfigured ? "On" : "Off"} hint={proxyConfigured ? "Stored URL is configured" : "Direct outbound egress"} tone={proxyConfigured ? "accent" : "neutral"} icon={<Globe2 className="h-3.5 w-3.5" />} />
        <StatCard label="Syslog / SIEM" value={syslogConfigured ? "On" : "Off"} hint={syslogConfigured ? `${stringValue(syslog.protocol) || "udp"} transport` : "No mirror target"} tone={syslogConfigured ? "accent" : "neutral"} icon={<Activity className="h-3.5 w-3.5" />} />
        <StatCard label="Scanner refresh" value={scannerMinutes > 0 ? `${scannerMinutes}m` : "Default"} hint={boolValue(config.scanner_offline_db) ? "Offline DB mode" : "Connected DB mode"} icon={<RefreshCw className="h-3.5 w-3.5" />} />
      </section>

      <PageSection title="NeuVector Coverage Map" description="Where common NeuVector system-config categories are operated in Constellation.">
        <div className="grid gap-3 lg:grid-cols-2 xl:grid-cols-4">
          {coverage.map((item) => (
            <Link
              key={item.nv}
              to={item.to}
              className="rounded-md border border-border bg-card p-3 transition-colors hover:bg-accent"
              data-testid="effective-config-coverage-card"
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="text-[10px] uppercase tracking-wider text-muted-foreground">NV {item.nv}</div>
                  <div className="mt-1 text-sm font-semibold">{item.constellation}</div>
                </div>
                <SourcePill source={item.source} />
              </div>
              <p className="mt-2 text-xs leading-5 text-muted-foreground">{item.detail}</p>
            </Link>
          ))}
        </div>
      </PageSection>

      <PageSection title="Source, Diff & Applied State" description="Operator review for what differs from the safe default and which components have reported the active revision.">
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
          </section>

          <section className="rounded-md border border-border bg-card p-3" data-testid="effective-config-default-diff">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-semibold">Current vs Default</h2>
              <span className="text-xs text-muted-foreground">{diffRows.length} explicit difference{diffRows.length === 1 ? "" : "s"}</span>
            </div>
            {diffRows.length === 0 ? (
              <p className="mt-3 text-xs text-muted-foreground">No runtime-mutable config differs from the safe default baseline.</p>
            ) : (
              <div className="mt-3 overflow-x-auto">
                <table className="min-w-full text-xs">
                  <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                    <tr>
                      <th className="px-2 py-1.5 font-medium">Key</th>
                      <th className="px-2 py-1.5 font-medium">Current</th>
                      <th className="px-2 py-1.5 font-medium">Default</th>
                      <th className="px-2 py-1.5 font-medium">Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {diffRows.map((row) => (
                      <tr key={row.key} className="border-t border-border">
                        <td className="px-2 py-2 font-medium">{row.label}</td>
                        <td className="max-w-[260px] break-all px-2 py-2 font-mono">{row.current}</td>
                        <td className="max-w-[220px] break-all px-2 py-2 font-mono text-muted-foreground">{row.baseline}</td>
                        <td className="px-2 py-2"><SourcePill source={row.source} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>

        <section className="mt-4 rounded-md border border-border bg-card p-3" data-testid="effective-config-applied-revisions">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-semibold">Component Applied Revision</h2>
            <span className="text-xs text-muted-foreground">target revision {q.data.revision}</span>
          </div>
          {componentsQ.isPending ? (
            <p className="mt-3 text-xs text-muted-foreground">Loading component reports...</p>
          ) : appliedRows.length === 0 ? (
            <p className="mt-3 text-xs text-muted-foreground">No component heartbeats are available yet.</p>
          ) : (
            <div className="mt-3 overflow-x-auto">
              <table className="min-w-full text-xs">
                <thead className="text-left text-[10px] uppercase tracking-wider text-muted-foreground">
                  <tr>
                    <th className="px-2 py-1.5 font-medium">Component</th>
                    <th className="px-2 py-1.5 font-medium">Host</th>
                    <th className="px-2 py-1.5 font-medium">Applied</th>
                    <th className="px-2 py-1.5 font-medium">Status</th>
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
                      <td className="px-2 py-2 font-mono">{row.reportedRevision}</td>
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

      <PageSection title="Configuration Groups" description="Values marked as stored are persisted in system config; secrets are shown only as redacted markers.">
        <div className="grid gap-4 xl:grid-cols-2">
          {groups.map((group) => (
            <Card
              key={group.title}
              title={
                <span className="inline-flex items-center gap-2">
                  <span className="text-muted-foreground [&_svg]:h-4 [&_svg]:w-4">{group.icon}</span>
                  {group.title}
                </span>
              }
              description={group.description}
              action={group.editTo ? (
                <Button asChild variant="ghost" size="sm">
                  <Link to={group.editTo}>
                    Edit
                    <ArrowRight className="h-3.5 w-3.5" />
                  </Link>
                </Button>
              ) : undefined}
            >
              <dl className="divide-y divide-border">
                {group.items.map((item) => <ConfigRow key={item.label} item={item} />)}
              </dl>
            </Card>
          ))}
        </div>
      </PageSection>

      <Card
        title="Redacted JSON"
        description="Exact response from /system/config after backend redaction. Use this for support and config-diff reviews."
      >
        <pre className="max-h-[460px] overflow-auto rounded-md border border-border bg-muted p-3 text-xs">
          {redactedJson}
        </pre>
      </Card>

      {!smtpConfigured || !syslogConfigured ? (
        <Card title="Operator Notes" description="Configuration areas that are commonly required during an NV cutover.">
          <ul className="space-y-2 text-sm text-muted-foreground">
            {!syslogConfigured ? <li>Syslog/SIEM mirroring is not configured.</li> : null}
            {!smtpConfigured ? <li>SMTP is not configured for email receivers.</li> : null}
            {config.tls_verify === false ? <li>Upstream TLS verification is disabled.</li> : null}
          </ul>
        </Card>
      ) : null}
    </PageContainer>
  );
}

function buildGroups(config: Record<string, unknown>): ConfigGroup[] {
  const proxy = asRecord(config.egress_proxy);
  const syslog = asRecord(config.syslog_siem_target);
  const smtp = asRecord(config.smtp);

  return [
    {
      title: "Platform & TLS",
      description: "Global runtime source, upstream trust, and support-safe redaction state.",
      icon: <SlidersHorizontal />,
      editTo: "/settings/network",
      items: [
        row("Upstream TLS verification", config.tls_verify === false ? "Off" : "On", config.tls_verify === false ? "stored" : "default"),
        row("Custom CA bundle", secretLabel(config.ca_bundle_pem), secretSource(config.ca_bundle_pem)),
        row("Hot reload", "Enabled", "default", "Consumers poll revision changes without process restart."),
        row("Audit history", <LinkValue to="/audit">Open audit log</LinkValue>, "managed", "System config PATCH events are recorded as system.config.update."),
      ],
    },
    {
      title: "Network & Proxy",
      description: "Outbound connectivity, upstream TLS trust, and corporate proxy routing.",
      icon: <Globe2 />,
      editTo: "/settings/network",
      items: [
        row("HTTPS proxy", stringValue(proxy.https_proxy) || "Not configured", stringValue(proxy.https_proxy) ? "stored" : "disabled"),
        row("No-proxy list", stringValue(proxy.no_proxy) || "Not configured", stringValue(proxy.no_proxy) ? "stored" : "default"),
        row("Registry pull proxy", stringValue(proxy.https_proxy) ? "Shared egress proxy" : "Direct egress", stringValue(proxy.https_proxy) ? "stored" : "default"),
        row("X-Forwarded-For handling", "Ingress controlled", "managed", "Per-ingress trust belongs in deployment/ingress config."),
      ],
    },
    {
      title: "Syslog / SIEM",
      description: "Audit and notification event mirror settings.",
      icon: <Activity />,
      editTo: "/settings/network",
      items: [
        row("Target", stringValue(syslog.host) ? `${stringValue(syslog.host)}:${numberValue(syslog.port) || 514}` : "Not configured", stringValue(syslog.host) ? "stored" : "disabled"),
        row("Protocol", stringValue(syslog.protocol) || "udp", stringValue(syslog.protocol) ? "stored" : "default"),
        row("Format", stringValue(syslog.format) || "rfc5424", stringValue(syslog.format) ? "stored" : "default"),
        row("Minimum severity", stringValue(syslog.min_level) || "All", stringValue(syslog.min_level) ? "stored" : "default"),
        row("Categories", arrayLabel(syslog.categories) || "All", Array.isArray(syslog.categories) && syslog.categories.length > 0 ? "stored" : "default"),
        row("mTLS client key", secretLabel(syslog.client_key), secretSource(syslog.client_key)),
      ],
    },
    {
      title: "Auth & Access",
      description: "Authentication providers, role mappings, session policy, and token controls.",
      icon: <KeyRound />,
      editTo: "/settings/access",
      items: [
        row("Auth providers", <LinkValue to="/settings/access">Access Control</LinkValue>, "managed", "LDAP, SAML, and OIDC are configured outside the system_config row."),
        row("Password/session policy", <LinkValue to="/settings/security-policy">Security Policy</LinkValue>, "managed"),
        row("API tokens", <LinkValue to="/settings/api-tokens">API tokens</LinkValue>, "managed"),
        row("Platform auth order", "Managed by providers", "managed", "NeuVector auth_order maps to enabled provider priority and role bindings."),
      ],
    },
    {
      title: "Scanner & CVE Sources",
      description: "Scanner database refresh behavior and CVE feed configuration.",
      icon: <ScanSearch />,
      editTo: "/settings/scanner",
      items: [
        row("DB refresh interval", numberValue(config.scanner_db_refresh_minutes) > 0 ? `${numberValue(config.scanner_db_refresh_minutes)} minutes` : "Deploy default", numberValue(config.scanner_db_refresh_minutes) > 0 ? "stored" : "default"),
        row("Refresh-now signal", numberValue(config.scanner_db_refresh_now) > 0 ? String(numberValue(config.scanner_db_refresh_now)) : "Not requested", numberValue(config.scanner_db_refresh_now) > 0 ? "stored" : "default"),
        row("Offline DB mode", boolValue(config.scanner_offline_db) ? "On" : "Off", boolValue(config.scanner_offline_db) ? "stored" : "default"),
        row("NVD importer", boolValue(config.nvd_enabled) ? "On" : "Off", boolValue(config.nvd_enabled) ? "stored" : "disabled"),
        row("NVD API key", secretLabel(config.nvd_api_key), secretSource(config.nvd_api_key)),
        row("NVD mirror", stringValue(config.nvd_mirror_url) || "Not configured", stringValue(config.nvd_mirror_url) ? "stored" : "default"),
      ],
    },
    {
      title: "Registry & Repository Scans",
      description: "Registry connections, repository scans, scan triggers, and proxy inheritance.",
      icon: <Database />,
      editTo: "/registries",
      items: [
        row("Registry inventory", <LinkValue to="/registries">Registries</LinkValue>, "managed"),
        row("Repository scans", <LinkValue to="/repositories">Repositories</LinkValue>, "managed"),
        row("Proxy inheritance", stringValue(proxy.https_proxy) ? "Uses egress proxy" : "Direct egress", stringValue(proxy.https_proxy) ? "stored" : "default"),
        row("Running image auto-scan", boolValue(config.auto_scan_disabled) ? "Off" : "On", boolValue(config.auto_scan_disabled) ? "stored" : "default"),
      ],
    },
    {
      title: "SMTP",
      description: "Global email sender for notification receivers.",
      icon: <Mail />,
      items: [
        row("Host", stringValue(smtp.host) || "Not configured", stringValue(smtp.host) ? "stored" : "disabled"),
        row("Port", numberValue(smtp.port) > 0 ? String(numberValue(smtp.port)) : "Default", numberValue(smtp.port) > 0 ? "stored" : "default"),
        row("Username", stringValue(smtp.username) || "Not configured", stringValue(smtp.username) ? "stored" : "default"),
        row("Password", secretLabel(smtp.password), secretSource(smtp.password)),
        row("From address", stringValue(smtp.from) || "Not configured", stringValue(smtp.from) ? "stored" : "default"),
        row("STARTTLS", boolValue(smtp.starttls) ? "On" : "Off", boolValue(smtp.starttls) ? "stored" : "default"),
      ],
    },
    {
      title: "Runtime Enforcement",
      description: "Runtime policy, network policy lifecycle, and running workload scan defaults.",
      icon: <Network />,
      editTo: "/runtime",
      items: [
        row("Automatic workload image scan", boolValue(config.auto_scan_disabled) ? "Off" : "On", boolValue(config.auto_scan_disabled) ? "stored" : "default"),
        row("Auto-scan rescan interval", numberValue(config.auto_scan_rescan_hours) > 0 ? `${numberValue(config.auto_scan_rescan_hours)} hours` : "24 hours", numberValue(config.auto_scan_rescan_hours) > 0 ? "stored" : "default"),
        row("Network policy lifecycle", <LinkValue to="/network">Network Activity rules</LinkValue>, "managed"),
        row("Runtime response rules", <LinkValue to="/response-rules">Response Rules</LinkValue>, "managed"),
      ],
    },
    {
      title: "Retention",
      description: "Storage windows for high-volume event and scan-job history.",
      icon: <Database />,
      editTo: "/settings/retention",
      items: [
        retentionRow("Network flows", config.network_flow_retention_days),
        retentionRow("Runtime and platform events", config.events_retention_days),
        retentionRow("Scan jobs", config.scan_job_retention_days),
      ],
    },
    {
      title: "Backup & Federation",
      description: "Operational continuity, config export, and cross-cluster policy sync.",
      icon: <Save />,
      editTo: "/settings/backup",
      items: [
        row("Backup schedules", <LinkValue to="/settings/backup">Backup</LinkValue>, "managed"),
        row("Config export/import", <LinkValue to="/settings/migration">Migration Imports</LinkValue>, "managed"),
        row("Federation", <LinkValue to="/federation">Federation</LinkValue>, "managed"),
        row("Git config sync", <LinkValue to="/integrations">Integrations</LinkValue>, "managed"),
      ],
    },
  ];
}

interface CoverageItem {
  nv: string;
  constellation: string;
  detail: string;
  to: string;
  source: ConfigSource;
}

function buildCoverage(
  config: Record<string, unknown>,
  state: { proxyConfigured: boolean; syslogConfigured: boolean; smtpConfigured: boolean },
): CoverageItem[] {
  return [
    {
      nv: "System Config",
      constellation: "Effective Config",
      detail: config.tls_verify === false ? "Runtime config is persisted with TLS verification disabled." : "Runtime config is loaded with safe TLS defaults.",
      to: "/settings/effective-config",
      source: "stored",
    },
    {
      nv: "Syslog",
      constellation: "Syslog / SIEM",
      detail: state.syslogConfigured ? "Event mirroring target is configured." : "No syslog/SIEM target is configured.",
      to: "/settings/network",
      source: state.syslogConfigured ? "stored" : "disabled",
    },
    {
      nv: "Registry Proxy",
      constellation: "Network & Proxy",
      detail: state.proxyConfigured ? "Registry and shared outbound clients inherit the configured egress proxy." : "Registry and shared outbound clients use direct egress.",
      to: "/settings/network",
      source: state.proxyConfigured ? "stored" : "default",
    },
    {
      nv: "Scanner",
      constellation: "Scanner & CVE Sources",
      detail: boolValue(config.scanner_offline_db) ? "Scanners are in offline DB mode." : "Scanners use connected DB refresh behavior.",
      to: "/settings/scanner",
      source: boolValue(config.scanner_offline_db) || numberValue(config.scanner_db_refresh_minutes) > 0 ? "stored" : "default",
    },
    {
      nv: "Auth",
      constellation: "Access Control",
      detail: "Auth providers, role bindings, service accounts, and API tokens are managed in Access Control.",
      to: "/settings/access",
      source: "managed",
    },
    {
      nv: "Webhooks / Email",
      constellation: "Integrations",
      detail: state.smtpConfigured ? "SMTP is configured for email receiver delivery." : "Receivers and webhooks are managed under Integrations; SMTP is not configured.",
      to: "/settings/integrations",
      source: state.smtpConfigured ? "stored" : "managed",
    },
    {
      nv: "Network Service",
      constellation: "Network Activity",
      detail: "Network map, sessions, PCAP, rules, and threats are operated from the cluster Network Activity workspace.",
      to: "/network",
      source: "managed",
    },
    {
      nv: "Federation",
      constellation: "Federation",
      detail: "Cross-cluster policy and user-group sync lives in the Federation workspace.",
      to: "/federation",
      source: "managed",
    },
  ];
}

function summarizeSources(items: ConfigItem[]): Array<{ source: ConfigSource; count: number }> {
  const order: ConfigSource[] = ["stored", "secret", "managed", "default", "disabled"];
  const counts = new Map<ConfigSource, number>();
  for (const item of items) counts.set(item.source, (counts.get(item.source) ?? 0) + 1);
  return order.map((source) => ({ source, count: counts.get(source) ?? 0 }));
}

function buildDefaultDiff(config: Record<string, unknown>): ConfigDiffRow[] {
  const proxy = asRecord(config.egress_proxy);
  const syslog = asRecord(config.syslog_siem_target);
  const smtp = asRecord(config.smtp);
  const rows: ConfigDiffRow[] = [];

  addDiff(rows, "tls_verify", "TLS verification", config.tls_verify === false ? "Off" : "On", "On", config.tls_verify === false ? "stored" : "default");
  addDiff(rows, "ca_bundle_pem", "Custom CA bundle", secretLabel(config.ca_bundle_pem), "Not configured", secretSource(config.ca_bundle_pem));
  addDiff(rows, "egress_proxy.https_proxy", "HTTPS proxy", stringValue(proxy.https_proxy) || "Not configured", "Not configured", stringValue(proxy.https_proxy) ? "stored" : "default");
  addDiff(rows, "egress_proxy.no_proxy", "No-proxy list", stringValue(proxy.no_proxy) || "Not configured", "Not configured", stringValue(proxy.no_proxy) ? "stored" : "default");

  addDiff(rows, "syslog_siem_target.host", "Syslog target", stringValue(syslog.host) ? `${stringValue(syslog.host)}:${numberValue(syslog.port) || 514}` : "Not configured", "Not configured", stringValue(syslog.host) ? "stored" : "default");
  addDiff(rows, "syslog_siem_target.protocol", "Syslog protocol", stringValue(syslog.protocol) || "udp", "udp", stringValue(syslog.protocol) ? "stored" : "default");
  addDiff(rows, "syslog_siem_target.tls", "Syslog TLS", boolValue(syslog.tls) ? "On" : "Off", "Off", boolValue(syslog.tls) ? "stored" : "default");
  addDiff(rows, "syslog_siem_target.format", "Syslog format", stringValue(syslog.format) || "rfc5424", "rfc5424", stringValue(syslog.format) ? "stored" : "default");
  addDiff(rows, "syslog_siem_target.min_level", "Syslog minimum severity", stringValue(syslog.min_level) || "All", "All", stringValue(syslog.min_level) ? "stored" : "default");
  addDiff(rows, "syslog_siem_target.categories", "Syslog categories", arrayLabel(syslog.categories) || "All", "All", Array.isArray(syslog.categories) && syslog.categories.length > 0 ? "stored" : "default");
  addDiff(rows, "syslog_siem_target.ca_cert", "Syslog CA cert", secretLabel(syslog.ca_cert), "Not configured", secretSource(syslog.ca_cert));
  addDiff(rows, "syslog_siem_target.client_cert", "Syslog client cert", secretLabel(syslog.client_cert), "Not configured", secretSource(syslog.client_cert));
  addDiff(rows, "syslog_siem_target.client_key", "Syslog client key", secretLabel(syslog.client_key), "Not configured", secretSource(syslog.client_key));

  addDiff(rows, "scanner_db_refresh_minutes", "Scanner DB refresh", numberValue(config.scanner_db_refresh_minutes) > 0 ? `${numberValue(config.scanner_db_refresh_minutes)} minutes` : "Deploy default", "Deploy default", numberValue(config.scanner_db_refresh_minutes) > 0 ? "stored" : "default");
  addDiff(rows, "scanner_db_refresh_now", "Scanner refresh-now signal", numberValue(config.scanner_db_refresh_now) > 0 ? String(numberValue(config.scanner_db_refresh_now)) : "Not requested", "Not requested", numberValue(config.scanner_db_refresh_now) > 0 ? "stored" : "default");
  addDiff(rows, "scanner_offline_db", "Scanner offline DB", boolValue(config.scanner_offline_db) ? "On" : "Off", "Off", boolValue(config.scanner_offline_db) ? "stored" : "default");
  addDiff(rows, "nvd_enabled", "NVD importer", boolValue(config.nvd_enabled) ? "On" : "Off", "Off", boolValue(config.nvd_enabled) ? "stored" : "default");
  addDiff(rows, "nvd_api_key", "NVD API key", secretLabel(config.nvd_api_key), "Not configured", secretSource(config.nvd_api_key));
  addDiff(rows, "nvd_mirror_url", "NVD mirror", stringValue(config.nvd_mirror_url) || "Not configured", "Not configured", stringValue(config.nvd_mirror_url) ? "stored" : "default");

  addDiff(rows, "smtp.host", "SMTP host", stringValue(smtp.host) || "Not configured", "Not configured", stringValue(smtp.host) ? "stored" : "default");
  addDiff(rows, "smtp.port", "SMTP port", numberValue(smtp.port) > 0 ? String(numberValue(smtp.port)) : "Default", "Default", numberValue(smtp.port) > 0 ? "stored" : "default");
  addDiff(rows, "smtp.username", "SMTP username", stringValue(smtp.username) || "Not configured", "Not configured", stringValue(smtp.username) ? "stored" : "default");
  addDiff(rows, "smtp.password", "SMTP password", secretLabel(smtp.password), "Not configured", secretSource(smtp.password));
  addDiff(rows, "smtp.from", "SMTP from", stringValue(smtp.from) || "Not configured", "Not configured", stringValue(smtp.from) ? "stored" : "default");
  addDiff(rows, "smtp.starttls", "SMTP STARTTLS", boolValue(smtp.starttls) ? "On" : "Off", "Off", boolValue(smtp.starttls) ? "stored" : "default");

  addDiff(rows, "network_flow_retention_days", "Network flow retention", retentionValue(config.network_flow_retention_days), "Keep forever", numberValue(config.network_flow_retention_days) > 0 ? "stored" : "default");
  addDiff(rows, "events_retention_days", "Event retention", retentionValue(config.events_retention_days), "Keep forever", numberValue(config.events_retention_days) > 0 ? "stored" : "default");
  addDiff(rows, "scan_job_retention_days", "Scan-job retention", retentionValue(config.scan_job_retention_days), "Keep forever", numberValue(config.scan_job_retention_days) > 0 ? "stored" : "default");
  addDiff(rows, "auto_scan_disabled", "Running image auto-scan", boolValue(config.auto_scan_disabled) ? "Off" : "On", "On", boolValue(config.auto_scan_disabled) ? "stored" : "default");
  addDiff(rows, "auto_scan_rescan_hours", "Auto-scan rescan interval", numberValue(config.auto_scan_rescan_hours) > 0 ? `${numberValue(config.auto_scan_rescan_hours)} hours` : "24 hours", "24 hours", numberValue(config.auto_scan_rescan_hours) > 0 ? "stored" : "default");

  return rows;
}

function addDiff(rows: ConfigDiffRow[], key: string, label: string, current: string, baseline: string, source: ConfigSource) {
  if (current === baseline) return;
  rows.push({ key, label, current, baseline, source });
}

function buildAppliedRevisionRows(components: ComponentInstance[], targetRevision: number): AppliedRevisionRow[] {
  return components
    .map((component) => {
      const revision = extractAppliedRevision(component.metadata ?? {});
      return {
        id: component.id,
        component: component.display_name || component.component,
        role: component.role,
        hostname: component.hostname,
        cluster: component.cluster_name || component.cluster_id || "org",
        reportedRevision: revision == null ? "not reported" : String(revision),
        status: appliedRevisionStatus(revision, targetRevision),
        lastSeenAt: component.last_seen_at,
      };
    })
    .sort((a, b) => statusRank(a.status) - statusRank(b.status) || a.component.localeCompare(b.component));
}

function extractAppliedRevision(metadata: Record<string, unknown>): string | number | null {
  const direct = firstRevisionValue(metadata, ["system_config_revision", "config_revision", "applied_config_revision", "applied_revision"]);
  if (direct != null) return direct;
  for (const key of ["system_config", "effective_config", "config"]) {
    const nested = asRecord(metadata[key]);
    const value = firstRevisionValue(nested, ["revision", "applied_revision", "system_config_revision"]);
    if (value != null) return value;
  }
  return null;
}

function firstRevisionValue(record: Record<string, unknown>, keys: string[]): string | number | null {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() !== "") return value.trim();
  }
  return null;
}

function appliedRevisionStatus(revision: string | number | null, targetRevision: number): AppliedRevisionRow["status"] {
  if (revision == null) return "unknown";
  const numeric = typeof revision === "number" ? revision : Number(revision);
  if (!Number.isFinite(numeric)) return String(revision) === String(targetRevision) ? "current" : "unknown";
  if (numeric < targetRevision) return "behind";
  if (numeric > targetRevision) return "ahead";
  return "current";
}

function statusRank(status: AppliedRevisionRow["status"]): number {
  switch (status) {
    case "behind": return 0;
    case "ahead": return 1;
    case "unknown": return 2;
    case "current": return 3;
  }
}

function ConfigRow({ item }: { item: ConfigItem }) {
  return (
    <div className="grid gap-2 py-3 text-sm sm:grid-cols-[190px_minmax(0,1fr)_92px]">
      <dt className="font-medium text-foreground">{item.label}</dt>
      <dd className="min-w-0 break-words text-foreground">
        {item.value}
        {item.detail ? <div className="mt-1 text-xs text-muted-foreground">{item.detail}</div> : null}
      </dd>
      <dd className="sm:text-right">
        <SourcePill source={item.source} />
      </dd>
    </div>
  );
}

function SourcePill({ source }: { source: ConfigSource }) {
  const label = source === "stored" ? "Stored" : source === "secret" ? "Redacted" : source === "disabled" ? "Off" : source === "managed" ? "Linked" : "Default";
  const cls =
    source === "stored" ? "border-primary/30 bg-primary/10 text-primary" :
    source === "secret" ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300" :
    source === "managed" ? "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300" :
    source === "disabled" ? "border-border bg-muted text-muted-foreground" :
    "border-border bg-background text-muted-foreground";
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>{label}</span>;
}

function AppliedStatusPill({ status }: { status: AppliedRevisionRow["status"] }) {
  const cls =
    status === "current" ? "border-primary/30 bg-primary/10 text-primary" :
    status === "behind" ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300" :
    status === "ahead" ? "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300" :
    "border-border bg-muted text-muted-foreground";
  const label = status === "current" ? "Current" : status === "behind" ? "Behind" : status === "ahead" ? "Ahead" : "Not reported";
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-[10px] font-medium ${cls}`}>{label}</span>;
}

function LinkValue({ to, children }: { to: string; children: ReactNode }) {
  return <Link to={to} className="text-[color:var(--color-primary)] hover:underline">{children}</Link>;
}

function row(label: string, value: ReactNode, source: ConfigSource, detail?: string): ConfigItem {
  return { label, value, source, detail };
}

function retentionRow(label: string, value: unknown): ConfigItem {
  const days = numberValue(value);
  if (days <= 0) return row(label, "Keep forever", "default", "No pruning window is configured.");
  return row(label, `${days} days`, "stored");
}

function retentionValue(value: unknown): string {
  const days = numberValue(value);
  return days > 0 ? `${days} days` : "Keep forever";
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function numberValue(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function boolValue(value: unknown): boolean {
  return value === true;
}

function arrayLabel(value: unknown): string {
  return Array.isArray(value) ? value.map((item) => String(item)).filter(Boolean).join(", ") : "";
}

function secretLabel(value: unknown): string {
  const text = stringValue(value);
  if (!text) return "Not configured";
  if (text === "***REDACTED***") return "Configured";
  return "Configured";
}

function secretSource(value: unknown): ConfigSource {
  return stringValue(value) ? "secret" : "disabled";
}

function formatDateTime(value?: string): string {
  if (!value) return "Not persisted";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
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
