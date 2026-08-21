import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { systemConfigApi } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Textarea, Select, Switch } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";

/**
 * Network & Proxy — outbound connectivity for the platform: egress proxy, upstream
 * TLS trust, and the syslog/SIEM mirror. All hot-reloaded (no restart).
 */
type SyslogTarget = {
  host?: string; port?: number; protocol?: string;
  format?: string; min_level?: string; categories?: string[];
  ca_cert?: string; client_cert?: string; client_key?: string;
};
type EgressProxy = { https_proxy?: string; no_proxy?: string };

export function NetworkProxyPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });

  const [httpsProxy, setHttpsProxy] = useState("");
  const [noProxy, setNoProxy] = useState("");
  const [tlsVerify, setTlsVerify] = useState(true);
  const [caBundle, setCaBundle] = useState("");
  const [syslogHost, setSyslogHost] = useState("");
  const [syslogPort, setSyslogPort] = useState(514);
  const [syslogProto, setSyslogProto] = useState("udp");
  const [syslogFormat, setSyslogFormat] = useState("rfc5424");
  const [syslogMinLevel, setSyslogMinLevel] = useState("");
  const [syslogCategories, setSyslogCategories] = useState("");
  const [syslogCaCert, setSyslogCaCert] = useState("");
  const [syslogClientCert, setSyslogClientCert] = useState("");
  const [syslogClientKey, setSyslogClientKey] = useState("");

  useEffect(() => {
    const c = q.data?.config;
    if (!c) return;
    const proxy = (c.egress_proxy ?? {}) as EgressProxy;
    const syslog = (c.syslog_siem_target ?? {}) as SyslogTarget;
    setHttpsProxy(proxy.https_proxy ?? "");
    setNoProxy(proxy.no_proxy ?? "");
    setTlsVerify(c.tls_verify !== false);
    setCaBundle(typeof c.ca_bundle_pem === "string" ? c.ca_bundle_pem : "");
    setSyslogHost(syslog.host ?? "");
    setSyslogPort(typeof syslog.port === "number" && syslog.port > 0 ? syslog.port : 514);
    setSyslogProto(syslog.protocol || "udp");
    setSyslogFormat(syslog.format || "rfc5424");
    setSyslogMinLevel(syslog.min_level ?? "");
    setSyslogCategories(Array.isArray(syslog.categories) ? syslog.categories.join(", ") : "");
    setSyslogCaCert(typeof syslog.ca_cert === "string" ? syslog.ca_cert : "");
    setSyslogClientCert(typeof syslog.client_cert === "string" ? syslog.client_cert : "");
    setSyslogClientKey(typeof syslog.client_key === "string" ? syslog.client_key : "");
  }, [q.data]);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => systemConfigApi.patch(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      toast.success("Network settings saved");
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status === 409) {
        void qc.invalidateQueries({ queryKey: ["system-config"] });
        toast.error("Config changed elsewhere; reloaded latest — please retry.");
        return;
      }
      const msg = (error as { response?: { data?: { error?: string } } })?.response?.data?.error;
      toast.error(msg ? `Save failed: ${msg}` : "Failed to save network settings");
    },
  });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    // Send the redacted CA marker unchanged when untouched — the backend preserves the
    // stored secret rather than wiping it.
    save.mutate({
      egress_proxy: { https_proxy: httpsProxy.trim(), no_proxy: noProxy.trim() },
      tls_verify: tlsVerify,
      ca_bundle_pem: caBundle,
      // client_key follows the redacted-secret pattern: the masked marker is sent
      // back unchanged so the backend keeps the stored key.
      syslog_siem_target: syslogHost.trim()
        ? {
            host: syslogHost.trim(), port: syslogPort, protocol: syslogProto,
            format: syslogFormat, min_level: syslogMinLevel,
            categories: syslogCategories.split(",").map((s) => s.trim()).filter(Boolean),
            ca_cert: syslogCaCert, client_cert: syslogClientCert, client_key: syslogClientKey,
          }
        : { host: "", port: 0, protocol: "" },
    });
  };

  const caSet = caBundle === "***REDACTED***";

  return (
    <div className="space-y-6">
      <PageHeader
        title="Network & Proxy"
        description="Outbound connectivity for the platform — how Constellation reaches the internet and where it mirrors audit events."
      />

      <VerdictBanner
        status={httpsProxy ? "info" : "ok"}
        title={httpsProxy ? "Egress routed through a proxy" : "Direct egress (no proxy configured)"}
        detail={tlsVerify ? "Upstream TLS verification is on." : "Upstream TLS verification is OFF — connections are not authenticated."}
      />

      <form className="space-y-6" onSubmit={submit}>
        <Card title="Egress proxy" description="Route the platform's outbound HTTP(S) — registry pulls, CVE feeds, webhooks — through a corporate proxy.">
          <div className="space-y-5">
            <Field label="HTTPS proxy URL" hint="e.g. http://proxy.internal:3128. Credentials in the URL are stored securely and masked here.">
              <TextInput value={httpsProxy} onChange={(e) => setHttpsProxy(e.target.value)} placeholder="http://proxy.internal:3128" />
            </Field>
            <Field label="No-proxy list" hint="Comma-separated hosts/CIDRs that bypass the proxy.">
              <TextInput value={noProxy} onChange={(e) => setNoProxy(e.target.value)} placeholder="10.0.0.0/8, .svc.cluster.local, localhost" />
            </Field>
          </div>
        </Card>

        <Card title="Upstream TLS" description="How the platform trusts the certificates of the servers it connects to.">
          <div className="space-y-5">
            <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-muted/30 px-4 py-3">
              <Switch
                checked={tlsVerify}
                onCheckedChange={setTlsVerify}
                label="Verify upstream TLS certificates"
                description="Keep on in production. Turning this off disables authentication of upstream servers."
              />
            </div>
            <Field label="Custom CA bundle (PEM)" hint={caSet ? "A CA bundle is set. Leave the masked value to keep it, or paste a new PEM to replace it." : "Optional. Add internal/private CA certificates to trust (concatenated PEM)."}>
              <Textarea
                value={caBundle}
                onChange={(e) => setCaBundle(e.target.value)}
                rows={caSet ? 2 : 6}
                className="font-mono text-xs"
                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              />
            </Field>
          </div>
        </Card>

        <Card title="Syslog / SIEM mirror" description="Mirror every audit + notification event to a syslog collector (Splunk, QRadar, Sentinel forwarder, rsyslog).">
          <div className="grid gap-5 sm:grid-cols-3">
            <Field label="Host" className="sm:col-span-2" hint="Collector hostname or IP. Leave blank to disable.">
              <TextInput value={syslogHost} onChange={(e) => setSyslogHost(e.target.value)} placeholder="siem.internal" />
            </Field>
            <Field label="Port">
              <TextInput type="number" min={1} max={65535} value={syslogPort}
                onChange={(e) => setSyslogPort(Number.parseInt(e.target.value, 10) || 514)} />
            </Field>
            <Field label="Protocol">
              <Select value={syslogProto} onChange={(e) => setSyslogProto(e.target.value)}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
                <option value="tls">TLS</option>
              </Select>
            </Field>
          </div>
          <Collapse label="Advanced — format, filtering & TLS certificates">
            <div className="space-y-5 pt-2">
              <div className="grid gap-5 sm:grid-cols-3">
                <Field label="Format" hint="Wire format sent to the collector.">
                  <Select value={syslogFormat} onChange={(e) => setSyslogFormat(e.target.value)}>
                    <option value="rfc5424">RFC5424 (syslog)</option>
                    <option value="json">JSON</option>
                    <option value="cef">CEF (ArcSight)</option>
                  </Select>
                </Field>
                <Field label="Minimum severity" hint="Drop events below this level. Blank = ship all.">
                  <Select value={syslogMinLevel} onChange={(e) => setSyslogMinLevel(e.target.value)}>
                    <option value="">All</option>
                    <option value="info">Info</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </Select>
                </Field>
                <Field label="Categories" hint="Comma-separated event kinds (e.g. finding, runtime, compliance). Blank = all.">
                  <TextInput value={syslogCategories} onChange={(e) => setSyslogCategories(e.target.value)} placeholder="finding, runtime, compliance" />
                </Field>
              </div>
              <p className="text-xs text-muted-foreground">TLS certificates apply only when Protocol = TLS. Leave the CA blank to use the system trust store; add a client cert + key for mutual TLS.</p>
              <Field label="Server CA (PEM)" hint="Optional. The collector's CA to verify its certificate.">
                <Textarea value={syslogCaCert} onChange={(e) => setSyslogCaCert(e.target.value)} rows={4} className="font-mono text-xs"
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" />
              </Field>
              <div className="grid gap-5 sm:grid-cols-2">
                <Field label="Client certificate (PEM)" hint="Optional. For mutual TLS.">
                  <Textarea value={syslogClientCert} onChange={(e) => setSyslogClientCert(e.target.value)} rows={4} className="font-mono text-xs"
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----" />
                </Field>
                <Field label="Client key (PEM)" hint={syslogClientKey === "***REDACTED***" ? "A client key is set. Leave the masked value to keep it, or paste a new key." : "Optional. For mutual TLS. Stored securely and masked."}>
                  <Textarea value={syslogClientKey} onChange={(e) => setSyslogClientKey(e.target.value)} rows={syslogClientKey === "***REDACTED***" ? 1 : 4} className="font-mono text-xs"
                    placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----" />
                </Field>
              </div>
            </div>
          </Collapse>
        </Card>

        <Button type="submit" variant="primary" size="lg" disabled={save.isPending || q.isLoading}>
          {save.isPending ? "Saving…" : "Save network settings"}
        </Button>
      </form>
    </div>
  );
}
