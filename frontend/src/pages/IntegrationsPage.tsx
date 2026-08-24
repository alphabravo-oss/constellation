// Wave N3: Integrations page rewritten from a mock-driven view into an actual
// operator console for the notifier delivery pipeline.
//
// Top tab "Receivers"   -> table of configured destinations + inline detail (delivery
//                          history, test-fire button, HMAC secret reveal, rotate-secret,
//                          template picker, rate-limit) + paused toggle. Add/edit each
//                          open a dedicated form page (ReceiverFormPage), not a drawer.
// Top tab "Routes"      -> Alertmanager-style routing tree, edited inline as a form-based
//                          route builder with a raw-YAML escape hatch (Monaco).
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import Editor from "@monaco-editor/react";
// @ts-expect-error - js-yaml ships no bundled type declarations in this project.
import yaml from "js-yaml";
import {
  AlertTriangle,
  ArrowRight,
  Copy,
  GitBranch,
  Pencil,
  Plus,
  PauseCircle,
  PlayCircle,
  PlugZap,
  RefreshCw,
  Route as RouteIcon,
  Save,
  Send,
  TimerReset,
  Trash2,
  X,
} from "lucide-react";

import {
  integrationDeliveries,
  receivers as receiversApi,
  routing as routingApi,
  systemConfigApi,
  type IntegrationDeliveryOverview,
  type Receiver,
  type ReceiverDelivery,
} from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select, Switch } from "@/components/ui/form";

export function IntegrationsPage() {
  const [tab, setTab] = useTabParam("tab", "receivers");
  const items = [
    { value: "receivers", label: "Receivers", content: <ReceiversTab /> },
    { value: "routes", label: "Routes", content: <RoutesTab /> },
    { value: "operations", label: "Operations", content: <OperationsTab /> },
  ];
  return (
    <div className="space-y-6">
      <PageHeader
        title="Notifier Integrations"
        description="Send alerts out to Slack, PagerDuty, Jira, ServiceNow, and generic webhooks. Every delivery is HMAC-signed, retried with backoff, and rate-limited per destination."
      />

      <Tabs value={tab} onValueChange={setTab} items={items} />
    </div>
  );
}

// ----------------------------- Delivery operations ------------------------------------

function OperationsTab() {
  const q = useQuery({
    queryKey: ["integration-delivery-overview"],
    queryFn: integrationDeliveries.overview,
  });
  const instances = useMemo(() => q.data?.integration_instances ?? [], [q.data?.integration_instances]);
  const [previewID, setPreviewID] = useState("");
  useEffect(() => {
    if (!previewID && instances.length > 0) {
      setPreviewID(instances[0].id);
    }
  }, [instances, previewID]);
  const preview = useMutation({
    mutationFn: (id: string) => integrationDeliveries.testPreview(id),
  });

  if (q.isPending) {
    return <p className="text-sm text-muted-foreground">Loading integration delivery operations...</p>;
  }
  const overview = q.data;
  const selectedID = previewID || instances[0]?.id || "";

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Integrations" value={overview?.summary.integration_instances_total ?? 0} />
        <StatCard label="Healthy" value={overview?.summary.healthy_receivers ?? 0} tone="accent" />
        <StatCard label="Degraded" value={overview?.summary.degraded_receivers ?? 0} tone={(overview?.summary.degraded_receivers ?? 0) > 0 ? "medium" : "neutral"} />
        <StatCard label="DLQ" value={overview?.summary.dead_letters_open ?? 0} tone={(overview?.summary.dead_letters_open ?? 0) > 0 ? "high" : "neutral"} />
      </section>

      <section className="grid gap-3 lg:grid-cols-3" data-testid="integration-connectors">
        {instances.length === 0 && <p className="text-xs text-muted-foreground">No integration receivers configured.</p>}
        {instances.map((instance) => {
          const health = receiverHealth(overview, instance.id);
          return (
            <article key={instance.id} className="rounded-lg border border-border bg-card p-4 text-xs">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="text-sm font-semibold">{instance.name}</h3>
                  <p className="mt-1 text-muted-foreground">{instance.type} · {instance.environment}</p>
                </div>
                <Status value={health?.status || instance.status} />
              </div>
              <dl className="mt-3 grid grid-cols-2 gap-2">
                <Info label="Owner" value={instance.owner || "-"} />
                <Info label="Events" value={instance.supported_events.join(", ") || "(all)"} />
                <Info label="p95" value={health?.p95_latency_ms ? `${health.p95_latency_ms}ms` : "-"} />
                <Info label="Success" value={health ? `${health.success_rate_24h}%` : "-"} />
              </dl>
              <p className="mt-3 truncate text-muted-foreground" title={instance.endpoint}>{instance.endpoint}</p>
              <button
                type="button"
                onClick={() => {
                  setPreviewID(instance.id);
                  preview.mutate(instance.id);
                }}
                data-testid={`integration-preview-${instance.id}`}
                className="mt-3 inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 hover:bg-accent"
              >
                <Send className="h-3.5 w-3.5" aria-hidden />
                Preview routing
              </button>
            </article>
          );
        })}
      </section>

      <section className="rounded-lg border border-border bg-card p-4" data-testid="routing-preview">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold">Read-only routing preview</h3>
            <p className="mt-1 text-xs text-muted-foreground">Preview handlers do not call receivers, persist deliveries, enqueue retries, or rotate secrets.</p>
          </div>
          <Button
            variant="outline"
            size="sm"
            disabled={!selectedID || preview.isPending}
            onClick={() => selectedID && preview.mutate(selectedID)}
          >
            <Send className="h-3.5 w-3.5" aria-hidden />
            Preview routing
          </Button>
        </div>
        {preview.data ? (
          <div className="mt-3 rounded-md bg-muted p-3 text-xs">
            <div className="font-medium">{preview.data.integration_instance.name}</div>
            <p className="mt-1 text-muted-foreground">{preview.data.message}</p>
            <div className="mt-2 flex flex-wrap gap-1">
              <Badge>sends: {preview.data.sends_notification ? "yes" : "no"}</Badge>
              <Badge>persists: {preview.data.persists_delivery ? "yes" : "no"}</Badge>
              <Badge>{preview.data.action.label}</Badge>
            </div>
          </div>
        ) : (
          <p className="mt-3 text-xs text-muted-foreground">Choose Preview routing on a receiver card.</p>
        )}
      </section>

      <section className="grid gap-4 xl:grid-cols-2">
        <OperationsList title="Routing rules" testID="routing-rules">
          {(overview?.routing_rules ?? []).map((rule) => (
            <article key={rule.id} className="rounded-md bg-muted p-3 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{rule.name}</span>
                <Status value={rule.enabled ? "active" : "disabled"} />
              </div>
              <div className="mt-1 text-muted-foreground">
                {rule.receiver_ids.join(", ") || "no receivers"} · {rule.throttle} · {rule.dedupe_window}
              </div>
            </article>
          ))}
        </OperationsList>

        <OperationsList title="Delivery history" testID="delivery-history">
          {(overview?.delivery_history ?? []).slice(0, 8).map((delivery) => (
            <article key={delivery.id} className="rounded-md bg-muted p-3 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono">{delivery.event_type}</span>
                <Status value={delivery.status} />
              </div>
              <div className="mt-1 text-muted-foreground">
                {receiverName(overview, delivery.receiver_id)} · {delivery.attempts} attempt{delivery.attempts === 1 ? "" : "s"}
                {delivery.error ? ` · ${delivery.error}` : ""}
              </div>
            </article>
          ))}
        </OperationsList>

        <OperationsList title="Retry queue" testID="retry-queue">
          {(overview?.retry_stats ?? []).map((retry) => (
            <article key={retry.receiver_id} className="rounded-md bg-muted p-3 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span>
                  <span className="font-medium">{receiverName(overview, retry.receiver_id)}</span>
                  <span className="ml-2 font-mono text-[10px] text-muted-foreground">{receiverRoutingKey(overview, retry.receiver_id)}</span>
                </span>
                <Badge>{retry.queued_retries} queued</Badge>
              </div>
              <div className="mt-1 text-muted-foreground">
                {retry.retry_rate_24h} retry rate · {retry.dead_letters_open} DLQ · {retry.backoff_policy}
              </div>
            </article>
          ))}
        </OperationsList>

        <OperationsList title="Guardrails" testID="integration-guardrails">
          {(overview?.guardrails ?? []).map((guardrail) => (
            <article key={guardrail.id} className="rounded-md bg-muted p-3 text-xs">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{guardrail.name}</span>
                <Status value={guardrail.enforced ? "enforced" : "monitor"} />
              </div>
              <p className="mt-1 text-muted-foreground">{guardrail.description}</p>
            </article>
          ))}
        </OperationsList>
      </section>
    </div>
  );
}

function OperationsList({ title, testID, children }: { title: string; testID: string; children: ReactNode }) {
  return (
    <section className="space-y-2" data-testid={testID}>
      <h3 className="text-sm font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function receiverName(overview: IntegrationDeliveryOverview | undefined, receiverID: string) {
  return overview?.integration_instances.find((instance) => instance.id === receiverID)?.name ?? receiverID;
}

function receiverRoutingKey(overview: IntegrationDeliveryOverview | undefined, receiverID: string) {
  return overview?.delivery_history.find((delivery) => delivery.receiver_id === receiverID)?.routing_rule_id || receiverID;
}

function receiverHealth(overview: IntegrationDeliveryOverview | undefined, receiverID: string) {
  return overview?.receiver_health.find((health) => health.receiver_id === receiverID);
}

// --------------------------------- Receivers tab --------------------------------------

function ReceiversTab() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["receivers"],
    queryFn: () => receiversApi.list(),
    refetchInterval: 10_000,
  });
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const selected = useMemo(
    () => (q.data?.receivers ?? []).find((r) => r.id === selectedID) ?? null,
    [q.data?.receivers, selectedID],
  );

  const recDeliveries = useMemo(() => {
    if (!selectedID) return [];
    return (q.data?.delivery_history ?? []).filter((d) => d.receiver_id === selectedID);
  }, [q.data?.delivery_history, selectedID]);

  const recs = q.data?.receivers ?? [];
  const healthy = recs.filter((r) => r.status === "healthy" && !r.paused).length;
  const degraded = recs.filter((r) => r.status === "degraded").length;
  const paused = recs.filter((r) => r.paused).length;

  const columns: Column<Receiver>[] = [
    {
      id: "name",
      header: "Name",
      cell: (r) => (
        <>
          <div className="font-medium">{r.name}</div>
          <div className="text-xs text-muted-foreground">{r.environment}</div>
        </>
      ),
    },
    { id: "kind", header: "Kind", cell: (r) => <span className="font-mono text-xs">{r.kind}</span> },
    {
      id: "endpoint",
      header: "Endpoint",
      cell: (r) => <span className="block max-w-[260px] truncate font-mono text-xs" title={r.endpoint}>{r.endpoint}</span>,
    },
    {
      id: "status",
      header: "Status",
      cell: (r) => (
        <>
          <Status value={r.paused ? "paused" : r.status} />
          {r.status_message && (
            <div className="mt-1 text-[10px] text-muted-foreground" title={r.status_message}>
              {r.status_message.slice(0, 48)}
            </div>
          )}
        </>
      ),
    },
    { id: "rate", header: "Rate", cell: (r) => <Badge>{r.rate_per_min}/min</Badge> },
    { id: "template", header: "Template", cell: (r) => <Badge>{r.template_id}</Badge> },
    {
      id: "paused",
      header: "Paused",
      cell: (r) => (
        <PauseToggle
          receiver={r}
          onChange={() => qc.invalidateQueries({ queryKey: ["receivers"] })}
        />
      ),
    },
    {
      id: "edit",
      header: "",
      cell: (r) => (
        <Button
          variant="outline"
          size="icon"
          aria-label="Edit receiver"
          data-testid={`receiver-edit-${r.id}`}
          onClick={(e) => {
            e.stopPropagation();
            navigate(`/settings/integrations/receivers/${r.id}`);
          }}
        >
          <Pencil className="h-3.5 w-3.5" aria-hidden />
        </Button>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Healthy" value={healthy} tone="accent" icon={<PlugZap className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Degraded" value={degraded} tone={degraded ? "high" : "neutral"} icon={<AlertTriangle className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Paused" value={paused} tone={paused ? "medium" : "neutral"} icon={<PauseCircle className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Total" value={recs.length} icon={<TimerReset className="h-3.5 w-3.5" aria-hidden />} />
      </section>

      <SmtpSettingsCard />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-muted-foreground">Select a receiver to inspect deliveries, send a test alert, or rotate its HMAC secret.</p>
        <Button variant="outline" size="sm" onClick={() => navigate("/settings/integrations/receivers/new")} data-testid="receiver-add">
          <Plus className="h-3.5 w-3.5" aria-hidden /> Add receiver
        </Button>
      </div>

      <div data-testid="receivers-table">
        <DataTable
          rows={recs}
          columns={columns}
          rowKey={(r) => r.id}
          onRowClick={(r) => setSelectedID(r.id)}
          selected={new Set(selectedID ? [selectedID] : [])}
          showDensityToggle={false}
          emptyState={
            <div className="px-3 py-8 text-center text-xs text-muted-foreground">
              No receivers configured. Create one via POST /api/v1/integrations/receivers.
            </div>
          }
        />
      </div>

      {selected && (
        <ReceiverDetail
          receiver={selected}
          deliveries={recDeliveries}
          onClose={() => setSelectedID(null)}
          onEdit={() => navigate(`/settings/integrations/receivers/${selected.id}`)}
          onMutated={() => qc.invalidateQueries({ queryKey: ["receivers"] })}
        />
      )}
    </div>
  );
}

// --------------------------------- SMTP email server ----------------------------------
//
// Global outbound email server (system config key `smtp`). Every "email" receiver
// delivers through this one shared SMTP relay. The stored password is returned by the
// API as the literal "***REDACTED***" sentinel — sending it back unchanged preserves
// the stored secret, so we seed the field with it and never surface the real value.

const SMTP_REDACTED = "***REDACTED***";

function SmtpSettingsCard() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });

  const [host, setHost] = useState("");
  const [port, setPort] = useState(587);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [from, setFrom] = useState("");
  const [starttls, setStarttls] = useState(true);

  // Seed the form from the stored smtp config whenever it (re)loads.
  useEffect(() => {
    if (!q.data) return;
    const s = (q.data.config.smtp ?? {}) as Record<string, unknown>;
    setHost(typeof s.host === "string" ? s.host : "");
    setPort(typeof s.port === "number" ? s.port : 587);
    setUsername(typeof s.username === "string" ? s.username : "");
    setPassword(typeof s.password === "string" ? s.password : "");
    setFrom(typeof s.from === "string" ? s.from : "");
    setStarttls(s.starttls !== false);
  }, [q.data]);

  const passwordIsRedacted = password === SMTP_REDACTED;

  const save = useMutation({
    mutationFn: () =>
      systemConfigApi.patch({
        smtp: {
          host: host.trim(),
          port,
          username: username.trim(),
          // Sending the sentinel back unchanged preserves the stored password.
          password,
          from: from.trim(),
          starttls,
        },
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      toast.success("SMTP settings saved");
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status === 409) {
        void qc.invalidateQueries({ queryKey: ["system-config"] });
        toast.error("Config changed elsewhere; reloaded latest — please retry.");
        return;
      }
      toast.error("Failed to save SMTP settings");
    },
  });

  return (
    <Card
      title="Email server (SMTP)"
      description="The shared outbound mail relay every email receiver delivers through. Configure it once here."
      action={
        <Button
          variant="primary"
          size="sm"
          onClick={() => save.mutate()}
          disabled={q.isLoading || save.isPending}
          data-testid="smtp-save"
        >
          <Save className="h-3.5 w-3.5" aria-hidden />
          {save.isPending ? "Saving…" : "Save SMTP settings"}
        </Button>
      }
    >
      <div className="space-y-5" data-testid="smtp-settings">
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Host" hint="SMTP server hostname.">
            <TextInput
              value={host}
              onChange={(e) => setHost(e.target.value)}
              placeholder="smtp.example.com"
              data-testid="smtp-host"
            />
          </Field>
          <Field label="Port" hint="Usually 587 (STARTTLS) or 465 (implicit TLS).">
            <TextInput
              type="number"
              min={1}
              value={port}
              onChange={(e) => {
                const n = Number.parseInt(e.target.value, 10);
                if (!Number.isNaN(n)) setPort(n);
              }}
              className="w-32"
              data-testid="smtp-port"
            />
          </Field>
          <Field label="Username" hint="SMTP auth username (often the From address).">
            <TextInput
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="notifications@example.com"
              data-testid="smtp-username"
            />
          </Field>
          <Field
            label="Password"
            hint={passwordIsRedacted ? "A password is already set — leave to keep the current password." : "SMTP auth password."}
          >
            <TextInput
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              data-testid="smtp-password"
            />
          </Field>
        </div>
        <Field label="From address" hint="The address alerts are sent from.">
          <TextInput
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            placeholder="Constellation Alerts <alerts@example.com>"
            data-testid="smtp-from"
          />
        </Field>
        <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
          <Switch
            checked={starttls}
            onCheckedChange={setStarttls}
            label="Require STARTTLS"
            description="Upgrade the connection to TLS before authenticating. Recommended for port 587."
          />
        </div>
      </div>
    </Card>
  );
}

// --------------------------------- Pause toggle ---------------------------------------

function PauseToggle({ receiver, onChange }: { receiver: Receiver; onChange: () => void }) {
  const m = useMutation({
    mutationFn: () => (receiver.paused ? receiversApi.unpause(receiver.id) : receiversApi.pause(receiver.id)),
    onSuccess: onChange,
  });
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={(e) => {
        e.stopPropagation();
        m.mutate();
      }}
      disabled={m.isPending}
    >
      {receiver.paused ? <PlayCircle className="h-3.5 w-3.5" aria-hidden /> : <PauseCircle className="h-3.5 w-3.5" aria-hidden />}
      {receiver.paused ? "Resume" : "Pause"}
    </Button>
  );
}

// --------------------------------- Receiver detail ------------------------------------
//
// Inline read-only-ish detail peek for a selected receiver (deliveries, test-fire,
// rotate HMAC secret, live template/rate patch). Add/edit of the receiver's core fields
// lives on the dedicated ReceiverFormPage — the pencil / Edit button navigates there.

function ReceiverDetail({
  receiver,
  deliveries,
  onClose,
  onEdit,
  onMutated,
}: {
  receiver: Receiver;
  deliveries: ReceiverDelivery[];
  onClose: () => void;
  onEdit: () => void;
  onMutated: () => void;
}) {
  const qc = useQueryClient();
  // Live per-receiver deliveries (richer than the org-wide preview).
  const deliveriesQ = useQuery({
    queryKey: ["receiver-deliveries", receiver.id],
    queryFn: () => receiversApi.deliveries(receiver.id, 50),
    refetchInterval: 5_000,
  });
  const live = deliveriesQ.data?.deliveries ?? deliveries;

  const testFire = useMutation({
    mutationFn: () => receiversApi.testFire(receiver.id),
    onSuccess: () => {
      onMutated();
      void qc.invalidateQueries({ queryKey: ["receiver-deliveries", receiver.id] });
    },
  });

  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const rotate = useMutation({
    mutationFn: () => receiversApi.rotateSecret(receiver.id),
    onSuccess: (data) => setRevealedSecret(data.secret_key),
  });

  const patchTemplate = useMutation({
    mutationFn: (template_id: string) => receiversApi.patch(receiver.id, { template_id }),
    onSuccess: onMutated,
  });

  const patchRate = useMutation({
    mutationFn: (rate_per_min: number) => receiversApi.patch(receiver.id, { rate_per_min }),
    onSuccess: onMutated,
  });

  // Reset the revealed secret when switching receivers.
  useEffect(() => {
    setRevealedSecret(null);
  }, [receiver.id]);

  return (
    <Card
      title={receiver.name}
      description={`${receiver.kind} · ${receiver.endpoint}`}
      action={
        <>
          <Button variant="outline" size="sm" onClick={onEdit} data-testid="receiver-detail-edit">
            <Pencil className="h-3.5 w-3.5" aria-hidden /> Edit
          </Button>
          <Button variant="ghost" size="icon" aria-label="Close detail" onClick={onClose}>
            <X className="h-3.5 w-3.5" aria-hidden />
          </Button>
        </>
      }
    >
      <div className="space-y-4" data-testid="receiver-drawer">
        <section className="grid grid-cols-2 gap-2 text-xs">
          <Info label="Status" value={receiver.paused ? "paused" : receiver.status} />
          <Info label="Environment" value={receiver.environment} />
          <Info label="Rate/min" value={`${receiver.rate_per_min}`} />
          <Info label="Template" value={receiver.template_id} />
          <Info label="Last verified" value={receiver.last_verified_at ?? "never"} />
          <Info label="Events" value={receiver.supported_events.length ? receiver.supported_events.join(", ") : "(all)"} />
        </section>

        <section className="space-y-2 rounded-md bg-muted/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => testFire.mutate()}
              disabled={testFire.isPending}
              data-testid="test-fire"
            >
              <Send className="h-3.5 w-3.5" aria-hidden /> Send test alert
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => rotate.mutate()}
              disabled={rotate.isPending}
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Rotate HMAC secret
            </Button>
          </div>
          {testFire.data && (
            <div className="text-xs text-muted-foreground">
              Test fire queued: <span className="font-mono">{testFire.data.delivery_id}</span>
              <br /> Idempotency: <span className="font-mono">{testFire.data.idempotency_key}</span>
            </div>
          )}
          {testFire.isError && (
            <div className="text-xs text-[color:var(--color-status-error)]">Test fire failed.</div>
          )}
          {revealedSecret && <SecretReveal value={revealedSecret} onDismiss={() => setRevealedSecret(null)} />}
        </section>

        <section className="space-y-5">
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">Configuration</h3>
          <Field label="Template" hint="Which message layout this destination renders alerts with.">
            <Select
              defaultValue={receiver.template_id}
              onChange={(e) => patchTemplate.mutate(e.target.value)}
              className="max-w-xs"
            >
              <option value="default">default</option>
              <option value="compact">compact</option>
              <option value="verbose">verbose</option>
            </Select>
          </Field>
          <Field label="Rate per minute" hint="Maximum deliveries per minute before this destination is throttled.">
            <TextInput
              type="number"
              min={1}
              defaultValue={receiver.rate_per_min}
              onBlur={(e) => {
                const n = Number.parseInt(e.target.value, 10);
                if (!Number.isNaN(n) && n !== receiver.rate_per_min) patchRate.mutate(n);
              }}
              className="w-32"
            />
          </Field>
        </section>

        <section className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">Delivery history</h3>
          <div className="max-h-72 overflow-y-auto rounded-md border border-border" data-testid="receiver-deliveries">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-muted text-[10px] uppercase text-muted-foreground">
                <tr>
                  <th className="px-2 py-1 text-left">Event</th>
                  <th className="px-2 py-1 text-left">State</th>
                  <th className="px-2 py-1 text-left">Att</th>
                  <th className="px-2 py-1 text-left">Latency</th>
                  <th className="px-2 py-1 text-left">Idempotency</th>
                </tr>
              </thead>
              <tbody>
                {live.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-2 py-6 text-center text-muted-foreground">No deliveries yet.</td>
                  </tr>
                )}
                {live.map((d) => (
                  <tr key={d.id} className="border-t border-border">
                    <td className="px-2 py-1.5">
                      <div className="font-mono">{d.event_type}</div>
                      <div className="text-[10px] text-muted-foreground">{d.severity}</div>
                    </td>
                    <td className="px-2 py-1.5">
                      <Status value={d.final_state || d.status} />
                      {d.error && <div className="mt-1 max-w-[180px] truncate text-[10px] text-muted-foreground" title={d.error}>{d.error}</div>}
                    </td>
                    <td className="px-2 py-1.5">{d.attempts}</td>
                    <td className="px-2 py-1.5">{d.latency_ms ? `${d.latency_ms}ms` : "-"}</td>
                    <td className="px-2 py-1.5 font-mono text-[10px]">{d.idempotency_key?.slice(0, 8) ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </Card>
  );
}

function SecretReveal({ value, onDismiss }: { value: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-[color:var(--color-status-warning)]/50 bg-[color:var(--color-status-warning)]/10 p-3 text-xs">
      <div className="font-semibold">New HMAC secret (one-time reveal)</div>
      <div className="mt-1 break-all rounded-md bg-background/60 p-2 font-mono">{value}</div>
      <div className="mt-2 flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            void navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          <Copy className="h-3 w-3" aria-hidden /> {copied ? "Copied" : "Copy"}
        </Button>
        <Button variant="outline" size="sm" onClick={onDismiss}>
          Dismiss
        </Button>
      </div>
      <p className="mt-2 text-[10px] text-muted-foreground">
        Save this somewhere safe — Constellation cannot show it again. Receivers must use this exact value to verify the
        X-Constellation-Signature header on outbound deliveries.
      </p>
    </div>
  );
}

// --------------------------------- Routes tab -----------------------------------------
//
// Alert routing is stored server-side as an Alertmanager-style routing.yaml, but hand-
// editing raw YAML is a terrible experience. This tab is a form-based route builder:
// it parses the YAML into a model, lets operators point label conditions at receivers
// with plain inputs + an inline route form, and serializes the model back to YAML on
// save. A raw YAML escape hatch stays available under "Advanced" for power users and for
// configs too exotic for the visual editor.

// A single child route: a set of label match conditions -> a target receiver.
interface RouteRule {
  receiver: string;
  match: Record<string, string>;
  continue: boolean;
  // Alertmanager v2 matchers (string list) — displayed read-only + preserved verbatim.
  matchers?: string[];
  // Any other keys on this route (group_by, group_wait, mute_time_intervals, …) that the
  // visual editor doesn't manage — kept verbatim so we never drop the operator's config.
  raw: Record<string, unknown>;
}

interface RoutingModel {
  defaultReceiver: string;
  routes: RouteRule[];
  // Preserved verbatim so serialize round-trips untouched config.
  rootRaw: Record<string, unknown>; // route.* keys other than receiver/routes
  docRaw: Record<string, unknown>; // top-level keys other than route (inhibit_rules, receivers, …)
}

type ParseResult = { ok: true; model: RoutingModel } | { ok: false };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Parse a routing.yaml string into the visual model, or signal that it's too advanced.
function parseRouting(text: string): ParseResult {
  if (!text.trim()) {
    return { ok: true, model: { defaultReceiver: "", routes: [], rootRaw: {}, docRaw: {} } };
  }
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch {
    return { ok: false };
  }
  if (doc == null) {
    return { ok: true, model: { defaultReceiver: "", routes: [], rootRaw: {}, docRaw: {} } };
  }
  if (!isObject(doc)) return { ok: false };
  const route = doc.route;
  if (!isObject(route)) return { ok: false };
  const rawRoutes = route.routes;
  if (rawRoutes !== undefined && !Array.isArray(rawRoutes)) return { ok: false };

  const routes: RouteRule[] = [];
  for (const child of (rawRoutes as unknown[]) ?? []) {
    if (!isObject(child)) return { ok: false };
    // Nested route sub-trees are beyond the flat visual editor — fall back to raw YAML.
    if (child.routes !== undefined) return { ok: false };
    const { receiver, match, matchers, ...restWithContinue } = child;
    const cont = restWithContinue.continue;
    delete (restWithContinue as Record<string, unknown>).continue;
    if (receiver !== undefined && typeof receiver !== "string") return { ok: false };
    const matchObj: Record<string, string> = {};
    if (match !== undefined) {
      if (!isObject(match)) return { ok: false };
      for (const [k, v] of Object.entries(match)) matchObj[k] = String(v);
    }
    let matchersArr: string[] | undefined;
    if (matchers !== undefined) {
      if (!Array.isArray(matchers)) return { ok: false };
      matchersArr = matchers.map((m) => String(m));
    }
    routes.push({
      receiver: typeof receiver === "string" ? receiver : "",
      match: matchObj,
      continue: cont === true,
      matchers: matchersArr,
      raw: restWithContinue as Record<string, unknown>,
    });
  }

  const { receiver: defReceiver, routes: _r, ...rootRaw } = route;
  const { route: _route, ...docRaw } = doc;
  return {
    ok: true,
    model: {
      defaultReceiver: typeof defReceiver === "string" ? defReceiver : "",
      routes,
      rootRaw,
      docRaw,
    },
  };
}

// Serialize the visual model back to Alertmanager-style routing.yaml, preserving any
// verbatim keys we captured on parse.
function serializeRouting(model: RoutingModel): string {
  const routeOut: Record<string, unknown> = {};
  if (model.defaultReceiver) routeOut.receiver = model.defaultReceiver;
  Object.assign(routeOut, model.rootRaw);
  const arr = model.routes.map((r) => {
    const o: Record<string, unknown> = {};
    if (r.receiver) o.receiver = r.receiver;
    if (r.matchers && r.matchers.length) o.matchers = r.matchers;
    if (Object.keys(r.match).length) o.match = r.match;
    if (r.continue) o.continue = true;
    Object.assign(o, r.raw);
    return o;
  });
  if (arr.length) routeOut.routes = arr;
  const docOut: Record<string, unknown> = { route: routeOut, ...model.docRaw };
  return yaml.dump(docOut, { noRefs: true, lineWidth: 120, sortKeys: false });
}

function RoutesTab() {
  const q = useQuery({ queryKey: ["routing-yaml"], queryFn: () => routingApi.get() });
  const receiversQ = useQuery({ queryKey: ["receivers"], queryFn: () => receiversApi.list() });
  const receiverOptions = useMemo(
    () => (receiversQ.data?.receivers ?? []).map((r) => r.name),
    [receiversQ.data?.receivers],
  );

  // `draft` (the raw YAML) is the single source of truth. The form derives its model by
  // parsing it, and form edits re-serialize the model back into `draft`. Editing the raw
  // YAML escape hatch also writes `draft`, so both stay in sync and Save always saves it.
  const [draft, setDraft] = useState<string>("");
  useEffect(() => {
    if (q.data?.yaml !== undefined) setDraft(q.data.yaml);
  }, [q.data?.yaml]);

  const parsed = useMemo(() => parseRouting(draft), [draft]);
  const save = useMutation({ mutationFn: (y: string) => routingApi.put(y) });

  // Inline editor state: index of the route being edited, or -1 for a new route, or null closed.
  const [editIndex, setEditIndex] = useState<number | null>(null);

  const model = parsed.ok ? parsed.model : null;

  const applyModel = (next: RoutingModel) => setDraft(serializeRouting(next));

  const openNew = () => setEditIndex(-1);
  const openEdit = (i: number) => setEditIndex(i);

  const handleSaveRoute = (rule: RouteRule) => {
    if (!model) return;
    const routes = [...model.routes];
    if (editIndex === -1) routes.push(rule);
    else if (editIndex !== null) routes[editIndex] = rule;
    applyModel({ ...model, routes });
    setEditIndex(null);
  };

  const handleDeleteRoute = (i: number) => {
    if (!model) return;
    applyModel({ ...model, routes: model.routes.filter((_, idx) => idx !== i) });
  };

  return (
    <div className="space-y-6" data-testid="routes-tab">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-2xl text-xs text-muted-foreground">
          An alert is matched top-to-bottom against these routes. The first route whose label
          conditions all match decides where the alert is sent; matching stops there unless
          <span className="mx-1 font-mono">continue</span>is on. If nothing matches, the alert goes
          to the <span className="font-medium">default receiver</span>.
        </p>
        <Button
          variant="primary"
          onClick={() => save.mutate(draft)}
          disabled={save.isPending}
          data-testid="routes-save"
        >
          <Save className="h-4 w-4" aria-hidden />
          {save.isPending ? "Saving…" : "Save routing"}
        </Button>
      </div>

      {save.data && (
        <div className="rounded-md border border-[color:var(--color-status-success)]/40 bg-[color:var(--color-status-success)]/10 px-3 py-2 text-xs text-[color:var(--color-status-success)]">
          Routing saved.
        </div>
      )}
      {save.isError && (
        <div className="rounded-md border border-[color:var(--color-status-error)]/40 bg-[color:var(--color-status-error)]/10 px-3 py-2 text-xs text-[color:var(--color-status-error)]">
          Save failed. Check the raw YAML under Advanced.
        </div>
      )}

      {model ? (
        <>
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <StatCard label="Routes" value={model.routes.length} tone="accent" icon={<RouteIcon className="h-3.5 w-3.5" aria-hidden />} />
            <StatCard label="Fallthrough" value={model.routes.filter((r) => r.continue).length} icon={<GitBranch className="h-3.5 w-3.5" aria-hidden />} hint="routes with continue on" />
            <StatCard label="Receivers" value={receiverOptions.length} icon={<PlugZap className="h-3.5 w-3.5" aria-hidden />} />
          </section>

          {/* Default receiver */}
          <Card
            title="Default receiver"
            description="Where alerts go when no route below matches."
          >
            <ReceiverSelect
              value={model.defaultReceiver}
              options={receiverOptions}
              allowEmpty
              onChange={(v) => applyModel({ ...model, defaultReceiver: v })}
              className="max-w-sm"
              data-testid="routes-default-receiver"
            />
          </Card>

          {/* Route list */}
          <Card
            title="Routes"
            description="Evaluated top-to-bottom — the first route whose conditions all match decides where an alert is delivered."
            action={
              <Button variant="outline" size="sm" onClick={openNew} data-testid="routes-add">
                <Plus className="h-3.5 w-3.5" aria-hidden /> Add route
              </Button>
            }
          >
            {model.routes.length === 0 ? (
              <div className="rounded-lg border border-dashed border-border bg-muted/20 px-4 py-8 text-center text-xs text-muted-foreground">
                No routes yet. Every alert goes to the default receiver. Click "Add route" to send
                specific alerts elsewhere.
              </div>
            ) : (
              <ol className="space-y-2" data-testid="routes-list">
                {model.routes.map((r, i) => (
                  <li
                    key={i}
                    className="flex items-start justify-between gap-3 rounded-lg border border-border bg-muted/20 p-3"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-1.5">
                        {Object.keys(r.match).length === 0 && (!r.matchers || r.matchers.length === 0) ? (
                          <span className="text-xs italic text-muted-foreground">matches everything</span>
                        ) : (
                          <>
                            {Object.entries(r.match).map(([k, v]) => (
                              <span key={k} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                                {k}={v}
                              </span>
                            ))}
                            {(r.matchers ?? []).map((m, mi) => (
                              <span key={`m${mi}`} className="rounded-md bg-muted px-1.5 py-0.5 font-mono text-[11px]" title="Alertmanager matcher">
                                {m}
                              </span>
                            ))}
                          </>
                        )}
                        <ArrowRight className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                        <span className="inline-flex items-center gap-1 rounded-md bg-[color:var(--color-primary)]/10 px-1.5 py-0.5 text-[11px] font-medium text-[color:var(--color-primary)]">
                          <Send className="h-3 w-3" aria-hidden /> {r.receiver || "(unset)"}
                        </span>
                        {r.continue && (
                          <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground" title="Keep matching later routes">
                            continue
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1">
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => openEdit(i)}
                        aria-label="Edit route"
                        data-testid={`routes-edit-${i}`}
                      >
                        <Pencil className="h-3.5 w-3.5" aria-hidden />
                      </Button>
                      <Button
                        variant="outline"
                        size="icon"
                        onClick={() => handleDeleteRoute(i)}
                        aria-label="Delete route"
                        className="text-muted-foreground hover:text-[color:var(--color-status-error)]"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden />
                      </Button>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        </>
      ) : (
        <div className="rounded-md border border-[color:var(--color-status-warning)]/40 bg-[color:var(--color-status-warning)]/10 px-3 py-2 text-xs text-[color:var(--color-status-warning)]">
          This routing config is too advanced for the visual editor (nested route trees or
          non-standard shape). Edit the YAML directly below — your config is preserved untouched.
        </div>
      )}

      {/* Inline route editor — an inline Card form (not a drawer) for the selected route. */}
      {model && editIndex !== null && (
        <RouteForm
          key={editIndex}
          initial={editIndex >= 0 ? model.routes[editIndex] : undefined}
          receiverOptions={receiverOptions}
          onClose={() => setEditIndex(null)}
          onSave={handleSaveRoute}
        />
      )}

      {/* Advanced: raw YAML escape hatch. Editing this updates the same draft. */}
      <Card>
        <Collapse
          label="Advanced: edit raw YAML"
          defaultOpen={!model}
        >
          <p className="mb-2 text-xs text-muted-foreground">
            The routing config exactly as stored (Alertmanager-style). Changes here feed the visual
            editor above and are saved by "Save routing".
          </p>
          <div className="overflow-hidden rounded-md border border-border">
            <Editor
              height="420px"
              language="yaml"
              theme="vs-dark"
              value={draft}
              onChange={(v) => setDraft(v ?? "")}
            />
          </div>
        </Collapse>
      </Card>
    </div>
  );
}

// A <select> of receiver names that always includes the current value (even if the
// receiver was deleted or lives outside the fetched list) so nothing silently changes.
function ReceiverSelect({
  value,
  options,
  onChange,
  allowEmpty,
  className,
  "data-testid": testid,
}: {
  value: string;
  options: string[];
  onChange: (v: string) => void;
  allowEmpty?: boolean;
  className?: string;
  "data-testid"?: string;
}) {
  const opts = value && !options.includes(value) ? [value, ...options] : options;
  return (
    <Select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={className}
      data-testid={testid}
    >
      {allowEmpty && <option value="">— none —</option>}
      {opts.map((o) => (
        <option key={o} value={o}>{o}</option>
      ))}
    </Select>
  );
}

// Inline form for adding/editing one route: match conditions, target receiver, continue.
// Renders as a Card (not a drawer); Save writes into the routing model, Cancel closes it.
function RouteForm({
  initial,
  receiverOptions,
  onClose,
  onSave,
}: {
  initial?: RouteRule;
  receiverOptions: string[];
  onClose: () => void;
  onSave: (rule: RouteRule) => void;
}) {
  type Pair = { k: string; v: string };
  const initialPairs: Pair[] = initial && Object.keys(initial.match).length
    ? Object.entries(initial.match).map(([k, v]) => ({ k, v }))
    : [{ k: "", v: "" }];
  const [pairs, setPairs] = useState<Pair[]>(initialPairs);
  const [receiver, setReceiver] = useState<string>(initial?.receiver ?? receiverOptions[0] ?? "");
  const [cont, setCont] = useState<boolean>(initial?.continue ?? false);

  const setPair = (i: number, patch: Partial<Pair>) =>
    setPairs((ps) => ps.map((p, idx) => (idx === i ? { ...p, ...patch } : p)));
  const addPair = () => setPairs((ps) => [...ps, { k: "", v: "" }]);
  const removePair = (i: number) => setPairs((ps) => (ps.length === 1 ? [{ k: "", v: "" }] : ps.filter((_, idx) => idx !== i)));

  const submit = () => {
    const match: Record<string, string> = {};
    for (const p of pairs) {
      const k = p.k.trim();
      if (k) match[k] = p.v;
    }
    onSave({
      receiver,
      match,
      continue: cont,
      // Preserve matchers + any other verbatim keys from the route being edited.
      matchers: initial?.matchers,
      raw: initial?.raw ?? {},
    });
  };

  return (
    <Card
      title={initial ? "Edit route" : "Add route"}
      description="Send alerts matching these label conditions to a specific receiver."
    >
      <div className="space-y-5" data-testid="route-drawer">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Match conditions</span>
            <Button variant="outline" size="sm" onClick={addPair}>
              <Plus className="h-3 w-3" aria-hidden /> Add condition
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            All conditions must match (e.g. <span className="font-mono">severity = critical</span>). Leave
            empty to match every alert.
          </p>
          <div className="space-y-2">
            {pairs.map((p, i) => (
              <div key={i} className="flex items-center gap-2">
                <TextInput
                  value={p.k}
                  onChange={(e) => setPair(i, { k: e.target.value })}
                  placeholder="label"
                  className="w-1/2 font-mono"
                />
                <span className="text-muted-foreground">=</span>
                <TextInput
                  value={p.v}
                  onChange={(e) => setPair(i, { v: e.target.value })}
                  placeholder="value"
                  className="w-1/2 font-mono"
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => removePair(i)}
                  aria-label="Remove condition"
                >
                  <X className="h-3.5 w-3.5" aria-hidden />
                </Button>
              </div>
            ))}
          </div>
          {initial?.matchers && initial.matchers.length > 0 && (
            <p className="text-[11px] text-muted-foreground">
              This route also has Alertmanager matchers preserved verbatim:{" "}
              <span className="font-mono">{initial.matchers.join(", ")}</span>
            </p>
          )}
        </div>

        <Field label="Target receiver">
          <ReceiverSelect value={receiver} options={receiverOptions} onChange={setReceiver} />
        </Field>

        <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
          <Switch
            checked={cont}
            onCheckedChange={setCont}
            label="Continue matching"
            description="Keep evaluating routes below this one even after this matches (send to multiple receivers)."
          />
        </div>

        <div className="flex items-center gap-3">
          <Button
            variant="primary"
            size="lg"
            onClick={submit}
            data-testid="route-drawer-save"
          >
            {initial ? "Update route" : "Add route"}
          </Button>
          <Button type="button" variant="ghost" size="lg" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </Card>
  );
}

// --------------------------------- shared bits ----------------------------------------

function Info({ label, value }: { label: string; value: string | ReactNode }) {
  return (
    <div className="rounded-md bg-muted/60 p-2">
      <div className="text-[10px] uppercase text-muted-foreground">{label}</div>
      <div className="mt-1 break-all font-medium">{value}</div>
    </div>
  );
}

function Badge({ children }: { children: ReactNode }) {
  return <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{children}</span>;
}

function Status({ value }: { value: string }) {
  const cls =
    value === "healthy" || value === "enabled" || value === "delivered" || value === "active"
      ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
      : value === "degraded" || value === "retrying" || value === "rate_limited" || value === "paused"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : value === "failed" || value === "dead_letter"
      ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
      : "bg-muted text-muted-foreground";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`}>{value}</span>;
}
