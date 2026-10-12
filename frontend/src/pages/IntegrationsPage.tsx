import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState, type ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Copy, Pencil, Plus, PauseCircle, PlayCircle, RefreshCw, Send, Trash2, X } from "lucide-react";
import { integrationDeliveries, receivers as receiversApi, routing as routingApi, type IntegrationDeliveryOverview, type Receiver, type ReceiverDelivery } from "@/api/client";
import { isRevisionConflict, parseRouting, serializeRouting, validRoutingSnapshot, type RoutingRule } from "@/lib/integration-routing";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ErrorState, EmptyState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";

export function IntegrationsPage() {
  const [rawTab, setTab] = useTabParam("tab", "receivers");
  const tab = ["routes", "operations"].includes(rawTab) ? rawTab : "receivers";
  return <div className="space-y-6"><PageHeader title="Notifier Integrations" description="Manage organization-wide alert destinations and notification routing. Delivery history shows observed outcomes; saved settings apply across clusters." />
    <Tabs value={tab} onValueChange={setTab} items={[{ value: "receivers", label: "Receivers", content: <ReceiversTab /> }, { value: "routes", label: "Routes", content: <RoutesTab /> }, { value: "operations", label: "Operations", content: <OperationsTab /> }]} />
  </div>;
}

function OperationsTab() {
  const q = useQuery({
    queryKey: ["integration-delivery-overview"],
    queryFn: integrationDeliveries.overview,
  });
  const instances = useMemo(() => q.data?.integration_instances ?? [], [q.data?.integration_instances]);
  const [previewID, setPreviewID] = useState("");
  const preview = useMutation({
    mutationFn: (id: string) => integrationDeliveries.testPreview(id),
  });

  if (q.isPending) {
    return <LoadingState label="Loading delivery operations…" />;
  }
  if (!q.data) return <ErrorState title="Could not load integration delivery operations." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  const overview = q.data;
  const selectedID = previewID || instances[0]?.id || "";

  return (
    <div className="space-y-6">
      <VerdictBanner status={q.isError ? "degraded" : "info"} title={q.isError ? "Delivery operations could not be refreshed" : "Observed organization delivery activity"} detail="These results describe loaded delivery evidence. Routing previews do not send a notification." />
      <StatGrid>
        <StatCard label="Integrations" value={overview?.summary.integration_instances_total ?? 0} />
        <StatCard label="Healthy" value={overview?.summary.healthy_receivers ?? 0} tone="accent" />
        <StatCard label="Degraded" value={overview?.summary.degraded_receivers ?? 0} tone={(overview?.summary.degraded_receivers ?? 0) > 0 ? "medium" : "neutral"} />
        <StatCard label="DLQ" value={overview?.summary.dead_letters_open ?? 0} tone={(overview?.summary.dead_letters_open ?? 0) > 0 ? "high" : "neutral"} />
      </StatGrid>

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
                disabled={preview.isPending || q.isError}
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
            disabled={!selectedID || preview.isPending || q.isError}
            onClick={() => selectedID && preview.mutate(selectedID)}
          >
            <Send className="h-3.5 w-3.5" aria-hidden />
            Preview routing
          </Button>
        </div>
        {preview.data && preview.variables === selectedID ? (
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

      {preview.isError && <p role="alert" className="text-sm text-status-error">Could not preview routing. Try again.</p>}
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

function ReceiversTab() {
  const qc = useQueryClient(); const navigate = useNavigate();
  const q = useQuery({ queryKey: ["receivers"], queryFn: receiversApi.list, refetchInterval: 10_000 });
  const [selectedID, setSelectedID] = useState<string | null>(null);
  const [rotatingID, setRotatingID] = useState<string | null>(null);
  const selected = q.data?.receivers.find((r) => r.id === selectedID);
  const recs = q.data?.receivers ?? [];
  const disabled = q.isError || q.isPending || !!rotatingID;
  const columns: Column<Receiver>[] = [
    { id: "name", header: "Receiver", kind: "name", hideable: false, cell: (r) => <div><span className="app-table-primary">{r.name}</span><p className="app-table-secondary">{r.environment}</p></div>, exportValue: (r) => r.name, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "kind", header: "Kind", kind: "badge", cell: (r) => r.kind },
    { id: "endpoint", header: "Endpoint", kind: "id", size: 224, minSize: 160, maxSize: 320, cell: (r) => r.endpoint },
    { id: "status", header: "Observed status", kind: "text", size: 184, minSize: 144, cell: (r) => <div><Status value={r.paused ? "paused" : r.status} />{r.status_message && <p className="text-xs text-muted-foreground">{r.status_message}</p>}</div>, exportValue: (r) => r.paused ? "paused" : r.status },
    { id: "rate", header: "Rate / min", kind: "count", size: 112, cell: (r) => r.rate_per_min },
    { id: "template", header: "Template", kind: "text", size: 144, minSize: 112, maxSize: 192, cell: (r) => r.template_id },
    { id: "paused", header: "Delivery", kind: "actions", size: 112, minSize: 112, maxSize: 128, exportable: false, cell: (r) => <PauseToggle receiver={r} disabled={disabled} onChange={() => void qc.invalidateQueries({ queryKey: ["receivers"] })} /> },
    { id: "edit", header: "", kind: "actions", size: 48, minSize: 48, maxSize: 48, hideable: false, exportable: false, cell: (r) => <Button variant="ghost" size="icon" disabled={disabled} aria-label={`Edit receiver ${r.name}`} data-testid={`receiver-edit-${r.id}`} onClick={() => void navigate({ href: `/settings/integrations/receivers/${encodeURIComponent(r.id)}` })}><Pencil className="h-4 w-4" /></Button> },
  ];
  if (q.isPending) return <LoadingState label="Loading receivers…" />;
  if (!q.data) return <ErrorState title="Could not load organization receivers." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  return <div className="space-y-6">
    <VerdictBanner status={q.isError ? "degraded" : "info"} title={q.isError ? "Receivers could not be refreshed" : `${recs.length} organization receivers configured`} detail={q.isError ? "Showing the last loaded receivers. Refresh before changing delivery settings." : "Receivers and routing are shared across clusters. Health labels describe the last observed delivery state."} />
    <StatGrid><StatCard label="Observed healthy" value={recs.filter((r) => r.status === "healthy" && !r.paused).length} /><StatCard label="Observed degraded" value={recs.filter((r) => r.status === "degraded").length} /><StatCard label="Paused" value={recs.filter((r) => r.paused).length} /><StatCard label="Configured receivers" value={recs.length} /></StatGrid>
    <div className="flex flex-wrap justify-between gap-3"><p className="text-sm text-muted-foreground">Select a receiver to inspect deliveries and operational actions.</p><div className="flex gap-3"><Button disabled={!!rotatingID} onClick={() => void navigate({ href: "/settings/integrations/smtp/edit" })}>Edit email server</Button><Button variant="primary" disabled={disabled} onClick={() => void navigate({ href: "/settings/integrations/receivers/new" })} data-testid="receiver-add"><Plus className="h-4 w-4" /> Add receiver</Button></div></div>
    <div data-testid="receivers-table"><DataTable rows={recs} columns={columns} rowKey={(r) => r.id} onRowClick={rotatingID ? undefined : (r) => setSelectedID(r.id)} selected={new Set(selectedID ? [selectedID] : [])} preferencesKey="integration-receivers" exportFileName="integration-receivers.csv" rowTestId={(r) => `receiver-row-${r.id}`} emptyState={<EmptyState title="No receivers configured" hint="Add a receiver to choose an alert destination." />} /></div>
    {rotatingID && <p role="status" className="text-sm text-muted-foreground">Rotating this receiver's secret. Wait for its result before changing selection.</p>}
    {selected && <ReceiverDetail key={selected.id} receiver={selected} deliveries={q.data.delivery_history.filter((d) => d.receiver_id === selected.id)} disabled={q.isError} onRotationChange={(pending) => setRotatingID(pending ? selected.id : null)} onClose={() => setSelectedID(null)} onEdit={() => void navigate({ href: `/settings/integrations/receivers/${encodeURIComponent(selected.id)}` })} onMutated={() => void qc.invalidateQueries({ queryKey: ["receivers"] })} />}
  </div>;
}

function PauseToggle({ receiver, disabled, onChange }: { receiver: Receiver; disabled: boolean; onChange: () => void }) {
  const mutation = useMutation({ mutationFn: () => receiver.paused ? receiversApi.unpause(receiver.id) : receiversApi.pause(receiver.id), onSuccess: onChange });
  return <div><Button disabled={disabled || mutation.isPending} onClick={() => mutation.mutate()} size="sm" variant="outline">{receiver.paused ? <PlayCircle className="h-4 w-4" /> : <PauseCircle className="h-4 w-4" />}{receiver.paused ? "Resume" : "Pause"}</Button>{mutation.isError && <p role="alert" className="text-xs text-status-error">Could not change delivery state.</p>}</div>;
}

function ReceiverDetail({ receiver, deliveries, disabled, onRotationChange, onClose, onEdit, onMutated }: {
  receiver: Receiver; deliveries: ReceiverDelivery[]; disabled: boolean; onRotationChange: (pending: boolean) => void; onClose: () => void; onEdit: () => void; onMutated: () => void;
}) {
  const qc = useQueryClient();
  const deliveryQ = useQuery({ queryKey: ["receiver-deliveries", receiver.id], queryFn: () => receiversApi.deliveries(receiver.id, 50), refetchInterval: 5_000 });
  const [confirmRotation, setConfirmRotation] = useState(false);
  const [secret, setSecret] = useState<{ receiverID: string; value: string } | null>(null);
  const testFire = useMutation({ mutationFn: (target: string) => receiversApi.testFire(target), onSuccess: (_, target) => { onMutated(); void qc.invalidateQueries({ queryKey: ["receiver-deliveries", target] }); } });
  const rotate = useMutation({ mutationFn: (target: string) => receiversApi.rotateSecret(target), onSuccess: (result, target) => { setSecret({ receiverID: target, value: result.secret_key }); setConfirmRotation(false); onMutated(); }, onSettled: () => onRotationChange(false) });
  const busy = rotate.isPending || testFire.isPending;
  const columns: Column<ReceiverDelivery>[] = [
    { id: "event", header: "Event", kind: "name", cell: (d) => <div><span className="font-mono">{d.event_type}</span><p className="app-table-secondary">{d.severity}</p></div>, exportValue: (d) => d.event_type, sort: (a, b) => a.event_type.localeCompare(b.event_type) },
    { id: "state", header: "Delivery state", kind: "text", size: 200, minSize: 152, cell: (d) => <div><Status value={d.final_state || d.status} />{d.error && <p className="text-xs text-muted-foreground">{d.error}</p>}</div>, exportValue: (d) => d.final_state || d.status, sort: (a, b) => (a.final_state || a.status).localeCompare(b.final_state || b.status) },
    { id: "attempts", header: "Attempts", kind: "count", cell: (d) => d.attempts, sort: (a, b) => a.attempts - b.attempts },
    { id: "latency", header: "Latency · ms", kind: "count", cell: (d) => d.latency_ms, exportValue: (d) => d.latency_ms, sort: (a, b) => a.latency_ms - b.latency_ms },
    { id: "idempotency", header: "Idempotency key", kind: "id", cell: (d) => d.idempotency_key || "—", sort: (a, b) => (a.idempotency_key ?? "").localeCompare(b.idempotency_key ?? "") },
  ];
  return <Card title={receiver.name} description={`${receiver.kind} · ${receiver.endpoint}`} action={<><Button disabled={busy || disabled} onClick={onEdit} data-testid="receiver-detail-edit"><Pencil className="h-4 w-4" /> Edit</Button><Button variant="ghost" size="icon" disabled={busy} aria-label="Close detail" onClick={onClose}><X className="h-4 w-4" /></Button></>}>
    <div className="space-y-5" data-testid="receiver-drawer">
      <Collapse label="Receiver configuration"><dl className="grid gap-3 sm:grid-cols-2"><Info label="Observed status" value={receiver.paused ? "paused" : receiver.status} /><Info label="Environment" value={receiver.environment} /><Info label="Rate / min" value={receiver.rate_per_min} /><Info label="Template" value={receiver.template_id} /><Info label="Last verified" value={receiver.last_verified_at || "Not recorded"} /><Info label="Supported events" value={receiver.supported_events.join(", ") || "All events"} /></dl></Collapse>
      <div className="space-y-3 rounded-md border border-border p-4"><p className="text-sm text-muted-foreground">Send test alert queues a real notification to this receiver. Routing preview on the Operations tab does not send one.</p><div className="flex flex-wrap gap-3"><Button disabled={busy || disabled} onClick={() => testFire.mutate(receiver.id)} data-testid="test-fire"><Send className="h-4 w-4" /> Send test alert</Button><Button disabled={busy || disabled} onClick={() => { rotate.reset(); setConfirmRotation(true); }}><RefreshCw className="h-4 w-4" /> Rotate HMAC secret</Button></div>
        {testFire.data && testFire.variables === receiver.id && <p role="status" className="text-sm">Test alert queued: <span className="font-mono">{testFire.data.delivery_id}</span>. Delivery success is reported in the history. Idempotency: <span className="font-mono">{testFire.data.idempotency_key}</span>.</p>}
        {testFire.isError && testFire.variables === receiver.id && <p role="alert" className="text-sm text-status-error">Could not queue this test alert. Try again.</p>}
        {confirmRotation && <div role="alert" className="space-y-3"><p className="text-sm">Rotating the HMAC secret for {receiver.name} invalidates its old key immediately. Update the destination with the new key before the next delivery.</p><div className="flex gap-3"><Button disabled={busy || disabled} variant="destructive" onClick={() => { onRotationChange(true); rotate.mutate(receiver.id); }}>{rotate.isPending ? "Rotating…" : "Confirm rotation"}</Button><Button disabled={busy} variant="ghost" onClick={() => setConfirmRotation(false)}>Cancel</Button></div></div>}
        {rotate.isError && rotate.variables === receiver.id && <p role="alert" className="text-sm text-status-error">Could not rotate this receiver's secret. Try again.</p>}
        {secret?.receiverID === receiver.id && <SecretReveal value={secret.value} onDismiss={() => setSecret(null)} />}
      </div>
      <div className="space-y-3"><h3 className="text-sm font-semibold">Delivery history · latest 50</h3>{deliveryQ.isError && <p role="alert" className="text-sm text-status-error">Could not refresh delivery history. Showing the last loaded deliveries.</p>}<div className="max-h-96 overflow-auto" data-testid="receiver-deliveries"><DataTable defaultDensity="compact" rows={deliveryQ.data?.deliveries ?? deliveries} columns={columns} rowKey={(d) => d.id} preferencesKey="receiver-deliveries" exportFileName="receiver-deliveries.csv" emptyState={<EmptyState title="No loaded deliveries" hint="This receiver has no delivery evidence in the loaded history." />} /></div></div>
    </div>
  </Card>;
}

function SecretReveal({ value, onDismiss }: { value: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false); const [failed, setFailed] = useState(false);
  return <div className="space-y-3 rounded-md border border-border p-4"><h3 className="text-sm font-semibold">New HMAC secret (one-time reveal)</h3><p className="break-all rounded-md bg-muted p-3 font-mono text-sm">{value}</p><p className="text-xs text-muted-foreground">Save this key. The server cannot show it again.</p><div className="flex gap-3"><Button onClick={async () => { setCopied(false); setFailed(false); try { await navigator.clipboard.writeText(value); setCopied(true); } catch { setFailed(true); } }}><Copy className="h-4 w-4" />{copied ? "Copied" : "Copy"}</Button><Button onClick={onDismiss}>Dismiss</Button></div>{failed && <p role="alert" className="text-sm text-status-error">Could not copy the key. Select and copy it manually.</p>}</div>;
}

function RoutesTab() {
  const navigate = useNavigate(); const qc = useQueryClient();
  const q = useQuery({ queryKey: ["routing-yaml"], queryFn: routingApi.get });
  const recQ = useQuery({ queryKey: ["receivers"], queryFn: receiversApi.list });
  const [pendingDelete, setPendingDelete] = useState<{ index: number; revision: number } | null>(null);
  const parsed = useMemo(() => validRoutingSnapshot(q.data) ? parseRouting(q.data.yaml) : null, [q.data]);
  const model = parsed?.ok ? parsed.model : null;
  const rows = (model?.routes ?? []).map((rule, index) => ({ rule, index }));
  const canChange = q.isSuccess && !q.isFetching;
  const remove = useMutation({ mutationFn: (input: { yaml: string; revision: number }) => routingApi.put(input.yaml, input.revision), onSuccess: () => { setPendingDelete(null); void qc.invalidateQueries({ queryKey: ["routing-yaml"] }); void qc.invalidateQueries({ queryKey: ["integration-delivery-overview"] }); }, onError: (error) => { if (isRevisionConflict(error)) void qc.invalidateQueries({ queryKey: ["routing-yaml"] }); } });
  const columns: Column<{ rule: RoutingRule; index: number }>[] = [
    { id: "order", header: "Order", kind: "count", cell: (r) => r.index + 1 },
    { id: "receiver", header: "Receiver", kind: "name", hideable: false, cell: (r) => r.rule.receiver || `Default (${model?.defaultReceiver || "unset"})` },
    { id: "conditions", header: "Conditions", kind: "text", size: 264, minSize: 160, maxSize: 360, cell: (r) => [...Object.entries(r.rule.match).map(([key, value]) => `${key}=${value}`), ...(r.rule.matchers ?? [])].join(" · ") || "Matches every alert" },
    { id: "continue", header: "Continue matching", kind: "status", cell: (r) => r.rule.continue ? "Yes" : "No" },
    { id: "actions", header: "Actions", kind: "actions", size: 112, minSize: 112, maxSize: 112, hideable: false, exportable: false, cell: (r) => <div className="flex gap-2"><Button size="icon" variant="ghost" disabled={!canChange || remove.isPending} aria-label={`Edit route ${r.index + 1}`} onClick={() => void navigate({ href: `/settings/integrations/routes/${r.index}/edit?revision=${q.data!.revision}` })}><Pencil className="h-4 w-4" /></Button><Button size="icon" variant="ghost" disabled={!canChange || remove.isPending} aria-label={`Delete route ${r.index + 1}`} onClick={() => { remove.reset(); setPendingDelete({ index: r.index, revision: q.data!.revision }); }}><Trash2 className="h-4 w-4" /></Button></div> },
  ];
  if (q.isPending) return <LoadingState label="Loading saved routing…" />;
  if (!validRoutingSnapshot(q.data)) return <ErrorState title="Could not load saved notification routing." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  return <div className="space-y-6" data-testid="routes-tab"><VerdictBanner status={q.isError ? "degraded" : "info"} title={q.isError ? "Saved routing could not be refreshed" : `Organization routing revision ${q.data.revision}`} detail="Alerts follow routes in order. Saving a route immediately updates the organization-wide document; continue matching allows later routes to run." />
    <StatGrid><StatCard label="Saved child routes" value={model ? rows.length : "Advanced tree"} /><StatCard label="Continue matching" value={model ? rows.filter((r) => r.rule.continue).length : "—"} /><StatCard label="Loaded receivers" value={recQ.data ? recQ.data.receivers.length : "—"} /><StatCard label="Saved revision" value={q.data.revision} /></StatGrid>
    <div className="flex flex-wrap justify-end gap-3"><Button disabled={q.isFetching || remove.isPending} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" /> Refresh</Button><Button disabled={!canChange || remove.isPending} onClick={() => void navigate({ href: "/settings/integrations/routing/edit" })}>Edit complete routing</Button><Button variant="primary" disabled={!canChange || !model || remove.isPending} onClick={() => void navigate({ href: "/settings/integrations/routes/new" })} data-testid="routes-add"><Plus className="h-4 w-4" /> Add route</Button></div>
    <Card title="Default receiver" description="Used when no child route matches."><p className="font-mono text-sm">{model?.defaultReceiver || (model ? "No default receiver" : "Defined in complete YAML")}</p></Card>
    {model ? <DataTable rows={rows} columns={columns} rowKey={(r) => r.index} preferencesKey="notification-routes" exportFileName="notification-routes.csv" testId="routes-list" emptyState={<EmptyState title="No child routes" hint="Alerts use the default receiver. Add a route to choose destinations for matching alerts." />} /> : <p className="text-sm text-muted-foreground">{parsed && !parsed.ok ? parsed.reason : "Open the complete routing editor to inspect this configuration."}</p>}
    {recQ.isError && <p role="alert" className="text-sm text-status-error">Could not load receiver information. Saved routing is still shown.</p>}
    {pendingDelete && <div role="alert" className="space-y-3 rounded-md border border-border p-4"><p className="text-sm">Delete saved route {pendingDelete.index + 1}? This immediately changes organization-wide notification routing.</p>{pendingDelete.revision !== q.data.revision && <p className="text-sm text-status-error">Routing changed. Close this confirmation and select the route again.</p>}<div className="flex gap-3"><Button variant="destructive" disabled={!canChange || !model || pendingDelete.revision !== q.data.revision || remove.isPending} onClick={() => { if (model && pendingDelete.revision === q.data!.revision) remove.mutate({ yaml: serializeRouting({ ...model, routes: model.routes.filter((_, index) => index !== pendingDelete.index) }), revision: pendingDelete.revision }); }}>{remove.isPending ? "Deleting…" : "Delete route"}</Button><Button disabled={remove.isPending} onClick={() => setPendingDelete(null)}>Cancel</Button></div></div>}
    {remove.isError && <p role="alert" className="text-sm text-status-error">{isRevisionConflict(remove.error) ? "Routing changed elsewhere. Reload the saved list before deleting." : "Could not delete this route. Try again."}</p>}
    <Collapse label="Saved routing YAML"><pre className="max-h-96 overflow-auto rounded-md border border-border bg-card p-4 font-mono text-xs">{q.data.yaml || "No routing YAML saved."}</pre></Collapse>
  </div>;
}

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
