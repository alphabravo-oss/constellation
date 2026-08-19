// Wave N3: Integrations page rewritten from a mock-driven view into an actual
// operator console for the notifier delivery pipeline.
//
// Top tab "Receivers"   -> table of configured destinations + detail drawer with
//                          delivery history, test-fire button, HMAC secret reveal
//                          (one-time), rotate-secret button, template picker,
//                          rate-limit + paused toggle.
// Top tab "Routes"      -> Alertmanager-style routing tree as YAML in a Monaco
//                          editor + tree-view side-by-side.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type ReactNode } from "react";
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

import { receivers as receiversApi, routing as routingApi, type Receiver, type ReceiverDelivery } from "@/api/client";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Drawer } from "@/components/ui/drawer";
import { Collapse } from "@/components/ui/collapse";

export function IntegrationsPage() {
  const [tab, setTab] = useTabParam("tab", "receivers");
  const items = [
    { value: "receivers", label: "Receivers", content: <ReceiversTab /> },
    { value: "routes", label: "Routes", content: <RoutesTab /> },
  ];
  return (
    <div className="space-y-4">
      <PageHeader
        title="Notifier Integrations"
        description="Send alerts out to Slack, PagerDuty, Jira, ServiceNow, and generic webhooks. Every delivery is HMAC-signed, retried with backoff, and rate-limited per destination."
      />

      <Tabs value={tab} onValueChange={setTab} items={items} />
    </div>
  );
}

// --------------------------------- Receivers tab --------------------------------------

function ReceiversTab() {
  const qc = useQueryClient();
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
  ];

  return (
    <div className="space-y-4">
      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Healthy" value={healthy} tone="accent" icon={<PlugZap className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Degraded" value={degraded} tone={degraded ? "high" : "neutral"} icon={<AlertTriangle className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Paused" value={paused} tone={paused ? "medium" : "neutral"} icon={<PauseCircle className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Total" value={recs.length} icon={<TimerReset className="h-3.5 w-3.5" aria-hidden />} />
      </section>

      <p className="text-xs text-muted-foreground">Select a receiver to inspect deliveries, send a test alert, or rotate its HMAC secret.</p>

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

      <ReceiverDrawer
        receiver={selected}
        deliveries={recDeliveries}
        onClose={() => setSelectedID(null)}
        onMutated={() => qc.invalidateQueries({ queryKey: ["receivers"] })}
      />
    </div>
  );
}

function PauseToggle({ receiver, onChange }: { receiver: Receiver; onChange: () => void }) {
  const m = useMutation({
    mutationFn: () => (receiver.paused ? receiversApi.unpause(receiver.id) : receiversApi.pause(receiver.id)),
    onSuccess: onChange,
  });
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        m.mutate();
      }}
      disabled={m.isPending}
      className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent"
    >
      {receiver.paused ? <PlayCircle className="h-3.5 w-3.5" aria-hidden /> : <PauseCircle className="h-3.5 w-3.5" aria-hidden />}
      {receiver.paused ? "Resume" : "Pause"}
    </button>
  );
}

// --------------------------------- Receiver drawer ------------------------------------

function ReceiverDrawer({
  receiver,
  deliveries,
  onClose,
  onMutated,
}: {
  receiver: Receiver | null;
  deliveries: ReceiverDelivery[];
  onClose: () => void;
  onMutated: () => void;
}) {
  const qc = useQueryClient();
  // Live per-receiver deliveries (richer than the org-wide preview).
  const deliveriesQ = useQuery({
    queryKey: ["receiver-deliveries", receiver?.id],
    queryFn: () => (receiver ? receiversApi.deliveries(receiver.id, 50) : Promise.resolve({ deliveries: [] })),
    enabled: !!receiver,
    refetchInterval: 5_000,
  });
  const live = deliveriesQ.data?.deliveries ?? deliveries;

  const testFire = useMutation({
    mutationFn: () => receiversApi.testFire(receiver!.id),
    onSuccess: () => {
      onMutated();
      void qc.invalidateQueries({ queryKey: ["receiver-deliveries", receiver?.id] });
    },
  });

  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const rotate = useMutation({
    mutationFn: () => receiversApi.rotateSecret(receiver!.id),
    onSuccess: (data) => setRevealedSecret(data.secret_key),
  });

  const patchTemplate = useMutation({
    mutationFn: (template_id: string) => receiversApi.patch(receiver!.id, { template_id }),
    onSuccess: onMutated,
  });

  const patchRate = useMutation({
    mutationFn: (rate_per_min: number) => receiversApi.patch(receiver!.id, { rate_per_min }),
    onSuccess: onMutated,
  });

  // Reset the revealed secret when switching receivers.
  useEffect(() => {
    setRevealedSecret(null);
  }, [receiver?.id]);

  return (
    <Drawer
      open={!!receiver}
      onOpenChange={(o) => { if (!o) onClose(); }}
      title={receiver?.name}
      description={receiver ? `${receiver.kind} · ${receiver.endpoint}` : undefined}
      width="lg"
    >
      {receiver && (
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
          <button
            type="button"
            onClick={() => testFire.mutate()}
            disabled={testFire.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2.5 py-1 text-xs hover:bg-accent"
            data-testid="test-fire"
          >
            <Send className="h-3.5 w-3.5" aria-hidden /> Send test alert
          </button>
          <button
            type="button"
            onClick={() => rotate.mutate()}
            disabled={rotate.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2.5 py-1 text-xs hover:bg-accent"
          >
            <RefreshCw className="h-3.5 w-3.5" aria-hidden /> Rotate HMAC secret
          </button>
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

      <section className="space-y-2">
        <h3 className="text-xs font-semibold uppercase text-muted-foreground">Configuration</h3>
        <div className="grid gap-2">
          <label className="flex items-center justify-between gap-2 text-xs">
            <span>Template</span>
            <select
              defaultValue={receiver.template_id}
              onChange={(e) => patchTemplate.mutate(e.target.value)}
              className="rounded-md border border-border bg-card px-2 py-1 text-xs"
            >
              <option value="default">default</option>
              <option value="compact">compact</option>
              <option value="verbose">verbose</option>
            </select>
          </label>
          <label className="flex items-center justify-between gap-2 text-xs">
            <span>Rate per minute</span>
            <input
              type="number"
              min={1}
              defaultValue={receiver.rate_per_min}
              onBlur={(e) => {
                const n = Number.parseInt(e.target.value, 10);
                if (!Number.isNaN(n) && n !== receiver.rate_per_min) patchRate.mutate(n);
              }}
              className="w-24 rounded-md border border-border bg-card px-2 py-1 text-xs"
            />
          </label>
        </div>
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
      )}
    </Drawer>
  );
}

function SecretReveal({ value, onDismiss }: { value: string; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-[color:var(--color-status-warning)]/50 bg-[color:var(--color-status-warning)]/10 p-3 text-xs">
      <div className="font-semibold">New HMAC secret (one-time reveal)</div>
      <div className="mt-1 break-all rounded-md bg-background/60 p-2 font-mono">{value}</div>
      <div className="mt-2 flex items-center gap-2">
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard.writeText(value);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-[11px]"
        >
          <Copy className="h-3 w-3" aria-hidden /> {copied ? "Copied" : "Copy"}
        </button>
        <button
          type="button"
          onClick={onDismiss}
          className="inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-[11px]"
        >
          Dismiss
        </button>
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
// with plain inputs + a drawer, and serializes the model back to YAML on save. A raw
// YAML escape hatch stays available under "Advanced" for power users and for configs
// too exotic for the visual editor.

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

  // Drawer state: index of the route being edited, or -1 for a new route, or null closed.
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
    <div className="space-y-4" data-testid="routes-tab">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-2xl text-xs text-muted-foreground">
          An alert is matched top-to-bottom against these routes. The first route whose label
          conditions all match decides where the alert is sent; matching stops there unless
          <span className="mx-1 font-mono">continue</span>is on. If nothing matches, the alert goes
          to the <span className="font-medium">default receiver</span>.
        </p>
        <button
          type="button"
          onClick={() => save.mutate(draft)}
          disabled={save.isPending}
          className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90 disabled:opacity-50"
          data-testid="routes-save"
        >
          <Save className="h-4 w-4" aria-hidden />
          {save.isPending ? "Saving…" : "Save routing"}
        </button>
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
          <section className="rounded-lg border border-border bg-card p-4">
            <label className="flex flex-col gap-1.5">
              <span className="text-sm font-medium">Default receiver</span>
              <span className="text-xs text-muted-foreground">Where alerts go when no route below matches.</span>
              <ReceiverSelect
                value={model.defaultReceiver}
                options={receiverOptions}
                allowEmpty
                onChange={(v) => applyModel({ ...model, defaultReceiver: v })}
                className="mt-1 max-w-sm"
                data-testid="routes-default-receiver"
              />
            </label>
          </section>

          {/* Route list */}
          <section className="space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold">Routes</h2>
              <button
                type="button"
                onClick={openNew}
                className="inline-flex items-center gap-1.5 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent"
                data-testid="routes-add"
              >
                <Plus className="h-3.5 w-3.5" aria-hidden /> Add route
              </button>
            </div>

            {model.routes.length === 0 ? (
              <div className="rounded-lg border border-dashed border-border bg-card px-4 py-8 text-center text-xs text-muted-foreground">
                No routes yet. Every alert goes to the default receiver. Click "Add route" to send
                specific alerts elsewhere.
              </div>
            ) : (
              <ol className="space-y-2" data-testid="routes-list">
                {model.routes.map((r, i) => (
                  <li
                    key={i}
                    className="flex items-start justify-between gap-3 rounded-lg border border-border bg-card p-3"
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
                      <button
                        type="button"
                        onClick={() => openEdit(i)}
                        className="rounded-md border border-border p-1.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                        aria-label="Edit route"
                        data-testid={`routes-edit-${i}`}
                      >
                        <Pencil className="h-3.5 w-3.5" aria-hidden />
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDeleteRoute(i)}
                        className="rounded-md border border-border p-1.5 text-muted-foreground hover:bg-accent hover:text-[color:var(--color-status-error)]"
                        aria-label="Delete route"
                      >
                        <Trash2 className="h-3.5 w-3.5" aria-hidden />
                      </button>
                    </div>
                  </li>
                ))}
              </ol>
            )}
          </section>
        </>
      ) : (
        <div className="rounded-md border border-[color:var(--color-status-warning)]/40 bg-[color:var(--color-status-warning)]/10 px-3 py-2 text-xs text-[color:var(--color-status-warning)]">
          This routing config is too advanced for the visual editor (nested route trees or
          non-standard shape). Edit the YAML directly below — your config is preserved untouched.
        </div>
      )}

      {/* Advanced: raw YAML escape hatch. Editing this updates the same draft. */}
      <section className="rounded-lg border border-border bg-card p-3">
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
      </section>

      {model && (
        <RouteDrawer
          key={editIndex ?? "closed"}
          open={editIndex !== null}
          initial={editIndex !== null && editIndex >= 0 ? model.routes[editIndex] : undefined}
          receiverOptions={receiverOptions}
          onClose={() => setEditIndex(null)}
          onSave={handleSaveRoute}
        />
      )}
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
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={`rounded-md border border-border bg-background px-2 py-1.5 text-sm ${className ?? ""}`}
      data-testid={testid}
    >
      {allowEmpty && <option value="">— none —</option>}
      {opts.map((o) => (
        <option key={o} value={o}>{o}</option>
      ))}
    </select>
  );
}

// Drawer form for adding/editing one route: match conditions, target receiver, continue.
function RouteDrawer({
  open,
  initial,
  receiverOptions,
  onClose,
  onSave,
}: {
  open: boolean;
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
    <Drawer
      open={open}
      onOpenChange={(o) => { if (!o) onClose(); }}
      title={initial ? "Edit route" : "Add route"}
      description="Send alerts matching these label conditions to a specific receiver."
    >
      <div className="space-y-5" data-testid="route-drawer">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Match conditions</span>
            <button
              type="button"
              onClick={addPair}
              className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent"
            >
              <Plus className="h-3 w-3" aria-hidden /> Add condition
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            All conditions must match (e.g. <span className="font-mono">severity = critical</span>). Leave
            empty to match every alert.
          </p>
          <div className="space-y-2">
            {pairs.map((p, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  value={p.k}
                  onChange={(e) => setPair(i, { k: e.target.value })}
                  placeholder="label"
                  className="w-1/2 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm"
                />
                <span className="text-muted-foreground">=</span>
                <input
                  value={p.v}
                  onChange={(e) => setPair(i, { v: e.target.value })}
                  placeholder="value"
                  className="w-1/2 rounded-md border border-border bg-background px-2 py-1.5 font-mono text-sm"
                />
                <button
                  type="button"
                  onClick={() => removePair(i)}
                  className="rounded-md border border-border p-1.5 text-muted-foreground hover:bg-accent"
                  aria-label="Remove condition"
                >
                  <X className="h-3.5 w-3.5" aria-hidden />
                </button>
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

        <label className="flex flex-col gap-1.5">
          <span className="text-sm font-medium">Target receiver</span>
          <ReceiverSelect value={receiver} options={receiverOptions} onChange={setReceiver} />
        </label>

        <label className="flex items-start gap-2">
          <input
            type="checkbox"
            checked={cont}
            onChange={(e) => setCont(e.target.checked)}
            className="mt-0.5"
          />
          <span className="text-sm">
            Continue matching
            <span className="block text-xs text-muted-foreground">
              Keep evaluating routes below this one even after this matches (send to multiple receivers).
            </span>
          </span>
        </label>

        <button
          type="button"
          onClick={submit}
          className="w-full rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90"
          data-testid="route-drawer-save"
        >
          {initial ? "Update route" : "Add route"}
        </button>
      </div>
    </Drawer>
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
