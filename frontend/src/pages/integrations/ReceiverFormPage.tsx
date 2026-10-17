import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Check, Copy } from "lucide-react";
import { receivers as receiversApi, type Receiver } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { Field, TextInput, Textarea, Select } from "@/components/ui/form";
import { ErrorState, LoadingState } from "@/components/ui/states";

const RECEIVER_KINDS = ["slack", "pagerduty", "jira", "servicenow", "teams", "webhook", "email"];
const TEMPLATES = ["default", "compact", "verbose"];
const LIST_PATH = "/settings/integrations";
const recipientText = (config?: Record<string, unknown>) => typeof config?.to === "string" ? config.to : Array.isArray(config?.to) ? config.to.filter((value): value is string => typeof value === "string").join(", ") : "";
const splitValues = (text: string) => text.split(/[\n,]/).map((value) => value.trim()).filter(Boolean);
const sameValues = (a: string[], b: string[]) => JSON.stringify(a) === JSON.stringify(b);
function httpsEndpoint(value: string) {
  try { const url = new URL(value); return url.protocol === "https:" && Boolean(url.hostname); } catch { return false; }
}

export function ReceiverFormPage() {
  const { id } = useParams({ strict: false });
  return <div className="space-y-6" data-testid="receiver-form-page">
    <PageHeader title={id ? "Edit receiver" : "Add receiver"} description="Configure an organization alert destination. Changes apply together when you save."
      backLink={<Link to="/settings/integrations" className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Integrations</Link>} />
    <ReceiverLoader key={id ?? "new"} receiverId={id} />
  </div>;
}

function ReceiverLoader({ receiverId }: { receiverId?: string }) {
  const q = useQuery({ queryKey: ["receiver-editor", receiverId], queryFn: () => receiversApi.list(), enabled: Boolean(receiverId), gcTime: 0 });
  const matches = q.data?.receivers.filter((receiver) => receiver.id === receiverId) ?? [];
  const [loaded, setLoaded] = useState<Receiver | null>(null);
  const initial = loaded ?? (q.isSuccess && !q.isFetching && matches.length === 1 ? matches[0] : undefined);
  if (!loaded && initial) setLoaded(initial);
  if (receiverId && (q.isPending || q.isFetching) && !initial) return <LoadingState label="Loading receiver…" />;
  if (receiverId && !initial) return <ErrorState title={q.isError ? "This receiver could not be loaded. Retry before editing." : "This receiver was not found in the current organization."} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  const unavailable = Boolean(receiverId && (q.isError || !q.isSuccess || matches.length !== 1 || q.fetchStatus !== "idle"));
  return <>
    {unavailable && <p role="alert" className="text-sm text-status-error">The saved receiver is unavailable or refreshing. Your draft is preserved; saving is paused. <Button variant="outline" onClick={() => void q.refetch()} disabled={q.isFetching}>Retry</Button></p>}
    <ReceiverEditor initial={initial} current={matches.length === 1 ? matches[0] : undefined} unavailable={unavailable} />
  </>;
}

function ReceiverEditor({ initial, current, unavailable }: { initial?: Receiver; current?: Receiver; unavailable: boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState(initial?.name ?? "");
  const [kind, setKind] = useState(initial?.kind ?? "slack");
  const [endpoint, setEndpoint] = useState(initial?.endpoint ?? "");
  const [recipients, setRecipients] = useState(() => recipientText(initial?.config));
  const [rate, setRate] = useState(String(initial?.rate_per_min ?? 60));
  const [template, setTemplate] = useState(initial?.template_id ?? "default");
  const [owner, setOwner] = useState(initial?.owner ?? "");
  const [environment, setEnvironment] = useState(initial?.environment ?? "production");
  const [events, setEvents] = useState(initial?.supported_events?.join("\n") ?? "");
  const [created, setCreated] = useState<{ id: string; secret_key: string } | null>(null);
  const isEmail = kind === "email";
  const to = splitValues(recipients);
  const rateValid = /^\d+$/.test(rate) && Number(rate) >= 1 && Number(rate) <= 2147483647;
  const endpointChanged = !initial || endpoint !== initial.endpoint;
  const endpointValid = Boolean(endpoint.trim()) && (!endpointChanged || httpsEndpoint(endpoint.trim()));
  const valid = Boolean(name.trim() && kind && environment.trim() && template.trim()) && rateValid && (isEmail ? to.length > 0 : endpointValid);
  const patchBody: Partial<Receiver> = {};
  if (initial) {
    if (name !== initial.name) patchBody.name = name.trim();
    if (Number(rate) !== initial.rate_per_min) patchBody.rate_per_min = Number(rate);
    if (template !== initial.template_id) patchBody.template_id = template;
    if (owner !== (initial.owner ?? "")) patchBody.owner = owner.trim();
    if (environment !== initial.environment) patchBody.environment = environment.trim();
    if (events !== (initial.supported_events?.join("\n") ?? "") && !sameValues(splitValues(events), initial.supported_events ?? [])) patchBody.supported_events = splitValues(events);
    if (isEmail) {
      if (!sameValues(to, splitValues(recipientText(initial.config)))) {
        const config = current?.config ?? initial.config;
        patchBody.config = { ...config, to: typeof config?.to === "string" ? to.join(", ") : to };
        patchBody.endpoint = `mailto:${to.join(",")}`;
      }
    } else if (endpointChanged) patchBody.endpoint = endpoint.trim();
  }
  const changed = !initial || Object.keys(patchBody).length > 0;
  const canSubmit = valid && changed && !unavailable;
  const save = useMutation({
    mutationFn: async () => {
      if (!canSubmit) throw new Error("Receiver cannot be saved");
      if (initial) {
        const query = qc.getQueryState<Awaited<ReturnType<typeof receiversApi.list>>>(["receiver-editor", initial.id]);
        const latest = query?.data?.receivers.filter((receiver) => receiver.id === initial.id) ?? [];
        if (query?.status !== "success" || query.fetchStatus !== "idle" || latest.length !== 1) throw new Error("Receiver cannot be saved");
        const body = { ...patchBody };
        if (body.config) {
          const config = latest[0].config;
          body.config = { ...config, to: typeof config?.to === "string" ? to.join(", ") : to };
        }
        await receiversApi.patch(initial.id, body);
        return null;
      }
      const body: Partial<Receiver> = { name: name.trim(), kind, rate_per_min: Number(rate), template_id: template,
        owner: owner.trim(), environment: environment.trim(), supported_events: splitValues(events) };
      if (isEmail) body.config = { to };
      else body.endpoint = endpoint.trim();
      return receiversApi.create(body);
    },
    onSuccess: (response) => {
      void qc.invalidateQueries({ queryKey: ["receivers"] });
      void qc.invalidateQueries({ queryKey: ["receiver-editor"] });
      if (initial) void navigate({ href: LIST_PATH });
      else if (response) setCreated(response);
    },
  });
  if (created) return <Card title="Receiver created" description={created.secret_key ? "Save the HMAC secret below. Constellation reveals it only once." : "The receiver was created, but its secret was not returned."}>
    {created.secret_key ? <div className="space-y-4">
      <div className="break-all rounded-md border border-status-warning/50 bg-status-warning/10 p-4 font-mono text-sm" data-testid="receiver-secret-key">{created.secret_key}</div>
      <p className="text-sm text-muted-foreground">Use this value to verify the X-Constellation-Signature header on outbound deliveries.</p>
      <div className="flex gap-3"><CopyButton text={created.secret_key} /><Button variant="ghost" onClick={() => void navigate({ href: LIST_PATH })}>Done</Button></div>
    </div> : <div className="space-y-4"><p role="alert" className="text-sm text-status-error">The creation succeeded. Return to integrations to review the saved receiver.</p><Button variant="ghost" onClick={() => void navigate({ href: LIST_PATH })}>Done</Button></div>}
  </Card>;
  const kinds = RECEIVER_KINDS.includes(kind) ? RECEIVER_KINDS : [...RECEIVER_KINDS, kind];
  const templates = [...new Set([...TEMPLATES, ...(initial?.template_id ? [initial.template_id] : []), template])];
  return <Card title="Receiver details" description="Destinations are shared across the organization. Saving configuration does not confirm delivery.">
    <form className="space-y-6" data-testid="receiver-form" onSubmit={(event) => { event.preventDefault(); if (canSubmit && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Name" htmlFor="receiver-name" required><TextInput id="receiver-name" autoFocus required value={name} onChange={(event) => setName(event.target.value)} placeholder="platform-oncall" data-testid="create-receiver-name" /></Field>
          <Field label="Kind" htmlFor="receiver-kind" hint={initial ? "The destination type is fixed after creation." : "Choose the kind of destination receiving alerts."}><Select id="receiver-kind" value={kind} disabled={Boolean(initial)} onChange={(event) => { if (!initial) setKind(event.target.value); }} data-testid="create-receiver-kind">{kinds.map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field>
        </div>
        {isEmail ? <Field label="Recipients" htmlFor="receiver-recipients" required hint="Comma-separated email addresses. Configure the shared SMTP server in Integrations before delivering email."><Textarea id="receiver-recipients" value={recipients} onChange={(event) => setRecipients(event.target.value)} placeholder="alice@example.com, bob@example.com" data-testid="create-receiver-recipients" /></Field>
          : <Field label="Endpoint URL" htmlFor="receiver-endpoint" required hint="Use a public HTTPS webhook or API URL. The service verifies the destination on save." error={endpoint && !endpointValid ? "Enter a valid HTTPS destination." : undefined}><TextInput id="receiver-endpoint" type="url" value={endpoint} onChange={(event) => setEndpoint(event.target.value)} placeholder="https://hooks.example.com/…" data-testid="create-receiver-endpoint" /></Field>}
        <Collapse label="Advanced">
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Rate per minute" htmlFor="receiver-rate" hint="Maximum deliveries per minute before this destination is throttled." error={!rateValid ? "Enter a whole number from 1 to 2147483647." : undefined}><TextInput id="receiver-rate" type="number" min="1" max="2147483647" step="1" required value={rate} onChange={(event) => setRate(event.target.value)} /></Field>
            <Field label="Template" htmlFor="receiver-template" hint="Choose the message layout. Existing custom template identifiers are preserved."><Select id="receiver-template" value={template} onChange={(event) => setTemplate(event.target.value)}>{templates.map((value) => <option key={value} value={value}>{value}</option>)}</Select></Field>
            <Field label="Owner" htmlFor="receiver-owner"><TextInput id="receiver-owner" value={owner} onChange={(event) => setOwner(event.target.value)} /></Field>
            <Field label="Environment" htmlFor="receiver-environment" required><TextInput id="receiver-environment" required value={environment} onChange={(event) => setEnvironment(event.target.value)} /></Field>
            <Field label="Event filters" htmlFor="receiver-events" hint="One event type or prefix per line, such as finding.escalated. Blank subscribes to all events." className="sm:col-span-2"><Textarea id="receiver-events" value={events} onChange={(event) => setEvents(event.target.value)} /></Field>
          </div>
        </Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this receiver. Check its destination and settings, then try again. Your draft is preserved.</p>}
        <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={!canSubmit || save.isPending} data-testid="create-receiver-save">{save.isPending ? "Saving…" : initial ? "Save receiver" : "Create receiver"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: LIST_PATH })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const [pending, setPending] = useState(false);
  const [failed, setFailed] = useState(false);
  const copy = async () => {
    setPending(true); setFailed(false); setCopied(false);
    try { await navigator.clipboard.writeText(text); setCopied(true); }
    catch { setFailed(true); }
    finally { setPending(false); }
  };
  return <div className="space-y-2">
    <Button type="button" variant="outline" disabled={pending} onClick={() => void copy()}>{copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}{copied ? "Copied" : pending ? "Copying…" : "Copy"}</Button>
    {failed && <p role="alert" className="text-sm text-status-error">Could not copy the secret. Select and copy the value manually.</p>}
  </div>;
}
