import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Plus, Save, X } from "lucide-react";
import { receivers, routing } from "@/api/client";
import { useRouteSearchParams } from "@/lib/route-search";
import { isRevisionConflict, parseRouting, routeIndex as parseIndex, routingRevision, serializeRouting, validRoutingSnapshot, type RoutingModel, type RoutingRule, type RoutingSnapshot } from "@/lib/integration-routing";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select, Switch, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
const backTo = "/settings/integrations?tab=routes";

export function RoutingRuleFormPage() {
  const { routeIndex } = useParams({ strict: false });
  const [search] = useRouteSearchParams();
  const index = routeIndex === undefined ? undefined : parseIndex(routeIndex);
  const revision = routingRevision(search.get("revision"));
  return <div className="space-y-6" data-testid="routing-rule-form-page"><PageHeader title={routeIndex === undefined ? "Add notification route" : "Edit notification route"} description="Route matching alerts to a receiver. Save updates the organization-wide routing document immediately."
    backLink={<Link to="." href={backTo} className="inline-flex items-center gap-2"><ArrowLeft className="h-4 w-4" /> Integrations</Link>} />
    {index === null || index !== undefined && revision === null ? <ErrorState title="Open this route from the saved routing list to edit the correct revision." /> : <RoutingRuleScope key={`${index ?? "new"}:${revision ?? "latest"}`} index={index} requiredRevision={revision} />}
  </div>;
}

function RoutingRuleScope({ index, requiredRevision }: { index?: number; requiredRevision: number | null }) {
  const q = useQuery({ queryKey: ["routing-yaml"], queryFn: routing.get });
  const [snapshot, setSnapshot] = useState<{ saved: RoutingSnapshot; model: RoutingModel } | null>(null);
  const parsed = useMemo(() => validRoutingSnapshot(q.data) ? parseRouting(q.data.yaml) : null, [q.data]);
  const validTarget = validRoutingSnapshot(q.data) && parsed?.ok && (index === undefined || requiredRevision === q.data.revision && !!parsed.model.routes[index]);
  useEffect(() => { if (!snapshot && q.isSuccess && !q.isFetching && validTarget && parsed?.ok) setSnapshot({ saved: q.data!, model: parsed.model }); }, [snapshot, q.isSuccess, q.isFetching, validTarget, parsed, q.data]);
  if (!snapshot) {
    if (q.isPending || q.isSuccess && q.isFetching || q.isSuccess && validTarget) return <LoadingState label="Loading saved routing…" />;
    return <ErrorState title={parsed && !parsed.ok ? parsed.reason : "This route or revision could not be loaded. Return to the saved routing list and reopen it."} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  }
  const conflict = q.data?.revision !== snapshot.saved.revision;
  const canSave = q.isSuccess && !q.isFetching && !conflict;
  return <>
    {q.isError && <ErrorState title="Could not refresh saved routing. your draft is preserved. refresh before saving." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
    {conflict && <p role="alert" className="text-sm text-status-error">Routing changed elsewhere. Your draft is preserved. Return to the saved list and reopen the latest revision before saving.</p>}
    <RoutingRuleEditor index={index} snapshot={snapshot.saved} model={snapshot.model} canSave={canSave} />
  </>;
}

function RoutingRuleEditor({ index, snapshot, model, canSave }: { index?: number; snapshot: RoutingSnapshot; model: RoutingModel; canSave: boolean }) {
  const initial = index === undefined ? undefined : model.routes[index];
  const [pairs, setPairs] = useState(() => Object.entries(initial?.match ?? {}).map(([key, value]) => ({ key, value })));
  const [receiver, setReceiver] = useState(initial?.receiver ?? "");
  const [continuing, setContinuing] = useState(initial?.continue ?? false);
  const navigate = useNavigate(); const qc = useQueryClient();
  const recQ = useQuery({ queryKey: ["receivers"], queryFn: receivers.list });
  const receiverOptions = [...new Set([receiver, ...(recQ.data?.receivers.map((r) => r.name) ?? [])].filter(Boolean))];
  const labelNames = pairs.map((pair) => pair.key.trim());
  const valid = labelNames.every(Boolean) && new Set(labelNames).size === labelNames.length;
  const save = useMutation({ mutationFn: () => {
    const rule: RoutingRule = { receiver, continue: continuing, match: Object.fromEntries(pairs.map((pair) => [pair.key.trim(), pair.value])), matchers: initial?.matchers, raw: initial?.raw ?? {} };
    const routes = [...model.routes]; if (index === undefined) routes.push(rule); else routes[index] = rule;
    return routing.put(serializeRouting({ ...model, routes }), snapshot.revision);
  }, onSuccess: () => { void qc.invalidateQueries({ queryKey: ["routing-yaml"] }); void qc.invalidateQueries({ queryKey: ["integration-delivery-overview"] }); void navigate({ href: backTo }); }, onError: (error) => { if (isRevisionConflict(error)) void qc.invalidateQueries({ queryKey: ["routing-yaml"] }); } });
  return <>
    <VerdictBanner status="info" title="Notification routing is shared across the organization" detail={`Saving replaces routing revision ${snapshot.revision} with this route change. Other rules, matchers and advanced settings are preserved.`} />
    <Card title="Route details" description="Conditions all match. a route with no conditions matches every alert."><form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (canSave && valid && recQ.isSuccess && !recQ.isFetching && !isRevisionConflict(save.error) && !save.isPending) save.mutate(); }}>
      {recQ.isError && <ErrorState title="Could not load receiver choices. your draft is preserved." action={<Button onClick={() => void recQ.refetch()}>Retry</Button>} />}
      <fieldset disabled={save.isPending} className="space-y-5"><div className="space-y-3"><div className="flex justify-between gap-3"><h2 className="text-sm font-medium">Match conditions</h2><Button type="button" onClick={() => setPairs([...pairs, { key: "", value: "" }])}><Plus className="h-4 w-4" /> Add condition</Button></div>
        {pairs.map((pair, i) => <div key={i} className="grid gap-3 sm:grid-cols-[1fr_1fr_auto]"><Field label={`Condition ${i + 1} label`} htmlFor={`route-label-${i}`}><TextInput id={`route-label-${i}`} value={pair.key} onChange={(e) => setPairs(pairs.map((p, j) => j === i ? { ...p, key: e.target.value } : p))} /></Field><Field label={`Condition ${i + 1} value`} htmlFor={`route-value-${i}`}><TextInput id={`route-value-${i}`} value={pair.value} onChange={(e) => setPairs(pairs.map((p, j) => j === i ? { ...p, value: e.target.value } : p))} /></Field><Button type="button" className="self-end" aria-label={`Remove condition ${i + 1}`} onClick={() => setPairs(pairs.filter((_, j) => j !== i))}><X className="h-4 w-4" /></Button></div>)}
        {!valid && <p role="alert" className="text-sm text-status-error">Use a nonblank, unique label for every condition.</p>}
      </div><Field label="Target receiver" htmlFor="route-receiver" hint="Receiver names already referenced by routing remain available, including external names."><Select id="route-receiver" value={receiver} onChange={(event) => setReceiver(event.target.value)} disabled={recQ.isPending || recQ.isError}><option value="">Use default receiver ({model.defaultReceiver || "unset"})</option>{receiverOptions.map((name) => <option key={name} value={name}>{name}</option>)}</Select></Field>
      <Collapse label="Advanced"><div className="space-y-4"><Switch checked={continuing} onCheckedChange={setContinuing} label="Continue matching" description="Keep evaluating later routes after this one matches." />{initial?.matchers?.length ? <p className="text-sm text-muted-foreground">Preserved matchers: <span className="font-mono">{initial.matchers.join(", ")}</span></p> : null}<p className="text-sm text-muted-foreground">Other route fields stay intact. Use the complete routing editor to change nested trees or advanced YAML.</p></div></Collapse></fieldset>
      {save.isError && <p role="alert" className="text-sm text-status-error">{isRevisionConflict(save.error) ? "Routing changed elsewhere. Your draft is preserved. Reopen the latest saved revision before saving." : "Could not save this route. Your draft is preserved. Try again."}</p>}
      <div className="flex justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" variant="primary" disabled={isRevisionConflict(save.error) || !canSave || !valid || !recQ.isSuccess || recQ.isFetching || save.isPending}><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save route"}</Button></div>
    </form></Card>
  </>;
}
