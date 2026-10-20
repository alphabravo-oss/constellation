import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import Editor from "@monaco-editor/react";
import "@/lib/monaco";
import { ArrowLeft, Save } from "lucide-react";
import { receivers, routing } from "@/api/client";
import { isRevisionConflict, parseRouting, routingYamlError, serializeRouting, validRoutingSnapshot, type RoutingSnapshot } from "@/lib/integration-routing";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
const backTo = "/settings/integrations?tab=routes";

export function RoutingConfigFormPage() {
  const q = useQuery({ queryKey: ["routing-yaml"], queryFn: routing.get });
  const [initial, setInitial] = useState<RoutingSnapshot | null>(null);
  useEffect(() => { if (!initial && q.isSuccess && !q.isFetching && validRoutingSnapshot(q.data)) setInitial(q.data); }, [initial, q.isSuccess, q.isFetching, q.data]);
  const conflict = !!initial && q.data?.revision !== initial.revision;
  return <div className="space-y-6" data-testid="routing-config-form-page"><PageHeader title="Edit notification routing" description="Change the default destination or edit the complete organization-wide routing YAML. Save persists the entire document."
    backLink={<Link to="." href={backTo} className="inline-flex items-center gap-2"><ArrowLeft className="h-4 w-4" /> Integrations</Link>} />
    {!initial ? q.isPending || q.isSuccess && q.isFetching || q.isSuccess && validRoutingSnapshot(q.data) ? <LoadingState label="Loading saved routing…" /> : <ErrorState title="Could not load saved routing. No editable document is available." action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : <>
      {q.isError && <ErrorState title="Could not refresh routing. Your draft is preserved. Refresh before saving." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
      {conflict && <p role="alert" className="text-sm text-status-error">Routing changed elsewhere. Your draft is preserved. Reopen the latest saved routing before saving.</p>}
      <RoutingConfigEditor initial={initial} canSave={q.isSuccess && !q.isFetching && !conflict} />
    </>}
  </div>;
}

function RoutingConfigEditor({ initial, canSave }: { initial: RoutingSnapshot; canSave: boolean }) {
  const [draft, setDraft] = useState(initial.yaml);
  const parsed = useMemo(() => parseRouting(draft), [draft]);
  const validation = routingYamlError(draft);
  const recQ = useQuery({ queryKey: ["receivers"], queryFn: receivers.list });
  const options = [...new Set([...(recQ.data?.receivers.map((r) => r.name) ?? []), ...(parsed.ok && parsed.model.defaultReceiver ? [parsed.model.defaultReceiver] : [])])];
  const navigate = useNavigate(); const qc = useQueryClient();
  const save = useMutation({ mutationFn: () => routing.put(draft, initial.revision), onSuccess: () => { void qc.invalidateQueries({ queryKey: ["routing-yaml"] }); void qc.invalidateQueries({ queryKey: ["integration-delivery-overview"] }); void navigate({ href: backTo }); }, onError: (error) => { if (isRevisionConflict(error)) void qc.invalidateQueries({ queryKey: ["routing-yaml"] }); } });
  return <><VerdictBanner status="info" title="Routing applies across the organization" detail={`You are editing saved revision ${initial.revision}. Nested trees, matchers, inhibition rules and receiver definitions stay in the complete YAML document.`} />
    <Card title="Routing configuration" description="The default receiver handles alerts with no matching child route."><form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (canSave && !validation && draft !== initial.yaml && !isRevisionConflict(save.error) && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5">
        {parsed.ok ? <Field label="Default receiver" htmlFor="routing-default-receiver"><Select id="routing-default-receiver" value={parsed.model.defaultReceiver} disabled={!recQ.isSuccess || recQ.isFetching} onChange={(event) => setDraft(serializeRouting({ ...parsed.model, defaultReceiver: event.target.value }))}><option value="">No default receiver</option>{options.map((name) => <option key={name} value={name}>{name}</option>)}</Select></Field> : <p className="text-sm text-muted-foreground">This configuration requires the complete YAML editor. Its content is preserved below.</p>}
        {recQ.isError && <ErrorState title="Could not load receiver choices. The YAML draft is preserved." action={<Button onClick={() => void recQ.refetch()}>Retry</Button>} />}
        <Collapse label="Advanced: complete routing YAML" defaultOpen={!parsed.ok}><div className="space-y-3"><p className="text-sm text-muted-foreground">Edit the complete document, including nested routing trees and advanced settings. Empty YAML clears the saved routing configuration.</p><div className="overflow-hidden rounded-md border border-border" data-testid="routing-yaml-editor"><Editor height="420px" language="yaml" theme="vs-dark" value={draft} onChange={(value) => setDraft(value ?? "")} options={{ readOnly: save.isPending }} /></div></div></Collapse>
      </fieldset>
      {validation && <p role="alert" className="text-sm text-status-error">{validation}</p>}
      {save.isError && <p role="alert" className="text-sm text-status-error">{isRevisionConflict(save.error) ? "Routing changed elsewhere. Your draft is preserved. Reopen the latest saved revision before saving." : "Could not save routing. Your draft is preserved. Try again."}</p>}
      <div className="flex justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" variant="primary" disabled={isRevisionConflict(save.error) || !canSave || !!validation || draft === initial.yaml || save.isPending}><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save routing"}</Button></div>
    </form></Card></>;
}
