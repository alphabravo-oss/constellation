import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Eye, Save } from "lucide-react";
import { responseRules, type ResponseRule, type ResponseRuleMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useEditorVisit } from "@/hooks/useEditorVisit";
import { useRouteSearchParams } from "@/lib/route-search";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select, Switch, Textarea } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";

type OverrideDraft = { mode: ResponseRuleMode; enabled: boolean; reason: string };

export function ResponseCatalogOverrideFormPage() {
  const { clusterId, cluster, isLoading } = useCluster();
  const { ruleId } = useParams({ strict: false });
  const { visit } = useEditorVisit(["response-catalog-override", clusterId, ruleId]);
  const [search] = useRouteSearchParams();
  const backTo = clusterId ? `/clusters/${clusterId}/response${search.size ? `?${search}` : ""}` : "/clusters";
  return <div className="space-y-6" data-testid="response-catalog-override-form-page">
    <PageHeader title="Edit response catalog override" description="Change the mode or enabled state of a built-in response rule. This override is shared across every cluster in the organization."
      backLink={<Link to="." href={backTo} className="inline-flex items-center gap-2 hover:text-foreground"><ArrowLeft className="h-4 w-4" /> Built-in response catalog</Link>} />
    {isLoading ? <LoadingState label="Loading cluster…" /> : !clusterId || !cluster ? <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." /> : !ruleId ? <ErrorState title="Choose a built-in rule from response catalog before editing an override." /> : <OverrideScope key={visit.context} editorContext={visit.context} ruleId={ruleId} backTo={backTo} />}
  </div>;
}

function OverrideScope({ editorContext, ruleId, backTo }: { editorContext: string; ruleId: string; backTo: string }) {
  const q = useQuery({ queryKey: ["response-rules"], queryFn: () => responseRules.list() });
  const loaded = q.data?.rules.find((rule) => rule.id === ruleId);
  const [initial, setInitial] = useState<ResponseRule | null>(null);
  useEffect(() => { if (!initial && q.isSuccess && loaded) setInitial(loaded); }, [initial, q.isSuccess, loaded]);
  if (!initial) {
    if (q.isPending || q.isSuccess && loaded) return <LoadingState label="Loading built-in response rule…" />;
    return <ErrorState title="This built-in rule could not be loaded from the organization catalog." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  }
  return <>
    {(q.isError || !loaded) && <ErrorState title="Could not refresh this built-in rule. Your draft is preserved. Refresh before previewing or saving." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
    <OverrideEditor editorContext={editorContext} initial={initial} current={loaded ?? initial} canAct={q.isSuccess && !!loaded && !q.isFetching} backTo={backTo} />
  </>;
}

function OverrideEditor({ editorContext, initial, current, canAct, backTo }: { editorContext: string; initial: ResponseRule; current: ResponseRule; canAct: boolean; backTo: string }) {
  const { isCurrent } = useEditorVisit([editorContext]);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [draft, setDraft] = useState<OverrideDraft>(() => ({ mode: initial.mode, enabled: initial.enabled, reason: initial.override_reason ?? "" }));
  const inputKey = JSON.stringify({ ruleId: initial.id, ...draft, current });
  const preview = useMutation({ mutationFn: async (input: { draft: OverrideDraft; key: string }) => {
    const response = await responseRules.preview(initial.id, input.draft);
    if (response.preview.rule_id !== initial.id || response.preview.next_mode !== input.draft.mode || response.preview.next_enabled !== input.draft.enabled || response.preview.persists) throw new Error("Invalid preview");
    return { preview: response.preview, key: input.key };
  } });
  const matchingPreview = preview.isSuccess && preview.data.key === inputKey ? preview.data.preview : undefined;
  const save = useMutation({
    mutationFn: (input: OverrideDraft) => responseRules.update(initial.id, { ...input, reason: input.reason.trim() }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["response-rules"] }); if (isCurrent()) void navigate({ href: backTo }); },
  });
  const busy = preview.isPending || save.isPending;
  const canPreview = canAct && !busy && !!draft.reason.trim();
  const canSave = canPreview && !!matchingPreview;
  const change = (next: OverrideDraft) => { setDraft(next); preview.reset(); save.reset(); };
  return <>
    <VerdictBanner status="info" title="This override changes organization-wide settings" detail="All clusters share this built-in rule configuration. Preview the effect and record a reason before saving. Agent availability and action delivery determine whether enforcement can run." />
    <Card title={initial.name} description={initial.description}>
      <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (canSave) save.mutate(draft); }}>
        <fieldset disabled={busy} className="space-y-5">
          <Field label="Mode" htmlFor="response-override-mode"><Select id="response-override-mode" value={draft.mode} onChange={(event) => change({ ...draft, mode: event.target.value as ResponseRuleMode })} data-testid="response-rule-mode-select"><option value="learn">Learn</option><option value="monitor">Monitor</option><option value="enforce">Enforce</option></Select></Field>
          <Switch label="Enable built-in rule" checked={draft.enabled} disabled={busy} onCheckedChange={(enabled) => change({ ...draft, enabled })} />
          <Field label="Change reason" htmlFor="response-override-reason" required hint="Record the owner, ticket or purpose of this organization-wide change."><Textarea id="response-override-reason" required value={draft.reason} onChange={(event) => change({ ...draft, reason: event.target.value })} data-testid="response-rule-reason" /></Field>
          <Collapse label="Built-in rule details"><dl className="space-y-4 rounded-md border border-border p-4 text-sm"><div><dt className="text-muted-foreground">Event type</dt><dd>{current.event_type}</dd></div><div><dt className="text-muted-foreground">Match</dt><dd className="break-words font-mono">{current.match}</dd></div><div><dt className="text-muted-foreground">Configured actions</dt><dd>{current.actions.join(", ")}</dd></div><div><dt className="text-muted-foreground">Built-in default</dt><dd>{current.default_mode} · {current.default_enabled ? "enabled" : "disabled"}</dd></div><div><dt className="text-muted-foreground">Saved configuration</dt><dd>{current.mode} · {current.enabled ? "enabled" : "disabled"}</dd></div></dl></Collapse>
        </fieldset>
        {preview.isError && preview.variables?.key === inputKey && <p role="alert" className="text-sm text-status-error">Could not preview this override. Your draft is preserved. Try again.</p>}
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this override. Your draft is preserved. Try again.</p>}
        {matchingPreview && <div className="space-y-3 rounded-md border border-border p-4 text-sm" data-testid="response-rule-preview-card"><h3 className="font-semibold">Organization-wide change preview</h3><p>{matchingPreview.impact}</p><p className="text-muted-foreground">{matchingPreview.current_mode} / {matchingPreview.current_enabled ? "enabled" : "disabled"} → {matchingPreview.next_mode} / {matchingPreview.next_enabled ? "enabled" : "disabled"}</p>{matchingPreview.warnings.length > 0 && <ul className="list-disc space-y-1 pl-5 text-status-warning">{matchingPreview.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul>}<p className="text-xs text-muted-foreground">Dry run only. Saving persists the override with your change reason.</p></div>}
        <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={busy} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="button" disabled={!canPreview} onClick={() => { if (canPreview) preview.mutate({ draft: { ...draft, reason: draft.reason.trim() }, key: inputKey }); }} data-testid="response-rule-preview"><Eye className="h-4 w-4" />{preview.isPending ? "Previewing…" : "Preview"}</Button><Button type="submit" variant="primary" disabled={!canSave} data-testid="response-rule-save"><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save"}</Button></div>
      </form>
    </Card>
  </>;
}
