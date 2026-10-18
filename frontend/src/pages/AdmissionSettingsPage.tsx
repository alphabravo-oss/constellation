import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { policies, type AdmissionState, type AdmissionStateInput } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useEditorVisit } from "@/hooks/useEditorVisit";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Select, Switch } from "@/components/ui/form";
import { ErrorState, LoadingState } from "@/components/ui/states";

export function AdmissionSettingsPage() {
  const { clusterId } = useCluster();
  const { visit } = useEditorVisit(["admission-settings", clusterId]);
  const backTo = clusterId ? `/clusters/${clusterId}/admission` : "/clusters";
  const q = useQuery({ queryKey: ["admission-settings-editor", clusterId], queryFn: () => policies.admissionState({ cluster_id: clusterId }), enabled: !!clusterId, gcTime: 0 });
  const state = q.data?.cluster_id === clusterId ? q.data : undefined;
  return <div className="space-y-6">
    <PageHeader title="Edit admission settings" description="Choose whether this cluster observes or blocks admission decisions. Changes apply when you save."
      backLink={<Link to="." href={backTo}>Back to Admission Control</Link>} />
    {!clusterId ? <ErrorState title="Select a cluster to edit admission settings." />
      : q.isPending ? <LoadingState label="Loading admission settings…" />
      : !state ? <ErrorState title="Could not load admission settings for this cluster." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      : <>
        {q.isError && <p role="alert" className="text-sm text-status-error">Could not refresh settings. Your draft is preserved.</p>}
        <AdmissionSettingsEditor key={visit.context} editorContext={visit.context} clusterId={clusterId} initial={state} backTo={backTo} />
      </>}
  </div>;
}

function AdmissionSettingsEditor({ editorContext, clusterId, initial, backTo }: { editorContext: string; clusterId: string; initial: AdmissionState; backTo: string }) {
  const { isCurrent } = useEditorVisit([editorContext]);
  const [draft, setDraft] = useState<AdmissionStateInput>({ enabled: initial.enabled, mode: initial.mode, default_action: initial.default_action, failure_policy: initial.failure_policy });
  const navigate = useNavigate();
  const qc = useQueryClient();
  const save = useMutation({
    mutationFn: () => policies.updateAdmissionState(draft, { cluster_id: clusterId }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["admission-state", clusterId] }); if (isCurrent()) void navigate({ href: backTo }); },
  });
  return <Card title="Admission settings" description="Protect can block deployments. Monitor records decisions without blocking them.">
    <form onSubmit={(event) => { event.preventDefault(); if (!save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5">
        <Switch label="Enable admission control" description="When disabled, admission rules do not block workloads." checked={draft.enabled} onCheckedChange={(enabled) => setDraft({ ...draft, enabled })} />
        <div className="grid gap-5 sm:grid-cols-3">
          <Field label="Mode" htmlFor="admission-mode"><Select id="admission-mode" value={draft.mode} onChange={(e) => setDraft({ ...draft, mode: e.target.value as AdmissionStateInput["mode"] })}><option value="monitor">Monitor</option><option value="protect">Protect</option></Select></Field>
          <Field label="Default action" htmlFor="admission-default" hint="Decision when no rule matches."><Select id="admission-default" value={draft.default_action} onChange={(e) => setDraft({ ...draft, default_action: e.target.value as AdmissionStateInput["default_action"] })}><option value="allow">Allow</option><option value="deny">Deny</option></Select></Field>
          <Field label="Failure policy" htmlFor="admission-failure" hint="API-server behavior when the webhook is unreachable."><Select id="admission-failure" value={draft.failure_policy} onChange={(e) => setDraft({ ...draft, failure_policy: e.target.value as AdmissionStateInput["failure_policy"] })}><option value="ignore">Ignore (fail open)</option><option value="fail">Fail (fail closed)</option></Select></Field>
        </div>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save admission settings. Your draft is preserved. Try again.</p>}
        <div className="flex gap-3"><Button type="submit" variant="primary">{save.isPending ? "Saving…" : "Save changes"}</Button><Button type="button" variant="ghost" onClick={() => navigate({ href: backTo })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
