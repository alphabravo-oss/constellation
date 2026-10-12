import { useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Plus, Trash2 } from "lucide-react";

import { groupsApi, policies, type Group, type GroupCriterion, type GroupKind, type GroupMode } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select, Textarea, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";

const MODES: GroupMode[] = ["discover", "monitor", "protect"];

export function GroupFormPage() {
  const { clusterId, isLoading, cluster, error } = useCluster();
  const { groupId } = useParams({ strict: false });
  const listPath = clusterId ? `/clusters/${clusterId}/groups` : "/groups";
  return <div className="space-y-6" data-testid="group-form-page">
    <PageHeader title={groupId ? "Edit group" : "Add group"}
      description="Choose workload selectors and the network and process modes applied to matching members."
      backLink={<Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Groups</Link>} />
    {isLoading ? <LoadingState label="Loading cluster…" />
      : !clusterId || (error && !cluster) ? <ErrorState title="Select an available cluster to manage groups." />
      : <GroupFormLoader key={`${clusterId}:${groupId ?? "new"}`} clusterId={clusterId} groupId={groupId} listPath={listPath} />}
  </div>;
}

function GroupFormLoader({ clusterId, groupId, listPath }: { clusterId: string; groupId?: string; listPath: string }) {
  const q = useQuery({
    queryKey: ["group-editor", clusterId, groupId],
    queryFn: () => groupsApi.list({ cluster_id: clusterId }),
    enabled: Boolean(groupId),
    gcTime: 0,
  });
  const defaultsQ = useQuery({
    queryKey: ["service-mode-defaults", clusterId],
    queryFn: () => policies.serviceModeDefaults({ cluster_id: clusterId }),
    enabled: !groupId,
    gcTime: 0,
  });
  const defaultsValid = defaultsQ.isSuccess && defaultsQ.data.cluster_id === clusterId && MODES.includes(defaultsQ.data.policy_mode as GroupMode) && MODES.includes(defaultsQ.data.profile_mode as GroupMode);
  const [loadedDefaults, setLoadedDefaults] = useState<{ policy_mode: GroupMode; profile_mode: GroupMode } | null>(null);
  if (!loadedDefaults && defaultsValid) setLoadedDefaults({ policy_mode: defaultsQ.data.policy_mode as GroupMode, profile_mode: defaultsQ.data.profile_mode as GroupMode });
  const matches = q.data?.groups.filter((group) => group.id === groupId) ?? [];
  const [loadedGroup, setLoadedGroup] = useState<Group | null>(null);
  const initial = loadedGroup ?? (q.isSuccess && matches.length === 1 ? matches[0] : undefined);
  // Capture the first confirmed record once. Refetching must never replace a draft.
  if (!loadedGroup && initial) setLoadedGroup(initial);
  if (groupId && q.isPending && !initial) return <LoadingState label="Loading group…" />;
  if (!groupId && defaultsQ.isPending && !loadedDefaults) return <LoadingState label="Loading group defaults…" />;
  if (!groupId && !loadedDefaults) return <ErrorState title="Group defaults could not be loaded for the selected cluster." action={<Button onClick={() => void defaultsQ.refetch()}>Retry</Button>} />;
  if (groupId && !initial) return <ErrorState
    title={q.isError ? "This group could not be loaded for the selected cluster." : "This group was not found in the selected cluster."}
    action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  if (initial?.cfg_type === "fed") return <ErrorState title="This group is managed by its federation master and cannot be edited here." />;
  const unavailable = groupId ? q.isError || matches.length !== 1 : !defaultsValid;
  return <>
    {unavailable && <ErrorState title={`${groupId ? "The saved group" : "Group defaults"} could not be refreshed. Your draft is preserved; retry before saving.`}
      action={<Button onClick={() => groupId ? void q.refetch() : void defaultsQ.refetch()}>Retry</Button>} />}
    <GroupEditor clusterId={clusterId} initial={initial} initialModes={loadedDefaults ?? undefined} listPath={listPath} unavailable={unavailable} />
  </>;
}

function GroupEditor({ clusterId, initial, initialModes, listPath, unavailable }: { clusterId: string; initial?: Group; initialModes?: { policy_mode: GroupMode; profile_mode: GroupMode }; listPath: string; unavailable: boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState(initial?.name ?? "");
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [kind, setKind] = useState<GroupKind>(initial?.kind ?? "ground");
  const [learnedFrom, setLearnedFrom] = useState(initial?.learned_from ?? "");
  const [policyMode, setPolicyMode] = useState<GroupMode>(initial?.policy_mode ?? initialModes?.policy_mode ?? "monitor");
  const [profileMode, setProfileMode] = useState<GroupMode>(initial?.profile_mode ?? initialModes?.profile_mode ?? "monitor");
  const [criteria, setCriteria] = useState<GroupCriterion[]>(() => initial?.criteria?.map((criterion) => ({ ...criterion })) ?? [{ key: "namespace", op: "eq", value: "" }]);
  const valid = Boolean(name.trim()) && criteria.every((criterion) => Boolean(criterion.key.trim()));
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), comment, kind, learned_from: learnedFrom,
        cfg_type: initial?.cfg_type ?? "user", policy_mode: policyMode, profile_mode: profileMode,
        criteria: criteria.map((criterion) => ({ ...criterion, key: criterion.key.trim() })),
        members: initial?.members ?? [] };
      return initial ? groupsApi.update(initial.id, body, { cluster_id: clusterId }) : groupsApi.create(body, { cluster_id: clusterId });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["groups", clusterId] });
      void qc.invalidateQueries({ queryKey: ["group-usage", clusterId] });
      void qc.invalidateQueries({ queryKey: ["dashboard", clusterId] });
      void navigate({ href: listPath });
    },
  });
  const conflict = (save.error as { response?: { status?: number } } | null)?.response?.status === 409;
  const updateCriterion = (index: number, patch: Partial<GroupCriterion>) => setCriteria((current) => current.map((criterion, i) => i === index ? { ...criterion, ...patch } : criterion));
  return <Card title="Group configuration" description="Membership is computed by the server. Every selector must match for a workload to join this group.">
    <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (valid && !unavailable && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <Field label="Name" htmlFor="group-name" required><TextInput id="group-name" autoFocus required value={name} onChange={(event) => setName(event.target.value)} /></Field>
        <Field label="Description" htmlFor="group-comment"><Textarea id="group-comment" value={comment} onChange={(event) => setComment(event.target.value)} /></Field>
        <section className="space-y-3" aria-labelledby="group-selectors-title">
          <h2 id="group-selectors-title" className="text-sm font-semibold">Membership selectors</h2>
          <p className="text-xs text-muted-foreground">Use namespace, cluster, id, or a label key such as label.app. Regular expressions use the server's Go syntax.</p>
          {criteria.length === 0 && <p className="text-sm text-muted-foreground">Without selectors this group will have no matching members.</p>}
          {criteria.map((criterion, index) => <div key={index} className="grid items-end gap-3 rounded-md border border-border p-4 sm:grid-cols-[1fr_1fr_1fr_auto]">
            <Field label={`Selector ${index + 1} key`} htmlFor={`group-key-${index}`} required><TextInput id={`group-key-${index}`} required value={criterion.key} onChange={(event) => updateCriterion(index, { key: event.target.value })} placeholder="namespace or label.app" /></Field>
            <Field label={`Selector ${index + 1} operator`} htmlFor={`group-op-${index}`}><Select id={`group-op-${index}`} value={criterion.op || "eq"} onChange={(event) => updateCriterion(index, { op: event.target.value as GroupCriterion["op"] })}><option value="eq">Equals</option><option value="contains">Contains</option><option value="regex">Regular expression</option></Select></Field>
            <Field label={`Selector ${index + 1} value`} htmlFor={`group-value-${index}`}><TextInput id={`group-value-${index}`} value={criterion.value} onChange={(event) => updateCriterion(index, { value: event.target.value })} /></Field>
            <Button type="button" variant="ghost" aria-label={`Remove selector ${index + 1}`} onClick={() => setCriteria((current) => current.filter((_, i) => i !== index))}><Trash2 className="h-4 w-4" /></Button>
          </div>)}
          <Button type="button" variant="outline" onClick={() => setCriteria((current) => [...current, { key: "", op: "eq", value: "" }])}><Plus className="h-4 w-4" /> Add selector</Button>
        </section>
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Network mode" htmlFor="group-policy-mode" hint="Discover learns traffic, Monitor reports violations, Protect enforces policy."><Select id="group-policy-mode" value={policyMode} onChange={(event) => setPolicyMode(event.target.value as GroupMode)}>{MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</Select></Field>
          <Field label="Process/file mode" htmlFor="group-profile-mode" hint="Applies the selected mode to member process and file profiles."><Select id="group-profile-mode" value={profileMode} onChange={(event) => setProfileMode(event.target.value as GroupMode)}>{MODES.map((mode) => <option key={mode} value={mode}>{mode}</option>)}</Select></Field>
        </div>
        <Collapse label="Advanced">
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Kind" htmlFor="group-kind"><Select id="group-kind" value={kind} onChange={(event) => setKind(event.target.value as GroupKind)}><option value="ground">User-defined</option><option value="learned">Learned</option><option value="federated">Federated</option></Select></Field>
            <Field label="Learned from" htmlFor="group-learned-from" hint="Workload template used as the source of a learned group."><TextInput id="group-learned-from" value={learnedFrom} onChange={(event) => setLearnedFrom(event.target.value)} /></Field>
          </div>
        </Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error">{conflict ? "This group is referenced by policy. Remove blocking references before changing its name or selectors." : "Could not save this group. Check the selectors and try again."} Your draft is preserved.</p>}
        <div className="flex items-center gap-3">
          <Button type="submit" variant="primary" size="lg" disabled={!valid || unavailable || save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button>
          <Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: listPath })}>Cancel</Button>
        </div>
      </fieldset>
    </form>
  </Card>;
}
