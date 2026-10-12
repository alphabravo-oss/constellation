import { useRef, useState } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, ArrowLeft, ArrowUp, Plus, Trash2 } from "lucide-react";
import { vulnProfiles, type VPEntry, type VulnProfile } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select, Switch, Textarea, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";

type EntryDraft = { key: number; entry: VPEntry; images: string; days: string; score: string; recent: string };
const DEFAULT_ENTRY: VPEntry = { name: "_recent", reserved: "_recent", recent_days: 14, severity_floor: "critical", action: "escalate" };
const toDraft = (entry: VPEntry, key: number): EntryDraft => ({ key, entry: { ...entry }, images: entry.images?.join("\n") ?? "", days: entry.days_to_fix?.toString() ?? "", score: entry.score_floor?.toString() ?? "", recent: entry.recent_days?.toString() ?? "" });
const lines = (value: string) => value.split("\n").map((line) => line.trim()).filter(Boolean);
const integerValid = (value: string) => value === "" || (/^\d+$/.test(value) && Number(value) <= 2147483647);
const scoreValid = (value: string) => value === "" || (value.trim() !== "" && Number.isFinite(Number(value)) && Number(value) >= 0 && Number(value) <= 10);

function draftBody(draft: EntryDraft): VPEntry {
  const entry = { ...draft.entry };
  if (draft.images !== (entry.images?.join("\n") ?? "")) entry.images = lines(draft.images);
  if (draft.days !== (entry.days_to_fix?.toString() ?? "")) entry.days_to_fix = draft.days === "" ? undefined : Number(draft.days);
  if (draft.score !== (entry.score_floor?.toString() ?? "")) entry.score_floor = draft.score === "" ? undefined : Number(draft.score);
  if (draft.recent !== (entry.recent_days?.toString() ?? "")) entry.recent_days = draft.recent === "" ? undefined : Number(draft.recent);
  return entry;
}

export function VulnProfileFormPage() {
  const { clusterId, isLoading, cluster, error } = useCluster();
  const { profileId } = useParams({ strict: false });
  const listPath = clusterId ? `/clusters/${clusterId}/vuln-profiles` : "/vuln-profiles";
  return <div className="space-y-6" data-testid="vuln-profile-form-page">
    <PageHeader title={profileId ? "Edit vulnerability profile" : "Add vulnerability profile"} description="Define ordered rules that acknowledge, defer, or escalate matching vulnerabilities when a scan completes."
      backLink={<Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Vulnerability Profiles</Link>} />
    {!clusterId ? <ErrorState title="Select an available cluster to manage vulnerability profiles." />
      : <ProfileScope key={`${clusterId}:${profileId ?? "new"}`} clusterId={clusterId} profileId={profileId} listPath={listPath}
          resolvedClusterId={cluster?.id} isLoading={isLoading} hasError={Boolean(error)} />}
  </div>;
}

function ProfileScope({ clusterId, profileId, listPath, resolvedClusterId, isLoading, hasError }: { clusterId: string; profileId?: string; listPath: string; resolvedClusterId?: string; isLoading: boolean; hasError: boolean }) {
  const qc = useQueryClient();
  const scopeReady = resolvedClusterId === clusterId && !isLoading && !hasError;
  const [wasReady, setWasReady] = useState(false);
  if (scopeReady && !wasReady) setWasReady(true);
  const retryScope = () => {
    void qc.invalidateQueries({ queryKey: ["clusters"] });
    void qc.invalidateQueries({ queryKey: ["cluster", clusterId] });
  };
  if (!scopeReady && !wasReady) return isLoading ? <LoadingState label="Loading cluster…" />
    : <ErrorState title="The selected cluster could not be resolved. Review its registration and retry." action={<Button onClick={retryScope}>Retry cluster</Button>} />;
  return <>
    {!scopeReady && <ErrorState title="Current cluster scope is unavailable. Your draft is preserved; saving is paused until the cluster resolves." action={<Button onClick={retryScope}>Retry cluster</Button>} />}
    <ProfileLoader clusterId={clusterId} profileId={profileId} listPath={listPath} scopeReady={scopeReady} />
  </>;
}

function ProfileLoader({ clusterId, profileId, listPath, scopeReady }: { clusterId: string; profileId?: string; listPath: string; scopeReady: boolean }) {
  const q = useQuery({ queryKey: ["vuln-profile-editor", clusterId, profileId], queryFn: () => vulnProfiles.list({ cluster_id: clusterId }), enabled: scopeReady && Boolean(profileId), gcTime: 0 });
  const matches = q.data?.profiles.filter((profile) => profile.id === profileId) ?? [];
  const [loaded, setLoaded] = useState<VulnProfile | null>(null);
  const initial = loaded ?? (q.isSuccess && matches.length === 1 ? matches[0] : undefined);
  if (!loaded && initial) setLoaded(initial);
  if (profileId && q.isPending && !initial) return <LoadingState label="Loading vulnerability profile…" />;
  if (profileId && !initial) return <ErrorState title={q.isError ? "This vulnerability profile could not be loaded for the selected cluster." : "This vulnerability profile was not found in the selected cluster."} action={<Button onClick={() => void q.refetch()}>Retry</Button>} />;
  const recordUnavailable = Boolean(profileId && (q.isError || matches.length !== 1));
  const unavailable = !scopeReady || recordUnavailable;
  return <>
    {recordUnavailable && scopeReady && <ErrorState title="Could not refresh the saved profile. Your draft is preserved; retry before saving." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
    <ProfileEditor initial={initial} clusterId={clusterId} listPath={listPath} unavailable={unavailable} />
  </>;
}

function ProfileEditor({ initial, clusterId, listPath, unavailable }: { initial?: VulnProfile; clusterId: string; listPath: string; unavailable: boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [active, setActive] = useState(initial?.active ?? false);
  const [entries, setEntries] = useState<EntryDraft[]>(() => (initial ? initial.entries ?? [] : [DEFAULT_ENTRY]).map(toDraft));
  const nextKey = useRef(entries.length);
  const [clustersText, setClustersText] = useState(initial?.domain_scope?.clusters?.join("\n") ?? "");
  const [namespacesText, setNamespacesText] = useState(initial?.domain_scope?.namespaces?.join("\n") ?? "");
  const valid = Boolean(name.trim()) && entries.every((draft) => Boolean(draft.entry.name.trim()) && integerValid(draft.days) && integerValid(draft.recent) && scoreValid(draft.score));
  const save = useMutation({
    mutationFn: () => {
      const domain = { ...(initial?.domain_scope ?? {}) };
      if (clustersText !== (domain.clusters?.join("\n") ?? "")) domain.clusters = lines(clustersText);
      if (namespacesText !== (domain.namespaces?.join("\n") ?? "")) domain.namespaces = lines(namespacesText);
      const body = { name: name.trim(), description, active, entries: entries.map(draftBody), domain_scope: domain };
      return initial ? vulnProfiles.update(initial.id, body) : vulnProfiles.create(body, { cluster_id: clusterId });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["vuln-profiles", clusterId] });
      void qc.invalidateQueries({ queryKey: ["policy-center", clusterId] });
      void navigate({ href: listPath });
    },
  });
  const change = (index: number, patch: Partial<EntryDraft>) => setEntries((current) => current.map((draft, i) => i === index ? { ...draft, ...patch } : draft));
  const changeEntry = (index: number, patch: Partial<VPEntry>) => setEntries((current) => current.map((draft, i) => i === index ? { ...draft, entry: { ...draft.entry, ...patch } } : draft));
  const move = (index: number, direction: -1 | 1) => setEntries((current) => {
    const next = [...current];
    const target = index + direction;
    if (target < 0 || target >= next.length) return current;
    [next[index], next[target]] = [next[target], next[index]];
    return next;
  });
  return <Card title="Vulnerability profile" description="Rules run in order. The first matching entry determines the vulnerability's profile decision.">
    <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (valid && !unavailable && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <Field label="Profile name" htmlFor="profile-name" required><TextInput id="profile-name" autoFocus required value={name} onChange={(event) => setName(event.target.value)} /></Field>
        <Field label="Description" htmlFor="profile-description"><Textarea id="profile-description" value={description} onChange={(event) => setDescription(event.target.value)} /></Field>
        <Switch checked={active} onCheckedChange={setActive} label="Apply profile on scan completion" description="When active, matching entries can change the findings created by future completed scans." />
        <section className="space-y-4" aria-labelledby="profile-entries-title">
          <h2 id="profile-entries-title" className="text-sm font-semibold">Ordered vulnerability rules</h2>
          {entries.length === 0 && <EmptyState title="No rules yet" hint="This profile will not change findings until a matching rule is added." />}
          {entries.map((draft, index) => <section key={draft.key} className="space-y-4 rounded-lg border border-border p-5" aria-label={`Rule ${index + 1}`}>
            <div className="flex flex-wrap items-center justify-between gap-3"><h3 className="text-sm font-semibold">Rule {index + 1}</h3><div className="flex gap-2">
              <Button type="button" variant="ghost" aria-label={`Move rule ${index + 1} up`} disabled={index === 0} onClick={() => move(index, -1)}><ArrowUp className="h-4 w-4" /></Button>
              <Button type="button" variant="ghost" aria-label={`Move rule ${index + 1} down`} disabled={index === entries.length - 1} onClick={() => move(index, 1)}><ArrowDown className="h-4 w-4" /></Button>
              <Button type="button" variant="ghost" aria-label={`Remove rule ${index + 1}`} onClick={() => setEntries((current) => current.filter((_, i) => i !== index))}><Trash2 className="h-4 w-4" /></Button>
            </div></div>
            <div className="grid gap-5 sm:grid-cols-2">
              <Field label="Rule name" htmlFor={`profile-entry-name-${draft.key}`} required hint="A label for this decision. Use the CVE expression under Advanced to match vulnerability IDs."><TextInput id={`profile-entry-name-${draft.key}`} required value={draft.entry.name} onChange={(event) => changeEntry(index, { name: event.target.value })} /></Field>
              <Field label="Action" htmlFor={`profile-entry-action-${draft.key}`}><Select id={`profile-entry-action-${draft.key}`} value={draft.entry.action} onChange={(event) => changeEntry(index, { action: event.target.value as VPEntry["action"] })}><option value="suppress">Suppress / acknowledge</option><option value="escalate">Escalate to critical</option></Select></Field>
              <Field label="Publication window" htmlFor={`profile-entry-reserved-${draft.key}`} hint="Recent rules require a vulnerability publication date in scan evidence."><Select id={`profile-entry-reserved-${draft.key}`} value={draft.entry.reserved || ""} onChange={(event) => changeEntry(index, { reserved: event.target.value })}><option value="">Any publication date</option><option value="_recent">Recently published (_recent)</option></Select></Field>
              {draft.entry.reserved === "_recent" && <Field label="Published within days" htmlFor={`profile-entry-recent-${draft.key}`} hint="Blank or zero uses the server's 14-day window." error={!integerValid(draft.recent) ? "Enter a whole number of days from 0 to 2147483647." : undefined}><TextInput id={`profile-entry-recent-${draft.key}`} type="number" min="0" max="2147483647" step="1" value={draft.recent} onChange={(event) => change(index, { recent: event.target.value })} /></Field>}
            </div>
            <Collapse label="Advanced matching and grace window">
              <div className="grid gap-5 sm:grid-cols-2">
                <Field label="CVE expression" htmlFor={`profile-entry-regex-${draft.key}`} hint="A Go regular expression such as ^CVE-2026-.*$. Blank matches any CVE ID."><TextInput id={`profile-entry-regex-${draft.key}`} value={draft.entry.name_regex ?? ""} onChange={(event) => changeEntry(index, { name_regex: event.target.value })} /></Field>
                <Field label="Minimum severity" htmlFor={`profile-entry-severity-${draft.key}`}><Select id={`profile-entry-severity-${draft.key}`} value={draft.entry.severity_floor ?? ""} onChange={(event) => changeEntry(index, { severity_floor: event.target.value })}><option value="">Any severity</option>{["info", "low", "medium", "high", "critical"].map((severity) => <option key={severity} value={severity}>{severity}</option>)}</Select></Field>
                <Field label="Minimum CVSS score" htmlFor={`profile-entry-score-${draft.key}`} hint="Optional score from 0 to 10." error={!scoreValid(draft.score) ? "Enter a score from 0 to 10." : undefined}><TextInput id={`profile-entry-score-${draft.key}`} type="number" min="0" max="10" step="any" value={draft.score} onChange={(event) => change(index, { score: event.target.value })} /></Field>
                <Field label="Days to fix" htmlFor={`profile-entry-days-${draft.key}`} hint="For suppression, a positive number defers the finding; blank or zero acknowledges it without a deadline." error={!integerValid(draft.days) ? "Enter a whole number of days from 0 to 2147483647." : undefined}><TextInput id={`profile-entry-days-${draft.key}`} type="number" min="0" max="2147483647" step="1" value={draft.days} onChange={(event) => change(index, { days: event.target.value })} /></Field>
                <Field label="Image patterns" htmlFor={`profile-entry-images-${draft.key}`} hint="One Go filepath glob per line. Blank matches any image."><Textarea id={`profile-entry-images-${draft.key}`} value={draft.images} onChange={(event) => change(index, { images: event.target.value })} /></Field>
                <Field label="Rule comment" htmlFor={`profile-entry-comment-${draft.key}`}><Textarea id={`profile-entry-comment-${draft.key}`} value={draft.entry.comment ?? ""} onChange={(event) => changeEntry(index, { comment: event.target.value })} /></Field>
              </div>
            </Collapse>
          </section>)}
          <Button type="button" variant="outline" onClick={() => { const key = nextKey.current++; setEntries((current) => [...current, toDraft({ name: "", action: "suppress" }, key)]); }}><Plus className="h-4 w-4" /> Add rule</Button>
        </section>
        <Collapse label="Advanced profile scope">
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Cluster scope" htmlFor="profile-scope-clusters" hint="One cluster identifier per line. Blank adds no further cluster restriction."><Textarea id="profile-scope-clusters" value={clustersText} onChange={(event) => setClustersText(event.target.value)} /></Field>
            <Field label="Namespace scope" htmlFor="profile-scope-namespaces" hint="One namespace per line. Blank matches all namespaces within the profile's cluster scope."><Textarea id="profile-scope-namespaces" value={namespacesText} onChange={(event) => setNamespacesText(event.target.value)} /></Field>
          </div>
        </Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this vulnerability profile. Check its rules and CVE expressions, then try again. Your draft is preserved.</p>}
        <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={!valid || unavailable || save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: listPath })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
