import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { baselines, fileProfiles, network, quarantine, type BaselineDetail, type BaselineMode, type DeploymentDetail, type FileProfileDetail, type FileProfileBundle } from "@/api/client";
import { useEditorVisit } from "@/hooks/useEditorVisit";
import { useRouteSearchParams } from "@/lib/route-search";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { PageHeader } from "@/components/ui/page";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { useDeploymentContext, currentDeployment, profileIsOwned, policyIsCurrent, workloadID, nextMode } from "./deployment-detail/context";
import { Select } from "@/components/ui/form";

const ACTIONS = {
  "apply-policy": { title: "Apply approved network policy", effect: "Queue the currently approved candidate for the policy applier. A successful request does not confirm that the cluster has applied it.", submit: "Queue apply", tab: "network" },
  "demote-policy": { title: "Demote network policy", effect: "Request a lower network policy mode for this exact workload. Review reported applier state after the request.", submit: "Demote policy", tab: "network" },
  "rollback-policy": { title: "Roll back network policy", effect: "Request the retained rollback reference for this exact workload. A successful request does not confirm deployed rollback.", submit: "Request rollback", tab: "network" },
  "lift-quarantine": { title: "Lift deployment quarantine", effect: "Lift the active admission quarantine for this exact workload. This does not change network policy or terminate existing connections.", submit: "Lift quarantine", tab: "network" },
  "process-mode": { title: "Change process baseline mode", effect: "Configure the next process profile mode for this workload. Agent support and reconciliation determine enforcement.", submit: "Save mode", tab: "runtime" },
  "file-mode": { title: "Change file profile mode", effect: "Configure the next file profile mode for this workload. Reported agent watches determine whether protection has taken effect.", submit: "Save mode", tab: "files" },
  "file-exception": { title: "Add file monitor exception", effect: "Configure an exception for this workload’s file monitor rules. Open Advanced to limit it to one rule or application.", submit: "Save exception", tab: "files" },
  "file-exception-delete": { title: "Remove file monitor exception", effect: "Remove the selected exception from this exact workload. Removing an exception may cause the matching rule to apply again.", submit: "Remove exception", tab: "files" },
  "file-rule-delete": { title: "Remove file monitor rule", effect: "Remove the selected monitor rule from this exact workload. The agent must reconcile the change.", submit: "Remove rule", tab: "files" },
  "file-bundle-import": { title: "Import file profile bundle", effect: "Replace this workload’s configured file rules and exceptions with the reviewed bundle. Existing configuration may be removed.", submit: "Import and replace", tab: "files" },
} as const;
type Action = keyof typeof ACTIONS;
const isAction = (value: string | undefined): value is Action => !!value && Object.hasOwn(ACTIONS, value);
type Profile = BaselineDetail | FileProfileDetail;
function parseBundle(value: string): FileProfileBundle {
  let bundle: FileProfileBundle;
  try { bundle = JSON.parse(value) as FileProfileBundle; } catch { throw new Error("Bundle JSON is invalid. Your draft is preserved."); }
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error("Enter a file profile bundle object.");
  if (bundle.schema_version !== undefined && (typeof bundle.schema_version !== "string" || bundle.schema_version.trim() !== "" && bundle.schema_version.trim() !== "constellation-file-profile-v1")) throw new Error("Unsupported file profile schema version.");
  if (bundle.kind !== undefined && (typeof bundle.kind !== "string" || bundle.kind.trim() !== "" && bundle.kind.trim().toLowerCase() !== "fileprofile")) throw new Error("Unsupported bundle kind.");
  if (bundle.rules !== undefined && !Array.isArray(bundle.rules) || bundle.exceptions !== undefined && !Array.isArray(bundle.exceptions)) throw new Error("Bundle rules and exceptions must be arrays.");
  if (!Object.hasOwn(bundle, "rules") && !Object.hasOwn(bundle, "exceptions")) throw new Error("Specify rules or exceptions explicitly. An empty object cannot replace a profile.");
  if (bundle.mode !== undefined && (typeof bundle.mode !== "string" || bundle.mode.trim() !== "" && !["learn", "monitor", "enforce"].includes(bundle.mode.trim().toLowerCase()))) throw new Error("Unsupported file profile mode.");
  return bundle;
}
type Snapshot = { detail: DeploymentDetail; profile?: Profile; revision: string };
function eligible(action: Action, detail: DeploymentDetail, profile: Profile | undefined, resource: string) {
  if (action === "process-mode") return !!detail.process_baseline && profileIsOwned(detail, detail.process_baseline) && !!profile && profileIsOwned(detail, profile);
  if (action.startsWith("file-")) {
    if (!detail.file_profile || !profileIsOwned(detail, detail.file_profile) || !profile || !profileIsOwned(detail, profile) || !("exceptions" in profile)) return false;
    if (action === "file-rule-delete") return profile.rules.some(rule => rule.id === resource);
    if (action === "file-exception-delete") return profile.exceptions.some(exception => exception.id === resource);
    return true;
  }
  if (action === "lift-quarantine") return !!detail.quarantine && detail.quarantine.cluster_id === detail.cluster_id && detail.quarantine.scope === "workload" && detail.quarantine.match_key === workloadID(detail) && !detail.quarantine.lifted_at;
  if (!policyIsCurrent(detail)) return false;
  const policy = detail.network_policy!;
  if (action === "apply-policy") return !!policy.target_mode && policy.approval_status === "approved" && !!policy.candidate_hash && policy.approved_candidate_hash === policy.candidate_hash && !policy.candidate_stale;
  if (action === "demote-policy") return policy.current_mode !== "discover";
  return !!policy.rollback_available && !!policy.rollback_ref;
}
function revision(action: Action, detail: DeploymentDetail, profile: Profile | undefined) {
  if (action === "lift-quarantine") return JSON.stringify(detail.quarantine);
  if (action === "process-mode" || action.startsWith("file-")) return JSON.stringify({ workload: profile?.workload_id, cluster: profile?.cluster_id, mode: profile?.mode, rules: profile?.rules, exceptions: profile && "exceptions" in profile ? profile.exceptions : undefined });
  const p = detail.network_policy;
  return JSON.stringify({ workload: p?.workload, cluster: p?.cluster_id, candidate: p?.candidate_hash, approved: p?.approved_candidate_hash, approval: p?.approval_status, mode: p?.current_mode, target: p?.target_mode, stale: p?.candidate_stale, rollback: p?.rollback_ref, available: p?.rollback_available });
}
const splitCSV = (value: string) => Array.from(new Set(value.split(",").map(item => item.trim()).filter(Boolean))).sort();

export function DeploymentActionFormPage() {
  const context = useDeploymentContext();
  const { action } = useParams({ strict: false });
  const [params] = useRouteSearchParams();
  const selectedAction = isAction(action) ? action : undefined;
  const info = selectedAction ? ACTIONS[selectedAction] : undefined;
  const resource = selectedAction === "file-rule-delete" ? params.get("rule") ?? "" : params.get("exception") ?? "";
  const desired = params.get("mode") ?? "";
  const { visit } = useEditorVisit(["deployment-action", context.clusterId, context.did, selectedAction, resource, desired]);
  const backTo = context.clusterId && context.did ? `/clusters/${context.clusterId}/deployments/${encodeURIComponent(context.did)}?tab=${info?.tab ?? "overview"}` : "/clusters";
  return <div className="space-y-5" data-testid="deployment-action-form-page">
    <PageHeader title={info?.title ?? "Deployment action"} description={info?.effect ?? "Choose a supported action from an exact deployment."} backLink={<a href={backTo} className="text-sm hover:underline">Back to deployment</a>} />
    {!selectedAction || !context.clusterId || !context.did ? <ErrorState title="Select a supported deployment action." /> : <DeploymentActionScope key={visit.context} editorContext={visit.context} context={context} action={selectedAction} resource={resource} desired={desired} backTo={backTo} />}
  </div>;
}

function DeploymentActionScope({ editorContext, context, action, resource, desired, backTo }: { editorContext: string; context: ReturnType<typeof useDeploymentContext>; action: Action; resource: string; desired: string; backTo: string }) {
  const { isCurrent } = useEditorVisit([editorContext]);
  const { clusterId, did, detail, q, qc, scopeReady, ready } = context;
  const navigate = useNavigate();
  const usesProfile = action === "process-mode" || action.startsWith("file-");
  const control = detail ? workloadID(detail) : "";
  const profileKey = ["deployment-action-profile", clusterId, did, action === "process-mode" ? "process" : "file", control];
  const profileQ = useQuery({ queryKey: profileKey, enabled: ready && usesProfile, queryFn: async (): Promise<Profile> => action === "process-mode" ? baselines.get(control, { cluster_id: clusterId }) : fileProfiles.get(control, { cluster_id: clusterId }) });
  const profile = usesProfile && !profileQ.isError ? profileQ.data : undefined;
  const sourceReady = ready && !!detail && (!usesProfile || profileQ.isSuccess && !profileQ.isFetching) && eligible(action, detail, profile, resource);
  const currentRevision = sourceReady && detail ? revision(action, detail, profile) : undefined;
  const [initial, setInitial] = useState<Snapshot>();
  useEffect(() => { if (!initial && sourceReady && detail && currentRevision) setInitial({ detail, profile, revision: currentRevision }); }, [initial, sourceReady, detail, profile, currentRevision]);
  const [reason, setReason] = useState("");
  const [mode, setMode] = useState<BaselineMode | "">(["learn", "monitor", "enforce"].includes(desired) ? desired as BaselineMode : "");
  const [filter, setFilter] = useState("");
  const [applications, setApplications] = useState("");
  const [description, setDescription] = useState("");
  const [ruleId, setRuleId] = useState("");
  const [bundleText, setBundleText] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const bundlePreview = (() => { if (!bundleText.trim()) return undefined; try { return parseBundle(bundleText); } catch { return undefined; } })();
  const clearsProfile = !!bundlePreview && !(bundlePreview.rules?.length || bundlePreview.exceptions?.length);
  const bundleRetargeted = !!bundlePreview && ((!!bundlePreview.workload_id && bundlePreview.workload_id !== control) || (!!bundlePreview.cluster_id && bundlePreview.cluster_id !== clusterId));
  const submitLock = useRef(false);
  const requestKey = useRef<{ identity: string; key: string } | undefined>(undefined);
  const changed = !!initial && currentRevision !== initial.revision;
  const allowedModes = initial?.profile ? [nextMode(initial.profile.mode, false), nextMode(initial.profile.mode, true)].filter((value): value is BaselineMode => !!value) : [];
  const modesValid = !action.endsWith("-mode") || allowedModes.includes(mode as BaselineMode);
  const fileProfile = initial?.profile && "exceptions" in initial.profile ? initial.profile : undefined;
  const draftValid = !!reason.trim() && modesValid && (action !== "file-exception" || !!filter.trim() && (!ruleId || fileProfile?.rules.some(rule => rule.id === ruleId))) && (action !== "file-bundle-import" || !!bundleText.trim() && confirmed);
  const save = useMutation({ mutationFn: async () => {
    if (!scopeReady || !clusterId || !did || !initial) throw new Error("Resolve this exact deployment before submitting.");
    const latest = currentDeployment(qc, clusterId, did);
    const source = qc.getQueryState<Profile>(profileKey);
    if (usesProfile && (source?.status !== "success" || source.fetchStatus !== "idle" || source.isInvalidated)) throw new Error("Refresh the runtime profile before submitting. Your draft is preserved.");
    const latestProfile = usesProfile ? source?.data : undefined;
    if (!eligible(action, latest, latestProfile, resource) || revision(action, latest, latestProfile) !== initial.revision) throw new Error("The reviewed target changed. Review the current state before submitting. Your draft is preserved.");
    const currentMode = latestProfile?.mode;
    if (action.endsWith("-mode") && (!currentMode || ![nextMode(currentMode, false), nextMode(currentMode, true)].includes(mode as BaselineMode))) throw new Error("The requested mode is not a valid next transition.");
    const bodyReason = reason.trim();
    if (!bodyReason) throw new Error("A reason is required.");
    const target = workloadID(latest);
    const identity = JSON.stringify([clusterId, did, action, initial.revision, bodyReason]);
    if (requestKey.current?.identity !== identity) requestKey.current = { identity, key: crypto.randomUUID() };
    if (action === "apply-policy" || action === "demote-policy") return network.policyAction(target, action === "apply-policy" ? "apply" : "demote", { reason: bodyReason, candidate_hash: latest.network_policy!.candidate_hash, idempotency_key: requestKey.current.key }, { cluster_id: clusterId });
    if (action === "rollback-policy") return network.rollbackPolicy(target, { reason: bodyReason, rollback_ref: latest.network_policy!.rollback_ref!, idempotency_key: requestKey.current.key }, { cluster_id: clusterId });
    if (action === "lift-quarantine") return quarantine.lift(latest.quarantine!.id, { reason: bodyReason });
    if (action === "process-mode") return baselines.setMode(target, { mode: mode as BaselineMode, reason: bodyReason }, { cluster_id: clusterId });
    if (action === "file-mode") return fileProfiles.setMode(target, { mode: mode as BaselineMode, reason: bodyReason }, { cluster_id: clusterId });
    if (action === "file-rule-delete") return fileProfiles.deleteRule(target, resource, { reason: bodyReason }, { cluster_id: clusterId });
    if (action === "file-exception-delete") return fileProfiles.deleteException(target, resource, { reason: bodyReason }, { cluster_id: clusterId });
    if (action === "file-exception") {
      if (!filter.trim() || ruleId && !(latestProfile && "exceptions" in latestProfile && latestProfile.rules.some(rule => rule.id === ruleId))) throw new Error("Choose a current rule and enter a path filter.");
      return fileProfiles.createException(target, { filter: filter.trim(), rule_id: ruleId || undefined, applications: splitCSV(applications), description: description.trim(), reason: bodyReason, enabled: true }, { cluster_id: clusterId });
    }
    const bundle = parseBundle(bundleText);
    if (!confirmed) throw new Error("Review the file profile bundle and confirm replacement.");
    return fileProfiles.importBundle(target, { bundle, reason: bodyReason, replace: true }, { cluster_id: clusterId });
  }, onSuccess: () => { void qc.invalidateQueries({ queryKey: ["deployment"] }); void qc.invalidateQueries({ queryKey: ["file-monitor-detail"] }); void qc.invalidateQueries({ queryKey: ["file-monitor-profiles"] }); void qc.invalidateQueries({ queryKey: ["baseline"] }); void qc.invalidateQueries({ queryKey: ["network-policy-lifecycle"] }); if (isCurrent()) void navigate({ href: backTo }); } });
  const retry = () => { if (scopeReady) { void q.refetch(); if (usesProfile && control) void profileQ.refetch(); } else { void qc.invalidateQueries({ queryKey: ["clusters"] }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId] }); } };
  if (!initial) return context.clusterError ? <ErrorState title="The selected cluster is unavailable." action={<Button onClick={retry}>Retry</Button>} /> : sourceReady ? <LoadingState label="Preparing reviewed target…" /> : !scopeReady && !context.clusterError ? <LoadingState label="Resolving cluster…" /> : q.isPending || usesProfile && profileQ.isPending && !q.isError && !!detail ? <LoadingState label="Loading deployment and runtime profile…" /> : <ErrorState title="This action is not available for the exact deployment and current reported state." action={<Button onClick={retry}>Retry</Button>} />;
  const targetResource = action === "file-rule-delete" ? fileProfile?.rules.find(rule => rule.id === resource) : action === "file-exception-delete" ? fileProfile?.exceptions.find(exception => exception.id === resource) : undefined;
  return <>
    <VerdictBanner detailMode="inline" status="info" title={`${initial.detail.namespace}/${initial.detail.name}`} detail={ACTIONS[action].effect} />
    {(!sourceReady || changed) && <ErrorState title={!sourceReady ? "Could not refresh the exact deployment or profile. Your draft is preserved; refresh before saving." : "The reviewed state changed. Your draft is preserved."} action={<div className="flex flex-wrap gap-2"><Button onClick={retry}>Retry</Button>{sourceReady && detail && <Button onClick={() => { setInitial({ detail, profile, revision: currentRevision! }); setConfirmed(false); }}>Review current state</Button>}</div>} />}
    <Card title="Review and submit" description={`Exact workload: ${workloadID(initial.detail)} · cluster ${clusterId}`}>
      <form className="space-y-5" onSubmit={event => { event.preventDefault(); if (!sourceReady || changed || !draftValid || save.isPending || submitLock.current) return; submitLock.current = true; void save.mutateAsync().catch(() => {}).finally(() => { submitLock.current = false; }); }}>
        <fieldset disabled={save.isPending} className="space-y-5">
          {targetResource && <p className="text-sm" data-testid="deployment-action-selected-resource">Selected: {targetResource.filter} · {targetResource.id}</p>}
          {action.endsWith("-mode") && <label className="block space-y-2 text-sm"><span>Next profile mode · current {initial.profile?.mode}</span><Select value={mode} onChange={event => setMode(event.target.value as BaselineMode)} className="h-10 w-full rounded-md border border-border bg-background px-3" required><option value="">Choose a mode</option>{allowedModes.map(value => <option key={value} value={value}>{value}</option>)}</Select></label>}
          {action === "file-exception" && <><label className="block space-y-2 text-sm"><span>Path filter</span><input required value={filter} onChange={event => setFilter(event.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 font-mono" /></label><Collapse label="Advanced: exception scope"><div className="space-y-4"><label className="block space-y-2 text-sm"><span>Rule</span><Select value={ruleId} onChange={event => setRuleId(event.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3"><option value="">Workload-wide</option>{fileProfile?.rules.map(rule => <option key={rule.id} value={rule.id}>{rule.filter}</option>)}</Select></label><label className="block space-y-2 text-sm"><span>Applications, comma separated</span><input value={applications} onChange={event => setApplications(event.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3" /></label><label className="block space-y-2 text-sm"><span>Description</span><input value={description} onChange={event => setDescription(event.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3" /></label></div></Collapse></>}
          {action === "file-bundle-import" && <><label className="block space-y-2 text-sm"><span>File profile bundle JSON</span><textarea required value={bundleText} onChange={event => setBundleText(event.target.value)} rows={10} className="w-full rounded-md border border-border bg-background p-3 font-mono" /></label>{clearsProfile && <p role="alert" className="text-sm text-status-warning">This explicitly empty bundle removes every configured rule and exception. The resulting mode is {bundlePreview?.mode || "learn"}.</p>}{bundleRetargeted && <p role="alert" className="text-sm text-status-warning">The bundle identifies another workload or cluster. Its portable configuration will be retargeted to this reviewed deployment.</p>}{bundlePreview && <p className="text-sm text-muted-foreground">Reviewed bundle: {bundlePreview.rules?.length ?? 0} rules · {bundlePreview.exceptions?.length ?? 0} exceptions · mode {bundlePreview.mode || (bundlePreview.rules?.length ? "monitor" : "learn")}. Missing schema version is interpreted by the server as v1.</p>}<label className="flex items-center gap-3 text-sm"><input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} /> I reviewed the bundle and will replace existing rules and exceptions.</label></>}
          <label className="block space-y-2 text-sm"><span>Reason</span><textarea required value={reason} onChange={event => setReason(event.target.value)} rows={3} className="w-full rounded-md border border-border bg-background p-3" data-testid="deployment-action-reason" /></label>
          <Collapse label="Advanced: reviewed source state"><pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all text-xs">{initial.revision}</pre></Collapse>
        </fieldset>
        {save.isError && <ErrorState title={save.error instanceof Error ? save.error.message : "Action failed. Your draft is preserved."} />}
        <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" disabled={!sourceReady || changed || !draftValid || save.isPending}>{save.isPending ? "Submitting…" : ACTIONS[action].submit}</Button></div>
      </form>
    </Card>
  </>;
}
