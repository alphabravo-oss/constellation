import { useEffect, useState, type ReactNode } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { findings, type Finding } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { useExportGuard, exportQueryReady } from "@/hooks/useExportGuard";
import { ambiguousFinding, findingChooserHref, findingDTOReady, findingEpochNanos, findingHref, findingReceiptMatches } from "@/lib/finding-instance";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, TextInput, Textarea } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";

type Action = "accept-risk" | "suppress" | "comment";
const ACTIONS = {
  "accept-risk": { title: "Accept finding risk", description: "Record a justified, temporary acceptance for this finding. It expires within 30 days." },
  suppress: { title: "Suppress finding", description: "Record why this finding should be suppressed. Suppression has no automatic expiry." },
  comment: { title: "Add finding comment", description: "Add a comment to this finding's history without changing its lifecycle." },
};
const MAX_EXPIRY_MS = 30 * 86400_000;
function localDateTime(timestamp: number) { const date = new Date(timestamp); return new Date(timestamp - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16); }
function expiryValid(value: string) { const timestamp = new Date(value).getTime(); return Boolean(value) && Number.isFinite(timestamp) && timestamp > Date.now() && timestamp <= Date.now() + MAX_EXPIRY_MS; }
function byteLength(value: string) { return new TextEncoder().encode(value).length; }
const uuidValid = (value: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

export function FindingAcceptRiskFormPage() { return <FindingActionForm action="accept-risk" />; }
export function FindingSuppressFormPage() { return <FindingActionForm action="suppress" />; }
export function FindingCommentFormPage() { return <FindingActionForm action="comment" />; }

function FindingActionForm({ action }: { action: Action }) {
  const { fid } = useParams({ strict: false });
  const { clusterId, cluster, isLoading, error } = useCluster();
  const operator = useTablePreferencesIdentity();
  const [params] = useRouteSearchParams();
  const firstSeen = params.get("first_seen_at") ?? undefined;
  const detailPath = clusterId && fid ? findingHref({ id: fid, first_seen_at: firstSeen ?? "" }, clusterId) : clusterId ? `/clusters/${clusterId}/findings` : "/findings";
  return <div className="space-y-6" data-testid="finding-action-form-page">
    <PageHeader title={ACTIONS[action].title} description={ACTIONS[action].description}
      backLink={<a href={detailPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Finding</a>} />
    {!clusterId || !fid ? <ErrorState title="Select an available cluster and finding to continue." />
      : <FindingScope key={`${operator?.org_id}:${operator?.user_id}:${clusterId}:${fid}:${firstSeen}:${action}`} clusterId={clusterId} findingId={fid} resolvedClusterId={cluster?.id} clusterLoading={isLoading} clusterError={Boolean(error)}>
          {(finding, unavailable, recheck, refresh) => <FindingActionEditor action={action} finding={finding} detailPath={findingHref(finding, clusterId)} clusterId={clusterId} unavailable={unavailable} recheck={recheck} refresh={refresh} />}
        </FindingScope>}
  </div>;
}

// Both the read-only detail and authoring pages prove the entity belongs to the
// active, settled cluster. Once loaded, retained content never enables stale writes.
export function FindingScope({ clusterId, findingId, resolvedClusterId, clusterLoading, clusterError, children }: {
  clusterId: string; findingId: string; resolvedClusterId?: string; clusterLoading: boolean; clusterError: boolean;
  children: (finding: Finding, unavailable: boolean, recheck: () => boolean, refresh: () => Promise<boolean>) => ReactNode;
}) {
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const [params, setParams] = useRouteSearchParams();
  const selectors = params.getAll("first_seen_at");
  const firstSeen = selectors[0];
  const validSelector = selectors.length <= 1 && (!selectors.length || findingEpochNanos(firstSeen) !== null);
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const cachedClusterReady = () => {
    const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const detail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle" || registry.isInvalidated)) return false;
    if (detail && (detail.status === "error" || detail.fetchStatus !== "idle" || detail.isInvalidated)) return false;
    if (!registry && !detail) return true;
    return (registry?.data?.clusters.find((item) => item.id === clusterId) ?? detail?.data)?.id === clusterId;
  };
  const clusterReady = !!identity?.org_id && !!identity?.user_id && resolvedClusterId === clusterId && !clusterLoading && !clusterError && !registryFetching && !detailFetching && cachedClusterReady();
  const key = ["finding", owner, clusterId, findingId, firstSeen ?? "legacy"];
  const q = useQuery({ queryKey: key, queryFn: () => firstSeen ? findings.instance(findingId, { first_seen_at: firstSeen, cluster_id: clusterId }) : findings.get(findingId), enabled: clusterReady && validSelector, gcTime: 0, refetchOnMount: "always" });
  const matching = findingDTOReady(q.data, findingId, clusterId, firstSeen);
  const ready = clusterReady && validSelector && q.isSuccess && q.fetchStatus === "idle" && !qc.getQueryState(key)?.isInvalidated && matching;
  useEffect(() => { if (ready && !firstSeen) setParams(current => { current.set("first_seen_at", q.data!.first_seen_at); return current; }, { replace: true }); }, [ready, firstSeen, q.data, setParams]);
  const scope = JSON.stringify([owner, clusterId, findingId, firstSeen ?? "legacy"]);
  const [snapshot, setSnapshot] = useState<{ scope: string; finding: Finding } | null>(null);
  const confirmed = snapshot?.scope === scope ? snapshot.finding : null;
  if (!confirmed && ready) setSnapshot({ scope, finding: q.data! });
  const retry = () => { void qc.invalidateQueries({ queryKey: ["clusters"], exact: true }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true }); if (clusterReady) void q.refetch(); };
  if (!confirmed && !ready) {
    if (!validSelector) return <ErrorState title="Select one valid observation timestamp to continue." />;
    if (ambiguousFinding(q.error)) return <ErrorState title="This finding has multiple retained observations." action={<a href={findingChooserHref(clusterId, findingId)}>Choose an observation</a>} />;
    if (clusterLoading || registryFetching || detailFetching || (clusterReady && (q.isPending || q.isFetching))) return <LoadingState label="Loading finding and cluster scope…" />;
    return <ErrorState title={!clusterReady ? "The selected cluster could not be resolved." : "This finding could not be loaded in the selected cluster."} action={<Button onClick={retry}>Retry</Button>} />;
  }
  const recheck = () => {
    const current = qc.getQueryState<Finding>(key);
    return clusterReady && cachedClusterReady() && exportQueryReady(qc, key, q.data) && findingDTOReady(current?.data, findingId, clusterId, firstSeen);
  };
  const refresh = async () => {
    if (!clusterReady || !cachedClusterReady()) return false;
    const result = await q.refetch();
    return cachedClusterReady() && result.isSuccess && result.fetchStatus === "idle" && findingDTOReady(result.data, findingId, clusterId, firstSeen) && !qc.getQueryState(key)?.isInvalidated;
  };
  return <>
    {!ready && <ErrorState title="Current finding or cluster scope is unavailable or refreshing. Your draft is preserved; saving is paused until it resolves." action={<Button onClick={retry}>Retry</Button>} />}
    {children(ready ? q.data : confirmed!, !ready, recheck, refresh)}
  </>;
}

function FindingActionEditor({ action, finding, detailPath, clusterId, unavailable, recheck, refresh }: { action: Action; finding: Finding; detailPath: string; clusterId: string; unavailable: boolean; recheck: () => boolean; refresh: () => Promise<boolean> }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const [text, setText] = useState("");
  const [expiry, setExpiry] = useState(() => localDateTime(Date.now() + 7 * 86400_000));
  const [approver, setApprover] = useState("");
  const captureCurrent = useExportGuard(JSON.stringify([identity?.org_id, identity?.user_id, clusterId, finding.id, finding.first_seen_at, finding.revision]), unavailable, recheck);
  const [reviewRequired, setReviewRequired] = useState(false);
  const review = useMutation({ mutationFn: async () => { if (!await refresh()) throw new Error("Observation refresh failed"); }, onSuccess: () => setReviewRequired(false) });
  const [uncertain, setUncertain] = useState(false);
  const trimmed = text.trim();
  const approverTrimmed = approver.trim();
  const approverOK = !approverTrimmed || (uuidValid(approverTrimmed) && approverTrimmed.toLowerCase() !== identity?.user_id.toLowerCase());
  const textOK = action === "accept-risk" ? trimmed.length >= 12 : action === "comment" ? Boolean(trimmed) && byteLength(trimmed) <= 16000 : Boolean(trimmed);
  const valid = textOK && (action !== "accept-risk" || (expiryValid(expiry) && approverOK));
  const save = useMutation({
    mutationFn: async () => {
      if (!valid || uncertain || reviewRequired || unavailable || !recheck() || (action === "accept-risk" && !expiryValid(expiry))) throw new Error("Finding action is unavailable");
      const current = captureCurrent();
      const selector = { first_seen_at: finding.first_seen_at, cluster_id: clusterId };
      const reviewed_revision = finding.revision!;
      const receipt = action === "accept-risk"
        ? await findings.instanceAcceptRisk(finding.id, selector, { reviewed_revision, reason: trimmed, accepted_until: new Date(expiry).toISOString(), ...(approverTrimmed ? { approver_id: approverTrimmed } : {}) })
        : action === "suppress" ? await findings.instanceSuppress(finding.id, selector, { reviewed_revision, reason: trimmed })
        : await findings.instanceAddComment(finding.id, selector, { reviewed_revision, body: trimmed });
      if (!current()) { setUncertain(true); throw new Error("The action response is no longer current. Reload before another write."); }
      if (!findingReceiptMatches(action === "comment" ? { ...receipt, id: (receipt as { finding_id?: string }).finding_id } : receipt, finding, clusterId, action === "comment")) { setUncertain(true); throw new Error("The saved observation could not be confirmed. Reload before trying another write."); }
      void qc.invalidateQueries({ queryKey: ["finding"] }); void qc.invalidateQueries({ queryKey: ["finding-comments"] });
      void qc.invalidateQueries({ queryKey: ["findings"] }); void qc.invalidateQueries({ queryKey: ["findings-cve"] });
      for (const key of ["risk-entity", "risk-related", "risk-related-critical", "risk-related-high", "bell-feed", "cmdk-findings", "vulnerability-exceptions", "asset-findings", "deployment-findings-inventory", "asset", "deployment", "dashboard"]) void qc.invalidateQueries({ queryKey: [key] });
      void navigate({ href: detailPath });
    },
    onError: error => { if ((error as { response?: { status?: number } }).response?.status === 409) setReviewRequired(true); },
  });
  return <Card title={finding.title} description={<span>{finding.external_id || finding.id} · {finding.lifecycle} · cluster {finding.cluster_id}</span>}>
    <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (valid && !unavailable && !uncertain && !reviewRequired && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <Field label={action === "comment" ? "Comment" : "Reason"} htmlFor="finding-action-text" required
          hint={action === "accept-risk" ? "At least 12 characters. Explain the justification and compensating controls." : action === "comment" ? "Comments are saved to this finding's history. Maximum 16,000 bytes." : "Explain why this finding should be suppressed. The reason is recorded in the audit log."}>
          <Textarea id="finding-action-text" required autoFocus rows={5} value={text} onChange={(event) => setText(event.target.value)} />
        </Field>
        {action === "accept-risk" && <>
          <Field label="Expiry (local time)" htmlFor="finding-action-expiry" required hint="Choose a future date and time within 30 days. The acceptance expires automatically.">
            <TextInput id="finding-action-expiry" type="datetime-local" value={expiry} min={localDateTime(Date.now())} max={localDateTime(Date.now() + MAX_EXPIRY_MS)} required onChange={(event) => setExpiry(event.target.value)} />
          </Field>
          {!expiryValid(expiry) && <p role="alert" className="text-sm text-status-error">Expiry must be in the future and within 30 days.</p>}
          <Collapse label="Advanced"><Field label="Approver ID (optional)" htmlFor="finding-action-approver" hint="Use a different user's UUID when recording an approver. Leaving this blank does not assign an approver.">
            <TextInput id="finding-action-approver" value={approver} onChange={(event) => setApprover(event.target.value)} placeholder="User UUID" />
          </Field>{!approverOK && <p role="alert" className="mt-2 text-sm text-status-error">Approver must be a valid UUID and differ from the requester.</p>}</Collapse>
        </>}
        {text && !textOK && <p role="alert" className="text-sm text-status-error">{action === "accept-risk" ? "Provide a reason of at least 12 characters." : action === "comment" ? "Provide a nonempty comment of at most 16,000 bytes." : "Provide a nonempty reason."}</p>}
        <Collapse label="Observation details"><dl className="space-y-2 text-sm"><div><dt>First observed</dt><dd className="font-mono">{finding.first_seen_at}</dd></div><div><dt>Reviewed revision</dt><dd>{finding.revision}</dd></div><div><dt>Lifecycle</dt><dd>{finding.lifecycle}</dd></div></dl></Collapse>
        {reviewRequired && <ErrorState title="This observation changed after review. Refresh it and review its current lifecycle before saving." action={<Button type="button" disabled={review.isPending || save.isPending} onClick={() => review.mutate()}>{review.isPending ? "Refreshing…" : "Refresh observation"}</Button>} />}
        {review.isError && <ErrorState title="Could not refresh the observation. Your draft is preserved; saving is paused." />}
        {save.isError && !reviewRequired && <ErrorState title={uncertain ? "The saved observation could not be confirmed. Your draft is preserved; reload before another write." : "Could not save this finding action. Your draft is preserved. Refresh the reviewed observation before retrying."} />}
        <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={!valid || unavailable || uncertain || reviewRequired || review.isPending || save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: detailPath })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
