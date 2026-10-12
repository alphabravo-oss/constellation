import { useState, type ReactNode } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { findings, type Finding } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
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
  const detailPath = clusterId && fid ? `/clusters/${clusterId}/findings/${encodeURIComponent(fid)}` : clusterId ? `/clusters/${clusterId}/findings` : "/findings";
  return <div className="space-y-6" data-testid="finding-action-form-page">
    <PageHeader title={ACTIONS[action].title} description={ACTIONS[action].description}
      backLink={<a href={detailPath} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Finding</a>} />
    {!clusterId || !fid ? <ErrorState title="Select an available cluster and finding to continue." />
      : <FindingScope key={`${clusterId}:${fid}:${action}`} clusterId={clusterId} findingId={fid} resolvedClusterId={cluster?.id} clusterLoading={isLoading} clusterError={Boolean(error)}>
          {(finding, unavailable, recheck) => <FindingActionEditor action={action} finding={finding} detailPath={detailPath} unavailable={unavailable} recheck={recheck} />}
        </FindingScope>}
  </div>;
}

// Both the read-only detail and authoring pages prove the entity belongs to the
// active, settled cluster. Once loaded, retained content never enables stale writes.
export function FindingScope({ clusterId, findingId, resolvedClusterId, clusterLoading, clusterError, children }: {
  clusterId: string; findingId: string; resolvedClusterId?: string; clusterLoading: boolean; clusterError: boolean;
  children: (finding: Finding, unavailable: boolean, recheck: () => boolean) => ReactNode;
}) {
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const cachedClusterReady = () => {
    const registry = qc.getQueryState<{ clusters: Array<{ id: string }> }>(["clusters"]);
    const detail = qc.getQueryState<{ id: string }>(["cluster", clusterId]);
    if (registry && (registry.status !== "success" || registry.fetchStatus !== "idle")) return false;
    if (detail && (detail.status === "error" || detail.fetchStatus !== "idle")) return false;
    if (!registry && !detail) return true;
    return (registry?.data?.clusters.find((item) => item.id === clusterId) ?? detail?.data)?.id === clusterId;
  };
  const clusterReady = resolvedClusterId === clusterId && !clusterLoading && !clusterError && !registryFetching && !detailFetching && cachedClusterReady();
  const key = ["finding", clusterId, findingId];
  const q = useQuery({ queryKey: key, queryFn: () => findings.get(findingId), enabled: clusterReady, gcTime: 0, refetchOnMount: "always" });
  const matching = q.data?.id === findingId && q.data.cluster_id === clusterId;
  const ready = clusterReady && q.isSuccess && q.fetchStatus === "idle" && matching;
  const [confirmed, setConfirmed] = useState<Finding | null>(null);
  if (!confirmed && ready) setConfirmed(q.data);
  const retry = () => { void qc.invalidateQueries({ queryKey: ["clusters"], exact: true }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true }); if (clusterReady) void q.refetch(); };
  if (!confirmed && !ready) {
    if (clusterLoading || registryFetching || detailFetching || (clusterReady && (q.isPending || q.isFetching))) return <LoadingState label="Loading finding and cluster scope…" />;
    return <ErrorState title={!clusterReady ? "The selected cluster could not be resolved." : "This finding could not be loaded in the selected cluster."} action={<Button onClick={retry}>Retry</Button>} />;
  }
  const recheck = () => {
    const current = qc.getQueryState<Finding>(key);
    return clusterReady && cachedClusterReady() && current?.status === "success" && current.fetchStatus === "idle" && current.data?.id === findingId && current.data.cluster_id === clusterId;
  };
  return <>
    {!ready && <ErrorState title="Current finding or cluster scope is unavailable or refreshing. Your draft is preserved; saving is paused until it resolves." action={<Button onClick={retry}>Retry</Button>} />}
    {children(ready ? q.data : confirmed!, !ready, recheck)}
  </>;
}

function FindingActionEditor({ action, finding, detailPath, unavailable, recheck }: { action: Action; finding: Finding; detailPath: string; unavailable: boolean; recheck: () => boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const identity = useTablePreferencesIdentity();
  const [text, setText] = useState("");
  const [expiry, setExpiry] = useState(() => localDateTime(Date.now() + 7 * 86400_000));
  const [approver, setApprover] = useState("");
  const trimmed = text.trim();
  const approverTrimmed = approver.trim();
  const approverOK = !approverTrimmed || (uuidValid(approverTrimmed) && approverTrimmed.toLowerCase() !== identity?.user_id.toLowerCase());
  const textOK = action === "accept-risk" ? trimmed.length >= 12 : action === "comment" ? Boolean(trimmed) && byteLength(trimmed) <= 16000 : Boolean(trimmed);
  const valid = textOK && (action !== "accept-risk" || (expiryValid(expiry) && approverOK));
  const save = useMutation({
    mutationFn: async () => {
      if (!valid || unavailable || !recheck() || (action === "accept-risk" && !expiryValid(expiry))) throw new Error("Finding action is unavailable");
      if (action === "accept-risk") await findings.acceptRisk(finding.id, { reason: trimmed, accepted_until: new Date(expiry).toISOString(), ...(approverTrimmed ? { approver_id: approverTrimmed } : {}) });
      else if (action === "suppress") await findings.suppress(finding.id, { reason: trimmed });
      else await findings.addComment(finding.id, { body: trimmed });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["finding"] }); void qc.invalidateQueries({ queryKey: ["finding-comments"] });
      void qc.invalidateQueries({ queryKey: ["findings"] }); void qc.invalidateQueries({ queryKey: ["findings-cve"] });
      void navigate({ href: detailPath });
    },
  });
  return <Card title={finding.title} description={<span>{finding.external_id || finding.id} · {finding.lifecycle} · cluster {finding.cluster_id}</span>}>
    <form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (valid && !unavailable && !save.isPending) save.mutate(); }}>
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
        {save.isError && <ErrorState title="Could not save this finding action. Your draft is preserved. Review the values and try again." />}
        <div className="flex gap-3"><Button type="submit" variant="primary" size="lg" disabled={!valid || unavailable || save.isPending}>{save.isPending ? "Saving…" : "Save"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => void navigate({ href: detailPath })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
