import { assetDisplayName } from "@/lib/asset-identity";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useParams } from "@tanstack/react-router";
import { assets, type AssetDetail, type ImageAcceptance } from "@/api/client";
import { dateInputDaysFromNow, dateInputEndOfDayWithinDays } from "@/lib/format";
import { PageContainer, PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Textarea, TextInput } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { assertAssetScope, assetDate, assetDetailKey, assetErrorMessage, useAssetDetailScope } from "./asset-detail-scope";

export function AssetImageAcceptanceFormPage({ action = "create" }: { action?: "create" | "revoke" }) {
  const scope = useAssetDetailScope();
  const { acceptanceId } = useParams({ strict: false });
  const { clusterId, aid, resolved, q } = scope;
  const backPath = clusterId && aid ? `/clusters/${encodeURIComponent(clusterId)}/assets/${encodeURIComponent(aid)}?tab=acceptance` : "/clusters";
  const context = `${scope.owner}:${clusterId}:${aid}:${action}:${acceptanceId ?? "new"}`;
  const [captured, setCaptured] = useState<{ context: string; data: AssetDetail }>();
  useEffect(() => {
    if (resolved && q.isSuccess && q.fetchStatus === "idle" && q.data?.image?.digest) {
      setCaptured((previous) => previous?.context === context ? previous : { context, data: q.data });
    }
  }, [resolved, q.isSuccess, q.fetchStatus, q.data, context]);
  const initial = captured?.context === context ? captured.data : undefined;
  return <PageContainer>
    <PageHeader title={action === "create" ? "Accept image risk" : "Revoke image risk acceptance"} description="Record an audited risk decision for an exact image digest. The decision applies across the organization, including other assets using this digest." backLink={<a href={backPath}>Asset risk acceptance</a>} />
    {!initial ? !resolved ? scope.clusterLoading ? <LoadingState label="Resolving image acceptance cluster…" /> : <ErrorState title="The requested cluster could not be resolved." error={scope.clusterError} action={<Button onClick={scope.retryCluster}>Retry cluster</Button>} />
      : q.isError ? <ErrorState title="The image asset could not be loaded." error={assetErrorMessage(q.error)} action={<Button onClick={() => void q.refetch()}>Retry asset</Button>} />
      : q.isPending || q.isFetching ? <LoadingState label="Loading exact image digest…" />
      : !q.data?.image?.digest ? <ErrorState title="This asset has no image digest that can be accepted." />
      : <LoadingState label="Preparing image risk decision…" />
      : <ImageAcceptanceEditor owner={scope.owner} key={context} action={action} acceptanceId={acceptanceId} initial={initial} clusterId={clusterId!} backPath={backPath} available={resolved && q.isSuccess && q.fetchStatus === "idle"} refreshing={scope.clusterLoading || q.isFetching} sourceError={scope.clusterError ?? q.error} recheck={scope.recheck} refresh={() => { scope.retryCluster(); if (resolved) void q.refetch(); }} />}
    <a href={backPath} className="inline-flex text-sm text-muted-foreground hover:text-foreground">Cancel</a>
  </PageContainer>;
}

function acceptanceIdentity(item: ImageAcceptance | undefined) { return item ? JSON.stringify([item.id, item.image_digest, item.rationale, item.accepted_until, item.status]) : ""; }

function ImageAcceptanceEditor({ owner, action, acceptanceId, initial, clusterId, backPath, available, refreshing, sourceError, recheck, refresh }: {
  owner: string; action: "create" | "revoke"; acceptanceId?: string; initial: AssetDetail; clusterId: string; backPath: string;
  available: boolean; refreshing: boolean; sourceError: unknown; recheck: () => AssetDetail | undefined; refresh: () => void;
}) {
  const qc = useQueryClient();
  const active = useRef(true);
  const submitting = useRef(false);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const [rationale, setRationale] = useState("");
  const [until, setUntil] = useState(() => dateInputDaysFromNow(14));
  const [result, setResult] = useState("");
  const [unconfirmed, setUnconfirmed] = useState(false);
  const digest = initial.image!.digest;
  const reviewedAcceptance = initial.image_acceptances.find((item) => item.id === acceptanceId && item.image_digest === digest);
  const current = available ? recheck() : undefined;
  const currentAcceptance = current?.image_acceptances.find((item) => item.id === acceptanceId && item.image_digest === digest);
  const unchanged = !!current && current.image?.digest === digest && (action === "create" ? !current.image_acceptances.some((item) => item.status === "active") : !!reviewedAcceptance && reviewedAcceptance.status === "active" && acceptanceIdentity(currentAcceptance) === acceptanceIdentity(reviewedAcceptance));
  const date = /^\d{4}-\d{2}-\d{2}$/.test(until) ? Date.parse(`${until}T23:59:59Z`) : NaN;
  const expiryValid = Number.isFinite(date) && date > Date.now() && until <= dateInputDaysFromNow(30);
  const ready = available && unchanged && !unconfirmed && (action === "revoke" || rationale.trim().length >= 12 && expiryValid);
  const currentScope = useRef(() => current);
  currentScope.current = () => available ? recheck() : undefined;
  const save = useMutation({
    mutationFn: async () => {
      const validTarget = (data: AssetDetail | undefined) => !!data && data.image?.digest === digest && (action === "create" ? !data.image_acceptances.some((item) => item.status === "active") : acceptanceIdentity(data.image_acceptances.find((item) => item.id === acceptanceId && item.image_digest === digest)) === acceptanceIdentity(reviewedAcceptance) && reviewedAcceptance?.status === "active");
      if (!active.current || !ready || !validTarget(currentScope.current())) throw new Error("The exact image or acceptance is unavailable, refreshing or changed. Your draft is preserved.");
      const identity = { expected_image_digest: digest, cluster_id: clusterId };
      const body = { rationale: rationale.trim(), accepted_until: dateInputEndOfDayWithinDays(until, 30), ...identity };
      const fresh = assertAssetScope(await assets.get(initial.asset.id), clusterId, initial.asset.id);
      if (!active.current || !validTarget(fresh) || !validTarget(currentScope.current())) throw new Error("The image digest or acceptance changed before submission. Return to the asset and review the current target. Your draft is preserved.");
      if (action === "create") {
        const response = await assets.createImageAcceptance(initial.asset.id, body);
        const recorded = response.image_acceptances?.find((item) => item.id === response.id);
        if (response.asset_id !== initial.asset.id || response.cluster_id !== clusterId || response.image_digest !== digest || !recorded || recorded.image_digest !== digest || recorded.status !== "active" || recorded.rationale !== body.rationale || Date.parse(recorded.accepted_until) !== Date.parse(body.accepted_until)) {
          if (active.current) setUnconfirmed(true);
          throw new Error("The response did not confirm the reviewed digest and risk decision. Review acceptance history before submitting another decision.");
        }
        return "Image risk acceptance recorded for this organization-wide digest. Findings remain visible until they are resolved separately.";
      }
      const response = await assets.revokeImageAcceptance(initial.asset.id, acceptanceId!, identity);
      const recorded = response.image_acceptances?.find((item) => item.id === acceptanceId);
      if (response.asset_id !== initial.asset.id || response.cluster_id !== clusterId || response.image_digest !== digest || response.status !== "revoked" || recorded?.image_digest !== digest || recorded.status !== "revoked") {
        if (active.current) setUnconfirmed(true);
        throw new Error("The response did not confirm revocation of the reviewed acceptance. Review acceptance history before trying again.");
      }
      return "Image risk acceptance revoked for this organization-wide digest.";
    },
    onSuccess: (message) => {
      void qc.invalidateQueries({ queryKey: assetDetailKey(clusterId, initial.asset.id, owner), exact: true });
      void qc.invalidateQueries({ queryKey: ["assets"] });
      if (active.current) setResult(message);
    },
    onSettled: () => { submitting.current = false; },
  });
  return <>
    <VerdictBanner detailMode="inline" status="info" title={action === "create" ? "Accepting risk does not remove findings" : "Revocation ends this risk decision"} detail="This decision is digest scoped and organization wide. It does not verify the image, resolve vulnerabilities or change network enforcement." />
    {!result && !available && (refreshing ? <p role="status" className="text-sm text-muted-foreground">Refreshing the current cluster or image. Your draft is preserved; wait before saving.</p> : <ErrorState title="The cluster or image could not be refreshed. Your draft is preserved; retry before saving." error={sourceError ? assetErrorMessage(sourceError) : undefined} />)}
    {!result && available && !unchanged && <ErrorState title={action === "create" ? "The image digest changed or an active acceptance already exists. Review the asset before accepting risk." : "The requested active acceptance is missing or changed. No other acceptance has been substituted."} />}
    <Card title={action === "create" ? "Image risk decision" : "Review acceptance revocation"} description="Review the immutable cluster, asset and image digest before saving.">
      <form className="space-y-5" onSubmit={(event) => { event.preventDefault(); if (ready && !submitting.current && !save.isPending && !result) { submitting.current = true; save.mutate(); } }}>
        <dl className="space-y-3 text-sm"><div><dt className="text-muted-foreground">Cluster</dt><dd>{clusterId}</dd></div><div><dt className="text-muted-foreground">Asset</dt><dd>{assetDisplayName(initial.asset, initial.image)}</dd></div><div><dt className="text-muted-foreground">Image digest · organization-wide scope</dt><dd><DigestDisclosure digest={digest} /></dd></div></dl>
        {action === "create" ? <fieldset className="space-y-5" disabled={save.isPending || !!result}>
          <Field label="Rationale" htmlFor="image-accept-rationale" required hint="At least 12 characters. Include a compensating control, ticket or deployment justification."><Textarea id="image-accept-rationale" required minLength={12} value={rationale} onChange={(event) => setRationale(event.target.value)} /></Field>
          <Field label="Accepted until" htmlFor="image-accept-until" required hint="Expires at the end of the selected UTC day, capped at 30 days from saving."><TextInput id="image-accept-until" type="date" required min={dateInputDaysFromNow(0)} max={dateInputDaysFromNow(30)} value={until} onChange={(event) => setUntil(event.target.value)} /></Field>
          <Collapse label="Advanced: digest scope"><div className="space-y-3 text-sm text-muted-foreground"><p>An acceptance applies to this exact digest across the organization. Another tag or changed image digest needs its own reviewed decision. The approver and decision are recorded in the audit log.</p><p>Saving is rejected if the asset's image digest or cluster changes after this review.</p></div></Collapse>
        </fieldset> : reviewedAcceptance && <div className="space-y-2 rounded-md border border-border p-4"><p className="text-sm">{reviewedAcceptance.rationale}</p><p className="text-xs text-muted-foreground">Accepted until {assetDate(reviewedAcceptance.accepted_until)} · {reviewedAcceptance.status}</p><p className="text-sm">Revoke this acceptance for all assets using the digest. This does not resolve their findings.</p></div>}
        {save.isError && <p role="alert" className="text-sm text-status-error">{assetErrorMessage(save.error)}</p>}
        {result && <p role="status" className="text-sm" data-testid="image-acceptance-result">{result}</p>}
        <div className="flex flex-wrap gap-3">{result ? <a href={backPath} className="rounded-md border border-border px-3 py-2 text-sm">Back to asset</a> : <Button type="submit" variant="primary" disabled={!ready || save.isPending}>{save.isPending ? "Saving…" : action === "create" ? "Save acceptance" : "Revoke acceptance"}</Button>}<Button type="button" onClick={refresh} disabled={save.isPending || !!result}>Refresh current target</Button></div>
      </form>
    </Card>
  </>;
}
