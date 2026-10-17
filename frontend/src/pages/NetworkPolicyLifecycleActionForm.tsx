import { useEffect, useRef, useState } from "react";
import {
  useIsFetching,
  useMutation,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import { network, type NetworkPolicyLifecycle } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import {
  policyActionAvailable,
  policyRevision,
  policySource,
  networkReturn,
} from "./network-secondary";
const META = {
  "apply-policy": {
    title: "Apply reviewed network policy",
    submit: "Apply policy",
  },
  "demote-policy": { title: "Demote network policy", submit: "Demote policy" },
  "rollback-policy": {
    title: "Roll back network policy",
    submit: "Roll back policy",
  },
};
export type LifecycleAction = keyof typeof META;
export function NetworkPolicyLifecycleActionForm({
  action,
}: {
  action: LifecycleAction;
}) {
  const [params] = useRouteSearchParams();
  const scope = useCluster();
  const source = policySource(params);
  const workload = params.get("workload") ?? "";
  return (
    <LifecycleActionScope
      key={JSON.stringify([scope.clusterId, workload, action, source])}
      action={action}
      clusterId={scope.clusterId}
      scope={scope}
      workload={workload}
      source={source}
      params={params}
    />
  );
}
function LifecycleActionScope({
  action,
  clusterId,
  scope,
  workload,
  source,
  params,
}: {
  action: LifecycleAction;
  clusterId?: string;
  scope: ReturnType<typeof useCluster>;
  workload: string;
  source: ReturnType<typeof policySource>;
  params: URLSearchParams;
}) {
  const qc = useQueryClient();
  const registry = useIsFetching({ queryKey: ["clusters"], exact: true });
  const clusterFetch = useIsFetching({
    queryKey: ["cluster", clusterId],
    exact: true,
  });
  const resolved =
    !!clusterId &&
    scope.cluster?.id === clusterId &&
    !scope.isLoading &&
    !scope.error &&
    !registry &&
    !clusterFetch &&
    clusterCacheReady(qc, clusterId);
  const key = ["network-lifecycle-action", clusterId, workload, source];
  const q = useQuery({
    queryKey: key,
    enabled: resolved && !!workload,
    queryFn: () => network.lifecycle({ ...source, cluster_id: clusterId! }),
  });
  const matches =
    q.data && q.data.summary.selected_cluster_id === clusterId
      ? q.data.items.filter(
          (p) => p.cluster_id === clusterId && p.workload === workload,
        )
      : [];
  const candidate = matches.length === 1 ? matches[0] : undefined;
  const ready =
    resolved &&
    q.isSuccess &&
    !q.isFetching &&
    !q.isError &&
    !!candidate &&
    policyActionAvailable(action, candidate);
  const [reviewed, setReviewed] = useState<NetworkPolicyLifecycle>();
  useEffect(() => {
    if (ready && !reviewed) setReviewed(candidate);
  }, [ready, reviewed, candidate]);
  const [reason, setReason] = useState("");
  const [result, setResult] = useState("");
  const [unconfirmed, setUnconfirmed] = useState(false);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const lock = useRef(false);
  const uncertain = useRef(false);
  const request = useRef<{ identity: string; key: string } | undefined>(
    undefined,
  );
  const currentOwner = useRef(resolved);
  currentOwner.current = resolved;
  const back = clusterId ? networkReturn(clusterId, params) : "/clusters";
  const changed =
    !!reviewed &&
    (!candidate || policyRevision(candidate) !== policyRevision(reviewed));
  const current = () => {
    const state =
      qc.getQueryState<Awaited<ReturnType<typeof network.lifecycle>>>(key);
    const found =
      state?.data && state.data.summary.selected_cluster_id === clusterId
        ? state.data.items.filter(
            (p) => p.cluster_id === clusterId && p.workload === workload,
          )
        : [];
    if (
      !active.current ||
      !currentOwner.current ||
      !clusterId ||
      !clusterCacheReady(qc, clusterId) ||
      state?.status !== "success" ||
      state.fetchStatus !== "idle" ||
      state.isInvalidated ||
      found.length !== 1 ||
      !reviewed ||
      policyRevision(found[0]) !== policyRevision(reviewed) ||
      !policyActionAvailable(action, found[0])
    )
      throw new Error(
        "Refresh and review this exact policy before saving. Your reason is preserved.",
      );
    return found[0];
  };
  const save = useMutation({
    mutationFn: async () => {
      if (!reason.trim() || uncertain.current)
        throw new Error("Review the current policy and provide a reason.");
      const selected = current();
      const fresh = await network.lifecycle({
        ...source,
        cluster_id: clusterId!,
      });
      current();
      const matches =
        fresh.summary.selected_cluster_id === clusterId
          ? fresh.items.filter(
              (p) => p.workload === workload && p.cluster_id === clusterId,
            )
          : [];
      if (
        matches.length !== 1 ||
        policyRevision(matches[0]) !== policyRevision(selected) ||
        !policyActionAvailable(action, matches[0])
      ) {
        qc.setQueryData(key, fresh);
        throw new Error(
          "The reviewed policy changed before submission. Your reason is preserved; review its current state.",
        );
      }
      const identity = JSON.stringify([
        action,
        policyRevision(selected),
        reason.trim(),
      ]);
      if (request.current?.identity !== identity)
        request.current = { identity, key: crypto.randomUUID() };
      const response =
        action === "rollback-policy"
          ? await network.rollbackPolicy(
              workload,
              {
                rollback_ref: selected.rollback_ref!,
                reason: reason.trim(),
                idempotency_key: request.current.key,
              },
              { cluster_id: clusterId! },
            )
          : await network.policyAction(
              workload,
              action === "apply-policy" ? "apply" : "demote",
              {
                candidate_hash: selected.candidate_hash,
                reason: reason.trim(),
                idempotency_key: request.current.key,
              },
              { cluster_id: clusterId! },
            );
      const expected =
        action === "rollback-policy"
          ? "rollback"
          : action === "apply-policy"
            ? "apply"
            : "demote";
      if (
        !response?.persists ||
        response.action !== expected ||
        response.policy?.workload !== workload ||
        response.policy.cluster_id !== clusterId ||
        response.policy.current_mode !== response.next_mode ||
        response.idempotency_key !== request.current.key
      ) {
        uncertain.current = true;
        if (active.current) setUnconfirmed(true);
        throw new Error(
          "The response did not confirm this reviewed policy action. Inspect current policy state before trying another action.",
        );
      }
      return `Configured policy action recorded (${response.action_id || response.action}). Reported applier status must be checked separately; this response does not confirm enforcement.`;
    },
    onSuccess: (message) => {
      void qc.invalidateQueries({ queryKey: ["network-policy-lifecycle"] });
      void qc.invalidateQueries({ queryKey: ["network-map"] });
      if (
        active.current &&
        currentOwner.current &&
        clusterId &&
        clusterCacheReady(qc, clusterId)
      )
        setResult(message);
    },
  });
  const retry = () =>
    resolved
      ? void q.refetch()
      : void qc.invalidateQueries({ queryKey: ["clusters"] });
  return (
    <div className="space-y-5" data-testid="network-action-page">
      <PageHeader
        title={META[action].title}
        description="Review one exact cluster/workload policy and its source window before recording a change."
        backLink={<a href={back}>Back to Network</a>}
      />
      {!reviewed ? (
        !resolved ? (
          scope.error ? (
            <ErrorState
              title="Could not resolve this cluster."
              action={<Button onClick={retry}>Retry</Button>}
            />
          ) : (
            <LoadingState label="Resolving cluster…" />
          )
        ) : q.isPending || q.isFetching ? (
          <LoadingState label="Loading current policy…" />
        ) : (
          <ErrorState
            title="This policy action is unavailable for the exact workload and cluster."
            action={<Button onClick={retry}>Retry</Button>}
          />
        )
      ) : (
        <Card
          title={`${workload} · ${reviewed.current_mode}`}
          description={`Policy candidates use a fixed seven-day source. Your ${source.hours}-hour Network view context is preserved for return navigation. Configured state and deployment are separate.`}
        >
          <form
            className="space-y-5"
            onSubmit={async (e) => {
              e.preventDefault();
              if (
                lock.current ||
                uncertain.current ||
                !ready ||
                changed ||
                !reason.trim() ||
                result
              )
                return;
              lock.current = true;
              try {
                await save.mutateAsync();
              } catch {
                /* Draft and error remain visible. */
              } finally {
                lock.current = false;
              }
            }}
          >
            {(!ready || changed) && (
              <ErrorState
                title="Current policy is unavailable or changed. Your draft is preserved."
                action={
                  <>
                    <Button type="button" onClick={retry}>
                      Retry
                    </Button>
                    {ready && candidate && (
                      <Button
                        type="button"
                        onClick={() => setReviewed(candidate)}
                      >
                        Review current state
                      </Button>
                    )}
                  </>
                }
              />
            )}
            <p className="text-sm">
              Cluster {clusterId} · Workload {workload}
            </p>
            <label className="block space-y-2 text-sm">
              <span>Reason</span>
              <textarea
                id="network-action-reason"
                required
                value={reason}
                disabled={save.isPending || !!result}
                onChange={(e) => setReason(e.target.value)}
                className="w-full rounded border border-border bg-background p-3"
              />
            </label>
            {action === "rollback-policy" && (
              <p className="break-all text-sm">
                Restore recorded bundle reference: {reviewed.rollback_ref}. The
                API does not return the historical bundle contents for a
                preview.
              </p>
            )}
            <Collapse label="Advanced: reviewed candidate and current manifest">
              <p className="break-all font-mono text-xs">
                Candidate {reviewed.candidate_hash} · approved{" "}
                {reviewed.approved_candidate_hash || "none"}
              </p>
              <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs">
                {reviewed.preview.yaml}
              </pre>
            </Collapse>
            {save.isError && (
              <ErrorState
                title="Could not confirm the policy action."
                error={save.error}
              />
            )}{" "}
            {unconfirmed && (
              <p role="alert">
                Inspect policy state before submitting another action.
              </p>
            )}
            {result && (
              <p role="status" data-testid="network-action-result">
                {result}
              </p>
            )}
            <div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5">
              <a
                href={back}
                className="rounded border border-border px-3 py-2 text-sm"
              >
                {result ? "Back to Network" : "Cancel"}
              </a>
              <Button
                type="submit"
                disabled={
                  !ready ||
                  changed ||
                  !reason.trim() ||
                  save.isPending ||
                  unconfirmed ||
                  !!result
                }
              >
                {save.isPending ? "Submitting…" : META[action].submit}
              </Button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}
