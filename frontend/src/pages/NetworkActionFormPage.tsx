import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { network, quarantine, type NetworkMap, type NetworkPolicyLifecycle, type NetworkWorkload } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select, Textarea, TextInput } from "@/components/ui/form";
import { ErrorState, LoadingState } from "@/components/ui/states";

type Action = "isolate" | "quarantine" | "block-ip" | "approve-policy";
const ACTIONS: Record<Action, { title: string; effect: string; submit: string }> = {
  isolate: { title: "Isolate workload", effect: "Queue a native default-deny NetworkPolicy for this workload’s pods, blocking all ingress and egress. The cluster’s policy applier must reconcile the queued policy before it takes effect.", submit: "Queue isolation" },
  quarantine: { title: "Quarantine workload", effect: "Add this workload to the admission webhook deny list. This blocks re-admission and rescheduling while quarantine is active; it does not stop traffic for pods already running.", submit: "Add quarantine" },
  "block-ip": { title: "Block peer IP", effect: "Queue a Cilium deny policy for traffic between this workload and the selected IP. This action requires Cilium; queued state does not confirm that traffic is blocked.", submit: "Queue IP block" },
  "approve-policy": { title: "Approve observed network policy", effect: "Approve the complete workload policy generated from observed traffic. This records approval of the reviewed candidate; applying it to the cluster remains a separate action on the Network Map.", submit: "Approve candidate" },
};
function isAction(value: string | undefined): value is Action { return !!value && Object.hasOwn(ACTIONS, value); }
function workloadFrom(map: NetworkMap | undefined, clusterId: string, workload: string) {
  if (map?.summary.selected_cluster_id !== clusterId) return undefined;
  const matches = map.workloads.filter((item) => item.id === workload && item.cluster_id === clusterId && item.kind !== "External" && item.namespace && `${item.namespace}/${item.name}` === workload);
  return matches.length === 1 ? matches[0] : undefined;
}
function cilium(map: NetworkMap | undefined) { return !!map?.summary.cni?.toLowerCase().includes("cilium"); }
function validIP(ip: string) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split(".").every((part) => Number(part) <= 255);
  if (!ip.includes(":") || !/^[\da-f:]+$/i.test(ip)) return false;
  try { return new URL(`http://[${ip}]/`).hostname.startsWith("["); } catch { return false; }
}
function errorMessage(error: unknown) {
  const response = (error as { response?: { data?: { error?: string } } } | null)?.response?.data?.error;
  return response || (error instanceof Error ? error.message : "The action failed. Your draft is preserved.");
}

export function NetworkActionFormPage() {
  const { action } = useParams({ strict: false });
  const [params] = useRouteSearchParams();
  const { clusterId, cluster, isLoading, error } = useCluster();
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
  const resolved = !!clusterId && cluster?.id === clusterId && !isLoading && !error && !registryFetching && !detailFetching && cachedClusterReady();
  const workload = params.get("workload") ?? "";
  const ip = params.get("ip") ?? "";
  const direction = params.get("direction") ?? "egress";
  const listPath = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/network` : "/clusters";
  const backSearch = params.get("back") ?? "";
  const backPath = `${listPath}${backSearch ? `?${new URLSearchParams(backSearch)}` : ""}`;
  const validContext = isAction(action) && !!workload && (action !== "block-ip" || validIP(ip) && ["egress", "ingress", "both"].includes(direction));
  const mapQ = useQuery({ queryKey: ["network-action-target", clusterId, workload], queryFn: () => network.map({ cluster_id: clusterId!, hours: 24 }), enabled: resolved && validContext, staleTime: 0 });
  const policyQ = useQuery({ queryKey: ["network-action-candidate", clusterId, workload], queryFn: () => network.lifecycle({ cluster_id: clusterId!, hours: 24 }), enabled: resolved && validContext && action === "approve-policy", staleTime: 0 });
  const target = clusterId ? workloadFrom(mapQ.data, clusterId, workload) : undefined;
  const matchingPolicies = policyQ.data && policyQ.data.summary.selected_cluster_id === clusterId ? policyQ.data.items.filter((item) => item.workload === workload && item.cluster_id === clusterId) : [];
  const candidate = matchingPolicies.length === 1 ? matchingPolicies[0] : undefined;
  const contextKey = `${clusterId}:${action}:${workload}:${ip}:${direction}`;
  const [loaded, setLoaded] = useState<{ key: string; target: NetworkWorkload; candidate?: NetworkPolicyLifecycle }>();
  const ready = resolved && mapQ.isSuccess && mapQ.fetchStatus === "idle" && !!target &&
    (action !== "approve-policy" || policyQ.isSuccess && policyQ.fetchStatus === "idle" && !!candidate);
  useEffect(() => {
    if (ready && target) {
      setLoaded((previous) => previous?.key === contextKey ? previous : { key: contextKey, target, candidate });
    }
  }, [ready, target, candidate, contextKey]);
  const initial = loaded?.key === contextKey ? loaded : undefined;
  const recheck = () => {
    const currentMap = qc.getQueryState<NetworkMap>(["network-action-target", clusterId, workload]);
    const currentPolicy = qc.getQueryState<{ summary: { selected_cluster_id?: string }; items: NetworkPolicyLifecycle[] }>(["network-action-candidate", clusterId, workload]);
    return resolved && cachedClusterReady() && currentMap?.status === "success" && currentMap.fetchStatus === "idle" &&
      !!workloadFrom(currentMap.data, clusterId!, workload) && (action !== "approve-policy" || currentPolicy?.status === "success" && currentPolicy.fetchStatus === "idle" && currentPolicy.data?.summary.selected_cluster_id === clusterId && currentPolicy.data.items.filter((item) => item.workload === workload && item.cluster_id === clusterId).length === 1);
  };
  const title = isAction(action) ? ACTIONS[action].title : "Network action";
  return <div className="space-y-6" data-testid="network-action-page">
    <PageHeader title={title} description="Review the exact cluster and workload before recording a network response."
      backLink={<a href={backPath} className="inline-flex items-center gap-1"><ArrowLeft className="h-3.5 w-3.5" /> Network Map</a>} />
    {!initial && (isLoading || registryFetching || detailFetching) ? <LoadingState label="Resolving cluster…" />
      : !initial && !resolved ? <ErrorState title="The requested cluster could not be resolved." error={error} />
      : !validContext ? <ErrorState title="This action link does not identify a valid workload or peer IP." />
      : !initial && (mapQ.isPending || mapQ.isFetching || action === "approve-policy" && (policyQ.isPending || policyQ.isFetching)) ? <LoadingState label="Loading action target…" />
      : !initial && !target ? <ErrorState title="This workload could not be loaded in the requested cluster." error={mapQ.error} action={<Button onClick={() => void mapQ.refetch()}>Retry</Button>} />
      : !initial && action === "approve-policy" && !candidate ? <ErrorState title="The workload policy candidate could not be loaded." error={policyQ.error} action={<Button onClick={() => void policyQ.refetch()}>Retry</Button>} />
      : initial ? <NetworkActionEditor key={contextKey} clusterId={clusterId!} action={action as Action} target={initial.target} ip={ip} initialDirection={direction as "egress" | "ingress" | "both"} candidate={candidate ?? initial.candidate} ciliumSupported={cilium(mapQ.data)} unavailable={!ready} recheck={recheck} backPath={backPath} refresh={() => { void qc.invalidateQueries({ queryKey: ["clusters"], exact: true }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true }); if (resolved) { void mapQ.refetch(); if (action === "approve-policy") void policyQ.refetch(); } }} />
      : <LoadingState label="Preparing action…" />}
    <a href={backPath} className="inline-flex text-sm text-muted-foreground hover:text-foreground">Cancel</a>
  </div>;
}

function NetworkActionEditor({ clusterId, action, target, ip, initialDirection, candidate, ciliumSupported, unavailable, recheck, backPath, refresh }: {
  clusterId: string; action: Action; target: NetworkWorkload; ip: string; initialDirection: "egress" | "ingress" | "both";
  candidate?: NetworkPolicyLifecycle; ciliumSupported: boolean; unavailable: boolean; recheck: () => boolean; backPath: string; refresh: () => void;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const active = useRef(true);
  const available = useRef(recheck);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const [reason, setReason] = useState("");
  const [direction, setDirection] = useState(initialDirection);
  const [expiry, setExpiry] = useState("24");
  const [reviewed, setReviewed] = useState(candidate);
  const [result, setResult] = useState("");
  const requestKey = useRef<{ identity: string; key: string } | null>(null);
  const candidateChanged = action === "approve-policy" && (!reviewed?.candidate_hash || reviewed.candidate_hash !== candidate?.candidate_hash);
  const valid = !!reason.trim() && !unavailable && !candidateChanged && (action !== "block-ip" || ciliumSupported) &&
    (action !== "quarantine" || /^\d+$/.test(expiry) && Number(expiry) >= 1 && Number(expiry) <= 720) &&
    (action !== "approve-policy" || !!reviewed?.target_mode);
  available.current = () => valid && recheck();
  const save = useMutation({
    mutationFn: async () => {
      if (!valid || !active.current || !available.current()) throw new Error("Current cluster or action target is unavailable or refreshing. Your draft is preserved.");
      const draft = { reason: reason.trim(), direction, expiry: Number(expiry), hash: reviewed?.candidate_hash };
      const currentMap = await network.map({ cluster_id: clusterId, hours: 24 });
      if (!active.current || !available.current()) throw new Error("The action target changed or began refreshing before submission.");
      if (!workloadFrom(currentMap, clusterId, target.id)) throw new Error("The workload is no longer available in this cluster. Your draft is preserved.");
      if (action === "block-ip" && !cilium(currentMap)) throw new Error("Single-IP blocking requires Cilium in this cluster.");
      if (action === "approve-policy") {
        const current = await network.lifecycle({ cluster_id: clusterId, hours: 24 });
        if (!active.current || !available.current()) throw new Error("The action target changed or began refreshing before submission.");
        const matches = current.summary.selected_cluster_id === clusterId ? current.items.filter((item) => item.workload === target.id && item.cluster_id === clusterId) : [];
        const cached = qc.getQueryData<{ items: NetworkPolicyLifecycle[] }>(["network-action-candidate", clusterId, target.id]);
        const cachedHash = cached?.items.find((item) => item.workload === target.id && item.cluster_id === clusterId)?.candidate_hash;
        if (matches.length !== 1 || !draft.hash || matches[0].candidate_hash !== draft.hash || cachedHash !== draft.hash) {
          void qc.invalidateQueries({ queryKey: ["network-action-candidate", clusterId, target.id] });
          throw new Error("The policy candidate changed. Review the updated candidate before approving; your reason is preserved.");
        }
        const identity = JSON.stringify([clusterId, target.id, draft.hash, draft.reason]);
        if (requestKey.current?.identity !== identity) requestKey.current = { identity, key: globalThis.crypto?.randomUUID?.() ?? `network-policy:${Date.now()}:${Math.random().toString(36).slice(2)}` };
        const response = await network.policyAction(target.id, "approve", { reason: draft.reason, candidate_hash: draft.hash, idempotency_key: requestKey.current.key }, { cluster_id: clusterId });
        return `Approval recorded${response.action_id ? ` (${response.action_id})` : ""}. Applying the policy remains a separate action.`;
      }
      if (action === "quarantine") {
        const response = await quarantine.create({ cluster_id: clusterId, scope: "workload", match_key: target.id, reason: draft.reason, expires_in_hours: draft.expiry });
        return `Admission quarantine recorded (${response.id}). Running pod traffic is unchanged.`;
      }
      const response = await network.enforcement.create(action === "isolate" ? { kind: "isolate", target: target.id, reason: draft.reason } : { kind: "block_ip", target: ip, workload: target.id, direction: draft.direction, reason: draft.reason }, { cluster_id: clusterId });
      return `${response.kind === "isolate" ? "Isolation" : "IP block"} queued (${response.id}, ${response.flavor}). Cluster enforcement is pending reconciliation.`;
    },
    onSuccess: (message) => {
      void qc.invalidateQueries({ queryKey: ["network-map"] });
      void qc.invalidateQueries({ queryKey: ["network-enforcement"] });
      void qc.invalidateQueries({ queryKey: ["network-policy-lifecycle"] });
      void qc.invalidateQueries({ queryKey: ["quarantine"] });
      if (active.current) setResult(message);
    },
  });
  const info = ACTIONS[action];
  return <Card title="Review action" description={info.effect}>
    <form className="space-y-5" onSubmit={(event) => { event.preventDefault(); if (valid && !save.isPending && !result) save.mutate(); }}>
      <dl className="grid gap-3 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Cluster</dt><dd className="font-mono">{clusterId}</dd></div><div><dt className="text-muted-foreground">Workload</dt><dd className="break-all font-mono">{target.id}</dd></div>{action === "block-ip" && <div><dt className="text-muted-foreground">Peer IP</dt><dd className="font-mono">{ip}</dd></div>}</dl>
      {unavailable && <p role="alert" className="text-sm text-status-error">Could not refresh the current target. Your draft is preserved. Retry before submitting.</p>}
      {action === "block-ip" && !ciliumSupported && <p role="alert" className="text-sm text-status-error">This action currently requires Cilium. This cluster cannot use the generated Cilium deny policy.</p>}
      {action === "approve-policy" && <section className="space-y-3">
        <p className="text-sm">Reviewing {reviewed?.current_mode} → {reviewed?.target_mode ?? "no proposed change"}. This candidate covers the workload’s observed traffic, including more than the selected flow.</p>
        {candidateChanged && <p role="alert" className="text-sm text-status-warning">The candidate changed since review. Your reason is preserved.</p>}
        {candidateChanged && <Button type="button" onClick={() => setReviewed(candidate)} disabled={save.isPending || unavailable}>Review updated candidate</Button>}
        {!reviewed?.target_mode && <p role="alert" className="text-sm text-muted-foreground">No policy change is currently available to approve.</p>}
        <pre className="max-h-80 overflow-auto rounded-md bg-muted p-3 text-xs" data-testid="network-action-policy-preview">{reviewed?.preview.yaml}</pre>
        <Collapse label="Advanced: policy manifests and candidate"><div className="space-y-3"><p className="break-all font-mono text-xs">Candidate: {reviewed?.candidate_hash || "unavailable"}</p>{Object.entries(reviewed?.preview.manifests ?? {}).map(([flavor, yaml]) => <div key={flavor}><p className="text-sm font-medium">{flavor}</p><pre className="max-h-60 overflow-auto rounded-md bg-muted p-3 text-xs">{yaml}</pre></div>)}</div></Collapse>
      </section>}
      <fieldset disabled={save.isPending || !!result} className="space-y-5">
        <Field label="Reason" htmlFor="network-action-reason" required hint="Record why this action is needed for the audit trail."><Textarea id="network-action-reason" required value={reason} onChange={(event) => setReason(event.target.value)} /></Field>
        {(action === "quarantine" || action === "block-ip") && <Collapse label="Advanced"><div className="space-y-4">
          {action === "quarantine" && <Field label="Expires after (hours)" htmlFor="network-action-expiry" hint="1–720 hours; defaults to 24 hours."><TextInput id="network-action-expiry" type="number" min={1} max={720} value={expiry} onChange={(event) => setExpiry(event.target.value)} /></Field>}
          {action === "block-ip" && <Field label="Traffic direction" htmlFor="network-action-direction"><Select id="network-action-direction" value={direction} onChange={(event) => setDirection(event.target.value as typeof direction)}><option value="egress">Egress to peer IP</option><option value="ingress">Ingress from peer IP</option><option value="both">Ingress and egress</option></Select></Field>}
        </div></Collapse>}
      </fieldset>
      {save.isError && <p role="alert" className="text-sm text-status-error">{errorMessage(save.error)}</p>}
      {result && <p role="status" className="text-sm" data-testid="network-action-result">{result}</p>}
      <div className="flex flex-wrap gap-3">{result ? <Button type="button" onClick={() => navigate({ href: backPath })}>Back to Network Map</Button> : <Button type="submit" variant="primary" disabled={!valid || save.isPending}>{save.isPending ? "Submitting…" : info.submit}</Button>}<Button type="button" variant="outline" onClick={refresh} disabled={save.isPending || !!result}>Refresh current target</Button></div>
    </form>
  </Card>;
}
