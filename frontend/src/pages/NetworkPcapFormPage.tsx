import { useEffect, useRef, useState } from "react";
import { useLocation } from "@tanstack/react-router";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { network, runtimePcap, type NetworkMap } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { networkViewHref, networkViewSnapshotFromParams } from "@/lib/network-saved-view-route";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { Field, Select, TextInput } from "@/components/ui/form";
import { ErrorState } from "@/components/ui/states";

type Draft = { workload: string; duration: string; protocol: string; src: string; dst: string; port: string; bpf: string; iface: string; files: string; size: string };
function validIP(value: string) {
  if (!value) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return value.split(".").every(part => Number(part) <= 255);
  if (!value.includes(":") || !/^[a-f\d:.]+$/i.test(value)) return false;
  try { return new URL(`http://[${value}]/`).hostname.startsWith("["); } catch { return false; }
}
function integer(value: string, min: number, max: number) { return /^\d+$/.test(value) && Number.isInteger(Number(value)) && Number(value) >= min && Number(value) <= max; }
function errorFor(d: Draft) {
  if (!/^[^/\s]+\/[^/\s]+$/.test(d.workload.trim())) return "Choose an exact namespace/workload from this cluster.";
  if (!integer(d.duration, 5, 300)) return "Duration must be a whole number from 5 to 300 seconds.";
  if (!["", "tcp", "udp", "icmp"].includes(d.protocol)) return "Choose a supported protocol.";
  if (!validIP(d.src.trim()) || !validIP(d.dst.trim())) return "Source and destination must be valid IP addresses when provided.";
  if (d.port && !integer(d.port, 1, 65535)) return "Destination port must be a whole number from 1 to 65535.";
  if (d.bpf.trim().length > 1024 || /[^a-z\d \t.:/()[\]<>=!&|+*%-]/i.test(d.bpf.trim())) return "The BPF filter contains unsupported characters or exceeds 1,024 characters.";
  if (d.iface.trim() && !/^[a-z\d._@-]{1,15}$/i.test(d.iface.trim())) return "Interface must be a Linux interface name of at most 15 characters.";
  if (!integer(d.files, 1, 20)) return "Choose 1 to 20 capture files.";
  if (Number(d.files) > 1 && (!integer(d.size, 1, 100) || Number(d.size) * Number(d.files) > 100)) return "Rolling files must use whole megabytes and total no more than 100 MB.";
  return null;
}
function targets(map: NetworkMap | undefined, clusterId: string) {
  return map?.summary.selected_cluster_id === clusterId ? map.workloads.filter(w => w.cluster_id === clusterId && w.kind !== "External" && w.namespace && w.id === `${w.namespace}/${w.name}`) : [];
}

export function NetworkPcapFormPage() {
  const context = useCluster();
  const identity = useTablePreferencesIdentity();
  const key = `${identity?.org_id}/${identity?.user_id}/${context.clusterId}`;
  return <NetworkPcapEditor key={key} context={context} owner={identity ? `${identity.org_id}/${identity.user_id}` : undefined} />;
}
function NetworkPcapEditor({ context, owner }: { context: ReturnType<typeof useCluster>; owner?: string }) {
  const { clusterId, cluster, isLoading, error } = context;
  const [params] = useRouteSearchParams();
  const hash = useLocation({ select: location => location.hash });
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const detailFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const cachedClusterReady = () => !!clusterId && clusterCacheReady(qc, clusterId);
  const resolved = Boolean(owner && clusterId && cluster?.id === clusterId && !isLoading && !error && !registryFetching && !detailFetching && cachedClusterReady());
  const mapKey = ["pcap-form-workloads", clusterId];
  const mapQ = useQuery({ queryKey: mapKey, queryFn: () => network.map({ cluster_id: clusterId!, hours: 24 }), enabled: resolved });
  const snapshot = networkViewSnapshotFromParams(params);
  const invalidContext = params.has("network_view") && !snapshot;
  const initial = snapshot?.pcap_filters;
  const [draft, setDraft] = useState<Draft>(() => ({ workload: initial?.workload ?? params.get("workload") ?? "", duration: String(initial?.duration_s ?? 30), protocol: initial?.protocol ?? "", src: initial?.src_ip ?? "", dst: initial?.dst_ip ?? "", port: initial?.dst_port ?? "", bpf: initial?.bpf_filter ?? "", iface: initial?.interface ?? "", files: initial?.file_count || "1", size: initial?.file_size_mb || "10" }));
  const set = (field: keyof Draft, value: string) => setDraft(d => ({ ...d, [field]: value }));
  const listParams = new URLSearchParams(params); listParams.set("tab", "pcap");
  const back = clusterId ? networkViewHref(clusterId, listParams, hash) : "/clusters";
  const availableTargets = targets(mapQ.data, clusterId ?? "");
  const target = availableTargets.filter(w => w.id === draft.workload.trim());
  const ready = !invalidContext && resolved && mapQ.isSuccess && mapQ.fetchStatus === "idle" && target.length === 1;
  const validation = errorFor(draft);
  const submitting = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [feedback, setFeedback] = useState<string>();
  const mutation = useMutation({
    mutationFn: async () => {
      const current = qc.getQueryState<NetworkMap>(mapKey);
      if (invalidContext || !mounted.current || !resolved || !cachedClusterReady() || current?.status !== "success" || current.fetchStatus !== "idle" || current.isInvalidated || targets(current.data, clusterId!).filter(w => w.id === draft.workload.trim()).length !== 1) throw new Error("Cluster or workload evidence changed. Refresh the target before requesting capture.");
      const invalid = errorFor(draft); if (invalid) throw new Error(invalid);
      return runtimePcap.start({ cluster_id: clusterId!, workload: draft.workload.trim(), namespace: target[0].namespace, duration_s: Number(draft.duration), protocol: draft.protocol || undefined, src_ip: draft.src.trim() || undefined, dst_ip: draft.dst.trim() || undefined, dst_port: draft.port ? Number(draft.port) : undefined, bpf_filter: draft.bpf.trim() || undefined, interface: draft.iface.trim() || undefined, file_count: Number(draft.files), file_size_mb: Number(draft.files) > 1 ? Number(draft.size) : undefined });
    },
    onSuccess: capture => {
      void qc.invalidateQueries({ queryKey: ["pcap-captures", clusterId] });
      setFeedback(capture?.id && capture.cluster_id === clusterId && capture.workload === draft.workload.trim() && ["pending", "running", "completed", "failed", "expired"].includes(capture.status) ? `Capture request ${capture.id} recorded. Status: ${capture.status}. The agent must claim and complete it before a file is available.` : "The server returned an unexpected capture identity. Review the capture list before making another request.");
    },
    onError: () => { submitting.current = false; },
  });
  return <div className="space-y-6" data-testid="network-pcap-form-page">
    <PageHeader title="Request packet capture" description="Record a bounded capture request for an exact workload. The runtime agent performs the capture and reports its result." backLink={<a href={back}>Back to packet captures</a>} />
    {invalidContext && <ErrorState title="The capture context is invalid. Return to the network workspace and review its filters before requesting capture." />}
    {!resolved && <ErrorState title={isLoading || registryFetching || detailFetching ? "Resolving cluster; requesting capture is paused." : "Cluster scope is unavailable. Your draft is preserved."} />}
    {mapQ.isError && <ErrorState title="Could not load workload evidence." action={<Button onClick={() => void mapQ.refetch()}>Retry workloads</Button>} />}
    <Card title="Capture request" description="Choose the workload and capture duration. Advanced options narrow the capture or configure rolling files.">
      <form className="space-y-5" onSubmit={event => { event.preventDefault(); if (!ready || validation || submitting.current) return; submitting.current = true; mutation.mutate(); }}>
        <Field label="Workload" htmlFor="capture-workload" required hint="Exact namespace/name in the selected cluster."><TextInput id="capture-workload" list="capture-workloads" value={draft.workload} onChange={event => set("workload", event.target.value)} required disabled={submitting.current} /><datalist id="capture-workloads">{availableTargets.map(w => <option key={w.id} value={w.id} />)}</datalist></Field>
        {draft.workload && !mapQ.isFetching && mapQ.isSuccess && target.length !== 1 && <p role="alert" className="text-sm text-destructive">This workload is not uniquely resolved in the selected cluster.</p>}
        <Field label="Duration (seconds)" htmlFor="capture-duration" required><TextInput id="capture-duration" type="number" min={5} max={300} step={1} value={draft.duration} onChange={event => set("duration", event.target.value)} disabled={submitting.current} /></Field>
        <Collapse label="Advanced capture options"><div className="space-y-4">
          <Field label="Protocol" htmlFor="capture-protocol"><Select id="capture-protocol" value={draft.protocol} onChange={event => set("protocol", event.target.value)} disabled={submitting.current}><option value="">Any</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></Select></Field>
          {([["src", "Source IP"], ["dst", "Destination IP"], ["port", "Destination port"], ["bpf", "BPF filter"], ["iface", "Interface"], ["files", "Capture files"], ["size", "MB per rolling file"]] as const).map(([field, label]) => <Field key={field} label={label} htmlFor={`capture-${field}`} hint={field === "files" ? "1–20 files; rolling files may total at most 100 MB." : field === "size" ? "Used only when capturing more than one file." : undefined}><TextInput id={`capture-${field}`} value={draft[field]} onChange={event => set(field, event.target.value)} disabled={submitting.current || field === "size" && Number(draft.files) <= 1} /></Field>)}
        </div></Collapse>
        {validation && <p className="text-sm text-muted-foreground">{validation}</p>}
        {mutation.isError && <ErrorState title="The capture request failed. Your draft is preserved." error={mutation.error} />}
        {feedback && <p role="status" className="rounded-md border border-border p-3 text-sm">{feedback}</p>}
        <div className="flex flex-wrap gap-3"><Button type="submit" variant="primary" disabled={!ready || !!validation || mutation.isPending || mutation.isSuccess}>{mutation.isPending ? "Requesting…" : mutation.isSuccess ? "Request submitted" : "Request capture"}</Button><Button type="button" variant="outline" disabled={mutation.isPending || mutation.isSuccess} onClick={() => { void qc.invalidateQueries({ queryKey: ["clusters"] }); void mapQ.refetch(); }}>Refresh target</Button><Button asChild variant="ghost"><a href={back}>{mutation.isSuccess ? "Back to captures" : "Cancel"}</a></Button></div>
      </form>
    </Card>
  </div>;
}
