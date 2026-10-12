import { useEffect, useState } from "react";
import { useIsFetching, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Save } from "lucide-react";
import { fileProfiles, type FileProfileDetail, type FileProfileRule, type FileProfileRuleBehavior } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { LoadingState, ErrorState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { VerdictBanner } from "@/components/ui/verdict-banner";

export function FileMonitorFormPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const qc = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ["clusters"], exact: true });
  const clusterFetching = useIsFetching({ queryKey: ["cluster", clusterId], exact: true });
  const scopeReady = !!clusterId && cluster?.id === clusterId && !clusterLoading && !clusterError && !registryFetching && !clusterFetching && clusterCacheReady(qc, clusterId);
  const { ruleId } = useParams({ strict: false });
  const [search] = useRouteSearchParams();
  const workload = search.get("workload") ?? "";
  const defaultBackTo = clusterId ? `/clusters/${clusterId}/file-monitor${workload ? `?workload=${encodeURIComponent(workload)}` : ""}` : "/clusters";
  const requestedBack = search.get("return_to");
  const backTo = clusterId && requestedBack && requestedBack.startsWith(`/clusters/${encodeURIComponent(clusterId)}/deployments/`) && /^\/clusters\/[^/]+\/deployments\/[^/?]+\?tab=files$/.test(requestedBack) ? requestedBack : defaultBackTo;
  return <div className="space-y-6" data-testid="file-monitor-form-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title={ruleId ? "Edit monitor rule" : "Add monitor rule"} description="Choose a file path to watch on this workload. Observation is the default; blocking access is an explicit choice."
      backLink={<a href={backTo} className="inline-flex items-center gap-2 hover:text-foreground"><ArrowLeft className="h-4 w-4" /> File Monitor</a>} />
    {!clusterId ? <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />
      : !workload ? <ErrorState title="Choose a workload from File Monitor before authoring a rule." />
      : <FileMonitorFormScope key={`${clusterId}:${workload}:${ruleId ?? "new"}`} clusterId={clusterId} workload={workload} ruleId={ruleId} backTo={backTo} scopeReady={scopeReady} resolving={clusterLoading} />}

  </div>;
}

function FileMonitorFormScope({ clusterId, workload, ruleId, backTo, scopeReady, resolving }: { clusterId: string; workload: string; ruleId?: string; backTo: string; scopeReady: boolean; resolving: boolean }) {
  const [initial, setInitial] = useState<{ profile: FileProfileDetail; rule?: FileProfileRule } | null>(null);
  const detailQ = useQuery({
    queryKey: ["file-monitor-detail", clusterId, workload],
    enabled: scopeReady,
    queryFn: async () => {
      const profile = await fileProfiles.get(workload, { cluster_id: clusterId });
      if (profile.workload_id !== workload || (profile.cluster_id && profile.cluster_id !== clusterId)) throw new Error("Scope mismatch");
      return profile;
    },
  });
  const loadedRule = detailQ.data?.rules.find((r) => r.id === ruleId);
  const validTarget = !!detailQ.data && (!ruleId || !!loadedRule);
  useEffect(() => {
    if (!initial && scopeReady && detailQ.isSuccess && validTarget) setInitial({ profile: detailQ.data!, rule: loadedRule });
  }, [initial, scopeReady, detailQ.isSuccess, validTarget, detailQ.data, loadedRule]);
  if (!initial) {
    if (!scopeReady) return resolving ? <LoadingState label="Loading cluster…" /> : <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />;
    if (detailQ.isPending || (detailQ.isSuccess && validTarget)) return <LoadingState label="Loading workload and rule…" />;
    return <ErrorState title={ruleId ? "This rule could not be loaded for the selected workload and cluster." : "This workload could not be loaded for the selected cluster."} action={<Button onClick={() => void detailQ.refetch()}>Retry</Button>} />;
  }
  const canSave = scopeReady && validTarget && detailQ.isSuccess && !detailQ.isFetching;
  return <>
    {(!scopeReady || detailQ.isError || !validTarget) && <ErrorState title="Could not refresh the selected workload or rule. Your draft is preserved. Refresh before saving." action={<Button onClick={() => void detailQ.refetch()}>Retry</Button>} />}
    <FileMonitorRuleEditor clusterId={clusterId} workload={workload} ruleId={ruleId} initial={initial.rule} profile={detailQ.data ?? initial.profile} backTo={backTo} canSave={canSave} />
  </>;
}

function FileMonitorRuleEditor({ clusterId, workload, ruleId, initial, profile, backTo, canSave }: {
  clusterId: string; workload: string; ruleId?: string; initial?: FileProfileRule; profile: FileProfileDetail; backTo: string; canSave: boolean;
}) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [filter, setFilter] = useState(initial?.filter ?? "/etc/");
  const [behavior, setBehavior] = useState<FileProfileRuleBehavior>(initial?.behavior ?? "monitor_change");
  const [recursive, setRecursive] = useState(initial?.recursive ?? true);
  const [enabled, setEnabled] = useState(initial?.enabled ?? true);
  const [description, setDescription] = useState(initial?.description ?? "");
  const [applications, setApplications] = useState(initial?.applications?.join(", ") ?? "");
  const [reason, setReason] = useState(ruleId ? "edited via file-monitor console" : "authored via file-monitor console");
  const save = useMutation({
    mutationFn: () => {
      const current = qc.getQueryState<FileProfileDetail>(["file-monitor-detail", clusterId, workload]);
      if (!canSave || !clusterCacheReady(qc, clusterId) || current?.status !== "success" || current.fetchStatus !== "idle" || current.isInvalidated || current.data?.workload_id !== workload || current.data.cluster_id && current.data.cluster_id !== clusterId || ruleId && !current.data.rules.some(rule => rule.id === ruleId)) throw new Error("Refresh and review the exact workload before saving. Your draft is preserved.");
      if (!reason.trim()) throw new Error("A reason is required.");
      const body = { filter: filter.trim(), behavior, recursive, enabled, description, applications: Array.from(new Set(applications.split(",").map(value => value.trim()).filter(Boolean))).sort(), reason: reason.trim() };
      return ruleId ? fileProfiles.updateRule(workload, ruleId, body, { cluster_id: clusterId }) : fileProfiles.createRule(workload, body, { cluster_id: clusterId });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["file-monitor-detail", clusterId, workload] });
      void qc.invalidateQueries({ queryKey: ["file-monitor-profiles", clusterId] });
      void qc.invalidateQueries({ queryKey: ["deployment"] });
      void navigate({ href: backTo });
    },
  });
  return <>
    <VerdictBanner status="info" title={`Rule for ${profile.name || workload}`} detail={`Workload profile mode: ${profile.mode}. Saving configures the rule; enforcement depends on the workload's profile mode and monitoring agent.`} />
    <Card title="File monitoring rule" description="Watch a path for changes. Open Advanced to change blocking behavior or rule status.">
      <form className="space-y-6" onSubmit={(e) => { e.preventDefault(); if (canSave && filter.trim() && reason.trim() && !save.isPending) save.mutate(); }}>
        <fieldset disabled={save.isPending} className="space-y-5">
          <label className="block space-y-2 text-sm"><span className="font-medium">Path filter</span><input required value={filter} onChange={(e) => setFilter(e.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 font-mono text-sm" placeholder="/etc/ or /bin/*" /><span className="block text-xs text-muted-foreground">Enter the file or directory path to watch, for example /etc/.</span></label>
          <label className="flex items-center gap-3 text-sm"><input type="checkbox" className="h-4 w-4" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> Include subdirectories</label>
          <label className="block space-y-2 text-sm"><span className="font-medium">Reason</span><input required value={reason} onChange={(event) => setReason(event.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm" /></label>
          <p className="text-sm text-muted-foreground">Current behavior: {behavior === "block_access" ? "block access" : "observe changes"}. Rule is {enabled ? "enabled" : "disabled"}.</p>
          <Collapse label="Advanced">
            <div className="space-y-5 rounded-md border border-border p-4">
              <label className="block space-y-2 text-sm"><span className="font-medium">Behavior</span><select value={behavior} onChange={(e) => setBehavior(e.target.value as FileProfileRuleBehavior)} className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm"><option value="monitor_change">Observe changes</option><option value="block_access">Block access</option></select></label>
              {behavior === "block_access" && <p className="text-sm text-status-warning">Blocking can prevent file access when the workload profile is enforcing. Check the path before saving.</p>}
              <label className="flex items-center gap-3 text-sm"><input type="checkbox" className="h-4 w-4" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enable rule</label>
              <label className="block space-y-2 text-sm"><span className="font-medium">Applications, comma separated</span><input value={applications} onChange={(event) => setApplications(event.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm" /></label>
              <label className="block space-y-2 text-sm"><span className="font-medium">Description</span><input value={description} onChange={(e) => setDescription(e.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm" /></label>
            </div>
          </Collapse>
        </fieldset>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this rule. Your draft is preserved. Try again.</p>}
        <div className="flex justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" size="lg" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" variant="primary" size="lg" disabled={!canSave || !filter.trim() || !reason.trim() || save.isPending}><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save"}</Button></div>
      </form>
    </Card>
  </>;
}
