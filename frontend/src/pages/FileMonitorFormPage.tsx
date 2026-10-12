import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Save } from "lucide-react";
import { fileProfiles, type FileProfileDetail, type FileProfileRule, type FileProfileRuleBehavior } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { LoadingState, ErrorState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { VerdictBanner } from "@/components/ui/verdict-banner";

export function FileMonitorFormPage() {
  const { clusterId, cluster, isLoading: clusterLoading } = useCluster();
  const { ruleId } = useParams({ strict: false });
  const [search] = useRouteSearchParams();
  const workload = search.get("workload") ?? "";
  const backTo = clusterId ? `/clusters/${clusterId}/file-monitor${workload ? `?workload=${encodeURIComponent(workload)}` : ""}` : "/clusters";
  return <div className="space-y-6" data-testid="file-monitor-form-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title={ruleId ? "Edit monitor rule" : "Add monitor rule"} description="Choose a file path to watch on this workload. Observation is the default; blocking access is an explicit choice."
      backLink={<Link to="." href={backTo} className="inline-flex items-center gap-2 hover:text-foreground"><ArrowLeft className="h-4 w-4" /> File Monitor</Link>} />
    {clusterLoading ? <LoadingState label="Loading cluster…" />
      : !clusterId || !cluster ? <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />
      : !workload ? <ErrorState title="Choose a workload from File Monitor before authoring a rule." />
      : <FileMonitorFormScope key={`${clusterId}:${workload}:${ruleId ?? "new"}`} clusterId={clusterId} workload={workload} ruleId={ruleId} backTo={backTo} />}
  </div>;
}

function FileMonitorFormScope({ clusterId, workload, ruleId, backTo }: { clusterId: string; workload: string; ruleId?: string; backTo: string }) {
  const [initial, setInitial] = useState<{ profile: FileProfileDetail; rule?: FileProfileRule } | null>(null);
  const detailQ = useQuery({
    queryKey: ["file-monitor-detail", clusterId, workload],
    queryFn: async () => {
      const profile = await fileProfiles.get(workload, { cluster_id: clusterId });
      if (profile.workload_id !== workload || (profile.cluster_id && profile.cluster_id !== clusterId)) throw new Error("Scope mismatch");
      return profile;
    },
  });
  const loadedRule = detailQ.data?.rules.find((r) => r.id === ruleId);
  const validTarget = !!detailQ.data && (!ruleId || !!loadedRule);
  useEffect(() => {
    if (!initial && detailQ.isSuccess && validTarget) setInitial({ profile: detailQ.data!, rule: loadedRule });
  }, [initial, detailQ.isSuccess, validTarget, detailQ.data, loadedRule]);
  if (!initial) {
    if (detailQ.isPending || (detailQ.isSuccess && validTarget)) return <LoadingState label="Loading workload and rule…" />;
    return <ErrorState title={ruleId ? "This rule could not be loaded for the selected workload and cluster." : "This workload could not be loaded for the selected cluster."} action={<Button onClick={() => void detailQ.refetch()}>Retry</Button>} />;
  }
  const canSave = validTarget && detailQ.isSuccess && !detailQ.isFetching;
  return <>
    {(detailQ.isError || !validTarget) && <ErrorState title="Could not refresh the selected workload or rule. Your draft is preserved. Refresh before saving." action={<Button onClick={() => void detailQ.refetch()}>Retry</Button>} />}
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
  const save = useMutation({
    mutationFn: () => {
      const body = { filter: filter.trim(), behavior, recursive, enabled, description, reason: ruleId ? "edited via file-monitor console" : "authored via file-monitor console" };
      return ruleId ? fileProfiles.updateRule(workload, ruleId, body, { cluster_id: clusterId }) : fileProfiles.createRule(workload, body, { cluster_id: clusterId });
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["file-monitor-detail", clusterId, workload] });
      void qc.invalidateQueries({ queryKey: ["file-monitor-profiles", clusterId] });
      void navigate({ href: backTo });
    },
  });
  return <>
    <VerdictBanner status="info" title={`Rule for ${profile.name || workload}`} detail={`Workload profile mode: ${profile.mode}. Saving configures the rule; enforcement depends on the workload's profile mode and monitoring agent.`} />
    <Card title="File monitoring rule" description="Watch a path for changes. Open Advanced to change blocking behavior or rule status.">
      <form className="space-y-6" onSubmit={(e) => { e.preventDefault(); if (canSave && filter.trim() && !save.isPending) save.mutate(); }}>
        <fieldset disabled={save.isPending} className="space-y-5">
          <label className="block space-y-2 text-sm"><span className="font-medium">Path filter</span><input required value={filter} onChange={(e) => setFilter(e.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 font-mono text-sm" placeholder="/etc/ or /bin/*" /><span className="block text-xs text-muted-foreground">Enter the file or directory path to watch, for example /etc/.</span></label>
          <label className="flex items-center gap-3 text-sm"><input type="checkbox" className="h-4 w-4" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} /> Include subdirectories</label>
          <p className="text-sm text-muted-foreground">Current behavior: {behavior === "block_access" ? "block access" : "observe changes"}. Rule is {enabled ? "enabled" : "disabled"}.</p>
          <Collapse label="Advanced">
            <div className="space-y-5 rounded-md border border-border p-4">
              <label className="block space-y-2 text-sm"><span className="font-medium">Behavior</span><select value={behavior} onChange={(e) => setBehavior(e.target.value as FileProfileRuleBehavior)} className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm"><option value="monitor_change">Observe changes</option><option value="block_access">Block access</option></select></label>
              {behavior === "block_access" && <p className="text-sm text-status-warning">Blocking can prevent file access when the workload profile is enforcing. Check the path before saving.</p>}
              <label className="flex items-center gap-3 text-sm"><input type="checkbox" className="h-4 w-4" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Enable rule</label>
              <label className="block space-y-2 text-sm"><span className="font-medium">Description</span><input value={description} onChange={(e) => setDescription(e.target.value)} className="h-10 w-full rounded-md border border-border bg-background px-3 text-sm" /></label>
            </div>
          </Collapse>
        </fieldset>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not save this rule. Your draft is preserved. Try again.</p>}
        <div className="flex justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" size="lg" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" variant="primary" size="lg" disabled={!canSave || !filter.trim() || save.isPending}><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save"}</Button></div>
      </form>
    </Card>
  </>;
}
