import { Plus } from "lucide-react";
import { type BaselineProcess, type ProcessRule, type BaselineTransition } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ModePill } from "@/components/ui/status-pill";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatGrid, StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { adjacentModes, baselinePath, SOURCE_NOTE, useBaselineContext } from "./context";

export function BaselineDetailPage() {
 const c = useBaselineContext(); const { clusterId, workload, profile: p, q, ready } = c;
 const [tab,setTab] = useTabParam("tab","processes");
 const root = clusterId ? baselinePath(clusterId,workload) : "/clusters";
 const link = (href: string, label: string, testId?: string) => <a href={ready ? href : undefined} aria-disabled={!ready} data-testid={testId} className="inline-flex items-center gap-2 rounded border border-border px-3 py-2 text-sm text-primary hover:bg-accent">{label}</a>;
 const processColumns: Column<BaselineProcess>[] = [
  { id:"name",header:"Process",kind:"name",code:true,cell:r=>r.name,exportValue:r=>r.name,sort:(a,b)=>a.name.localeCompare(b.name) },
  { id:"path",header:"Path",kind:"text",wrap:true,code:true,cell:r=>r.path||"Not reported",exportValue:r=>r.path },
  { id:"args",header:"Arguments",kind:"text",wrap:true,cell:r=>r.args?.join(" ")||"Not reported",exportValue:r=>r.args?.join(" ")||"" },
  { id:"seen",header:"Retained observations",kind:"count",cell:r=>r.observed_count,exportValue:r=>r.observed_count },
  { id:"first",header:"First observed",kind:"date",cell:r=>r.first_seen||"Not reported",exportValue:r=>r.first_seen },
  { id:"last",header:"Last observed",kind:"date",cell:r=>r.last_seen||"Not reported",exportValue:r=>r.last_seen },
 ];
 const ruleColumns: Column<ProcessRule>[] = [
  { id:"name",header:"Process",kind:"name",cell:r=>link(`${root}/rules/${encodeURIComponent(r.rule_id)}/edit`,r.name||"Any process"),exportValue:r=>r.name },
  { id:"path",header:"Path",kind:"text",wrap:true,code:true,cell:r=>r.path||"Any path",exportValue:r=>r.path },
  { id:"action",header:"Action",kind:"status",cell:r=>r.action,exportValue:r=>r.action },
  { id:"user",header:"User",kind:"text",cell:r=>r.user||"Any user",exportValue:r=>r.user },
  { id:"enabled",header:"Enabled",kind:"status",cell:r=>r.enabled?"Yes":"No",exportValue:r=>r.enabled },
  { id:"sha256",header:"Executable hash",kind:"text",wrap:true,code:true,cell:r=>r.sha256||"Any hash",exportValue:r=>r.sha256||"" },
  { id:"parent",header:"Parent process",kind:"text",cell:r=>r.parent_name||"Any parent",exportValue:r=>r.parent_name||"" },
  { id:"updates",header:"Allow updates",kind:"status",cell:r=>r.allow_update?"Yes":"No",exportValue:r=>r.allow_update },
  { id:"description",header:"Description",kind:"text",wrap:true,cell:r=>r.description||"—",exportValue:r=>r.description },
  { id:"remove",header:"Remove",kind:"actions",cell:r=>link(`${root}/actions/delete-rule?rule=${encodeURIComponent(r.rule_id)}`,"Remove"),exportable:false },
 ];
 const transitionColumns: Column<BaselineTransition & { key: number }>[] = [
  {id:"at",header:"At",kind:"date",cell:r=>r.at,exportValue:r=>r.at},
  {id:"from",header:"From",kind:"status",cell:r=>r.from||"Initial",exportValue:r=>r.from},
  {id:"to",header:"To",kind:"status",cell:r=>r.to,exportValue:r=>r.to},
  {id:"reason",header:"Reason",kind:"name",wrap:true,cell:r=>r.reason,exportValue:r=>r.reason},
  {id:"actor",header:"Actor",kind:"id",cell:r=>r.actor||"Not reported",exportValue:r=>r.actor},
 ];
 return <div className="space-y-5" data-testid="baselines-drawer-body" data-cluster-id={clusterId ?? ""}>
  <PageHeader title={workload || "Process baseline"} description="Review observed processes, configured rules, and mode changes for one exact workload." backLink={<a href={clusterId ? `/clusters/${clusterId}/runtime/baselines` : "/clusters"}>Back to baselines</a>} actions={<Button disabled={!c.scopeReady||q.isFetching} onClick={c.retry}>Refresh</Button>} />
  <VerdictBanner status={p ? "info":"degraded"} title={p ? <>Configured mode: <ModePill mode={p.mode}/></>:"Process baseline evidence unavailable"} detail={p ? SOURCE_NOTE:"Load this exact workload in the selected cluster before assessing its profile."}/>
  <StatGrid><StatCard label="Observed processes" value={p?.learned_processes_count ?? "—"}/><StatCard label="Configured rules" value={p?.rules.length ?? "—"}/><StatCard label="Alerts · retained 24h" value={p?.monitored_alerts_24h ?? "—"}/><StatCard label="Blocks · retained 24h" value={p?.enforced_blocks_24h ?? "—"}/><StatCard label="Last new process" value={p ? p.last_new_process_at || "Not reported" : "—"} valueKind="text"/></StatGrid>
  {!c.scopeReady ? c.error ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={c.retry}>Retry</Button>}/>:<LoadingState label="Resolving cluster…"/>:q.isPending?<LoadingState label="Loading baseline…"/>:q.isError?<ErrorState title="Could not load or refresh this profile." error={q.error} action={<Button onClick={c.retry}>Retry</Button>}/>:!p?<ErrorState title="Returned profile does not match this workload and cluster."/>:<>
   {q.isFetching&&<p role="status" className="text-sm text-muted-foreground">Refreshing profile… Authoring is paused.</p>}
   <Tabs key={`${clusterId}/${workload}`} value={["processes","rules","history"].includes(tab)?tab:"processes"} onValueChange={setTab} items={[
    {value:"processes",label:"Observed processes",content:<Card title="Observed processes" description="Aggregated from the latest 1,000 retained execution events; missing activity does not establish runtime coverage."><DataTable rows={p.processes} columns={processColumns} rowKey={r=>JSON.stringify([r.name,r.path])} testId="baselines-drawer-process-table" preferencesKey="baseline-processes" exportFileName="baseline-processes.csv" exportLabel="Export returned process evidence" emptyState={<p>No processes reported in the retained source.</p>}/></Card>},
    {value:"rules",label:"Configured rules",content:<Card title="Process rules" description="Configure allow or deny matches. Protection depends on the profile mode, agent support, and reconciliation."><div className="mb-4">{link(`${root}/rules/new`,"Add process rule","baseline-rule-add")}<Plus className="ml-2 inline h-4 w-4" aria-hidden/></div><DataTable rows={p.rules} columns={ruleColumns} rowKey={r=>r.rule_id} testId="baseline-rules-table" preferencesKey="baseline-rules" exportFileName="baseline-rules.csv" emptyState={<p>No process rules configured.</p>}/></Card>},
    {value:"history",label:"Mode history",content:<div className="space-y-5"><Card title="Change configured mode" description="Review the current profile and choose one adjacent lifecycle mode on a dedicated page."><div className="flex flex-wrap gap-3">{adjacentModes(p.mode).map(mode=><span key={mode}>{link(`${root}/actions/mode?mode=${mode}`,`${mode === "learn" ? "Roll back" : p.mode === "enforce" ? "Roll back" : "Promote"} to ${mode}`,mode === "learn"||p.mode==="enforce"?"baselines-drawer-rollback":"baselines-drawer-promote")}</span>)}</div></Card><DataTable rows={p.transitions.map((r,index)=>({...r,key:index}))} columns={transitionColumns} rowKey={r=>r.key} testId="baselines-drawer-timeline" preferencesKey="baseline-transitions" exportFileName="baseline-mode-history.csv" emptyState={<p>No mode transitions reported.</p>}/></div>},
   ]}/><Collapse label="Advanced: exact identity and source coverage"><p className="text-sm">Cluster: {p.cluster_id} · Workload: {p.workload_id}</p><p className="mt-2 text-sm text-muted-foreground">{SOURCE_NOTE} Rules and mode transitions have no response cap. Mode changes and rule edits configure policy; they do not acknowledge deployment.</p></Collapse>
  </>}
 </div>;
}
