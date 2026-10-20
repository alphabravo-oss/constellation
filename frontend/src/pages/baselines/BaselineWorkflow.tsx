import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { baselines, type BaselineDetail, type BaselineMode, type ProcessRuleInput, type ProcessRule } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { clusterCacheReady } from "@/lib/cluster-evidence";
import { adjacentModes, baselinePath, baselineRevision, currentBaseline, useBaselineContext } from "./context";
import { Select } from "@/components/ui/form";

export type BaselineWorkflowKind = "new" | "edit" | "mode" | "delete-rule";
export function BaselineWorkflow({ kind, ruleId = "", desiredMode = "" }: { kind: BaselineWorkflowKind; ruleId?: string; desiredMode?: string }) {
 const context = useBaselineContext();
 return <BaselineWorkflowScope key={`${context.clusterId}/${context.workload}/${kind}/${ruleId}/${desiredMode}`} context={context} kind={kind} ruleId={ruleId} desiredMode={desiredMode}/>;
}
function BaselineWorkflowScope({ context: c, kind, ruleId, desiredMode }: { context: ReturnType<typeof useBaselineContext>; kind: BaselineWorkflowKind; ruleId: string; desiredMode: string }) {
 const [reviewed,setReviewed] = useState<BaselineDetail>();
 const existing = c.profile?.rules.find(r=>r.rule_id===ruleId);
 const eligible = !!c.profile && ((kind!=="edit"&&kind!=="delete-rule")||!!existing);
 useEffect(()=>{if(c.ready&&eligible&&!reviewed)setReviewed(c.profile);},[c.ready,c.profile,eligible,reviewed]);
 const backTo = c.clusterId ? `${baselinePath(c.clusterId,c.workload)}?tab=${kind==="mode"?"history":"rules"}` : "/clusters";
 const title = kind==="new"?"Add process rule":kind==="edit"?"Edit process rule":kind==="mode"?"Change process baseline mode":"Remove process rule";
 return <div className="space-y-5" data-testid="baseline-workflow-page"><PageHeader title={title} description="Review and configure one exact workload profile. Saving does not acknowledge agent enforcement." backLink={<a href={backTo}>Back to baseline</a>}/>
  {!reviewed ? !c.scopeReady ? c.error ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={c.retry}>Retry</Button>}/>:<LoadingState label="Resolving cluster…"/>:c.q.isPending||c.q.isFetching&&!c.q.isError?<LoadingState label="Loading exact workload profile…"/>:<ErrorState title="This rule or profile is unavailable for the exact workload and cluster." action={<Button onClick={c.retry}>Retry</Button>}/>:<BaselineEditor context={c} kind={kind} ruleId={ruleId} desiredMode={desiredMode} reviewed={reviewed} review={setReviewed} backTo={backTo} available={c.ready&&eligible}/>}</div>;
}
function BaselineEditor({ context:c,kind,ruleId,desiredMode,reviewed,review,backTo,available }: {context:ReturnType<typeof useBaselineContext>;kind:BaselineWorkflowKind;ruleId:string;desiredMode:string;reviewed:BaselineDetail;review:(p:BaselineDetail)=>void;backTo:string;available:boolean}) {
 const initialRule = reviewed.rules.find(r=>r.rule_id===ruleId);
 const [name,setName]=useState(initialRule?.name??""); const [path,setPath]=useState(initialRule?.path??"");
 const [action,setAction]=useState<"allow"|"deny">(initialRule?.action??"allow");const [user,setUser]=useState(initialRule?.user??"");
 const [sha256,setSha256]=useState(initialRule?.sha256??"");const [parent,setParent]=useState(initialRule?.parent_name??"");
 const [allowUpdate,setAllowUpdate]=useState(initialRule?.allow_update??false);const [enabled,setEnabled]=useState(initialRule?.enabled??true);const [description,setDescription]=useState(initialRule?.description??"");
 const [mode,setMode]=useState(desiredMode||adjacentModes(reviewed.mode)[0]||"");const [reason,setReason]=useState("");const [confirmed,setConfirmed]=useState(false);
 const lock=useRef(false);const navigate=useNavigate();
 const active=useRef(true);useEffect(()=>{active.current=true;return()=>{active.current=false;};},[]);
 const owner=useRef({cluster:c.clusterId,workload:c.workload,ready:c.scopeReady});owner.current={cluster:c.clusterId,workload:c.workload,ready:c.scopeReady};
 const [unconfirmed,setUnconfirmed]=useState(false);const uncertainLock=useRef(false);
 const uncertain=()=>{uncertainLock.current=true;if(active.current)setUnconfirmed(true);throw new Error("The response did not confirm the reviewed change. Return to the baseline and inspect current configuration before submitting another change.");};
 const confirmRule=(response:ProcessRule,body:ProcessRuleInput)=>{
  if(!response||typeof response.rule_id!=="string"||!response.rule_id.trim()||kind==="edit"&&response.rule_id!==ruleId||![response.updated_at].every(value=>typeof value==="string"&&Number.isFinite(Date.parse(value)))||response.name!==body.name||response.path!==body.path||response.action!==body.action||response.user!==body.user||response.sha256!==body.sha256||response.parent_name!==body.parent_name||response.allow_update!==body.allow_update||response.enabled!==body.enabled||response.description!==body.description)uncertain();
  return response;
 };
 const changed=!!c.profile&&baselineRevision(c.profile)!==baselineRevision(reviewed);
 const collision=kind==="new"&&c.profile?.rules.some(r=>r.name===name.trim()&&r.path===path.trim());
 const valid=kind==="mode"?!!reason.trim()&&adjacentModes(reviewed.mode).includes(mode as BaselineMode):kind==="delete-rule"?confirmed:!!(name.trim()||path.trim())&&!collision;
 const save=useMutation({mutationFn:async()=>{
  const current=currentBaseline(c.qc,c.clusterId!,c.workload);
  if(!available||baselineRevision(current)!==baselineRevision(reviewed))throw new Error("The reviewed profile changed. Refresh and review before saving; your draft is preserved.");
  const scoped={cluster_id:c.clusterId!};
  if(kind==="mode"){
   if(!reason.trim()||!adjacentModes(current.mode).includes(mode as BaselineMode))throw new Error("Choose one adjacent mode and provide a reason.");
   const response=await baselines.setMode(c.workload,{mode:mode as BaselineMode,reason:reason.trim(),expected_mode:reviewed.mode},scoped);
   if(response?.workload_id!==c.workload||response.cluster_id!==c.clusterId||response.mode!==mode)uncertain();
   return response;
  }
  const selected=current.rules.find(r=>r.rule_id===ruleId);
  if(kind!=="new"&&!selected)throw new Error("The selected rule disappeared. Your draft is preserved.");
  if(kind==="delete-rule"){
   if(!confirmed)throw new Error("Confirm removing this exact rule.");
   const response=await baselines.deleteRule(c.workload,ruleId,{...scoped,expected_updated_at:selected!.updated_at});
   if(response?.deleted!==ruleId)uncertain();return response;
  }
  if(!name.trim()&&!path.trim())throw new Error("Enter a process name or path.");
  const body:ProcessRuleInput={name:name.trim(),path:path.trim(),action,user:user.trim(),sha256:sha256.trim().toLowerCase(),parent_name:parent.trim(),allow_update:allowUpdate,enabled,description:description.trim()};
  if(kind==="new"){
   if(current.rules.some(r=>r.name===body.name&&r.path===body.path))throw new Error("A rule with this name and path already exists. Edit that rule.");
   return confirmRule(await baselines.createRule(c.workload,{...body,require_absent:true},scoped),body);
  }
  return confirmRule(await baselines.updateRule(c.workload,ruleId,{...body,expected_updated_at:selected!.updated_at},scoped),body);
 },onSuccess:()=>{void c.qc.invalidateQueries({queryKey:["baseline"]});void c.qc.invalidateQueries({queryKey:["baselines"]});void c.qc.invalidateQueries({queryKey:["deployment"]});if(active.current&&owner.current.cluster===reviewed.cluster_id&&owner.current.workload===reviewed.workload_id&&owner.current.ready&&clusterCacheReady(c.qc,reviewed.cluster_id!))void navigate({href:backTo});}});
 const canSave=available&&!changed&&valid&&!save.isPending&&!unconfirmed;
 const field=(label:string,value:string,update:(value:string)=>void,required=false)=> <label className="block space-y-2 text-sm"><span>{label}</span><input required={required} value={value} onChange={e=>update(e.target.value)} className="w-full rounded border border-border bg-background px-3 py-2"/></label>;
 return <><VerdictBanner status="info" title={`${reviewed.workload_id} · configured mode ${reviewed.mode}`} detail={`Exact cluster: ${reviewed.cluster_id}. Saving configures policy; agent support and reconciliation determine its effect.`}/>
  {(!available||changed)&&<ErrorState title={!available?"Could not refresh the selected profile or rule. Your draft is preserved; refresh before saving.":"The reviewed profile changed. Your draft is preserved."} action={<div className="flex flex-wrap gap-2"><Button onClick={c.retry}>Retry</Button>{available&&c.profile&&<Button onClick={()=>{review(c.profile!);setConfirmed(false);}}>Review current state</Button>}</div>}/>}
  {unconfirmed&&<p role="alert" className="text-sm text-status-warning">Confirmation is unavailable. Inspect the current baseline before submitting another change.</p>}
  {save.isError&&<ErrorState title="Could not save the configured change." error={save.error}/>} {collision&&<p role="alert" className="text-sm text-status-warning">A rule with this name and path already exists. Edit that rule.</p>}
  <Card title={kind==="mode"?"Configured mode":kind==="delete-rule"?"Review removal":"Process rule"} description="Changes apply only to this workload and cluster."><form className="space-y-5" onSubmit={async e=>{e.preventDefault();if(lock.current||uncertainLock.current||!canSave)return;lock.current=true;try{await save.mutateAsync();}catch{/* Mutation feedback retains the draft. */}finally{lock.current=false;}}}><fieldset disabled={save.isPending} className="space-y-5">
   {kind==="mode"?<>{field("Reason",reason,setReason,true)}<label className="block space-y-2 text-sm"><span>Next configured mode</span><Select value={mode} onChange={e=>setMode(e.target.value)} className="w-full rounded border border-border bg-background px-3 py-2"><option value="">Select a mode</option>{adjacentModes(reviewed.mode).map(m=><option key={m}>{m}</option>)}{mode&&!adjacentModes(reviewed.mode).includes(mode as BaselineMode)&&<option value={mode}>Unavailable: {mode}</option>}</Select></label><p className="text-sm text-muted-foreground">Learn records observations; monitor reports deviations; enforce configures blocking. A configured mode is not evidence of deployed enforcement.</p></>:kind==="delete-rule"?<><p className="text-sm">Remove {initialRule?.name||"any process"} · {initialRule?.path||"any path"} · {initialRule?.action} · rule {ruleId}. Existing observations and mode remain.</p><label className="flex gap-3 text-sm"><input type="checkbox" checked={confirmed} onChange={e=>setConfirmed(e.target.checked)}/> I reviewed this exact rule and confirm removal.</label></>:<>{field("Process name",name,setName)}{field("Executable path",path,setPath)}<label className="block space-y-2 text-sm"><span>Action</span><Select value={action} onChange={e=>setAction(e.target.value as "allow"|"deny")} className="w-full rounded border border-border bg-background px-3 py-2"><option value="allow">Allow</option><option value="deny">Deny</option></Select></label><p className="text-sm text-muted-foreground">Enter a process name, executable path, or both. This form adds a distinct match; edit an existing match to replace its settings.</p><Collapse label="Advanced"><div className="space-y-4">{field("User match",user,setUser)}{field("Executable SHA-256",sha256,setSha256)}{field("Parent process",parent,setParent)}{field("Description",description,setDescription)}<label className="flex gap-3 text-sm"><input type="checkbox" checked={allowUpdate} onChange={e=>setAllowUpdate(e.target.checked)}/> Allow executable updates</label><label className="flex gap-3 text-sm"><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)}/> Rule enabled</label></div></Collapse></>}
  </fieldset><div className="flex flex-wrap justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={save.isPending} onClick={()=>void navigate({href:backTo})}>Cancel</Button><Button type="submit" disabled={!canSave}>{save.isPending?"Saving…":kind==="delete-rule"?"Remove rule":"Save"}</Button></div></form></Card></>;
}
