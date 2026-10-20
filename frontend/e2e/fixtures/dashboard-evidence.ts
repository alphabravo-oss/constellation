import { expect, type Page } from "@playwright/test";
import { csv } from "./dashboard-cohorts";
import { notificationThreats } from "./network-inventory";

export const evidenceCluster = "11111111-1111-4111-8111-111111111111";
export const evidenceRoot = `/clusters/${evidenceCluster}`;
const sibling = "22222222-2222-4222-8222-222222222222";
const now = Date.now();
export const runtimeBound = new Date(now - 24 * 3600000).toISOString().replace("Z", "123Z");
export const chartBound = new Date(now - 14 * 24 * 3600000).toISOString().replace("Z", "654Z");
const observed = new Date(now).toISOString();
const uuid = (i: number) => `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`;
type Scope = { org: string; cluster_id: string };
type Event = Scope & { id: string; source: string; severity: string; verdict: string; title: string; at: string };
type Check = Scope & { id: string; framework: string; control_id: string; title: string; status: string; effective_status: string; severity: string; evidence: string; evaluated_at: string };
export function dashboardEvidence() {
 const events: Event[] = Array.from({length:203},(_,i)=>({org:"org",cluster_id:evidenceCluster,id:String(i+1),source:"runtime_event",severity:i%2?"critical":"high",verdict:["alert","block","quarantine"][i%3],title:`retained-alert-${i+1}`,at:new Date(now-i*1000).toISOString()}));
 events.push(...[
  {id:"1001",title:"runtime-boundary",at:runtimeBound,verdict:"alert",severity:"high"},
  {id:"1002",title:"future-without-upper-bound",at:new Date(now+3600000).toISOString(),verdict:"block",severity:"critical"},
  {id:"1003",title:"before-runtime-window",at:new Date(now-25*3600000).toISOString(),verdict:"alert",severity:"high"},
  {id:"1004",title:"chart-boundary-excluded",at:chartBound,verdict:"alert",severity:"high"},
  {id:"1005",title:"chart-only-low-verdict",at:new Date(now-2*86400000).toISOString(),verdict:"allow",severity:"critical"},
  {id:"1006",title:"low-severity-runtime",at:observed,verdict:"alert",severity:"low"},
  {id:"1007",title:"allowed-not-runtime-alert",at:observed,verdict:"allow",severity:"low"},
  {id:"1008",title:"sibling-event",at:observed,verdict:"alert",severity:"high",cluster_id:sibling},
  {id:"1009",title:"foreign-event",at:observed,verdict:"alert",severity:"high",org:"foreign"},
 ].map(row=>({org:"org",cluster_id:evidenceCluster,source:"runtime_event",...row})));
 const runtimeRows=()=>events.filter(r=>r.org==="org"&&r.cluster_id===evidenceCluster&&r.at>=runtimeBound&&["alert","block","quarantine"].includes(r.verdict));
 const chartRows=()=>events.filter(r=>r.org==="org"&&r.cluster_id===evidenceCluster&&r.at>chartBound&&["high","critical"].includes(r.severity));
 const checks:Check[]=Array.from({length:205},(_,i)=>({org:"org",cluster_id:evidenceCluster,id:uuid(i+1),framework:i<110?"cis":"gdpr",control_id:String(i+1).padStart(4,"0"),title:`graded-control-${i+1}`,status:i<82?"pass":"fail",effective_status:i<82?"pass":"fail",severity:"high",evidence:`retained-control-evidence-${i+1}`,evaluated_at:observed}));
 checks.push(...[
  {id:uuid(300),title:"active-exempted-failure",status:"fail",effective_status:"exempted"},
  {id:uuid(301),title:"manual-control",status:"manual",effective_status:"manual"},
  {id:uuid(302),title:"not-applicable-control",status:"not_applicable",effective_status:"not_applicable"},
  {id:uuid(303),title:"expired-exemption-still-graded",control_id:"9999",status:"fail",effective_status:"fail"},
  {id:uuid(304),title:"sibling-control",status:"pass",effective_status:"pass",cluster_id:sibling},
  {id:uuid(305),title:"foreign-control",status:"pass",effective_status:"pass",org:"foreign"},
 ].map(row=>({org:"org",cluster_id:evidenceCluster,framework:"gdpr",control_id:row.id,severity:"high",evidence:"exception evidence",evaluated_at:observed,...row})));
 const ownedChecks=()=>checks.filter(r=>r.org==="org"&&r.cluster_id===evidenceCluster);
 const graded=()=>ownedChecks().filter(r=>["pass","fail"].includes(r.effective_status));
 const frameworks=()=>["cis","gdpr"].map(framework=>{const rows=ownedChecks().filter(r=>r.framework===framework),pass=rows.filter(r=>r.effective_status==="pass").length,fail=rows.filter(r=>r.effective_status==="fail").length;return{framework,total:rows.length,pass,fail,manual:rows.filter(r=>r.effective_status==="manual").length,exempted:rows.filter(r=>r.effective_status==="exempted").length,pass_pct:Math.round(pass*100/(pass+fail))};});
 const finding=(i:number,target_type="image-workload",extra={})=>({id:uuid(1000+i),revision:"1",row_id:`${uuid(1000+i)}:${(now/1000).toFixed(6)}`,org:"org",cluster_id:evidenceCluster,source_cluster_id:evidenceCluster,target_cluster_id:null,kind:"vulnerability",target_type,external_id:`CVE-2099-${i}`,title:`tile-finding-${i}`,severity:"high",lifecycle:"open",asset_id:uuid(900),risk_score:80,attack_techniques:[],first_seen_at:observed,last_seen_at:observed,platform_role:"",detail_json:{fixed:i%2?"1.2":""},...extra});
 const findings=[...Array.from({length:103},(_,i)=>finding(i+1)),...Array.from({length:5},(_,i)=>finding(200+i,"host")),finding(300,"platform"),finding(301,"workload"),finding(302,"image-workload",{lifecycle:"accepted"}),finding(303,"image-workload",{org:"foreign"}),finding(304,"image-workload",{cluster_id:sibling,source_cluster_id:sibling})];
 const canonical=()=>findings.filter(r=>r.org==="org"&&r.cluster_id===evidenceCluster&&r.target_type!=="workload");
 const open=()=>canonical().filter(r=>r.lifecycle==="open");
 const workload=(i:number,factors:Record<string,unknown>,extra={})=>({id:uuid(2000+i),org:"org",cluster_id:evidenceCluster,namespace:i===1?"operations":"prod",name:`fact-workload-${i}`,kind:"Deployment",platform_role:i===1?"core":"",risk_score:80,risk_factors:factors,finding_count:1,critical_count:0,high_count:1,first_seen_at:observed,last_seen_at:observed,...extra});
 const workloads=[...Array.from({length:103},(_,i)=>workload(i+1,{privileged:i===0?0:i===1?null:i===2?false:1,run_as_root:i===0?false:i===1?0:i===2?null:1,net_exposure:i===0?null:i===1?false:i===2?0:1})),workload(104,{}),workload(105,{privileged:1,run_as_root:1,net_exposure:1},{org:"foreign"}),workload(106,{privileged:1,run_as_root:1,net_exposure:1},{cluster_id:sibling})];
 const ownedWorkloads=()=>workloads.filter(r=>r.org==="org"&&r.cluster_id===evidenceCluster);
 const tileCounts=()=>({image:open().filter(r=>r.target_type==="image-workload").length,host:open().filter(r=>r.target_type==="host").length,fixable:open().filter(r=>!!r.detail_json.fixed).length,privileged:ownedWorkloads().filter(r=>Object.hasOwn(r.risk_factors,"privileged")).length,run_as_root:ownedWorkloads().filter(r=>Object.hasOwn(r.risk_factors,"run_as_root")).length,net_exposure:ownedWorkloads().filter(r=>Object.hasOwn(r.risk_factors,"net_exposure")).length});
 let expectedTile:string|undefined;
 const activity=Array.from({length:20},(_,i)=>({id:String(100+i),at:observed,action:`selected-action-${i}`,actor:"operator",target_kind:"organization",target_id:"org"}));
 let missing=false,newer=false;const requests:URL[]=[];
 const auditRows=()=>activity.filter(row=>!missing||row.id!=="119").map(row=>({id:Number(row.id),event_id:row.id,at:row.at,action:row.action,actor_id:row.actor,target_kind:row.target_kind,target_id:row.target_id,prev_hash:"previous",chain_hash:`chain-${row.id}`}));
 async function install(page:Page){await page.route("**/api/v1/**",async route=>{
  const url=new URL(route.request().url()),p=url.searchParams,path=url.pathname.replace(/^\/api\/v1/,"");expect(route.request().method(),"Evidence reconciliation is read-only").toBe("GET");requests.push(url);
  if(path==="/auth/me")return route.fulfill({json:{user_id:"admin",org_id:"org",email:"admin@example.test",roles:["GlobalAdmin"]}});
  if(path==="/clusters")return route.fulfill({json:{clusters:[{id:evidenceCluster,name:"Evidence cluster",state:"connected"},{id:sibling,name:"Sibling",state:"connected"}]}});
  if(path==="/runtime-threats"&&!p.has("cluster_id"))return route.fulfill({json:notificationThreats(url)});
  if(path==="/findings"||path==="/findings.csv"){
   const scoped=p.has("cluster_id");if(scoped)expect(p.get("cluster_id")).toBe(evidenceCluster);if(expectedTile&&scoped&&p.get("limit")!=="250"){expect(p.get("kind")).toBe("vulnerability");expect(p.get("lifecycle")).toBe("open");expect(p.get("target_type")).toBe(expectedTile==="fixable"?null:expectedTile);expect(p.get("fixable")).toBe(expectedTile==="fixable"?"1":null);}
   const base=(scoped?canonical():findings.filter(r=>r.org==="org"&&r.target_type!=="workload")).filter(r=>(!p.get("kind")||r.kind===p.get("kind"))&&(!p.get("target_type")||r.target_type===p.get("target_type"))&&(!p.get("fixable")||!!r.detail_json.fixed)),rows=base.filter(r=>!p.get("lifecycle")||r.lifecycle===p.get("lifecycle"));
   if(path.endsWith(".csv")){expect(p.get("limit")).toBe("100000");expect(Number(p.get("offset")??0)).toBe(0);return route.fulfill({contentType:"text/csv",body:csv(["id","kind","external_id","title","severity","risk_score","lifecycle","asset_id","first_seen_at","last_seen_at","accepted_until","platform_role"],rows.map(r=>[r.id,r.kind,r.external_id,r.title,r.severity,r.risk_score,r.lifecycle,r.asset_id,r.first_seen_at,r.last_seen_at,"",r.platform_role]))});}
   const limit=Number(p.get("limit")??100),offset=Number(p.get("offset")??0);return route.fulfill({json:{findings:rows.slice(offset,offset+limit),total:rows.length,limit,offset,has_more:offset+limit<rows.length,lifecycle_counts:Object.fromEntries(["open","accepted","suppressed","triaged","in_progress","resolved"].map(state=>[state,base.filter(r=>r.lifecycle===state).length]))}});
  }
  if(path==="/deployments"||path==="/deployments.csv"){
   expect(p.get("cluster_id")).toBe(evidenceCluster);expect(p.get("risk_fact")).toBe(expectedTile);expect(p.get("hide_platform")).toBe("false");const rows=ownedWorkloads().filter(r=>Object.hasOwn(r.risk_factors,p.get("risk_fact")!));
   if(path.endsWith(".csv")){expect(p.has("offset")).toBe(false);return route.fulfill({contentType:"text/csv",body:csv(["Namespace","Platform Role","Name","Kind","Risk","Findings","Critical","High","Privileged","RunAsRoot","HostNetwork","LastSeen"],rows.map(r=>[r.namespace,r.platform_role,r.name,r.kind,r.risk_score,r.finding_count,r.critical_count,r.high_count,Number(r.risk_factors.privileged)>0?"yes":"",Number(r.risk_factors.run_as_root)>0?"yes":"","",r.last_seen_at]))});}
   const limit=Number(p.get("limit")),offset=Number(p.get("offset")??0);expect(limit).toBe(100);return route.fulfill({json:{deployments:rows.slice(offset,offset+limit),total:rows.length,limit,offset,has_more:offset+limit<rows.length,platform_count:1,summary:{total:rows.length,at_risk:rows.length,finding_count:rows.length,critical_count:0,high_count:rows.length}}});
  }
  if(path==="/dashboard/summary"){expect(p.get("cluster_id")).toBe(evidenceCluster);return route.fulfill({json:{findings_total:open().length,open_findings:open().length,accepted_risks:canonical().filter(r=>r.lifecycle==="accepted").length,findings_by_severity:{critical:0,high:open().length,medium:0,low:0,info:0},recent_activity:activity,posture:{security_score:42,score_breakdown:{},vulns_by_location:{image:tileCounts().image,host:tileCounts().host},vuln_signals:{fixable:tileCounts().fixable},hardening:{privileged:tileCounts().privileged,run_as_root:tileCounts().run_as_root,exposed:tileCounts().net_exposure},enforcement:{},cves_by_mode:{},exposed_by_mode:{},top_vulnerable:[]}}});}
  if(path==="/runtime/overview"){expect(p.get("hours")).toBe("24");expect(p.get("cluster_id")).toBe(evidenceCluster);return route.fulfill({json:{summary:{window_start:runtimeBound,alerts:runtimeRows().length,blocks:runtimeRows().filter(r=>r.verdict==="block").length},subsystems:[],rules:[],recent_events:[],workloads:[]}});}
  if(path==="/dashboard/events-timeline"){expect(p.get("cluster_id")).toBe(evidenceCluster);return route.fulfill({json:{window_start:chartBound,events_timeline:[{date:observed.slice(0,10),total:chartRows().length,critical:chartRows().filter(r=>r.severity==="critical").length}]}});}
  if(path==="/security/timeline"||path==="/security/timeline.csv"){
   expect(p.get("cluster_id")).toBe(evidenceCluster);expect(p.get("type")).toBe("runtime_event");expect(p.has("to")).toBe(false);expect(p.has("hours")).toBe(false);
   const runtime=p.get("verdict")!==null;expect(p.get("after")).toBe(runtime?runtimeBound:chartBound);expect(p.get("after_exclusive")).toBe(runtime?null:"true");expect(p.get("verdict")).toBe(runtime?"alert,block,quarantine":null);expect(p.get("severity")).toBe(runtime?null:"critical,high");
   const after=p.get("after")!,exclusive=p.get("after_exclusive")==="true",severity=p.get("severity")?.split(","),verdict=p.get("verdict")?.split(",");
   const rows=events.filter(r=>r.org==="org"&&r.cluster_id===p.get("cluster_id")&&r.source===p.get("type")&&(exclusive?r.at>after:r.at>=after)&&(!severity||severity.includes(r.severity))&&(!verdict||verdict.includes(r.verdict))).sort((a,b)=>b.at.localeCompare(a.at)||Number(b.id)-Number(a.id));
   if(path.endsWith(".csv")){expect(p.has("offset")).toBe(false);expect(p.has("limit")).toBe(false);return route.fulfill({contentType:"text/csv",headers:{"X-Export-Total":String(rows.length),"X-Export-Limit":"10000","X-Export-Truncated":"false"},body:csv(["id","source","cluster_id","at","severity","verdict","title","namespace","workload_id","reference","platform_role"],rows.map(r=>[r.id,r.source,r.cluster_id,r.at,r.severity,r.verdict,r.title,"","","",""]))});}
   const offset=Number(p.get("offset")??0),limit=Number(p.get("limit"));expect(limit).toBe(100);return route.fulfill({json:{items:rows.slice(offset,offset+limit),total:rows.length,limit,offset,has_more:offset+limit<rows.length,from:after,to:observed,lower_only:true,after_exclusive:exclusive}});
  }
  if(path==="/audit/events"){
   expect(p.has("cluster_id")).toBe(false);expect(p.get("offset")).toBe("0");const ids=p.get("event_ids");let rows=auditRows();if(ids!==null){expect(ids).toBe(activity.map(r=>r.id).join(","));expect(p.get("limit")).toBe("20");rows=rows.filter(r=>ids.split(",").includes(r.event_id));}else{expect(p.get("limit")).toBe("100");if(newer)rows.unshift({id:999,event_id:"999",at:observed,action:"newer-unselected-action",actor_id:"operator",target_kind:"organization",target_id:"org",prev_hash:"previous",chain_hash:"chain-999"});}return route.fulfill({json:{events:rows,has_more:false}});
  }
  if(path==="/compliance/frameworks")return route.fulfill({json:{frameworks:[{id:"cis",name:"CIS",category:"kubernetes"},{id:"gdpr",name:"GDPR",category:"regulatory"}]}});
  if(path==="/compliance/summary"){expect(p.get("cluster_id")).toBe(evidenceCluster);return route.fulfill({json:{frameworks:frameworks()}});}
  if(path==="/compliance/exemptions")return route.fulfill({json:{exemptions:[]}});
  if(path==="/compliance/checks"||path==="/compliance/checks/export.csv"){
   expect(p.get("cluster_id")).toBe(evidenceCluster);expect(p.get("framework")).toBe("all");expect(p.get("status")).toBe("graded");expect(p.get("sort")).toBe("framework");expect(p.get("order")).toBe("asc");
   const rows=checks.filter(r=>r.org==="org"&&r.cluster_id===p.get("cluster_id")&&["pass","fail"].includes(r.effective_status)).sort((a,b)=>a.framework.localeCompare(b.framework)||a.control_id.localeCompare(b.control_id)||a.id.localeCompare(b.id));
   if(path.endsWith(".csv")){expect(p.has("offset")).toBe(false);expect(p.has("limit")).toBe(false);return route.fulfill({contentType:"text/csv",headers:{"X-Export-Total":String(rows.length),"X-Export-Limit":"100000","X-Export-Truncated":"false"},body:csv(["Evidence ID","Cluster ID","Asset ID","Framework","Control","Title","Original status","Effective status","Severity","Evidence","Remediation","Evaluated at","Exemption ID","Exemption expires at"],rows.map(r=>[r.id,r.cluster_id,"",r.framework,r.control_id,r.title,r.status,r.effective_status,r.severity,r.evidence,"",r.evaluated_at,"",""]))});}
   const limit=Number(p.get("limit")),offset=Number(p.get("offset")??0);expect(limit).toBe(100);const pass=rows.filter(r=>r.effective_status==="pass").length,fail=rows.length-pass;return route.fulfill({json:{checks:rows.slice(offset,offset+limit),cluster_id:evidenceCluster,framework:"",status:"graded",profile:"",control_id:"",q:"",sort:"framework",order:"asc",limit,offset,total:rows.length,has_more:offset+limit<rows.length,summary:{total:rows.length,pass,fail,manual:0,not_applicable:0,exempted:0,graded:rows.length,ungraded:0}}});
  }
  return route.fulfill({status:404,json:{error:`Unavailable fixture source: ${path}`}});
 });}
 return {install,requests,activity,runtimeRows,chartRows,graded,frameworks,tileCounts,expectTile:(value:string|undefined)=>{expectedTile=value;},changeAudit:()=>{missing=true;newer=true;}};
}
