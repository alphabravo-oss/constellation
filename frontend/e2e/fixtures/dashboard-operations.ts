import { expect, type Page } from "@playwright/test";
import type { SystemHealthHeartbeat, ScannerWorker, FedMember } from "../../src/api/client";
import { conversationInventory, notificationThreats } from "./network-inventory";
export const operationsCluster = "11111111-1111-4111-8111-111111111111";
export const operationsRoot = `/clusters/${operationsCluster}`;
const sibling = "22222222-2222-4222-8222-222222222222";
export function dashboardOperations(){
 const at=new Date().toISOString();
 const heartbeat=(component:string,hostname:string,status:string,metadata?:SystemHealthHeartbeat["metadata"],cluster_id=operationsCluster):SystemHealthHeartbeat=>({component,hostname,status,metadata,cluster_id,cluster_name:cluster_id===operationsCluster?"Operations cluster":"Sibling",version:"1",commit:"test-commit",commit_short:"test",uptime_seconds:3600,restart_count:0,last_seen_at:at});
 const db=(name:string,max:number,idle:number,jobs:number)=>({max_concurrent:max,idle_capacity:idle,active_jobs:jobs,vulndb:{bundle_version:`host-${name}`},engine_db:{trivy:{download_revision:`trivy-download-${name}`,applied_revision:`trivy-applied-${name}`,status:"ready"},grype:{download_revision:`grype-download-${name}`,applied_revision:`grype-applied-${name}`,status:"ready"}}});
 const heartbeats=[heartbeat("controller","controller-a","healthy"),heartbeat("controller","controller-b","degraded"),heartbeat("enforcer","enforcer-a","crashlooping"),heartbeat("enforcer","enforcer-b","drift"),heartbeat("scanner","scanner-a","healthy",db("a",8,6,2)),heartbeat("scanner","scanner-b","healthy",db("b",4,3,1)),heartbeat("scanner","scanner-stale","stale",db("stale",100,100,0)),heartbeat("admission","admission-a","healthy"),heartbeat("other","unclassified-worker","healthy")];
 const fleet=[...heartbeats,heartbeat("scanner","scanner-peer","healthy",db("peer",12,9,3),sibling)];
 const worker=(id:string,version?:string):ScannerWorker=>({id,cvedb_version:version,cvedb_create_time:version?at:undefined,joined_timestamp:Date.now()/1000,server:id,port:443,scanned_containers:0,scanned_hosts:0,scanned_images:0,scanned_serverless:0});
 const workers=[worker("a","worker-version"),worker("b","worker-version"),worker("missing-db")];
 const members:FedMember[]=[{id:"a",cluster_id:operationsCluster,name:"Active A",role:"joint",endpoint:"https://a.test",status:"active",last_sync_at:at,revision:12},{id:"b",cluster_id:sibling,name:"Active B",role:"joint",endpoint:"https://b.test",status:"active",last_sync_at:at,revision:12},{id:"c",cluster_id:"33333333-3333-4333-8333-333333333333",name:"Stale C",role:"joint",endpoint:"https://c.test",status:"disconnected",last_sync_at:at,revision:11}];
 const groups=[...Array.from({length:6},(_,i)=>({org:"org",cluster:operationsCluster,policy_mode:["discover","discover","monitor","protect","protect","protect"][i],profile_mode:["discover","monitor","monitor","monitor","protect","protect"][i]})),{org:"org",cluster:sibling,policy_mode:"protect",profile_mode:"protect"},{org:"foreign",cluster:operationsCluster,policy_mode:"protect",profile_mode:"protect"}];
 const policies=[{org:"org",cluster:operationsCluster,enabled:true,engine:"constellation-admission",mode:"protect",actions:[]},{org:"org",cluster:null,enabled:true,engine:"constellation-admission",mode:"audit",actions:["deny"]},{org:"org",cluster:operationsCluster,enabled:true,engine:"constellation-admission",mode:"monitor",actions:[]},{org:"org",cluster:operationsCluster,enabled:false,engine:"constellation-admission",mode:"enforce",actions:[]},{org:"org",cluster:operationsCluster,enabled:true,engine:"other",mode:"enforce",actions:[]},{org:"org",cluster:sibling,enabled:true,engine:"constellation-admission",mode:"enforce",actions:[]},{org:"foreign",cluster:operationsCluster,enabled:true,engine:"constellation-admission",mode:"enforce",actions:[]}];
 let admission:"enforce"|"monitor"|"none"="enforce",federation:"master"|"joint"|"standalone"="master",version:"lifecycle"|"worker"|"bundle"|"missing"="lifecycle",fail=false;
 const requests:URL[]=[];
 const enforcement=()=>{const owned=groups.filter(g=>g.org==="org"&&g.cluster===operationsCluster),eligible=policies.filter(p=>p.org==="org"&&(!p.cluster||p.cluster===operationsCluster)&&p.enabled&&p.engine==="constellation-admission"),selected=admission==="enforce"?eligible:admission==="monitor"?eligible.filter(p=>p.mode==="monitor"):[];return{groups:owned.length,...Object.fromEntries(["discover","monitor","protect"].flatMap(mode=>[[mode,owned.filter(g=>g.policy_mode===mode).length],[`profile_${mode}`,owned.filter(g=>g.profile_mode===mode).length]])),admission_policies:selected.length,admission_enforcing:selected.filter(p=>["enforce","protect","block"].includes(p.mode)||/deny|block/i.test(JSON.stringify(p.actions))).length};};
 async function install(page:Page){await page.route("**/api/v1/**",async route=>{
  const url=new URL(route.request().url()),p=url.searchParams,path=url.pathname.replace(/^\/api\/v1/,"");expect(route.request().method(),"Reported operations qualification must not author configuration").toBe("GET");requests.push(url);
  if(path==="/auth/me")return route.fulfill({json:{user_id:"admin",org_id:"org",email:"admin@example.test",roles:["GlobalAdmin"]}});
  if(path==="/clusters")return route.fulfill({json:{clusters:[{id:operationsCluster,name:"Operations cluster",state:"connected"},{id:sibling,name:"Sibling",state:"connected"}]}});
  if(path==="/runtime-threats"&&!p.has("cluster_id"))return route.fulfill({json:notificationThreats(url)});
  if(path==="/findings")return route.fulfill({json:{findings:[],total:0,limit:Number(p.get("limit")??100),offset:0,has_more:false,lifecycle_counts:{open:0,accepted:0,suppressed:0,triaged:0,in_progress:0,resolved:0}}});
  if(fail&&["/scan/status","/scan/scanner","/system-health",`/system-health/clusters/${operationsCluster}`,"/federation/state","/federation/members"].includes(path))return route.fulfill({status:503,json:{error:"Source unavailable"}});
  if(path==="/dashboard/summary"){expect(p.get("cluster_id")).toBe(operationsCluster);return route.fulfill({json:{findings_total:0,open_findings:0,accepted_risks:0,findings_by_severity:{critical:0,high:0,medium:0,low:0,info:0},recent_activity:[],posture:{security_score:42,score_breakdown:{},vulns_by_location:{},vuln_signals:{},hardening:{},enforcement:enforcement(),cves_by_mode:{},exposed_by_mode:{},top_vulnerable:[]}}});}
  if(path===`/system-health/clusters/${operationsCluster}`)return route.fulfill({json:{heartbeats}});
  if(path==="/system-health"){expect(p.has("cluster_id")).toBe(false);return route.fulfill({json:{heartbeats:fleet}});}
  if(path==="/scan/status"){expect(p.has("cluster_id")).toBe(false);return route.fulfill({json:{scanned:27,scheduled:17,scanning:5,failed:3,...(version==="lifecycle"?{cvedb_version:"lifecycle-version",cvedb_create_time:at}:{})}});}
  if(path==="/scan/scanner"){expect(p.has("cluster_id")).toBe(false);return route.fulfill({json:{scanners:["lifecycle","worker"].includes(version)?workers:workers.map(({cvedb_version: _version,cvedb_create_time: _time,...r})=>r)}});}
  if(path==="/cve/bundle/status")return route.fulfill({json:{available:version!=="missing",...(version!=="missing"?{version:"bundle-version",imported_at:at}:{})}});
  if(path==="/federation/state"){expect(p.has("cluster_id")).toBe(false);return route.fulfill({json:{state:federation,revision:12,updated_at:at,...(federation==="joint"?{master_id:"upstream"}:{})}});}
  if(path==="/federation/members"){expect(federation).toBe("master");expect(p.has("cluster_id")).toBe(false);return route.fulfill({json:{members}});}
  if(path==="/network/conversations")return route.fulfill({json:conversationInventory(url,[])});
  if(path==="/network/exposure")return route.fulfill({json:{ingress:[],egress:[]}});
  if(path==="/compliance/summary")return route.fulfill({json:{frameworks:[]}});
  if(path==="/runtime/overview")return route.fulfill({json:{summary:{window_start:at,alerts:0,blocks:0},subsystems:[],rules:[],recent_events:[],workloads:[]}});
  if(path==="/dashboard/events-timeline")return route.fulfill({json:{events_timeline:[]}});
  return route.fulfill({status:404,json:{error:`No operation fixture for ${path}`}});
 });}
 return{install,heartbeats,fleet,workers,members,requests,enforcement,setAdmission:(value:typeof admission)=>{admission=value;},setVersion:(value:typeof version)=>{version=value;},setFederation:(value:typeof federation)=>{federation=value;},setFailure:(value:boolean)=>{fail=value;}};
}
