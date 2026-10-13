import { expect, type Page } from "@playwright/test";
export const aliasCluster = "11111111-1111-4111-8111-111111111111";
export const aliasSibling = "22222222-2222-4222-8222-222222222222";
export const aliasEntity = "00000000-0000-4000-8000-000000000001";
export type AliasCase = { contract: string; from: string; to: string; defaults?: Record<string,string> };
const componentDefaults=(role:string)=>({role});
export const legacyMappings:Array<[string,string,Record<string,string>?]>=[
 ["dashboard","dashboard"],["findings/$","findings"],["nodes/$","nodes"],["hosts/$","nodes"],["containers","containers"],["images/$","images"],["serverless/$","serverless"],["repositories","repositories"],["assets/$","assets"],["deployments/$","deployments"],["services/$","deployments"],["workloads/$","deployments"],["compliance","compliance"],["registries/$","registries"],["registry/$","registries"],["exceptions/$","exceptions"],["runtime/$","runtime"],["response","response"],["response-rules/$","response-rules"],["vuln-profiles","vuln-profiles"],["vulnerability-profiles","vuln-profiles"],["groups/$","groups"],["file-monitor/$","file-monitor"],["timeline","timeline"],["events","timeline"],["activity","timeline"],["incidents","timeline",{tab:"incident"}],["security-events","timeline"],["network","network"],["network-activity","network"],["network-rules/$","network-rules"],["neuvector","neuvector"],["waf/$","runtime-signatures"],["dlp/$","runtime-dlp"],["runtime-policies/$","runtime-policies"],["runtime-dlp/$","runtime-dlp"],["runtime-signatures/$","runtime-signatures"],["admission/$","admission"],["admission-control/$","admission"],["policy","policy"],["policies/$","policies"],["audit","audit"],["audit-log","audit"],["components","components"],["controllers","components",componentDefaults("controller")],["enforcers","components",componentDefaults("enforcer")],["agents","components",componentDefaults("enforcer")],["scanners","components",componentDefaults("scanner")],["risk/$",`risk/deployment/${aliasEntity}`],
];
export const scopedMappings:Array<[string,string,Record<string,string>?]>=[
 ["hosts/$","nodes"],["services/$","deployments"],["workloads/$","deployments"],["registry/$","registries"],["vulnerability-profiles","vuln-profiles"],["events","timeline"],["activity","timeline"],["incidents","timeline",{tab:"incident"}],["security-events","timeline"],["network-activity","network"],["waf/$","runtime-signatures"],["dlp/$","runtime-dlp"],["admission-control/$","admission"],["audit-log","audit"],["controllers","components",componentDefaults("controller")],["enforcers","components",componentDefaults("enforcer")],["agents","components",componentDefaults("enforcer")],["scanners","components",componentDefaults("scanner")],["vulndb","/settings/scanner"],["cve-sources","/settings/scanner"],["notifications","/settings/integrations"],["system-config","/settings/effective-config"],["sysconfig","/settings/effective-config"],["system-health","/settings/health"],["settings","/settings"],["tokens/$","/settings/api-tokens"],["attestation-trust/$","/settings/attestation-trust"],
];
export const organizationMappings:Array<[string,string]>=[
 ["health","/settings/health"],["coverage","/posture"],["system-health","/settings/health"],["access-control/$","/settings/access"],["system-config","/settings/effective-config"],["sysconfig","/settings/effective-config"],["vulndb","/settings/scanner"],["cve-sources","/settings/scanner"],["notifications","/settings/integrations"],["integrations/$","/settings/integrations"],["tokens/$","/settings/api-tokens"],["attestation-trust/$","/settings/attestation-trust"],["attestation/$","/settings/attestation-trust"],
];
export const settingsMappings:Array<[string,string]>=[
 ["system-health","/settings/health"],["tokens/$","/settings/api-tokens"],["attestation/$","/settings/attestation-trust"],["access-control/$","/settings/access"],["notifications/$","/settings/integrations"],["vulndb","/settings/scanner"],
];
const base=(path:string)=>path.replace(/\/\$$/,"");
export const declaredAliases:AliasCase[]=[
 {contract:"rootRoute:/login",from:"/login",to:"/auth/login"},
 ...legacyMappings.map(([path,to,defaults])=>({contract:`authenticatedRoute:${path}`,from:path==="risk/$"?`/risk/deployment/${aliasEntity}`:`/${base(path)}`,to:`/clusters/${aliasCluster}/${to}`,defaults})),
 ...scopedMappings.map(([path,to,defaults])=>({contract:`app_clusters_idRoute:${path}`,from:`/clusters/${aliasSibling}/${base(path)}`,to:to.startsWith("/")?to:`/clusters/${aliasSibling}/${to}`,defaults})),
 ...organizationMappings.map(([path,to])=>({contract:`authenticatedRoute:${path}`,from:`/${base(path)}`,to})),
 ...settingsMappings.map(([path,to])=>({contract:`app_settingsRoute:${path}`,from:`/settings/${base(path)}`,to})),
];
export const deepAliases:AliasCase[]=[
 ...["nodes","hosts","assets","images","serverless","deployments","services","workloads","registries","registry"].map(path=>({contract:`flat ${path} detail`,from:`/${path}/${aliasEntity}`,to:`/clusters/${aliasCluster}/${path==="hosts"?"nodes":["services","workloads"].includes(path)?"deployments":path==="registry"?"registries":path}/${aliasEntity}`})),
 ...["response-rules","groups","network-rules","runtime-policies","runtime-dlp","runtime-signatures","dlp","waf","policies","admission-control","admission"].map(path=>({contract:`flat ${path} form`,from:`/${path}/new`,to:`/clusters/${aliasCluster}/${path==="dlp"?"runtime-dlp":path==="waf"?"runtime-signatures":path==="admission-control"?"admission":path}/new`})),
 ...["hosts","services","workloads","registry"].map(path=>({contract:`scoped ${path} detail`,from:`/clusters/${aliasSibling}/${path}/${aliasEntity}`,to:`/clusters/${aliasSibling}/${path==="hosts"?"nodes":path==="registry"?"registries":"deployments"}/${aliasEntity}`})),
 ...["dlp","waf","admission-control"].map(path=>({contract:`scoped ${path} form`,from:`/clusters/${aliasSibling}/${path}/new`,to:`/clusters/${aliasSibling}/${path==="dlp"?"runtime-dlp":path==="waf"?"runtime-signatures":"admission"}/new`})),
 ...["/access-control","/settings/access-control"].map(path=>({contract:`${path} form`,from:`${path}/users/new`,to:"/settings/access/users/new"})),
 ...["/integrations","/settings/notifications"].map(path=>({contract:`${path} form`,from:`${path}/receivers/new`,to:"/settings/integrations/receivers/new"})),
 ...["/tokens","/settings/tokens",`/clusters/${aliasSibling}/tokens`].map(path=>({contract:`${path} form`,from:`${path}/new`,to:"/settings/api-tokens/new"})),
 ...["/attestation","/attestation-trust","/settings/attestation",`/clusters/${aliasSibling}/attestation-trust`].flatMap(path=>[{contract:`${path} form`,from:`${path}/new`,to:"/settings/attestation-trust/new"},{contract:`${path} edit`,from:`${path}/${aliasEntity}`,to:`/settings/attestation-trust/${aliasEntity}`}]),
 {contract:"flat finding acceptance form",from:`/findings/${aliasEntity}/accept-risk`,to:`/clusters/${aliasCluster}/findings/${aliasEntity}/accept-risk`},
 {contract:"flat runtime baseline form",from:`/runtime/baselines/${aliasEntity}/rules/new`,to:`/clusters/${aliasCluster}/runtime/baselines/${aliasEntity}/rules/new`},
 {contract:"flat file profile form",from:`/file-monitor/${aliasEntity}`,to:`/clusters/${aliasCluster}/file-monitor/${aliasEntity}`},
 {contract:"scoped DLP edit",from:`/clusters/${aliasSibling}/dlp/${aliasEntity}`,to:`/clusters/${aliasSibling}/runtime-dlp/${aliasEntity}`},
 {contract:"scoped WAF edit",from:`/clusters/${aliasSibling}/waf/${aliasEntity}`,to:`/clusters/${aliasSibling}/runtime-signatures/${aliasEntity}`},
 {contract:"scoped admission settings",from:`/clusters/${aliasSibling}/admission-control/settings`,to:`/clusters/${aliasSibling}/admission/settings`},
];
export async function installAliasFixture(page:Page,{empty=false,failed=false}:{empty?:boolean;failed?:boolean}={}){
 const requests:URL[]=[];await page.route("**/api/v1/**",async route=>{const url=new URL(route.request().url()),path=url.pathname.replace(/^\/api\/v1/,"");expect(route.request().method(),"Alias navigation may not author security or settings data").toBe("GET");requests.push(url);
 if(path==="/auth/me")return route.fulfill({json:{user_id:"admin",org_id:"org",email:"admin@example.test",roles:["GlobalAdmin"]}});
 if(path==="/auth/providers")return route.fulfill({json:{providers:[]}});
 if(path==="/clusters")return failed?route.fulfill({status:503,json:{error:"Cluster inventory unavailable"}}):route.fulfill({json:{clusters:empty?[]:[{id:aliasSibling,name:"Less active sibling",state:"connected",deployments:0},{id:aliasCluster,name:"Active destination",state:"connected",deployments:50}]}});
 // Unavailable domain evidence is intentional: qualify routing without fabricating
 // healthy source data or allowing any mutation, even through legacy detail GETs.
 return route.fulfill({status:404,json:{error:`No read-only alias fixture evidence: ${path}`}});
 });return requests;
}
