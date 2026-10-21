import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { identitySettings, type IdentitySettings } from "@/api/client";
import { useAuth } from "@/contexts/AuthContext";
import { PageContainer, PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { LoadingState, ErrorState } from "@/components/ui/states";
import { Button, Form } from "@/ui";

export function IdentitySettingsPage(){
 const {me}=useAuth();
 const q=useQuery({queryKey:["identity-settings"],queryFn:identitySettings.get,enabled:me?.roles.includes("GlobalAdmin")});
 if(!me?.roles.includes("GlobalAdmin"))return <PageContainer><PageHeader title="Sign-in methods" description="Administrator access is required."/></PageContainer>;
 if(q.isPending)return <LoadingState/>;
 if(q.isError)return <ErrorState error={q.error} action={<Button onClick={()=>void q.refetch()}>Retry</Button>}/>;
 return <IdentityForm key={q.data.revision} initial={q.data}/>;
}
function IdentityForm({initial}:{initial:IdentitySettings}){
 const cache=useQueryClient();const [local,setLocal]=useState(initial.local);const [oidc,setOIDC]=useState(initial.oidc);
 const [secret,setSecret]=useState("");const [mapping,setMapping]=useState(JSON.stringify(initial.oidc?.role_mapping??{},null,2));const [error,setError]=useState("");const [busy,setBusy]=useState(false);
 async function save(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError("");
  try{const roleMapping:Record<string,string>=JSON.parse(mapping);await identitySettings.put({local,oidc:oidc?{...oidc,role_mapping:roleMapping}:null,revision:initial.revision,...(secret?{client_secret:secret}:{})});await cache.invalidateQueries({queryKey:["identity-settings"]});toast.success("Sign-in methods saved");}
  catch(err){setError(err instanceof Error?err.message:"Unable to save sign-in methods");}finally{setBusy(false);}
 }
 function provider(field:string,value:string){setOIDC(old=>old?{...old,[field]:value}:old);}
 return <PageContainer><PageHeader title="Sign-in methods" description="Choose local accounts, single sign-on, or both."/>
 <form onSubmit={save} className="space-y-6">
 {error&&<p role="alert" className="text-sm text-status-error">{error}</p>}
 <Card title="Local accounts"><div className="space-y-4">
 <Form.Field label="Local sign-in">{ids=><Form.Select {...ids} options={[{value:"on",label:"Enabled"},{value:"off",label:"Disabled"}]} value={local.enabled?"on":"off"} onValueChange={v=>setLocal({...local,enabled:v==="on"})}/>}</Form.Field>
 <p className="text-sm text-muted-foreground">When disabled, normal local sessions are revoked. The recovery administrator still works if single sign-on is unavailable or unconfigured.</p>
 <div className="grid gap-4 sm:grid-cols-2">
 <Form.Field label="Require TOTP">{ids=><Form.Select {...ids} options={[{value:"everyone",label:"Everyone"},{value:"admins",label:"Administrators only"}]} value={local.totp_policy} onValueChange={v=>setLocal({...local,totp_policy:v as "everyone"|"admins"})}/>}</Form.Field>
 <Form.Field label="Login page methods">{ids=><Form.Select {...ids} options={[{value:"all",label:"All enabled methods"},{value:"local",label:"Local accounts"},{value:"sso",label:"Single sign-on"}]} value={local.display} onValueChange={v=>setLocal({...local,display:v as "all"|"local"|"sso"})}/>}</Form.Field>
 {([ ["password_min_length","Minimum password length",12,128], ["session_seconds","Session lifetime (seconds)",60,86400], ["ip_rate","Attempts per IP per minute",1,100], ["account_rate","Failures before account backoff",1,20] ] as const).map(([field,label,min,max])=><Form.Field key={field} label={label}>{ids=><Form.Input {...ids} type="number" min={min} max={max} required value={local[field]} onChange={e=>setLocal({...local,[field]:Number(e.target.value)})}/>}</Form.Field>)}
 </div></div></Card>
 <Card title="Single sign-on provider (OIDC)"><div className="space-y-4">
 <Form.Field label="Single sign-on">{ids=><Form.Select {...ids} options={[{value:"off",label:"Unconfigured"},{value:"on",label:"Configured"}]} value={oidc?"on":"off"} onValueChange={v=>setOIDC(v==="off"?null:{issuer_url:"",client_id:"",audience:"",redirect_url:window.location.origin+"/api/v1/auth/oidc/callback",roles_claim:"alphabravo_roles",role_mapping:{},org_name:"default",scopes:["openid","email","profile"]})}/>}</Form.Field>
 <p className="text-sm text-muted-foreground">Status: {initial.oidc?(initial.ready?"Ready":"Provider unavailable"):"Unconfigured"}</p>
 {oidc&&<><div className="grid gap-4 sm:grid-cols-2">{([ ["issuer_url","Issuer URL"], ["client_id","Client ID"], ["audience","Audience"], ["redirect_url","Redirect URL"], ["roles_claim","Roles claim"] ] as const).map(([field,label])=><Form.Field label={label} key={field}>{ids=><Form.Input {...ids} required={field!=="audience"} value={oidc[field]} onChange={e=>provider(field,e.target.value)}/>}</Form.Field>)}<Form.Field label="Client secret" helper="Leave empty to keep the current secret.">{ids=><Form.Input {...ids} type="password" autoComplete="new-password" value={secret} onChange={e=>setSecret(e.target.value)}/>}</Form.Field></div>
 <Form.Field label="Role mapping" helper="JSON object mapping exact claim values to product roles. Unmapped users have no access.">{ids=><Form.Textarea {...ids} value={mapping} onChange={e=>setMapping(e.target.value)}/>}</Form.Field></>}
 </div></Card>
 <Card title="Recovery administrator"><p className="text-sm">TOTP required. Session lifetime: {initial.break_glass.session_seconds/60} minutes.</p><p className="mt-2 text-sm text-muted-foreground">Every recovery sign-in emits a critical audit event and an operator alert.</p></Card>
 <Button type="submit" disabled={busy}>{busy?"Saving…":"Save sign-in methods"}</Button>
 </form></PageContainer>;
}
