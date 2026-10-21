import { useQuery } from "@tanstack/react-query";
import { identitySettings } from "@/api/client";
import { PageContainer, PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { LoadingState, ErrorState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";

type Mapping = {claim:string;role:string};
const columns:Column<Mapping>[]=[{id:"claim",header:"Claim value",cell:r=>r.claim},{id:"role",header:"Product role",cell:r=>r.role}];
export function IdentitySettingsPage(){
 const q=useQuery({queryKey:["identity-settings"],queryFn:identitySettings.get});
 if(q.isPending)return <LoadingState />;
 if(q.isError)return <ErrorState error={q.error} action={<Button onClick={()=>void q.refetch()}>Retry</Button>}/>;
 const {oidc,ready,break_glass:emergency}=q.data;
 return <PageContainer><PageHeader title="Single sign-on provider (OIDC)" description="Your organization’s sign-in provider and emergency administrator status." />
 <VerdictBanner status={ready?"ok":"degraded"} title={ready?"Single sign-on is ready":"Single sign-on is unavailable"} numbers={[{label:"Break-glass",value:emergency.enabled?"Enabled":"Disabled"}]} />
 <Card title="Single sign-on provider (OIDC)"><dl className="grid gap-3 text-sm sm:grid-cols-2">
 {Object.entries({Status:oidc?(ready?"Ready":"Provider unavailable"):"Unconfigured","Issuer URL":oidc?.issuer_url,"Client ID":oidc?.client_id,Audience:oidc?.audience,"Roles claim":oidc?.roles_claim,"Redirect URL":oidc?.redirect_url}).map(([name,value])=><div key={name}><dt className="text-muted-foreground">{name}</dt><dd className="break-all">{value??"—"}</dd></div>)}
 </dl><p className="mt-4 text-sm text-muted-foreground">Configuration is managed by your deployment administrator. Client secrets are never displayed.</p></Card>
 <Card title="Role mapping"><DataTable preferencesKey="identity-role-mapping" rows={Object.entries(oidc?.role_mapping??{}).map(([claim,role])=>({claim,role}))} columns={columns} rowKey={r=>r.claim}/><p className="text-sm text-muted-foreground">Unmapped identities have no access. Group changes apply on the next token, within ten minutes.</p></Card>
 <Card title="Break-glass"><dl className="grid gap-3 text-sm sm:grid-cols-3"><div><dt className="text-muted-foreground">Status</dt><dd>{emergency.enabled?"Enabled":"Disabled"}</dd></div><div><dt className="text-muted-foreground">Authenticator</dt><dd>TOTP required</dd></div><div><dt className="text-muted-foreground">Session lifetime</dt><dd>{emergency.session_seconds/60} minutes</dd></div></dl><p className="mt-4 text-sm text-muted-foreground">Emergency access emits a critical audit event and an operator alert.</p></Card>
 </PageContainer>;
}
