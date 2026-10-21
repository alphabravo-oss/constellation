import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { localUsers, type LocalEnrollment, type LocalUser } from "@/api/client";
import { useAuth } from "@/contexts/AuthContext";
import { PageContainer, PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { LoadingState, ErrorState } from "@/components/ui/states";
import { Button, Form } from "@/ui";

const roles = ["Analyst", "Auditor", "ClusterAdmin", "SecurityAdmin", "GlobalAdmin"].map(value=>({value,label:value.replace(/([a-z])([A-Z])/g,"$1 $2")}));
export function UsersPage() {
 const { me } = useAuth();
 const cache = useQueryClient();
 const q = useQuery({queryKey:["local-users"],queryFn:localUsers.list,enabled:me?.roles.includes("GlobalAdmin")});
 const [email,setEmail]=useState("");const [name,setName]=useState("");const [password,setPassword]=useState("");const [role,setRole]=useState("Analyst");
 const [setup,setSetup]=useState<LocalEnrollment|null>(null);const [busy,setBusy]=useState(false);const [error,setError]=useState("");
 const [reset,setReset]=useState<LocalUser|null>(null);const [newPassword,setNewPassword]=useState("");
 if(!me?.roles.includes("GlobalAdmin")) return <PageContainer><PageHeader title="Users" description="Administrator access is required." /></PageContainer>;
 async function change(user:LocalUser,action:string,body:{password?:string;role?:string}={}){
  setBusy(true);setError("");setSetup(null);
  try{const out=await localUsers.change(user.id,action,body);if(out.password||out.totp_secret)setSetup(out);await cache.invalidateQueries({queryKey:["local-users"]});setReset(null);setNewPassword("");toast.success("User updated");}
  catch(err){setError(err instanceof Error?err.message:"Unable to update user");}finally{setBusy(false);}
 }
 async function create(e:React.FormEvent){
  e.preventDefault();setBusy(true);setError("");setSetup(null);
  try{setSetup(await localUsers.create({email,display_name:name,password,role}));setEmail("");setName("");setPassword("");await cache.invalidateQueries({queryKey:["local-users"]});toast.success("User created");}
  catch(err){setError(err instanceof Error?err.message:"Unable to create user");}finally{setBusy(false);}
 }
 const columns:Column<LocalUser>[]=[
  {id:"email",header:"Email",cell:u=><div><span>{u.email}</span><p className="text-meta text-muted-foreground">{u.display_name}{u.break_glass?" · Recovery administrator":""}</p></div>},
  {id:"status",header:"Status",cell:u=>u.status},
  {id:"role",header:"Role",cell:u=><Form.Select aria-label={`Role for ${u.email}`} options={roles} value={u.roles[0]} disabled={busy||u.break_glass||u.id===me?.user_id} onValueChange={role=>void change(u,"role",{role})}/>},
  {id:"last",header:"Last sign-in",cell:u=>u.last_login?new Date(u.last_login).toLocaleString():"Never"},
  {id:"actions",header:"Actions",cell:u=><div className="flex flex-wrap gap-2"><Button size="sm" intent="default" disabled={busy||u.status==="disabled"||u.break_glass||u.id===me?.user_id} onClick={()=>void change(u,"disable")}>Disable</Button><Button size="sm" intent="default" disabled={busy} onClick={()=>{setReset(u);setSetup(null);}}>Reset password</Button><Button size="sm" intent="default" disabled={busy} onClick={()=>void change(u,"reset-totp")}>Reset TOTP</Button></div>},
 ];
 return <PageContainer><PageHeader title="Users" description="Create local accounts, assign roles and manage access." />
 {error&&<p role="alert" className="text-sm text-status-error">{error}</p>}
 {setup&&<Card title="Account setup" description="Shown once. Share privately with the account owner and enroll the authenticator before signing in."><dl className="space-y-3 text-sm">{setup.password&&<div><dt>Password</dt><dd className="break-all font-mono" data-testid="setup-password">{setup.password}</dd></div>}{setup.totp_secret&&<><div><dt>Authenticator seed</dt><dd className="break-all font-mono" data-testid="setup-totp">{setup.totp_secret}</dd></div><div><dt>Enrollment URI</dt><dd className="break-all font-mono">{setup.totp_uri}</dd></div></>}</dl><Button className="mt-4" intent="default" onClick={()=>setSetup(null)}>Dismiss setup</Button></Card>}
 {reset&&<Card title={`Reset password for ${reset.email}`}><form className="space-y-4" onSubmit={e=>{e.preventDefault();void change(reset,"reset-password",{password:newPassword});}}><Form.Field label="New password" helper="Leave empty to generate a strong password.">{ids=><Form.Input {...ids} type="password" autoComplete="new-password" value={newPassword} onChange={e=>setNewPassword(e.target.value)}/>}</Form.Field><div className="flex gap-2"><Button type="submit" disabled={busy}>Reset password</Button><Button type="button" intent="default" onClick={()=>setReset(null)}>Cancel</Button></div></form></Card>}
 <Card title="Create user"><form onSubmit={create} className="space-y-4"><div className="grid gap-4 sm:grid-cols-2">
 <Form.Field label="Email" required>{ids=><Form.Input {...ids} type="email" required autoComplete="off" value={email} onChange={e=>setEmail(e.target.value)}/>}</Form.Field>
 <Form.Field label="Display name">{ids=><Form.Input {...ids} value={name} onChange={e=>setName(e.target.value)}/>}</Form.Field>
 <Form.Field label="Password" helper="Leave empty to generate. Breached passwords are refused offline.">{ids=><Form.Input {...ids} type="password" autoComplete="new-password" value={password} onChange={e=>setPassword(e.target.value)}/>}</Form.Field>
 <Form.Field label="Role">{ids=><Form.Select {...ids} options={roles} value={role} onValueChange={setRole}/>}</Form.Field>
 </div><Button type="submit" disabled={busy}>{busy?"Saving…":"Create user"}</Button></form></Card>
 <Card title="Local accounts">{q.isPending?<LoadingState/>:q.isError?<ErrorState error={q.error} action={<Button onClick={()=>void q.refetch()}>Retry</Button>}/>:<DataTable preferencesKey="local-users" rows={q.data.users} columns={columns} rowKey={u=>u.id}/>}</Card>
 </PageContainer>;
}
