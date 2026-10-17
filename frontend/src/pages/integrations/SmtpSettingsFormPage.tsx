import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Save } from "lucide-react";
import { systemConfigApi, type SystemConfigResponse } from "@/api/client";
import { isRevisionConflict } from "@/lib/integration-routing";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Field, Switch, TextInput } from "@/components/ui/form";
import { PageHeader } from "@/components/ui/page";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
const backTo = "/settings/integrations";
const REDACTED = "***REDACTED***";

export function SmtpSettingsFormPage() {
  const q = useQuery({ queryKey: ["system-config"], queryFn: systemConfigApi.get });
  const [initial, setInitial] = useState<SystemConfigResponse | null>(null);
  useEffect(() => { if (!initial && q.isSuccess && !q.isFetching) setInitial(q.data); }, [initial, q.isSuccess, q.isFetching, q.data]);
  const conflict = !!initial && q.data?.revision !== initial.revision;
  return <div className="space-y-6" data-testid="smtp-settings-form-page"><PageHeader title="Edit email server" description="Configure the organization-wide SMTP relay used by every email receiver. Saved passwords remain hidden."
    backLink={<Link to="." href={backTo} className="inline-flex items-center gap-2"><ArrowLeft className="h-4 w-4" /> Integrations</Link>} />
    {!initial ? q.isPending || q.isSuccess ? <LoadingState label="Loading email settings…" /> : <ErrorState title="Could not load email server settings." action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : <>
      {q.isError && <ErrorState title="Could not refresh email settings. Your draft is preserved. Refresh before saving." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
      {conflict && <p role="alert" className="text-sm text-status-error">System configuration changed elsewhere. Your draft is preserved. Reopen the latest settings before saving.</p>}
      <SmtpEditor initial={initial} canSave={q.isSuccess && !q.isFetching && !conflict} />
    </>}
  </div>;
}

function SmtpEditor({ initial, canSave }: { initial: SystemConfigResponse; canSave: boolean }) {
  const stored = (initial.config.smtp ?? {}) as Record<string, unknown>;
  const [host, setHost] = useState(typeof stored.host === "string" ? stored.host : "");
  const [port, setPort] = useState(String(typeof stored.port === "number" ? stored.port : 587));
  const [username, setUsername] = useState(typeof stored.username === "string" ? stored.username : "");
  const [password, setPassword] = useState(typeof stored.password === "string" ? stored.password : "");
  const [from, setFrom] = useState(typeof stored.from === "string" ? stored.from : "");
  const [starttls, setStarttls] = useState(stored.starttls !== false);
  const navigate = useNavigate(); const qc = useQueryClient();
  const numberPort = Number(port);
  const valid = port.trim() !== "" && Number.isInteger(numberPort) && numberPort >= 1 && numberPort <= 65535;
  const save = useMutation({ mutationFn: () => systemConfigApi.patch({ smtp: { host: host.trim(), port: numberPort, username: username.trim(), password, from: from.trim(), starttls } }, initial.revision), onSuccess: () => { void qc.invalidateQueries({ queryKey: ["system-config"] }); void navigate({ href: backTo }); }, onError: (error) => { if (isRevisionConflict(error)) void qc.invalidateQueries({ queryKey: ["system-config"] }); } });
  return <><VerdictBanner status="info" title="This email server is shared across the organization" detail={`Saving updates system configuration revision ${initial.revision}. The stored password is preserved when the redacted value is unchanged.`} />
    <Card title="Email server (SMTP)" description="Every email receiver uses this relay."><form className="space-y-6" onSubmit={(event) => { event.preventDefault(); if (canSave && valid && !isRevisionConflict(save.error) && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5"><Field label="Host" htmlFor="smtp-host" hint="Leave empty to remove the SMTP relay configuration."><TextInput id="smtp-host" value={host} onChange={(event) => setHost(event.target.value)} data-testid="smtp-host" /></Field><Field label="From address" htmlFor="smtp-from"><TextInput id="smtp-from" value={from} onChange={(event) => setFrom(event.target.value)} data-testid="smtp-from" /></Field>
        <Collapse label="Advanced: connection and authentication"><div className="space-y-5 rounded-md border border-border p-4"><Field label="Port" htmlFor="smtp-port" hint="Usually 587 for STARTTLS or 465 for implicit TLS."><TextInput id="smtp-port" type="number" min={1} max={65535} value={port} onChange={(event) => setPort(event.target.value)} data-testid="smtp-port" /></Field><Field label="Username" htmlFor="smtp-username"><TextInput id="smtp-username" value={username} onChange={(event) => setUsername(event.target.value)} data-testid="smtp-username" /></Field><Field label="Password" htmlFor="smtp-password" hint={password === REDACTED ? "A password is set. Leave this field unchanged to preserve it." : "Enter the SMTP authentication password."}><TextInput id="smtp-password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} data-testid="smtp-password" /></Field><Switch label="Require STARTTLS" checked={starttls} onCheckedChange={setStarttls} description="Upgrade the connection before authentication." /></div></Collapse>
      </fieldset>
      {!valid && <p role="alert" className="text-sm text-status-error">Use an integer port from 1 to 65535.</p>}
      {save.isError && <p role="alert" className="text-sm text-status-error">{isRevisionConflict(save.error) ? "System configuration changed elsewhere. Your draft is preserved. Reopen the latest settings before saving." : "Could not save email settings. Your draft is preserved. Try again."}</p>}
      <div className="flex justify-end gap-3 border-t border-border pt-5"><Button type="button" variant="ghost" disabled={save.isPending} onClick={() => void navigate({ href: backTo })}>Cancel</Button><Button type="submit" variant="primary" disabled={isRevisionConflict(save.error) || !canSave || !valid || save.isPending}><Save className="h-4 w-4" />{save.isPending ? "Saving…" : "Save email settings"}</Button></div>
    </form></Card></>;
}
