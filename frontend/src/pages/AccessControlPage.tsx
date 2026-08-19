import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ArrowRight, KeyRound, Plus, ShieldCheck, Trash2, UserRoundCog, UsersRound } from "lucide-react";
import { toast } from "sonner";

import {
  accessControl,
  accessControlAdmin,
  type AccessControlRole,
  type AccessControlUser,
  type AccessControlPermissionMatrixRow,
} from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Drawer } from "@/components/ui/drawer";

const userColumns: Column<AccessControlUser>[] = [
  {
    id: "user",
    header: "User",
    cell: (u) => (
      <div>
        <div className="font-medium">{u.name}</div>
        <div className="text-xs text-muted-foreground">{u.email}</div>
      </div>
    ),
  },
  { id: "auth", header: "Auth", cell: (u) => <>{u.auth_provider_id} · {u.mfa_enabled ? "MFA" : "no MFA"}</>, className: "text-xs" },
  {
    id: "roles",
    header: "Roles",
    cell: (u) => <div className="flex flex-wrap gap-1">{u.roles.map((role) => <Badge key={role}>{role}</Badge>)}</div>,
  },
  { id: "status", header: "Status", cell: (u) => <Status value={u.status} /> },
  { id: "last_seen", header: "Last Seen", cell: (u) => formatDate(u.last_login_at), className: "text-xs text-muted-foreground" },
];

const permissionColumns: Column<AccessControlPermissionMatrixRow>[] = [
  { id: "domain", header: "Domain", cell: (row) => row.domain, className: "text-xs font-medium" },
  { id: "permissions", header: "Permissions", cell: (row) => row.permissions.join(", "), className: "font-mono text-xs" },
  { id: "roles", header: "Roles", cell: (row) => row.roles.join(", "), className: "text-xs" },
  { id: "notes", header: "Notes", cell: (row) => row.notes, className: "text-xs text-muted-foreground" },
];

export function AccessControlPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["access-control"], queryFn: () => accessControl.overview() });
  const roles = useMemo(() => q.data?.roles ?? [], [q.data?.roles]);
  const [tab, setTab] = useTabParam("tab", "users");
  const [bindingOpen, setBindingOpen] = useState(false);
  const [saOpen, setSaOpen] = useState(false);

  const invalidate = () => qc.invalidateQueries({ queryKey: ["access-control"] });
  const deleteBinding = useMutation({
    mutationFn: (id: string) => accessControlAdmin.deleteRoleBinding(id),
    onSuccess: () => { toast.success("Role binding removed"); void invalidate(); },
    onError: () => toast.error("Failed to remove binding"),
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading access control...</p>;
  const data = q.data;

  const tabs = [
    {
      value: "users",
      label: "Users",
      count: data?.users?.length,
      content: (
        <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="access-users">
          <DataTable rows={data?.users ?? []} columns={userColumns} rowKey={(u) => u.id} />
        </div>
      ),
    },
    {
      value: "roles",
      label: "Roles & Permissions",
      count: roles.length,
      content: (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold">Roles</h2>
          </div>
          <div className="grid gap-3 lg:grid-cols-2" data-testid="access-roles">
            {roles.map((role) => <RoleCard key={role.name} role={role} />)}
          </div>

          <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="permission-matrix">
            <div className="border-b border-border p-4"><h2 className="text-sm font-semibold">Permission matrix</h2></div>
            <DataTable rows={data?.permission_matrix ?? []} columns={permissionColumns} rowKey={(row) => row.domain} />
          </div>

          <section className="rounded-lg border border-border bg-card p-4" data-testid="access-bindings">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-semibold">Scoped bindings</h2>
              <button type="button" onClick={() => setBindingOpen(true)} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-2.5 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90">
                <Plus className="h-3.5 w-3.5" /> Add binding
              </button>
            </div>
            <div className="space-y-2">
              {(data?.role_bindings ?? []).length === 0 && <p className="text-xs text-muted-foreground">No scoped bindings.</p>}
              {(data?.role_bindings ?? []).map((binding) => (
                <article key={binding.id} className="flex items-center justify-between gap-2 rounded-md bg-muted p-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="truncate text-xs font-medium">{binding.subject_id}</div>
                      <Badge>{binding.role_id}</Badge>
                    </div>
                    <div className="mt-1 font-mono text-xs text-muted-foreground">
                      {binding.scopes.map((scope) => `${scope.kind}:${scope.values.join("|")}`).join(", ") || "org-wide"}
                    </div>
                  </div>
                  <button type="button" aria-label="Remove binding" disabled={deleteBinding.isPending} onClick={() => { if (window.confirm(`Remove binding of ${binding.subject_id} → ${binding.role_id}?`)) deleteBinding.mutate(binding.id); }} className="shrink-0 rounded-md p-1.5 text-muted-foreground hover:bg-background hover:text-destructive disabled:opacity-50">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </article>
              ))}
            </div>
          </section>
        </div>
      ),
    },
    {
      value: "sso",
      label: "SSO / Auth",
      count: data?.auth_providers?.length,
      content: (
        <section className="rounded-lg border border-border bg-card p-4" data-testid="auth-providers">
          <div className="space-y-2">
            {(data?.auth_providers ?? []).length === 0 && <p className="text-xs text-muted-foreground">No auth providers configured.</p>}
            {(data?.auth_providers ?? []).map((provider) => (
              <article key={provider.id} className="rounded-md border border-border p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-medium">{provider.name}</div>
                  <Status value={provider.status} />
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{provider.type} · {provider.domains.join(", ")}</p>
              </article>
            ))}
          </div>
        </section>
      ),
    },
    {
      value: "service-accounts",
      label: "Service Accounts",
      count: data?.service_accounts?.length,
      content: (
        <div className="space-y-3" data-testid="service-accounts">
          <div className="flex items-center justify-between">
            <Link to="/settings/api-tokens" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              Manage API tokens <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <button type="button" onClick={() => setSaOpen(true)} className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-2.5 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90">
              <Plus className="h-3.5 w-3.5" /> New service account
            </button>
          </div>
          {(data?.service_accounts ?? []).length === 0 && <p className="text-xs text-muted-foreground">No service accounts.</p>}
          {(data?.service_accounts ?? []).map((account) => (
            <article key={account.id} className="rounded-md border border-border p-3">
              <div className="flex items-center justify-between gap-2">
                <div className="text-sm font-medium">{account.name}</div>
                <Status value={account.status} />
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{account.description}</p>
              <div className="mt-2 flex flex-wrap gap-1">
                {account.scopes.map((scope) => <Badge key={scope}>{scope}</Badge>)}
              </div>
            </article>
          ))}
        </div>
      ),
    },
    {
      value: "guardrails",
      label: "Guardrails",
      count: data?.guardrails?.length,
      content: (
        <section className="rounded-lg border border-border bg-card p-4" data-testid="access-guardrails">
          <div className="space-y-2">
            {(data?.guardrails ?? []).length === 0 && <p className="text-xs text-muted-foreground">No guardrails.</p>}
            {(data?.guardrails ?? []).map((guardrail) => (
              <article key={guardrail.id} className="rounded-md bg-muted p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-xs font-medium">{guardrail.name}</div>
                  <Status value={guardrail.severity} />
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{guardrail.description}</p>
              </article>
            ))}
          </div>
        </section>
      ),
    },
  ];

  return (
    <PageContainer>
      <PageHeader
        title="Access Control"
        description="Who can do what in your organization — users, roles, scoped bindings, SSO, and service accounts."
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="Users" value={data?.summary.users_total ?? 0} icon={<UsersRound className="h-3.5 w-3.5" />} />
        <StatCard label="Roles" value={data?.summary.roles_total ?? 0} icon={<ShieldCheck className="h-3.5 w-3.5" />} />
        <StatCard label="Bindings" value={data?.summary.role_bindings_total ?? 0} icon={<UserRoundCog className="h-3.5 w-3.5" />} />
        <StatCard label="API tokens" value={data?.summary.api_tokens_total ?? 0} icon={<KeyRound className="h-3.5 w-3.5" />} href="/settings/api-tokens" />
      </section>

      <Tabs value={tab} onValueChange={setTab} items={tabs} />

      <RoleBindingDrawer open={bindingOpen} onOpenChange={setBindingOpen} roles={roles} onSaved={invalidate} />
      <ServiceAccountDrawer open={saOpen} onOpenChange={setSaOpen} onSaved={invalidate} />
    </PageContainer>
  );
}

function RoleBindingDrawer({ open, onOpenChange, roles, onSaved }: { open: boolean; onOpenChange: (o: boolean) => void; roles: AccessControlRole[]; onSaved: () => void }) {
  const [subjectId, setSubjectId] = useState("");
  const [subjectType, setSubjectType] = useState("user");
  const [roleId, setRoleId] = useState("");
  const [scopeKind, setScopeKind] = useState("");
  const [scopeValues, setScopeValues] = useState("");
  const save = useMutation({
    mutationFn: () =>
      accessControlAdmin.createRoleBinding({
        subject_id: subjectId.trim(),
        subject_type: subjectType,
        role_id: roleId,
        scopes: scopeKind.trim()
          ? [{ kind: scopeKind.trim(), values: scopeValues.split(",").map((v) => v.trim()).filter(Boolean), inherited: false }]
          : [],
      }),
    onSuccess: () => { toast.success("Role binding created"); onOpenChange(false); setSubjectId(""); setRoleId(""); setScopeKind(""); setScopeValues(""); onSaved(); },
    onError: () => toast.error("Failed to create binding"),
  });
  return (
    <Drawer open={open} onOpenChange={onOpenChange} title="Add role binding" description="Grant a role to a subject, optionally scoped to specific resources.">
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <Field label="Subject ID"><input value={subjectId} onChange={(e) => setSubjectId(e.target.value)} required className={inputCls} placeholder="user@org or id" /></Field>
        <Field label="Subject type">
          <select value={subjectType} onChange={(e) => setSubjectType(e.target.value)} className={inputCls}>
            <option value="user">user</option>
            <option value="group">group</option>
            <option value="service_account">service account</option>
          </select>
        </Field>
        <Field label="Role">
          <select value={roleId} onChange={(e) => setRoleId(e.target.value)} required className={inputCls}>
            <option value="" disabled>Select a role…</option>
            {roles.map((r) => <option key={r.name} value={r.name}>{r.name}</option>)}
          </select>
        </Field>
        <Field label="Scope kind (optional)"><input value={scopeKind} onChange={(e) => setScopeKind(e.target.value)} className={inputCls} placeholder="cluster / namespace" /></Field>
        <Field label="Scope values (comma-separated)"><input value={scopeValues} onChange={(e) => setScopeValues(e.target.value)} className={inputCls} placeholder="prod-1, prod-2" /></Field>
        <button type="submit" disabled={save.isPending} className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">{save.isPending ? "Creating…" : "Create binding"}</button>
      </form>
    </Drawer>
  );
}

function ServiceAccountDrawer({ open, onOpenChange, onSaved }: { open: boolean; onOpenChange: (o: boolean) => void; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [scopes, setScopes] = useState("");
  const save = useMutation({
    mutationFn: () =>
      accessControlAdmin.createServiceAccount({
        name: name.trim(),
        description: description.trim() || undefined,
        scopes: scopes.split(",").map((s) => s.trim()).filter(Boolean),
      }),
    onSuccess: () => { toast.success("Service account created"); onOpenChange(false); setName(""); setDescription(""); setScopes(""); onSaved(); },
    onError: () => toast.error("Failed to create service account"),
  });
  return (
    <Drawer open={open} onOpenChange={onOpenChange} title="New service account" description="A non-human identity for automation, with scoped permissions.">
      <form className="space-y-3" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} required className={inputCls} placeholder="ci-scanner" /></Field>
        <Field label="Description"><input value={description} onChange={(e) => setDescription(e.target.value)} className={inputCls} /></Field>
        <Field label="Scopes (comma-separated)"><input value={scopes} onChange={(e) => setScopes(e.target.value)} className={inputCls} placeholder="findings:read, scan:write" /></Field>
        <button type="submit" disabled={save.isPending} className="w-full rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">{save.isPending ? "Creating…" : "Create service account"}</button>
      </form>
    </Drawer>
  );
}

const inputCls = "mt-1 w-full rounded-md border border-border bg-background p-2 text-sm";
function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <label className="block text-xs font-medium">{label}{children}</label>;
}


function RoleCard({ role }: { role: AccessControlRole }) {
  return (
    <article className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold">{role.name}</h3>
          <p className="mt-1 text-xs text-muted-foreground">{role.description}</p>
        </div>
          <Badge>{role.type}</Badge>
      </div>
      <div className="mt-3 flex flex-wrap gap-1">
        {role.permissions.map((permission) => <Badge key={permission}>{permission}</Badge>)}
      </div>
    </article>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{children}</span>;
}

function Status({ value }: { value: string }) {
  const cls = value === "active" || value === "enabled" || value === "configured"
    ? "bg-[color:var(--color-status-success)]/15 text-[color:var(--color-status-success)]"
    : value === "rotation_due" || value === "planned" || value === "medium" || value === "pending_rotation" || value === "restricted"
      ? "bg-[color:var(--color-status-warning)]/15 text-[color:var(--color-status-warning)]"
      : value === "disabled" || value === "expired" || value === "high" || value === "critical" || value === "suspended"
        ? "bg-[color:var(--color-status-error)]/15 text-[color:var(--color-status-error)]"
        : "bg-muted text-muted-foreground";
  return <span className={`rounded-md px-2 py-1 text-xs ${cls}`}>{value}</span>;
}

function formatDate(value: string) {
  if (!value) return "not synced";
  return new Date(value).toLocaleString();
}
