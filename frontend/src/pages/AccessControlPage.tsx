import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { ArrowRight, KeyRound, Pencil, Plus, ShieldCheck, Trash2, UserRoundCog, UsersRound } from "lucide-react";
import { toast } from "sonner";

import {
  accessControl,
  accessControlAdmin,
  authServersApi,
  type AccessControlRole,
  type AccessControlUser,
  type AccessControlPermissionMatrixRow,
} from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";

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

const roleColumns: Column<AccessControlRole>[] = [
  {
    id: "role",
    header: "Role",
    cell: (r) => (
      <div>
        <div className="font-medium">{r.name}</div>
        {r.description && <div className="text-xs text-muted-foreground">{r.description}</div>}
      </div>
    ),
  },
  { id: "type", header: "Type", cell: (r) => <Badge>{r.type}</Badge> },
  {
    id: "permissions",
    header: "Permissions",
    cell: (r) => (
      <div className="flex flex-wrap gap-1">
        {r.permissions.length === 0 ? (
          <span className="text-xs text-muted-foreground">—</span>
        ) : (
          r.permissions.map((p) => <Badge key={p}>{p}</Badge>)
        )}
      </div>
    ),
  },
];

const permissionColumns: Column<AccessControlPermissionMatrixRow>[] = [
  { id: "domain", header: "Domain", cell: (row) => row.domain, className: "text-xs font-medium" },
  { id: "permissions", header: "Permissions", cell: (row) => row.permissions.join(", "), className: "font-mono text-xs" },
  { id: "roles", header: "Roles", cell: (row) => row.roles.join(", "), className: "text-xs" },
  { id: "notes", header: "Notes", cell: (row) => row.notes, className: "text-xs text-muted-foreground" },
];

export function AccessControlPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["access-control"], queryFn: () => accessControl.overview() });
  const roles = useMemo(() => q.data?.roles ?? [], [q.data?.roles]);
  const [tab, setTab] = useTabParam("tab", "users");

  const authServersQuery = useQuery({ queryKey: ["auth-servers"], queryFn: () => authServersApi.list() });
  const authProviders = authServersQuery.data ?? [];

  const invalidate = () => qc.invalidateQueries({ queryKey: ["access-control"] });
  const invalidateAuth = () => qc.invalidateQueries({ queryKey: ["auth-servers"] });
  const deleteBinding = useMutation({
    mutationFn: (id: string) => accessControlAdmin.deleteRoleBinding(id),
    onSuccess: () => { toast.success("Role binding removed"); void invalidate(); },
    onError: () => toast.error("Failed to remove binding"),
  });
  const deleteProvider = useMutation({
    mutationFn: (id: string) => authServersApi.delete(id),
    onSuccess: () => { toast.success("Provider deleted"); void invalidateAuth(); },
    onError: () => toast.error("Failed to delete provider"),
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading access control...</p>;
  const data = q.data;

  const tabs = [
    {
      value: "users",
      label: "Users",
      count: data?.users?.length,
      content: (
        <Card padded={false}>
          <div className="overflow-x-auto" data-testid="access-users">
            <DataTable rows={data?.users ?? []} columns={userColumns} rowKey={(u) => u.id} />
          </div>
        </Card>
      ),
    },
    {
      value: "roles",
      label: "Roles & Permissions",
      count: roles.length,
      content: (
        <div className="space-y-6">
          <Card
            title="Scoped bindings"
            description="Grants of a role to a subject, optionally narrowed to specific clusters or namespaces. This is where you assign access."
            action={
              <Button variant="primary" size="sm" onClick={() => navigate("/settings/access/bindings/new")}>
                <Plus className="h-3.5 w-3.5" /> Add binding
              </Button>
            }
          >
            <div className="space-y-2" data-testid="access-bindings">
              {(data?.role_bindings ?? []).length === 0 && <p className="text-xs text-muted-foreground">No scoped bindings.</p>}
              {(data?.role_bindings ?? []).map((binding) => (
                <article key={binding.id} className="flex items-center justify-between gap-2 rounded-lg border border-border bg-muted/30 p-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="truncate text-xs font-medium">{binding.subject_id}</div>
                      <Badge>{binding.role_id}</Badge>
                    </div>
                    <div className="mt-1 font-mono text-xs text-muted-foreground">
                      {binding.scopes.map((scope) => `${scope.kind}:${scope.values.join("|")}`).join(", ") || "org-wide"}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Remove binding"
                    disabled={deleteBinding.isPending}
                    onClick={() => { if (window.confirm(`Remove binding of ${binding.subject_id} → ${binding.role_id}?`)) deleteBinding.mutate(binding.id); }}
                    className="shrink-0 text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </article>
              ))}
            </div>
          </Card>

          <Card
            title="Roles"
            description="The named permission sets you can bind. Built-in roles are fixed; custom roles are defined by your org."
            padded={false}
          >
            <div className="overflow-x-auto" data-testid="access-roles">
              <DataTable rows={roles} columns={roleColumns} rowKey={(r) => r.name} />
            </div>
            <div className="border-t border-border px-5 py-3">
              <Collapse label="Permission matrix — by domain">
                <div className="overflow-x-auto" data-testid="permission-matrix">
                  <DataTable rows={data?.permission_matrix ?? []} columns={permissionColumns} rowKey={(row) => row.domain} />
                </div>
              </Collapse>
            </div>
          </Card>
        </div>
      ),
    },
    {
      value: "sso",
      label: "SSO / Auth",
      count: authProviders.length,
      content: (
        <Card
          title="Authentication providers"
          description="Identity providers (LDAP, SAML, OIDC) that federate sign-in for your organization."
          action={
            <Button variant="primary" size="sm" onClick={() => navigate("/settings/access/sso/new")}>
              <Plus className="h-3.5 w-3.5" /> Add provider
            </Button>
          }
        >
          <div className="space-y-2" data-testid="auth-providers">
            {authServersQuery.isPending && <p className="text-xs text-muted-foreground">Loading providers…</p>}
            {!authServersQuery.isPending && authProviders.length === 0 && (
              <p className="text-xs text-muted-foreground">No authentication providers yet. Add one to federate sign-in.</p>
            )}
            {authProviders.map((provider) => {
              const detail =
                provider.type === "ldap" ? provider.config.url
                : provider.type === "oidc" ? provider.config.issuer_url
                : provider.config.entity_id;
              return (
                <article key={provider.id} className="flex items-center justify-between gap-2 rounded-lg border border-border p-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <div className="truncate text-sm font-medium">{provider.name}</div>
                      <Badge>{provider.type}</Badge>
                      <Status value={provider.enabled ? "enabled" : "disabled"} />
                    </div>
                    <p className="mt-1 truncate font-mono text-xs text-muted-foreground">{detail || "—"}</p>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label="Edit provider"
                      onClick={() => navigate(`/settings/access/sso/${provider.id}`)}
                      className="text-muted-foreground hover:text-foreground"
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      aria-label="Delete provider"
                      disabled={deleteProvider.isPending}
                      onClick={() => { if (window.confirm(`Delete ${provider.name}?`)) deleteProvider.mutate(provider.id!); }}
                      className="text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </article>
              );
            })}
          </div>
        </Card>
      ),
    },
    {
      value: "service-accounts",
      label: "Service Accounts",
      count: data?.service_accounts?.length,
      content: (
        <Card
          title="Service accounts"
          description="Non-human identities for automation, each with a scoped set of permissions."
          action={
            <Button variant="primary" size="sm" onClick={() => navigate("/settings/access/service-accounts/new")}>
              <Plus className="h-3.5 w-3.5" /> New service account
            </Button>
          }
        >
          <div className="space-y-3" data-testid="service-accounts">
            <Link to="/settings/api-tokens" className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
              Manage API tokens <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            {(data?.service_accounts ?? []).length === 0 && <p className="text-xs text-muted-foreground">No service accounts.</p>}
            {(data?.service_accounts ?? []).map((account) => (
              <article key={account.id} className="rounded-lg border border-border p-3">
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
        </Card>
      ),
    },
    {
      value: "guardrails",
      label: "Guardrails",
      count: data?.guardrails?.length,
      content: (
        <Card title="Guardrails" description="Org-wide policies that constrain what roles and bindings are allowed to do.">
          <div className="space-y-2" data-testid="access-guardrails">
            {(data?.guardrails ?? []).length === 0 && <p className="text-xs text-muted-foreground">No guardrails.</p>}
            {(data?.guardrails ?? []).map((guardrail) => (
              <article key={guardrail.id} className="rounded-lg border border-border bg-muted/30 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-xs font-medium">{guardrail.name}</div>
                  <Status value={guardrail.severity} />
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{guardrail.description}</p>
              </article>
            ))}
          </div>
        </Card>
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
    </PageContainer>
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
