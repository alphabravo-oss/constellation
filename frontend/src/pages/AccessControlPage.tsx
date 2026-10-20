import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowRight, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { accessControl, accessControlAdmin,  type AccessControlRole, type AccessControlUser, type AccessControlPermissionMatrixRow, type AccessControlAPIToken } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { ErrorState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatusPill } from "@/components/ui/status-pill";

const userColumns: Column<AccessControlUser>[] = [
  {
    id: "user",
    header: "User", exportValue: (u) => `${u.name} <${u.email}>`, kind: "name", wrap: true,
    cell: (u) => (
      <div>
        <div className="font-medium">{u.name}</div>
        <div className="text-xs text-muted-foreground">{u.email}</div>
      </div>
    ),
  },
  { id: "auth", header: "Auth", exportValue: (u) => u.auth_provider_id, kind: "text", wrap: true, size: 176, minSize: 144, maxSize: 208, cell: (u) => <>{u.auth_provider_id.startsWith("oidc:") ? "Single sign-on" : "Break-glass"}</>, className: "text-xs" },
  {
    id: "roles",
    header: "Roles", exportValue: (u) => u.roles.join("; "), kind: "text", wrap: true, size: 224, minSize: 160, maxSize: 320,
    cell: (u) => <div className="flex flex-wrap gap-1">{u.roles.map((role) => <Badge key={role}>{role}</Badge>)}</div>,
  },
  { id: "status",header:"Status",exportValue:u=>u.status,kind:"status",cell:u=><Status value={u.status}/> },
  { id: "last_seen", header: "Last seen", exportValue: (u) => u.last_login_at ?? "", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (u) => formatDate(u.last_login_at), className: "text-xs text-muted-foreground" },
];

const roleColumns: Column<AccessControlRole>[] = [
  {
    id: "role",
    header: "Role", exportValue: (r) => r.name, kind: "name", wrap: true,
    cell: (r) => (
      <div>
        <div className="font-medium">{r.name}</div>
        {r.description && <div className="text-xs text-muted-foreground">{r.description}</div>}
      </div>
    ),
  },
  { id: "type", header: "Type", exportValue: (r) => r.type, kind: "badge", cell: (r) => <Badge>{r.type}</Badge> },
  {
    id: "permissions",
    header: "Permissions", exportValue: (r) => r.permissions.join("; "), kind: "text", wrap: true, size: 320, minSize: 240, maxSize: 480, grow: true,
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
  { id: "domain", header: "Domain", exportValue: (r) => r.domain, kind: "name", wrap: true, cell: (row) => row.domain, className: "text-xs font-medium" },
  { id: "permissions", header: "Permissions", exportValue: (r) => r.permissions.join("; "), kind: "text", wrap: true, size: 320, minSize: 240, maxSize: 480, grow: true, cell: (row) => row.permissions.join(", "), className: "font-mono text-xs" },
  { id: "roles", header: "Roles", exportValue: (r) => r.roles.join("; "), kind: "text", wrap: true, size: 224, minSize: 160, maxSize: 320, cell: (row) => row.roles.join(", "), className: "text-xs" },
  { id: "notes", header: "Notes", exportValue: (r) => r.notes, kind: "text", wrap: true, size: 240, minSize: 160, maxSize: 360, cell: (row) => row.notes, className: "text-xs text-muted-foreground" },
];

const tokenColumns: Column<AccessControlAPIToken>[] = [
  {
    id: "token",
    header: "Token", exportValue: (t) => `${t.name}; scopes=${t.scopes.join("|")}`, kind: "name", wrap: true,
    cell: (token) => (
      <div>
        <div className="font-medium">{token.name}</div>
        <div className="font-mono text-xs text-muted-foreground">{token.scopes.join(", ") || "no scopes"}</div>
      </div>
    ),
  },
  { id: "status",header:"Status",exportValue:u=>u.status,kind:"status",cell:u=><Status value={u.status}/> },
  { id: "expires", header: "Expires", exportValue: (t) => t.expires_at ?? "", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (token) => formatDate(token.expires_at), className: "text-xs text-muted-foreground" },
];

export function AccessControlPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const q = useQuery({ queryKey: ["access-control"], queryFn: () => accessControl.overview() });
  const roles = useMemo(() => q.data?.roles ?? [], [q.data?.roles]);
  const [tab, setTab] = useTabParam("tab", "users");

  const invalidate = () => qc.invalidateQueries({ queryKey: ["access-control"] });
  const deleteBinding = useMutation({
    mutationFn: (id: string) => accessControlAdmin.deleteRoleBinding(id),
    onSuccess: () => { toast.success("Role binding removed"); void invalidate(); },
    onError: () => toast.error("Failed to remove binding"),
  });
  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading access control...</p>;
  if (q.isError || !q.data) return <PageContainer><PageHeader title="Access control" description="Users, roles and scoped access for your organization." /><VerdictBanner status="degraded" title="Access inventory unavailable" /><ErrorState error={q.error} action={<Button onClick={() => void q.refetch()}>Retry</Button>} /></PageContainer>;
  const data = q.data;

  const tabs = [
    {
      value: "users",
      label: "Users",
      count: data?.users?.length,
      content: (
        <div className="space-y-3">
          <Card padded={false}>
            <div className="overflow-x-auto" data-testid="access-users">
              <DataTable preferencesKey="access-users" exportFileName="access-users" rows={data?.users ?? []} columns={userColumns} rowKey={(u) => u.id} />
            </div>
          </Card>
        </div>
      ),
    },
    {
      value: "roles",
      label: "Roles and permissions",
      count: roles.length,
      content: (
        <div className="space-y-6">
          <Card
            title="Scoped bindings"
            description="Grants of a role to a subject, optionally narrowed to specific clusters or namespaces. This is where you assign access."
            action={
              <Button variant="primary" size="sm" onClick={() => navigate({ href: "/settings/access/bindings/new" })}>
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
            action={
              <Button variant="primary" size="sm" onClick={() => navigate({ href: "/settings/access/roles/new" })}>
                <Plus className="h-3.5 w-3.5" /> New role
              </Button>
            }
          >
            <div className="overflow-x-auto" data-testid="access-roles">
              <DataTable preferencesKey="access-roles" exportFileName="access-roles" rows={roles} columns={roleColumns} rowKey={(r) => r.name} />
            </div>
            <div className="border-t border-border px-5 py-3">
              <Collapse label="Permission matrix — by domain">
                <div className="overflow-x-auto" data-testid="permission-matrix">
                  <DataTable preferencesKey="access-permissions" exportFileName="access-permissions" rows={data?.permission_matrix ?? []} columns={permissionColumns} rowKey={(row) => row.domain} />
                </div>
              </Collapse>
            </div>
          </Card>
        </div>
      ),
    },
    {
      value: "service-accounts",
      label: "Service accounts",
      count: data?.service_accounts?.length,
      content: (
        <Card
          title="Service accounts"
          description="Non-human identities for automation, each with a scoped set of permissions."
          action={
            <Button variant="primary" size="sm" onClick={() => navigate({ href: "/settings/access/service-accounts/new" })}>
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
            <div className="border-t border-border pt-3" data-testid="service-tokens">
              <div className="mb-2 text-xs font-medium text-muted-foreground">API tokens</div>
              <DataTable preferencesKey="access-tokens" exportFileName="access-tokens" rows={data?.api_tokens ?? []} columns={tokenColumns} rowKey={(token) => token.id} />
            </div>
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
        title="Access control"
        description="Who can do what in your organization — users, roles, scoped bindings, SSO, and service accounts."
      />

      <VerdictBanner status="info" title={`${data.summary.users_total} users and ${data.summary.role_bindings_total} scoped bindings reported`} detail="Review roles and bindings to understand organization access." actions={<Button variant="outline" disabled={q.isFetching} onClick={() => void q.refetch()}>Refresh</Button>} numbers={[{ label: "Users", value: data?.summary.users_total ?? 0 }, { label: "Roles", value: data?.summary.roles_total ?? 0 }, { label: "Bindings", value: data?.summary.role_bindings_total ?? 0 }, { label: "API tokens", value: data?.summary.api_tokens_total ?? 0, href: "/settings/api-tokens" }]} />
      

      <Tabs value={tab} onValueChange={setTab} items={tabs} />
    </PageContainer>
  );
}

function Badge({ children }: { children: React.ReactNode }) {
  return <span className="rounded-md bg-muted px-1.5 py-0.5 text-micro text-muted-foreground">{children}</span>;
}

function Status({ value }: { value: string }) {
  const tone: "success" | "warning" | "error" | "info" | "pending" | "neutral" = value === "active" || value === "enabled" || value === "configured"
    ? "success"
    : value === "rotation_due" || value === "planned" || value === "medium" || value === "pending_rotation" || value === "restricted"
      ? "warning"
    : value === "disabled" || value === "expired" || value === "high" || value === "critical" || value === "suspended" || value === "locked"
        ? "error"
        : "neutral";
  return <StatusPill label={value} tone={tone} />;
}

function formatDate(value: string) {
  if (!value) return "not synced";
  return new Date(value).toLocaleString();
}
