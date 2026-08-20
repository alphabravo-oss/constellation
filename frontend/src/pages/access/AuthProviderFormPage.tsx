import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { toast } from "sonner";
import { ArrowLeft } from "lucide-react";

import { authServersApi, type AuthServer, type AuthServerConfig } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select, Switch, Textarea } from "@/components/ui/form";

const BACK_TO = "/settings/access?tab=sso";

type ConfigFieldDef = { key: keyof AuthServerConfig; label: string; secret?: boolean; textarea?: boolean; placeholder?: string };

const CONFIG_FIELDS: Record<string, ConfigFieldDef[]> = {
  ldap: [
    { key: "url", label: "Server URL", placeholder: "ldaps://ldap.example.com:636" },
    { key: "bind_dn", label: "Bind DN", placeholder: "cn=admin,dc=example,dc=com" },
    { key: "bind_password", label: "Bind password", secret: true },
    { key: "base_dn", label: "Base DN", placeholder: "dc=example,dc=com" },
    { key: "user_filter", label: "User filter", placeholder: "(uid=%s)" },
    { key: "group_attribute", label: "Group attribute", placeholder: "memberOf" },
    { key: "email_attribute", label: "Email attribute", placeholder: "mail" },
  ],
  saml: [
    { key: "idp_metadata_xml", label: "IdP metadata XML", textarea: true },
    { key: "entity_id", label: "Entity ID" },
    { key: "acs_url", label: "ACS URL" },
    { key: "sp_cert_pem", label: "SP certificate (PEM)", textarea: true },
    { key: "sp_key_pem", label: "SP private key (PEM)", secret: true, textarea: true },
  ],
  oidc: [
    { key: "issuer_url", label: "Issuer URL", placeholder: "https://accounts.example.com" },
    { key: "client_id", label: "Client ID" },
    { key: "client_secret", label: "Client secret", secret: true },
    { key: "redirect_url", label: "Redirect URL", placeholder: "https://app.example.com/auth/callback" },
    { key: "scopes", label: "Scopes (comma-separated)", placeholder: "openid, profile, email" },
  ],
};

/**
 * AuthProviderFormPage — /settings/access/sso/new (create) and
 * /settings/access/sso/:id (edit). A dedicated form page (the Astronomer
 * add/edit-as-a-page pattern, replacing the old drawer). Configures an identity provider
 * that federates sign-in for the organization.
 */
export function AuthProviderFormPage() {
  const { id } = useParams<{ id: string }>();
  const authServersQuery = useQuery({ queryKey: ["auth-servers"], queryFn: () => authServersApi.list(), enabled: Boolean(id) });

  if (id && authServersQuery.isPending) {
    return <p className="text-sm text-muted-foreground">Loading provider…</p>;
  }
  const provider = id ? (authServersQuery.data ?? []).find((p) => p.id === id) ?? null : null;
  if (id && !provider) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Edit authentication provider"
          backLink={<Link to={BACK_TO} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Access Control</Link>}
        />
        <p className="text-sm text-muted-foreground">Provider not found.</p>
      </div>
    );
  }

  return <AuthProviderForm provider={provider} />;
}

function AuthProviderForm({ provider }: { provider: AuthServer | null }) {
  const navigate = useNavigate();
  const isEdit = Boolean(provider?.id);
  const [type, setType] = useState<string>(provider?.type ?? "oidc");
  const [name, setName] = useState(provider?.name ?? "");
  const [authOrder, setAuthOrder] = useState<number>(provider?.auth_order ?? 0);
  const [enabled, setEnabled] = useState<boolean>(provider?.enabled ?? true);
  const [defaultRole, setDefaultRole] = useState(provider?.role_mapping?.default ?? "");
  const [config, setConfig] = useState<Record<string, string>>(() => {
    const c: Record<string, string> = {};
    const src = (provider?.config ?? {}) as Record<string, unknown>;
    for (const [k, v] of Object.entries(src)) {
      if (k === "scopes" && Array.isArray(v)) c[k] = v.join(", ");
      else if (typeof v === "string") c[k] = v;
    }
    // Never prefill secrets — on edit they render blank ("leave blank to keep").
    c.bind_password = ""; c.sp_key_pem = ""; c.client_secret = "";
    return c;
  });
  const setField = (k: string, v: string) => setConfig((p) => ({ ...p, [k]: v }));

  const save = useMutation({
    mutationFn: () => {
      const outConfig: Record<string, unknown> = {};
      for (const f of CONFIG_FIELDS[type]) {
        if (f.key === "scopes") {
          const arr = (config.scopes ?? "").split(",").map((s) => s.trim()).filter(Boolean);
          if (arr.length) outConfig.scopes = arr;
          continue;
        }
        const val = (config[f.key] ?? "").trim();
        if (f.secret && isEdit && !val) continue; // omit blank secret on edit → keep existing
        if (val) outConfig[f.key] = val;
      }
      const body: Omit<AuthServer, "id" | "revision"> = {
        type,
        name: name.trim(),
        enabled,
        auth_order: Number.isNaN(authOrder) ? 0 : authOrder,
        config: outConfig as AuthServerConfig,
        role_mapping: { rules: provider?.role_mapping?.rules ?? {}, default: defaultRole.trim() },
      };
      if (isEdit && provider?.id) {
        return authServersApi.update(provider.id, { ...body, id: provider.id, revision: provider.revision });
      }
      return authServersApi.create(body);
    },
    onSuccess: () => { toast.success(isEdit ? "Provider updated" : "Provider created"); navigate(BACK_TO); },
    onError: () => toast.error(isEdit ? "Failed to update provider" : "Failed to create provider"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title={isEdit ? "Edit authentication provider" : "Add authentication provider"}
        description="Configure an identity provider that federates sign-in for your organization."
        backLink={<Link to={BACK_TO} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Access Control</Link>}
      />

      <Card title="Provider configuration" description="Choose the protocol and fill in the connection details.">
        <form className="space-y-5" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
          <Field label="Type">
            <Select value={type} onChange={(e) => setType(e.target.value)}>
              <option value="ldap">LDAP</option>
              <option value="saml">SAML</option>
              <option value="oidc">OIDC</option>
            </Select>
          </Field>
          <Field label="Name">
            <TextInput value={name} onChange={(e) => setName(e.target.value)} required placeholder="Corporate SSO" />
          </Field>
          <Field label="Auth order" hint="Lower numbers are tried first when multiple providers are enabled.">
            <TextInput
              type="number"
              min={0}
              value={authOrder}
              onChange={(e) => setAuthOrder(Number.parseInt(e.target.value, 10))}
              className="w-28"
            />
          </Field>
          <div className="rounded-lg border border-border bg-muted/30 px-4 py-3">
            <Switch checked={enabled} onCheckedChange={setEnabled} label="Enabled" description="Allow sign-in through this provider." />
          </div>

          {CONFIG_FIELDS[type].map((f) => (
            <Field
              key={f.key}
              label={f.label}
              hint={f.secret && isEdit ? "Leave blank to keep the current secret." : undefined}
            >
              {f.textarea ? (
                <Textarea
                  value={config[f.key] ?? ""}
                  onChange={(e) => setField(f.key, e.target.value)}
                  placeholder={f.secret && isEdit ? "••••••••" : f.placeholder}
                  rows={4}
                />
              ) : (
                <TextInput
                  type={f.secret ? "password" : "text"}
                  value={config[f.key] ?? ""}
                  onChange={(e) => setField(f.key, e.target.value)}
                  placeholder={f.secret && isEdit ? "••••••••" : f.placeholder}
                />
              )}
            </Field>
          ))}

          <Field label="Default role" hint="Role granted to users who sign in through this provider.">
            <TextInput value={defaultRole} onChange={(e) => setDefaultRole(e.target.value)} placeholder="viewer" />
          </Field>

          <div className="flex items-center gap-3">
            <Button type="submit" variant="primary" size="lg" disabled={save.isPending}>
              {save.isPending ? "Saving…" : isEdit ? "Save changes" : "Create provider"}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(BACK_TO)}>Cancel</Button>
          </div>
        </form>
      </Card>
    </div>
  );
}
