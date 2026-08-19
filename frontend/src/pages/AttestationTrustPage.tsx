// Route: /settings/attestation-trust.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  ArrowLeft,
  BadgeCheck,
  CheckCircle2,
  Edit2,
  Fingerprint,
  Plus,
  RefreshCw,
  Save,
  ShieldCheck,
  Trash2,
} from "lucide-react";

import {
  repositoryScanAttestationTrustPolicies,
  type RepositoryAttestationTrustPolicy,
  type RepositoryAttestationTrustPolicyInput,
} from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Drawer } from "@/components/ui/drawer";
import { Collapse } from "@/components/ui/collapse";

type PolicyFormState = {
  name: string;
  description: string;
  enabled: boolean;
  auto_verify: boolean;
  subject_kind: "image";
  source_types: string[];
  repository_ref_patterns: string;
  source_ref_patterns: string;
  predicate_types: string;
  allowed_identities: string;
  allowed_issuers: string;
  require_rekor: boolean;
  verifier_mode: "keyless" | "public-key";
  public_key_pem: string;
};

const SOURCE_TYPES = [
  "repository",
  "registry",
  "runtime-agent",
  "manual",
  "discoverer",
  "platform",
  "host",
  "serverless",
];

const DEFAULT_FORM: PolicyFormState = {
  name: "",
  description: "",
  enabled: true,
  auto_verify: true,
  subject_kind: "image",
  source_types: ["repository"],
  repository_ref_patterns: "",
  source_ref_patterns: "",
  predicate_types: "https://slsa.dev/provenance/v1",
  allowed_identities: "",
  allowed_issuers: "https://token.actions.githubusercontent.com",
  require_rekor: false,
  verifier_mode: "keyless",
  public_key_pem: "",
};

export function AttestationTrustPage() {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<RepositoryAttestationTrustPolicy | null>(null);
  const [form, setForm] = useState<PolicyFormState>(DEFAULT_FORM);
  // Editor lives in a drawer (progressive disclosure): closed while browsing,
  // opened by "New policy" / row Edit. openEditor(null) = create, openEditor(p) = edit.
  const [editorOpen, setEditorOpen] = useState(false);
  const openEditor = (policy: RepositoryAttestationTrustPolicy | null) => {
    setEditing(policy);
    setForm(policy ? policyToForm(policy) : DEFAULT_FORM);
    setEditorOpen(true);
  };
  const policiesQ = useQuery({
    queryKey: ["attestation-trust-policies"],
    queryFn: () => repositoryScanAttestationTrustPolicies.list(),
  });
  const policies = policiesQ.data?.policies ?? [];
  const stats = useMemo(() => summarizePolicies(policies), [policies]);

  const savePolicy = useMutation({
    mutationFn: () => {
      const input = formToPolicyInput(form);
      if (editing) {
        return repositoryScanAttestationTrustPolicies.update(editing.id, input);
      }
      return repositoryScanAttestationTrustPolicies.create(input);
    },
    onSuccess: (resp) => {
      toast.success(editing ? "Trust policy updated" : "Trust policy created");
      setEditing(resp.policy);
      setForm(policyToForm(resp.policy));
      setEditorOpen(false);
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: any) => toast.error(`Save failed: ${errorMessage(err)}`),
  });

  const quickUpdate = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<RepositoryAttestationTrustPolicyInput> }) =>
      repositoryScanAttestationTrustPolicies.update(id, patch),
    onSuccess: () => {
      toast.success("Policy updated");
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: any) => toast.error(`Update failed: ${errorMessage(err)}`),
  });

  const removePolicy = useMutation({
    mutationFn: (id: string) => repositoryScanAttestationTrustPolicies.remove(id),
    onSuccess: () => {
      toast.success("Trust policy deleted");
      setEditing(null);
      setForm(DEFAULT_FORM);
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: any) => toast.error(`Delete failed: ${errorMessage(err)}`),
  });

  const verifyPending = useMutation({
    mutationFn: (id: string) => repositoryScanAttestationTrustPolicies.verifyPending(id, { limit: 50 }),
    onSuccess: (resp) => {
      toast.success(`Verified ${resp.verified} attestations; ${resp.trusted} trusted`);
      void qc.invalidateQueries({ queryKey: ["attestation-trust-policies"] });
      void qc.invalidateQueries({ queryKey: ["repository-scans"] });
    },
    onError: (err: any) => toast.error(`Verification failed: ${errorMessage(err)}`),
  });

  const busy = quickUpdate.isPending || removePolicy.isPending || verifyPending.isPending;
  const policyColumns: Column<RepositoryAttestationTrustPolicy>[] = [
    {
      id: "policy",
      header: "Policy",
      className: "align-top",
      cell: (policy) => (
        <>
          <div className="font-medium">{policy.name}</div>
          <div className="mt-1 break-words text-xs text-muted-foreground">{policy.description || "No description"}</div>
          <div className="mt-2 flex flex-wrap gap-1">
            <StatusPill active={policy.enabled} label={policy.enabled ? "enabled" : "disabled"} />
            <StatusPill active={policy.auto_verify} label={policy.auto_verify ? "auto" : "manual"} />
            <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">{policy.verifier_mode || "keyless"}</span>
            {policy.require_rekor ? <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">rekor</span> : null}
          </div>
        </>
      ),
    },
    {
      id: "scope",
      header: "Scope",
      className: "align-top text-xs",
      cell: (policy) => (
        <>
          <div className="font-mono">{policy.subject_kind}</div>
          <div className="mt-1 text-muted-foreground">{policy.source_types.length ? policy.source_types.join(", ") : "all sources"}</div>
          <div className="mt-1 text-muted-foreground">{policy.repository_ref_patterns.length} repo patterns</div>
        </>
      ),
    },
    {
      id: "trust",
      header: "Trust",
      className: "align-top text-xs",
      cell: (policy) => (
        <>
          <div>{firstOrCount(policy.predicate_types)}</div>
          {policy.verifier_mode === "public-key" ? (
            <div className="mt-1 text-muted-foreground">public key</div>
          ) : (
            <>
              <div className="mt-1 text-muted-foreground">{policy.allowed_identities.length} identities</div>
              <div className="mt-1 text-muted-foreground">{policy.allowed_issuers.length} issuers</div>
            </>
          )}
        </>
      ),
    },
    {
      id: "actions",
      header: "Actions",
      className: "align-top text-right",
      cell: (policy) => (
        <div className="flex justify-end gap-1">
          <IconButton label={policy.enabled ? "Disable policy" : "Enable policy"} disabled={busy} onClick={() => quickUpdate.mutate({ id: policy.id, patch: { enabled: !policy.enabled } })}>
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label={policy.auto_verify ? "Disable auto verify" : "Enable auto verify"} disabled={busy} onClick={() => quickUpdate.mutate({ id: policy.id, patch: { auto_verify: !policy.auto_verify } })}>
            <BadgeCheck className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Verify pending attestations" disabled={busy || !policy.enabled} onClick={() => verifyPending.mutate(policy.id)}>
            <RefreshCw className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Edit policy" disabled={busy} onClick={() => openEditor(policy)}>
            <Edit2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
          <IconButton label="Delete policy" disabled={busy} onClick={() => { if (window.confirm(`Delete "${policy.name}"? Existing attestation links will no longer satisfy admission.`)) { removePolicy.mutate(policy.id); } }}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6" data-testid="attestation-trust-page">
      <PageHeader
        eyebrow={
          <Link to="/settings" className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> Back to Settings
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" aria-hidden />
            Attestation trust
          </span>
        }
        description="Verify that container images are signed by a source you trust before they're allowed to run (Sigstore/cosign, SLSA provenance)."
        actions={
          <button
            type="button"
            onClick={() => openEditor(null)}
            className="inline-flex items-center gap-2 rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90"
            data-testid="attestation-trust-new"
          >
            <Plus className="h-4 w-4" aria-hidden />
            New policy
          </button>
        }
      />

      <section className="grid gap-3 sm:grid-cols-3">
        <Metric label="Policies" value={stats.total} icon={Fingerprint} />
        <Metric label="Enabled" value={stats.enabled} icon={CheckCircle2} />
        <Metric label="Auto verify" value={stats.autoVerify} icon={BadgeCheck} />
      </section>

      <section>
        <div className="overflow-hidden rounded-lg border border-border bg-card" data-testid="attestation-trust-table">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <h2 className="text-sm font-medium">Trust policies</h2>
            <button
              type="button"
              onClick={() => policiesQ.refetch()}
              disabled={policiesQ.isFetching}
              className="inline-flex items-center gap-1 rounded-md border border-border px-2.5 py-1.5 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${policiesQ.isFetching ? "animate-spin" : ""}`} aria-hidden />
              Refresh
            </button>
          </div>
          {policiesQ.isLoading ? (
            <div className="p-6 text-sm text-muted-foreground">Loading policies…</div>
          ) : policiesQ.error ? (
            <div className="p-6 text-sm text-destructive">Failed to load trust policies.</div>
          ) : policies.length === 0 ? (
            <div className="p-6 text-sm text-muted-foreground">No attestation trust policies yet.</div>
          ) : (
            <>
              <div className="divide-y divide-border md:hidden">
                {policies.map((policy) => (
                  <PolicyCard
                    key={policy.id}
                    policy={policy}
                    selected={editing?.id === policy.id}
                    busy={quickUpdate.isPending || removePolicy.isPending || verifyPending.isPending}
                    onEdit={() => openEditor(policy)}
                    onToggleEnabled={() => quickUpdate.mutate({ id: policy.id, patch: { enabled: !policy.enabled } })}
                    onToggleAuto={() => quickUpdate.mutate({ id: policy.id, patch: { auto_verify: !policy.auto_verify } })}
                    onVerify={() => verifyPending.mutate(policy.id)}
                    onDelete={() => {
                      if (window.confirm(`Delete "${policy.name}"? Existing attestation links will no longer satisfy admission.`)) {
                        removePolicy.mutate(policy.id);
                      }
                    }}
                  />
                ))}
              </div>
              <div className="hidden md:block">
                <DataTable
                  rows={policies}
                  columns={policyColumns}
                  rowKey={(policy) => policy.id}
                  selected={new Set(editing ? [editing.id] : [])}
                />
              </div>
            </>
          )}
        </div>

      </section>

      <Drawer
        open={editorOpen}
        onOpenChange={setEditorOpen}
        title={editing ? "Edit trust policy" : "New trust policy"}
        description="Verify an image's signature/attestation before it's allowed to run."
      >
        <PolicyEditor
          form={form}
          editing={editing}
          saving={savePolicy.isPending}
          onChange={setForm}
          onSubmit={() => savePolicy.mutate()}
        />
      </Drawer>
    </div>
  );
}

function PolicyCard({
  policy,
  selected,
  busy,
  onEdit,
  onToggleEnabled,
  onToggleAuto,
  onVerify,
  onDelete,
}: {
  policy: RepositoryAttestationTrustPolicy;
  selected: boolean;
  busy: boolean;
  onEdit: () => void;
  onToggleEnabled: () => void;
  onToggleAuto: () => void;
  onVerify: () => void;
  onDelete: () => void;
}) {
  return (
    <article className={`space-y-3 p-4 ${selected ? "bg-accent/40" : ""}`} data-testid="attestation-trust-row">
      <div>
        <div className="font-medium">{policy.name}</div>
        <div className="mt-1 break-words text-xs text-muted-foreground">{policy.description || "No description"}</div>
      </div>
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <div className="text-muted-foreground">Scope</div>
          <div className="mt-1 font-mono">{policy.subject_kind}</div>
          <div className="mt-1 break-words">{policy.source_types.length ? policy.source_types.join(", ") : "all sources"}</div>
        </div>
        <div>
          <div className="text-muted-foreground">Trust</div>
          <div className="mt-1 break-words">{firstOrCount(policy.predicate_types)}</div>
          <div className="mt-1 text-muted-foreground">
            {policy.verifier_mode === "public-key" ? "public key" : `${policy.allowed_identities.length} identities · ${policy.allowed_issuers.length} issuers`}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap gap-1">
        <StatusPill active={policy.enabled} label={policy.enabled ? "enabled" : "disabled"} />
        <StatusPill active={policy.auto_verify} label={policy.auto_verify ? "auto" : "manual"} />
        <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">{policy.verifier_mode || "keyless"}</span>
        {policy.require_rekor ? <span className="rounded-md bg-muted px-1.5 py-0.5 text-[10px]">rekor</span> : null}
      </div>
      <div className="flex flex-wrap gap-1">
        <IconButton label={policy.enabled ? "Disable policy" : "Enable policy"} disabled={busy} onClick={onToggleEnabled}>
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label={policy.auto_verify ? "Disable auto verify" : "Enable auto verify"} disabled={busy} onClick={onToggleAuto}>
          <BadgeCheck className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label="Verify pending attestations" disabled={busy || !policy.enabled} onClick={onVerify}>
          <RefreshCw className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label="Edit policy" disabled={busy} onClick={onEdit}>
          <Edit2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
        <IconButton label="Delete policy" disabled={busy} onClick={onDelete}>
          <Trash2 className="h-3.5 w-3.5" aria-hidden />
        </IconButton>
      </div>
    </article>
  );
}

function PolicyEditor({
  form,
  editing,
  saving,
  onChange,
  onSubmit,
}: {
  form: PolicyFormState;
  editing: RepositoryAttestationTrustPolicy | null;
  saving: boolean;
  onChange: (next: PolicyFormState) => void;
  onSubmit: () => void;
}) {
  const set = <K extends keyof PolicyFormState>(key: K, value: PolicyFormState[K]) => onChange({ ...form, [key]: value });
  return (
    <form
      data-testid="attestation-trust-editor"
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit();
      }}
    >
      {editing ? (
        <div className="mb-3 break-all font-mono text-[10px] text-muted-foreground">{editing.id}</div>
      ) : null}

      <div className="space-y-3">
        <Label text="Name">
          <input
            value={form.name}
            onChange={(event) => set("name", event.target.value)}
            className="mt-1 w-full rounded-md border border-border bg-background p-2 text-sm"
            required
            data-testid="attestation-trust-name"
          />
        </Label>

        <Label text="Description">
          <textarea
            value={form.description}
            onChange={(event) => set("description", event.target.value)}
            rows={2}
            className="mt-1 w-full rounded-md border border-border bg-background p-2 text-sm"
          />
        </Label>

        <div className="grid gap-2 sm:grid-cols-2">
          <Toggle label="Enabled" checked={form.enabled} onChange={(checked) => set("enabled", checked)} />
          <Toggle label="Auto verify" checked={form.auto_verify} onChange={(checked) => set("auto_verify", checked)} />
        </div>

        <Label text="Verifier">
          <select
            value={form.verifier_mode}
            onChange={(event) => set("verifier_mode", event.target.value as PolicyFormState["verifier_mode"])}
            className="mt-1 w-full rounded-md border border-border bg-background p-2 text-sm"
          >
            <option value="keyless">keyless (Sigstore OIDC identity)</option>
            <option value="public-key">public key (cosign)</option>
          </select>
        </Label>

        <div>
          <div className="mb-1 text-xs font-medium">Sources</div>
          <div className="grid grid-cols-2 gap-1">
            {SOURCE_TYPES.map((sourceType) => (
              <label key={sourceType} className="flex items-center gap-2 rounded-md border border-border px-2 py-1.5 text-xs">
                <input
                  type="checkbox"
                  checked={form.source_types.includes(sourceType)}
                  onChange={(event) => {
                    const next = event.target.checked
                      ? [...form.source_types, sourceType]
                      : form.source_types.filter((item) => item !== sourceType);
                    set("source_types", next);
                  }}
                />
                {sourceType}
              </label>
            ))}
          </div>
        </div>

        {form.verifier_mode === "public-key" ? (
          <TextList label="Cosign public key" value={form.public_key_pem} onChange={(value) => set("public_key_pem", value)} required />
        ) : (
          <>
            <TextList label="Allowed identities" value={form.allowed_identities} onChange={(value) => set("allowed_identities", value)} required />
            <TextList label="Allowed issuers" value={form.allowed_issuers} onChange={(value) => set("allowed_issuers", value)} required />
          </>
        )}

        <Collapse label="Advanced">
          <div className="space-y-3">
            <Toggle label="Require Rekor transparency log" checked={form.require_rekor} onChange={(checked) => set("require_rekor", checked)} />
            <TextList label="Repository patterns" value={form.repository_ref_patterns} onChange={(value) => set("repository_ref_patterns", value)} />
            <TextList label="Source ref patterns" value={form.source_ref_patterns} onChange={(value) => set("source_ref_patterns", value)} />
            <TextList label="Predicate types" value={form.predicate_types} onChange={(value) => set("predicate_types", value)} required />
          </div>
        </Collapse>

        <button
          type="submit"
          disabled={saving}
          className="inline-flex w-full items-center justify-center gap-2 rounded-md border border-border bg-primary px-3 py-2 text-sm font-medium text-primary-foreground shadow-sm hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="attestation-trust-save"
        >
          <Save className="h-4 w-4" aria-hidden />
          {saving ? "Saving…" : "Save policy"}
        </button>
      </div>
    </form>
  );
}

function TextList({
  label,
  value,
  onChange,
  required,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  required?: boolean;
}) {
  return (
    <Label text={label}>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        rows={3}
        required={required}
        spellCheck={false}
        className="mt-1 w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
      />
    </Label>
  );
}

function Metric({ label, value, icon: Icon }: { label: string; value: number; icon: typeof Fingerprint }) {
  return (
    <div className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Icon className="h-4 w-4" aria-hidden />
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold">{value}</div>
    </div>
  );
}

function StatusPill({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`rounded-md px-1.5 py-0.5 text-[10px] ${active ? "bg-status-success/10 text-status-success" : "bg-muted text-muted-foreground"}`}>
      {label}
    </span>
  );
}

function IconButton({
  label,
  disabled,
  onClick,
  children,
}: {
  label: string;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      title={label}
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
      className="inline-flex h-8 w-8 items-center justify-center rounded-md border border-border hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
    >
      {children}
    </button>
  );
}

function Label({ text, children }: { text: string; children: React.ReactNode }) {
  return (
    <label className="block text-xs font-medium">
      {text}
      {children}
    </label>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2 text-xs font-medium">
      {label}
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
    </label>
  );
}

function summarizePolicies(policies: RepositoryAttestationTrustPolicy[]) {
  return {
    total: policies.length,
    enabled: policies.filter((policy) => policy.enabled).length,
    autoVerify: policies.filter((policy) => policy.enabled && policy.auto_verify).length,
  };
}

function policyToForm(policy: RepositoryAttestationTrustPolicy): PolicyFormState {
  return {
    name: policy.name,
    description: policy.description,
    enabled: policy.enabled,
    auto_verify: policy.auto_verify,
    subject_kind: "image",
    source_types: policy.source_types,
    repository_ref_patterns: listToText(policy.repository_ref_patterns),
    source_ref_patterns: listToText(policy.source_ref_patterns),
    predicate_types: listToText(policy.predicate_types),
    allowed_identities: listToText(policy.allowed_identities),
    allowed_issuers: listToText(policy.allowed_issuers),
    require_rekor: policy.require_rekor,
    verifier_mode: policy.verifier_mode || "keyless",
    public_key_pem: policy.public_key_pem || "",
  };
}

function formToPolicyInput(form: PolicyFormState): RepositoryAttestationTrustPolicyInput {
  return {
    name: form.name.trim(),
    description: form.description.trim(),
    enabled: form.enabled,
    auto_verify: form.auto_verify,
    subject_kind: form.subject_kind,
    source_types: uniqueList(form.source_types),
    repository_ref_patterns: textToList(form.repository_ref_patterns),
    source_ref_patterns: textToList(form.source_ref_patterns),
    predicate_types: textToList(form.predicate_types),
    allowed_identities: form.verifier_mode === "public-key" ? [] : textToList(form.allowed_identities),
    allowed_issuers: form.verifier_mode === "public-key" ? [] : textToList(form.allowed_issuers),
    require_rekor: form.require_rekor,
    verifier_mode: form.verifier_mode,
    public_key_pem: form.verifier_mode === "public-key" ? form.public_key_pem.trim() : "",
  };
}

function listToText(values: string[]): string {
  return values.join("\n");
}

function textToList(value: string): string[] {
  return uniqueList(value.split(/[\n,]/g));
}

function uniqueList(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of values) {
    const value = raw.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    out.push(value);
  }
  return out;
}

function firstOrCount(values: string[]): string {
  if (values.length === 0) return "none";
  if (values.length === 1) return values[0];
  return `${values[0]} +${values.length - 1}`;
}

function errorMessage(err: any): string {
  return String(err?.response?.data ?? err?.message ?? err);
}
